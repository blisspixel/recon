"""Run the full discovery scan: corpus → results → gaps → candidates → diff.

Wraps run_corpus.py + find_gaps.py + triage_candidates.py + diff_runs.py
into one timestamped invocation suitable for monthly cadence. Use this when
you want to track catalog drift over time:

    # Saturday morning, monthly cadence:
    python validation/scan.py --corpus validation/corpus-private/consolidated.txt

A run directory is created at ``validation/runs-private/<UTC-stamp>/`` with:
  * ``results.ndjson`` - default raw batch stream (``results.json`` with ``--json-array``)
  * ``gaps.json``    - bucketed unclassified terminals
  * ``candidates.json`` - pre-filtered triage list (intra-org / covered dropped)
  * ``meta.json``    - scan metadata (timestamp, private corpus path, normalized counts, ...)
  * ``diff.json``    - only when --compare-to is provided; per-domain deltas

The ``meta.json`` shape lets ``recon`` (or any tool) answer "when was this
scanned, what was found?" without re-running. Subsequent scans use
``--compare-to <prior-run>`` to surface drift.

This is the framework that anyone can use; the corpus and run outputs stay
local under ``validation/corpus-private/`` and ``validation/runs-private/``
(gitignored).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent

_PRIVATE_SCAN_OUTPUT_ROOTS = (
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "live_runs",
    REPO_ROOT / "validation" / "local",
)


class BatchRunResult(NamedTuple):
    results_path: Path
    completed: bool
    timed_out: bool


class CorpusStats(NamedTuple):
    input_rows: int
    scheduled_domains: int
    duplicate_rows_removed: int
    invalid_rows: int


class FinalizeContext(NamedTuple):
    results_path: Path
    run_dir: Path
    stamp: str
    output_root: Path
    compare_to: Path | None
    no_compare: bool
    ct: bool
    label: str
    corpus: Path
    corpus_input_rows: int
    domain_count: int
    duplicate_rows_removed: int
    invalid_rows: int
    concurrency: int
    timeout: float
    max_runtime: float | None
    min_count: int
    batch_completed: bool
    batch_timed_out: bool
    started_utc: str


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%SZ")


def _validate_scan_output_root(output_root: Path) -> Path:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from validation.run_path_safety import validate_private_output_root

    return validate_private_output_root(
        output_root,
        repo_root=REPO_ROOT,
        allowed_roots=_PRIVATE_SCAN_OUTPUT_ROOTS,
    )


def _validate_private_run_dir(run_dir: Path) -> Path:
    resolved = run_dir.resolve(strict=False)
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError:
        return resolved
    allowed = tuple(root.resolve(strict=False) for root in _PRIVATE_SCAN_OUTPUT_ROOTS)
    if any(resolved == root or resolved.is_relative_to(root) for root in allowed):
        return resolved
    allowed_text = ", ".join(str(root.relative_to(REPO_ROOT)) for root in _PRIVATE_SCAN_OUTPUT_ROOTS)
    raise ValueError(f"run directory inside this checkout must be under one of: {allowed_text}")


def _validate_private_scan_input_path(path: Path) -> Path:
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError:
        return resolved
    allowed = tuple(root.resolve(strict=False) for root in _PRIVATE_SCAN_OUTPUT_ROOTS)
    if any(resolved == root or resolved.is_relative_to(root) for root in allowed):
        return resolved
    allowed_text = ", ".join(str(root.relative_to(REPO_ROOT)) for root in _PRIVATE_SCAN_OUTPUT_ROOTS)
    raise ValueError(f"private validation input inside this checkout must be under one of: {allowed_text}")


def _corpus_stats(corpus: Path) -> CorpusStats:
    """Mirror batch normalization and deduplication without exposing inputs."""
    if not corpus.exists():
        return CorpusStats(0, 0, 0, 0)

    from recon_tool.validator import validate_domain

    rows = [
        line.strip()
        for line in corpus.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    seen: set[tuple[str, str]] = set()
    invalid_rows = 0
    for row in rows:
        normalized_raw = row.lower().strip()
        try:
            dedupe_key = ("valid", validate_domain(row))
        except ValueError:
            invalid_rows += 1
            dedupe_key = ("invalid", normalized_raw)
        seen.add(dedupe_key)
    return CorpusStats(
        input_rows=len(rows),
        scheduled_domains=len(seen),
        duplicate_rows_removed=len(rows) - len(seen),
        invalid_rows=invalid_rows,
    )


def _count_result_records(results_path: Path) -> int:
    return sum(1 for _ in _iter_result_records(results_path))


def _iter_result_records(results_path: Path) -> Iterator[dict[str, Any]]:
    """Yield result records from NDJSON or JSON-array output.

    NDJSON can have a malformed final line after an external interrupt; skip
    malformed lines so partial-run finalization and CT retry synthesis keep the
    valid streamed prefix.
    """
    if not results_path.exists():
        return
    if results_path.suffix == ".ndjson":
        with contextlib.suppress(OSError), results_path.open(encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                with contextlib.suppress(ValueError):
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        yield parsed
        return
    with contextlib.suppress(OSError, ValueError):
        parsed_json = json.loads(results_path.read_text(encoding="utf-8"))
        if isinstance(parsed_json, list):
            for item in parsed_json:
                if isinstance(item, dict):
                    yield item
        elif isinstance(parsed_json, dict):
            yield parsed_json


def _find_results_path(run_dir: Path) -> Path | None:
    for name in ("results.ndjson", "results.json"):
        candidate = run_dir / name
        if candidate.exists():
            return candidate
    return None


def _write_ct_budget_summary(results_path: Path, run_dir: Path) -> None:
    """Emit a ct_budget_summary.json summarising the CT pipeline outcome.

    Two inputs feed the summary:
      1. Per-domain ``ct_attempt_outcome`` values from the just-completed
         batch (counts each enum value).
      2. The persisted adaptive-limiter state under
         ``~/.recon/rate-limit-state`` (post-run interval, breaker
         status, success / rate_limit / failure tallies).

    The result is an operator-facing tally that answers "what did the
    CT pipeline actually do this run?" without needing to scan the
    NDJSON by hand.
    """
    outcome_counts: dict[str, int] = {}
    total = 0

    def _tally(rec: dict[str, Any]) -> None:
        nonlocal total
        total += 1
        outcome = rec.get("ct_attempt_outcome") or "not_attempted"
        outcome_counts[str(outcome)] = outcome_counts.get(str(outcome), 0) + 1

    for rec in _iter_result_records(results_path):
        _tally(rec)

    # Pick up the persisted rate-limiter snapshots written by the
    # batch subprocess. The state files live in the operator's recon
    # config dir; if RECON_CONFIG_DIR is set we read from there.
    rl_dir_env = os.environ.get("RECON_CONFIG_DIR")
    rl_root = Path(rl_dir_env) if rl_dir_env else Path.home() / ".recon"
    rl_dir = rl_root / "rate-limit-state"
    limiter_snapshots: dict[str, dict[str, Any]] = {}
    if rl_dir.exists():
        for state_file in sorted(rl_dir.glob("*.json")):
            with contextlib.suppress(OSError, ValueError):
                limiter_snapshots[state_file.stem] = json.loads(state_file.read_text(encoding="utf-8"))

    summary = {
        "records_total": total,
        "outcome_counts": outcome_counts,
        "limiter_snapshots": limiter_snapshots,
        "written_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    (run_dir / "ct_budget_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    # Short stdout note so the operator sees the headline.
    cache_n = outcome_counts.get("cache_hit", 0)
    live_n = outcome_counts.get("live_success", 0)
    rl_n = outcome_counts.get("live_rate_limited", 0)
    br_n = outcome_counts.get("breaker_open", 0)
    cmiss_n = outcome_counts.get("cache_miss", 0)
    print(
        f"  ct_budget_summary: {total} records - "
        f"cache_hit={cache_n} live_success={live_n} "
        f"rate_limited={rl_n} breaker_open={br_n} cache_miss={cmiss_n}",
        flush=True,
    )


def _run_step(cmd: list[str], description: str) -> None:
    print(f"  {description} ...", flush=True)
    # S603 noqa: arg list is constructed locally from validated paths.
    result = subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), check=False
    )
    if result.returncode != 0:
        print(f"    FAILED: {result.stderr.strip() or result.stdout.strip()}", file=sys.stderr)
        raise SystemExit(2)


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        taskkill = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
        subprocess.run(  # noqa: S603 - fixed Windows process-tree terminator argv
            [str(taskkill), "/PID", str(proc.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the full discovery scan: corpus to results to gaps to candidates to diff."
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help=(
            "Corpus file (one domain per line). Recommend a curated, gitignored list under validation/corpus-private/."
        ),
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPO_ROOT / "validation" / "runs-private",
        help="Where to create the timestamped run directory.",
    )
    parser.add_argument(
        "--label",
        type=str,
        default="",
        help="Optional human-readable label written into meta.json (e.g. 'monthly-2026-05').",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Batch concurrency (default 4 with --no-ct keeps DNS load polite).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Per-domain resolve timeout seconds passed to recon batch.",
    )
    parser.add_argument(
        "--max-runtime",
        type=float,
        default=None,
        help=(
            "Optional wall-clock seconds for the batch subprocess. When reached, "
            "the streamed NDJSON records are finalized as a partial scan."
        ),
    )
    parser.add_argument(
        "--finalize-existing",
        type=Path,
        default=None,
        help=(
            "No network: finalize an existing run directory that already contains "
            "results.ndjson or results.json. Useful after an interrupted partial CT session."
        ),
    )
    parser.add_argument(
        "--ct",
        action="store_true",
        help="Hit cert-transparency providers. Default is --no-ct because corpus runs are typically large.",
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=3,
        help="Drop suffixes seen fewer than N times in the candidates list (default 3).",
    )
    parser.add_argument(
        "--compare-to",
        type=Path,
        default=None,
        help="Prior run directory to diff against. Defaults to the latest run if any exists.",
    )
    parser.add_argument(
        "--no-compare",
        action="store_true",
        help="Skip the diff step even if a prior run exists.",
    )
    parser.add_argument(
        "--json-array",
        action="store_true",
        help=(
            "Use the legacy single-JSON-array output (recon batch --json) "
            "instead of the streaming NDJSON default. Slower for big "
            "corpora because everything buffers until completion; useful "
            "if a downstream consumer expects an array."
        ),
    )
    parser.add_argument(
        "--ct-retry-from",
        type=Path,
        default=None,
        help=(
            "Read a prior run's results.ndjson and re-resolve only the "
            "records where ct_attempt_outcome indicates a degradation "
            "(live_rate_limited, breaker_open, live_other_failure, "
            "cache_miss). Multi-session corpus enumeration: chain calls "
            "across days to build CT coverage without re-fetching "
            "domains that already succeeded. Implies --ct."
        ),
    )
    return parser


def _validate_cli_options(args: argparse.Namespace) -> None:
    """Reject option combinations that cannot produce coherent scan metadata."""
    if args.finalize_existing is not None and args.ct_retry_from is not None:
        raise ValueError("--finalize-existing cannot be combined with --ct-retry-from")
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than 0")
    if args.max_runtime is not None and args.max_runtime <= 0:
        raise ValueError("--max-runtime must be greater than 0")
    if args.max_runtime is not None and args.json_array:
        raise ValueError("--max-runtime requires streaming NDJSON; remove --json-array")


def _synthesize_ct_retry_corpus(retry_from: Path, output_root: Path) -> Path:
    """Build a filtered corpus of only the CT-degraded domains from a prior run.

    Reads the prior run's ``results.ndjson``, collects the domains whose
    ``ct_attempt_outcome`` shows a degradation, and writes them to a
    synthesized corpus file whose path is returned. Exits with code 2 on a bad
    path and with code 0 (nothing to do) when no degraded records are found.
    The caller treats this as implying ``--ct``.
    """
    if not retry_from.exists():
        print(f"error: --ct-retry-from path not found: {retry_from}", file=sys.stderr)
        raise SystemExit(2)
    prior = retry_from
    if prior.is_dir():
        prior_results = _find_results_path(prior)
        if prior_results is None:
            print(f"error: no results.ndjson or results.json in {retry_from}", file=sys.stderr)
            raise SystemExit(2)
        prior = prior_results
    if not prior.exists():
        print(f"error: results file not found in {retry_from}", file=sys.stderr)
        raise SystemExit(2)
    degraded_outcomes = {
        "live_rate_limited",
        "breaker_open",
        "live_other_failure",
        "cache_miss",
    }
    degraded_domains: list[str] = []
    seen_domains: set[str] = set()
    from recon_tool.validator import validate_domain

    for rec in _iter_result_records(prior):
        outcome = rec.get("ct_attempt_outcome")
        dom = rec.get("queried_domain")
        if outcome not in degraded_outcomes or not isinstance(dom, str) or not dom:
            continue
        with contextlib.suppress(ValueError):
            validated = validate_domain(dom)
            if validated not in seen_domains:
                degraded_domains.append(validated)
                seen_domains.add(validated)
    if not degraded_domains:
        print("--ct-retry-from: no degraded records in prior run; nothing to retry")
        raise SystemExit(0)
    retry_inputs_dir = output_root / "_inputs"
    retry_inputs_dir.mkdir(parents=True, exist_ok=True)
    synth = retry_inputs_dir / f"ct-retry-{datetime.now(UTC).strftime('%Y%m%d-%H%M%SZ')}.txt"
    synth.parent.mkdir(parents=True, exist_ok=True)
    synth.write_text("\n".join(degraded_domains) + "\n", encoding="utf-8")
    print(
        f"--ct-retry-from {retry_from}: re-running CT for "
        f"{len(degraded_domains)} degraded domains via {synth}"
    )
    return synth


def _run_batch(
    corpus: Path,
    run_dir: Path,
    *,
    args: argparse.Namespace,
    domain_count: int,
) -> BatchRunResult:
    """Run the recon batch resolve, streaming output into the run directory.

    Default is NDJSON streaming (one line per domain, flushed as completed) so
    very large corpora stay memory-bounded and produce visible progress;
    ``--json-array`` opts back into the legacy single-array output. Returns the
    results path plus completion status; exits with code 2 if the batch
    subprocess fails for anything other than an explicit ``--max-runtime`` stop.
    """
    output_mode = "--json" if args.json_array else "--ndjson"
    batch_cmd = [
        sys.executable,
        "-m",
        "recon_tool.cli",
        "batch",
        str(corpus),
        output_mode,
        "--include-unclassified",
        "--concurrency",
        str(args.concurrency),
        "--timeout",
        str(args.timeout),
    ]
    if not args.ct:
        batch_cmd.append("--no-ct")

    ct_str = "on" if args.ct else "off"
    fmt_str = "json-array" if args.json_array else "ndjson"
    print(
        f"  resolving {domain_count} domains "
        f"(concurrency={args.concurrency}, timeout={args.timeout:g}s, ct={ct_str}, format={fmt_str}) ...",
        flush=True,
    )
    results_path = run_dir / ("results.json" if args.json_array else "results.ndjson")
    with results_path.open("w", encoding="utf-8") as out:
        popen_kwargs: dict[str, Any] = {}
        if os.name != "nt":
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(  # noqa: S603 - arg list constructed locally
            batch_cmd,
            stdout=out,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO_ROOT),
            **popen_kwargs,
        )
        try:
            _, stderr_text = proc.communicate(timeout=args.max_runtime)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.communicate(timeout=5)
            runtime_text = f"{args.max_runtime:g}" if args.max_runtime is not None else "unknown"
            print(
                f"    partial: max runtime {runtime_text}s reached; finalizing streamed records",
                flush=True,
            )
            return BatchRunResult(results_path=results_path, completed=False, timed_out=True)
    if proc.returncode != 0:
        print(f"    FAILED: {stderr_text.strip()}", file=sys.stderr)
        raise SystemExit(2)
    return BatchRunResult(results_path=results_path, completed=True, timed_out=False)


def _maybe_run_diff(
    results_path: Path,
    run_dir: Path,
    stamp: str,
    *,
    output_root: Path,
    compare_to: Path | None,
    no_compare: bool,
) -> tuple[Path | None, Path | None]:
    """Diff this run against a prior one. Returns ``(diff_path, compare_target)``.

    Picks the most recent prior run when ``--compare-to`` is not given, unless
    ``--no-compare`` is set. ``diff_path`` is set only when a diff actually ran;
    ``compare_target`` reflects the run that was (or would have been) compared.
    """
    diff_path: Path | None = None
    compare_target = compare_to
    if compare_target is None and not no_compare:
        # Pick the most recent existing run that isn't this one.
        prior_candidates = [p for p in sorted(output_root.iterdir()) if p.is_dir() and p.name != stamp]
        if prior_candidates:
            compare_target = prior_candidates[-1]

    if compare_target is not None and not no_compare:
        # Prior runs may have written either ``results.ndjson`` (current
        # default) or ``results.json`` (legacy ``--json-array``); accept both.
        prior_ndjson = compare_target / "results.ndjson"
        prior_json = compare_target / "results.json"
        prior_results = prior_ndjson if prior_ndjson.exists() else prior_json
        if prior_results.exists():
            diff_path = run_dir / "diff.json"
            _run_step(
                [
                    sys.executable,
                    "validation/diff_runs.py",
                    "--before",
                    str(prior_results),
                    "--after",
                    str(results_path),
                    "--output",
                    str(diff_path),
                ],
                f"diff_runs vs {compare_target.name}",
            )
        else:
            print(f"  skipping diff: no results.ndjson or results.json in {compare_target}")
            diff_path = None
    return diff_path, compare_target


def _finalize_scan(ctx: FinalizeContext) -> None:
    if ctx.ct:
        _write_ct_budget_summary(ctx.results_path, ctx.run_dir)

    _run_step(
        [
            sys.executable,
            "validation/find_gaps.py",
            "--input",
            str(ctx.results_path),
            "--output",
            str(ctx.run_dir / "gaps.json"),
            "--samples",
            "10",
        ],
        "find_gaps",
    )

    _run_step(
        [
            sys.executable,
            "validation/triage_candidates.py",
            "--gaps",
            str(ctx.run_dir / "gaps.json"),
            "--fingerprints",
            "src/recon_tool/data/fingerprints/",
            "--output",
            str(ctx.run_dir / "candidates.json"),
            "--min-count",
            str(ctx.min_count),
        ],
        "triage_candidates",
    )

    skip_diff = ctx.no_compare or not ctx.batch_completed
    if not ctx.batch_completed and not ctx.no_compare:
        print("  skipping diff: partial scan; compare only after a complete run")
    diff_path, compare_target = _maybe_run_diff(
        ctx.results_path,
        ctx.run_dir,
        ctx.stamp,
        output_root=ctx.output_root,
        compare_to=ctx.compare_to,
        no_compare=skip_diff,
    )

    gaps_count = 0
    candidates_count = 0
    with contextlib.suppress(OSError, json.JSONDecodeError):
        gaps_count = len(json.loads((ctx.run_dir / "gaps.json").read_text(encoding="utf-8")))
    with contextlib.suppress(OSError, json.JSONDecodeError):
        candidates_count = len(json.loads((ctx.run_dir / "candidates.json").read_text(encoding="utf-8")))

    completed_records = _count_result_records(ctx.results_path)
    meta: dict[str, Any] = {
        "scan_stamp": ctx.stamp,
        "scan_started_utc": ctx.started_utc,
        "scan_finalized_utc": datetime.now(UTC).isoformat(),
        "label": ctx.label,
        "corpus_path": str(ctx.corpus),
        "corpus_input_rows": ctx.corpus_input_rows,
        "domain_count": ctx.domain_count,
        "duplicate_rows_removed": ctx.duplicate_rows_removed,
        "invalid_rows": ctx.invalid_rows,
        "results_records": completed_records,
        "batch_completed": ctx.batch_completed,
        "batch_timed_out": ctx.batch_timed_out,
        "batch_timeout_seconds": ctx.timeout,
        "batch_max_runtime_seconds": ctx.max_runtime,
        "concurrency": ctx.concurrency,
        "ct_enabled": bool(ctx.ct),
        "gaps_total": gaps_count,
        "candidates_after_triage": candidates_count,
        "compared_to": str(compare_target) if compare_target else None,
        "diff_path": str(diff_path) if diff_path else None,
    }
    (ctx.run_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    completion = "complete" if ctx.batch_completed else "partial"
    print()
    print(
        f"Scan {completion}: {completed_records}/{ctx.domain_count} records, "
        f"{gaps_count} gaps, {candidates_count} candidates after triage"
    )
    print(f"  results:    {ctx.results_path}")
    print(f"  gaps:       {ctx.run_dir / 'gaps.json'}")
    print(f"  candidates: {ctx.run_dir / 'candidates.json'}")
    if diff_path:
        print(f"  diff:       {diff_path}")
    print(f"  meta:       {ctx.run_dir / 'meta.json'}")
    if candidates_count > 0:
        print()
        print("Next: hand candidates.json to the /recon-fingerprint-triage skill,")
        print("or open it in your editor and triage by hand.")


def main() -> None:
    args = _build_parser().parse_args()
    try:
        args.output_root = _validate_scan_output_root(args.output_root)
        if args.finalize_existing is not None:
            args.finalize_existing = _validate_private_run_dir(args.finalize_existing)
        if args.ct_retry_from is not None:
            args.ct_retry_from = _validate_private_scan_input_path(args.ct_retry_from)
        _validate_cli_options(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    corpus = args.corpus
    # --ct-retry-from synthesizes a filtered corpus from the prior run, listing
    # only the domains whose CT was degraded. It implies --ct (re-fetching with
    # CT off would defeat the purpose).
    if args.ct_retry_from is not None:
        corpus = _synthesize_ct_retry_corpus(args.ct_retry_from, args.output_root)
        args.ct = True

    if not corpus.exists():
        print(f"error: corpus file not found: {corpus}", file=sys.stderr)
        raise SystemExit(2)

    started_utc = datetime.now(UTC).isoformat()
    corpus_stats = _corpus_stats(corpus)
    domain_count = corpus_stats.scheduled_domains
    if corpus_stats.duplicate_rows_removed:
        print(
            f"Input preflight: {corpus_stats.duplicate_rows_removed} duplicate row(s) "
            "removed by batch normalization"
        )
    if corpus_stats.invalid_rows:
        print(f"Input preflight: {corpus_stats.invalid_rows} malformed row(s) will produce validation errors")
    if args.finalize_existing is not None:
        run_dir = args.finalize_existing
        results_path = _find_results_path(run_dir)
        if results_path is None:
            print(f"error: no results.ndjson or results.json in {run_dir}", file=sys.stderr)
            raise SystemExit(2)
        completed_records = _count_result_records(results_path)
        batch_completed = domain_count > 0 and completed_records >= domain_count
        print(f"Finalizing existing scan {run_dir.name}: {completed_records}/{domain_count} records")
        _finalize_scan(
            FinalizeContext(
                results_path=results_path,
                run_dir=run_dir,
                stamp=run_dir.name,
                output_root=args.output_root,
                compare_to=args.compare_to,
                no_compare=args.no_compare,
                ct=args.ct,
                label=args.label,
                corpus=corpus,
                corpus_input_rows=corpus_stats.input_rows,
                domain_count=domain_count,
                duplicate_rows_removed=corpus_stats.duplicate_rows_removed,
                invalid_rows=corpus_stats.invalid_rows,
                concurrency=args.concurrency,
                timeout=args.timeout,
                max_runtime=args.max_runtime,
                min_count=args.min_count,
                batch_completed=batch_completed,
                batch_timed_out=False,
                started_utc=started_utc,
            )
        )
        return

    args.output_root.mkdir(parents=True, exist_ok=True)
    stamp = _utc_stamp()
    run_dir = args.output_root / stamp
    run_dir.mkdir(parents=True, exist_ok=False)

    print(f"Scan {stamp} - {domain_count} domains, corpus={corpus}")
    print(f"Run directory: {run_dir}")

    # Step 1: batch resolve.
    batch_result = _run_batch(
        corpus,
        run_dir,
        args=args,
        domain_count=domain_count,
    )

    _finalize_scan(
        FinalizeContext(
            results_path=batch_result.results_path,
            run_dir=run_dir,
            stamp=stamp,
            output_root=args.output_root,
            compare_to=args.compare_to,
            no_compare=args.no_compare,
            ct=args.ct,
            label=args.label,
            corpus=corpus,
            corpus_input_rows=corpus_stats.input_rows,
            domain_count=domain_count,
            duplicate_rows_removed=corpus_stats.duplicate_rows_removed,
            invalid_rows=corpus_stats.invalid_rows,
            concurrency=args.concurrency,
            timeout=args.timeout,
            max_runtime=args.max_runtime,
            min_count=args.min_count,
            batch_completed=batch_result.completed,
            batch_timed_out=batch_result.timed_out,
            started_utc=started_utc,
        )
    )


if __name__ == "__main__":
    main()
