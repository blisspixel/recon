"""Run the full discovery scan: corpus → results → gaps → candidates → diff.

Wraps run_corpus.py + find_gaps.py + triage_candidates.py + diff_runs.py
into one timestamped invocation suitable for monthly cadence. Use this when
you want to track catalog drift over time:

    # Saturday morning, monthly cadence:
    python validation/scan.py --corpus validation/corpus-private/consolidated.txt

A run directory is created at ``validation/runs-private/<UTC-stamp>/`` with:
  * ``results.json`` — raw recon batch output (one entry per domain)
  * ``gaps.json``    — bucketed unclassified terminals
  * ``candidates.json`` — pre-filtered triage list (intra-org / covered dropped)
  * ``meta.json``    — scan metadata (timestamp, corpus path, counts, ...)
  * ``diff.json``    — only when --compare-to is provided; per-domain deltas

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
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def _count_corpus(corpus: Path) -> int:
    if not corpus.exists():
        return 0
    return sum(
        1
        for line in corpus.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


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
    with contextlib.suppress(OSError), results_path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            total += 1
            outcome = rec.get("ct_attempt_outcome")
            if outcome is None:
                outcome = "not_attempted"
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1

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
        "written_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    (run_dir / "ct_budget_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    # Short stdout note so the operator sees the headline.
    cache_n = outcome_counts.get("cache_hit", 0)
    live_n = outcome_counts.get("live_success", 0)
    rl_n = outcome_counts.get("live_rate_limited", 0)
    br_n = outcome_counts.get("breaker_open", 0)
    cmiss_n = outcome_counts.get("cache_miss", 0)
    print(
        f"  ct_budget_summary: {total} records — "
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
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
    args = parser.parse_args()

    corpus = args.corpus
    # --ct-retry-from synthesizes a filtered corpus file from the prior
    # run, listing only the domains whose CT was degraded. It implies
    # --ct (re-fetching with CT off would defeat the purpose).
    if args.ct_retry_from is not None:
        if not args.ct_retry_from.exists():
            print(f"error: --ct-retry-from path not found: {args.ct_retry_from}", file=sys.stderr)
            raise SystemExit(2)
        prior = args.ct_retry_from
        if prior.is_dir():
            prior = prior / "results.ndjson"
        if not prior.exists():
            print(f"error: results.ndjson not found in {args.ct_retry_from}", file=sys.stderr)
            raise SystemExit(2)
        degraded_outcomes = {
            "live_rate_limited",
            "breaker_open",
            "live_other_failure",
            "cache_miss",
        }
        degraded_domains: list[str] = []
        with prior.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                outcome = rec.get("ct_attempt_outcome")
                if outcome in degraded_outcomes:
                    dom = rec.get("queried_domain")
                    if dom:
                        degraded_domains.append(dom)
        if not degraded_domains:
            print("--ct-retry-from: no degraded records in prior run; nothing to retry")
            raise SystemExit(0)
        synth = args.output_root.parent / f"_ct-retry-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%SZ')}.txt"
        synth.parent.mkdir(parents=True, exist_ok=True)
        synth.write_text("\n".join(degraded_domains) + "\n", encoding="utf-8")
        print(
            f"--ct-retry-from {args.ct_retry_from}: re-running CT for "
            f"{len(degraded_domains)} degraded domains via {synth}"
        )
        corpus = synth
        args.ct = True

    if not corpus.exists():
        print(f"error: corpus file not found: {corpus}", file=sys.stderr)
        raise SystemExit(2)

    args.output_root.mkdir(parents=True, exist_ok=True)
    stamp = _utc_stamp()
    run_dir = args.output_root / stamp
    run_dir.mkdir(parents=True, exist_ok=False)

    domain_count = _count_corpus(corpus)
    print(f"Scan {stamp} — {domain_count} domains, corpus={corpus}")
    print(f"Run directory: {run_dir}")

    # Step 1: batch resolve. Default is NDJSON streaming (one line per
    # domain, flushed as completed) so very large corpora stay memory-bounded
    # and produce visible progress in real time. ``--json-array`` opts back
    # into the legacy single-array output.
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
    ]
    if not args.ct:
        batch_cmd.append("--no-ct")

    ct_str = "on" if args.ct else "off"
    fmt_str = "json-array" if args.json_array else "ndjson"
    print(
        f"  resolving {domain_count} domains (concurrency={args.concurrency}, ct={ct_str}, format={fmt_str}) ...",
        flush=True,
    )
    results_filename = "results.json" if args.json_array else "results.ndjson"
    results_path = run_dir / results_filename
    with results_path.open("w", encoding="utf-8") as out:
        result = subprocess.run(  # noqa: S603 — arg list constructed locally
            batch_cmd,
            stdout=out,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
    if result.returncode != 0:
        print(f"    FAILED: {result.stderr.strip()}", file=sys.stderr)
        raise SystemExit(2)

    # Step 1.5: write ct_budget_summary.json. Aggregates per-domain
    # ct_attempt_outcome counts from the just-completed batch and pulls
    # the persisted limiter state from ~/.recon/rate-limit-state/.
    # Operator can see at a glance: how many records hit cache, how
    # many got fresh CT, how many were rate-limited / breaker-blocked,
    # and what state the limiters wound down in.
    if args.ct:
        _write_ct_budget_summary(results_path, run_dir)

    # Step 2: gap analysis
    _run_step(
        [
            sys.executable,
            "validation/find_gaps.py",
            "--input",
            str(results_path),
            "--output",
            str(run_dir / "gaps.json"),
            "--samples",
            "10",
        ],
        "find_gaps",
    )

    # Step 3: triage filter
    _run_step(
        [
            sys.executable,
            "validation/triage_candidates.py",
            "--gaps",
            str(run_dir / "gaps.json"),
            "--fingerprints",
            "recon_tool/data/fingerprints/",
            "--output",
            str(run_dir / "candidates.json"),
            "--min-count",
            str(args.min_count),
        ],
        "triage_candidates",
    )

    # Step 4: diff against prior (optional)
    diff_path: Path | None = None
    compare_target: Path | None = args.compare_to
    if compare_target is None and not args.no_compare:
        # Pick the most recent existing run that isn't this one.
        prior_candidates = [p for p in sorted(args.output_root.iterdir()) if p.is_dir() and p.name != stamp]
        if prior_candidates:
            compare_target = prior_candidates[-1]

    if compare_target is not None and not args.no_compare:
        diff_path = run_dir / "diff.json"
        # Prior runs may have written either ``results.ndjson`` (current
        # default) or ``results.json`` (legacy ``--json-array``); accept
        # both. ``diff_runs.py`` already reads NDJSON.
        prior_ndjson = compare_target / "results.ndjson"
        prior_json = compare_target / "results.json"
        prior_results = prior_ndjson if prior_ndjson.exists() else prior_json
        if prior_results.exists():
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

    # Step 5: meta.json
    gaps_count = 0
    candidates_count = 0
    with contextlib.suppress(OSError, json.JSONDecodeError):
        gaps_count = len(json.loads((run_dir / "gaps.json").read_text(encoding="utf-8")))
    with contextlib.suppress(OSError, json.JSONDecodeError):
        candidates_count = len(json.loads((run_dir / "candidates.json").read_text(encoding="utf-8")))

    meta: dict[str, Any] = {
        "scan_stamp": stamp,
        "scan_started_utc": datetime.now(timezone.utc).isoformat(),
        "label": args.label,
        "corpus_path": str(corpus),
        "domain_count": domain_count,
        "concurrency": args.concurrency,
        "ct_enabled": bool(args.ct),
        "gaps_total": gaps_count,
        "candidates_after_triage": candidates_count,
        "compared_to": str(compare_target) if compare_target else None,
        "diff_path": str(diff_path) if diff_path else None,
    }
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print()
    print(f"Scan complete: {gaps_count} gaps, {candidates_count} candidates after triage")
    print(f"  results:    {results_path}")
    print(f"  gaps:       {run_dir / 'gaps.json'}")
    print(f"  candidates: {run_dir / 'candidates.json'}")
    if diff_path:
        print(f"  diff:       {diff_path}")
    print(f"  meta:       {run_dir / 'meta.json'}")
    if candidates_count > 0:
        print()
        print("Next: hand candidates.json to the /recon-fingerprint-triage skill,")
        print("or open it in your editor and triage by hand.")


if __name__ == "__main__":
    main()
