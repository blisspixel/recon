"""Aggregate CT-enabled validation sessions without publishing target rows.

The input is one or more private validation run directories, each containing
``results.ndjson`` or ``results.json`` plus optional ``meta.json``. The output is
aggregate JSON only: counts, outcome buckets, and run basenames. It deliberately
does not emit domains, tenant IDs, organization names, or per-domain rows.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

_PRIVATE_SCAN_ROOTS = (
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "live_runs",
    REPO_ROOT / "validation" / "local",
)

_CT_DATA_OUTCOMES = {"cache_hit", "live_success"}
_OUTCOME_PRIORITY = {
    "live_success": 50,
    "cache_hit": 40,
    "live_rate_limited": 30,
    "live_other_failure": 20,
    "cache_miss": 20,
    "breaker_open": 10,
    "not_attempted": 0,
}


def _is_self_or_child(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def _validate_private_path(path: Path, *, kind: str) -> Path:
    resolved = path.resolve(strict=False)
    resolved_repo = REPO_ROOT.resolve(strict=False)
    if not _is_self_or_child(resolved, resolved_repo):
        return resolved
    allowed = tuple(root.resolve(strict=False) for root in _PRIVATE_SCAN_ROOTS)
    if any(_is_self_or_child(resolved, root) for root in allowed):
        return resolved
    allowed_text = ", ".join(_display_path(root) for root in allowed)
    raise ValueError(f"{kind} inside this checkout must be under one of: {allowed_text}")


def _find_results_path(run_dir: Path) -> Path:
    for name in ("results.ndjson", "results.json"):
        candidate = run_dir / name
        if candidate.exists():
            return candidate
    raise ValueError(f"no results.ndjson or results.json in {run_dir}")


def _iter_result_records(results_path: Path) -> Iterator[dict[str, Any]]:
    if results_path.suffix == ".ndjson":
        with results_path.open(encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                with contextlib.suppress(ValueError):
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        yield parsed
        return

    parsed_json = json.loads(results_path.read_text(encoding="utf-8"))
    if isinstance(parsed_json, list):
        for item in parsed_json:
            if isinstance(item, dict):
                yield item
    elif isinstance(parsed_json, dict):
        yield parsed_json


def _load_meta(run_dir: Path) -> dict[str, Any]:
    meta_path = run_dir / "meta.json"
    with contextlib.suppress(OSError, ValueError):
        parsed = json.loads(meta_path.read_text(encoding="utf-8"))
        if isinstance(parsed, dict):
            return parsed
    return {}


def _record_outcome(record: dict[str, Any]) -> str:
    raw = record.get("ct_attempt_outcome") or "not_attempted"
    return str(raw)


def _is_better_outcome(candidate: str, current: str | None) -> bool:
    if current is None:
        return True
    return _OUTCOME_PRIORITY.get(candidate, 1) > _OUTCOME_PRIORITY.get(current, 1)


def summarize_sessions(run_dirs: list[Path]) -> dict[str, Any]:
    """Return aggregate counts for private CT run directories."""
    if not run_dirs:
        raise ValueError("at least one run directory is required")

    raw_outcomes: Counter[str] = Counter()
    best_by_domain: dict[str, str] = {}
    runs: list[dict[str, Any]] = []
    total_records = 0
    total_records_with_domain = 0

    for run_dir in run_dirs:
        validated_run_dir = _validate_private_path(run_dir, kind="input run directory")
        results_path = _find_results_path(validated_run_dir)
        run_outcomes: Counter[str] = Counter()
        run_records = 0
        run_records_with_domain = 0

        for record in _iter_result_records(results_path):
            run_records += 1
            total_records += 1
            outcome = _record_outcome(record)
            run_outcomes[outcome] += 1
            raw_outcomes[outcome] += 1
            domain = record.get("queried_domain")
            if isinstance(domain, str) and domain:
                run_records_with_domain += 1
                total_records_with_domain += 1
                if _is_better_outcome(outcome, best_by_domain.get(domain)):
                    best_by_domain[domain] = outcome

        meta = _load_meta(validated_run_dir)
        runs.append(
            {
                "run": validated_run_dir.name,
                "records": run_records,
                "records_with_domain": run_records_with_domain,
                "domain_count": meta.get("domain_count"),
                "results_records": meta.get("results_records"),
                "batch_completed": meta.get("batch_completed"),
                "batch_timed_out": meta.get("batch_timed_out"),
                "ct_enabled": meta.get("ct_enabled"),
                "outcome_counts": dict(sorted(run_outcomes.items())),
            }
        )

    best_outcomes = Counter(best_by_domain.values())
    ct_data_domains = sum(count for outcome, count in best_outcomes.items() if outcome in _CT_DATA_OUTCOMES)
    unique_domains = len(best_by_domain)
    coverage_ratio = round(ct_data_domains / unique_domains, 6) if unique_domains else 0.0

    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "session_count": len(run_dirs),
        "record_count": total_records,
        "records_with_domain": total_records_with_domain,
        "unique_domains_observed": unique_domains,
        "ct_data_domains": ct_data_domains,
        "ct_data_coverage_ratio": coverage_ratio,
        "degraded_or_unresolved_domains": unique_domains - ct_data_domains,
        "raw_outcome_counts": dict(sorted(raw_outcomes.items())),
        "best_outcome_counts": dict(sorted(best_outcomes.items())),
        "runs": runs,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate private CT validation sessions without emitting target rows."
    )
    parser.add_argument("run_dirs", nargs="+", type=Path, help="Private run directories to aggregate.")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON output path.")
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    try:
        summary = summarize_sessions(args.run_dirs)
        text = json.dumps(summary, indent=2) + "\n"
        if args.output is None:
            sys.stdout.write(text)
        else:
            output = _validate_private_path(args.output, kind="output file")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(text, encoding="utf-8")
            print(f"wrote aggregate CT session summary to {output}")
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
