"""Run a live validation corpus and emit JSON + summary artifacts.

Example:
    python validation\\run_corpus.py --corpus validation\\corpus-50-diverse.txt
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from recon_tool.validation_runner import (
    compare_batch_results,
    compare_batch_summaries,
    render_summary_markdown,
    run_batch_validation_sync,
    summarize_batch_results,
)


def _default_output_dir(base: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    return base / "live_runs" / stamp


def main() -> None:
    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Run a live recon validation corpus and write artifacts.")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=base / "corpus-50-diverse.txt",
        help="Corpus file with one domain per line.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to write results.json, summary.json, and summary.md.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Batch concurrency (same semantics as `recon batch -c`).",
    )
    parser.add_argument(
        "--label",
        type=str,
        default="Live validation run",
        help="Human-readable label for the Markdown summary.",
    )
    parser.add_argument(
        "--compare-to",
        type=Path,
        default=None,
        help="Optional prior results.json file to compare headline counts against.",
    )
    args = parser.parse_args()

    output_dir = args.output_dir or _default_output_dir(base)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = run_batch_validation_sync(args.corpus, concurrency=max(1, min(20, args.concurrency)))
    summary = summarize_batch_results(results)

    comparison: dict[str, int] | None = None
    detailed_comparison: dict[str, object] | None = None
    if args.compare_to is not None:
        previous_data = json.loads(args.compare_to.read_text(encoding="utf-8"))
        if not isinstance(previous_data, list) or not all(isinstance(entry, dict) for entry in previous_data):
            msg = f"Comparison file must be a JSON array of objects: {args.compare_to}"
            raise ValueError(msg)
        comparison = compare_batch_summaries(summarize_batch_results(previous_data), summary)
        detailed_comparison = compare_batch_results(previous_data, results)

    (output_dir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (output_dir / "summary.md").write_text(
        render_summary_markdown(
            args.label,
            summary,
            results,
            comparison=comparison,
            detailed_comparison=detailed_comparison,
        ),
        encoding="utf-8",
    )
    if detailed_comparison is not None:
        (output_dir / "comparison.json").write_text(json.dumps(detailed_comparison, indent=2), encoding="utf-8")

    print(f"wrote {output_dir / 'results.json'}")
    print(f"wrote {output_dir / 'summary.json'}")
    print(f"wrote {output_dir / 'summary.md'}")
    if detailed_comparison is not None:
        print(f"wrote {output_dir / 'comparison.json'}")


if __name__ == "__main__":
    main()
