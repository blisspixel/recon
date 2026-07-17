"""Run a live validation corpus and emit JSON + summary artifacts.

Example:
    python validation\\run_corpus.py --corpus validation\\corpus-private\\consolidated.txt
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from recon_tool.validation_runner import (
    compare_batch_results,
    compare_batch_summaries,
    render_summary_markdown,
    run_batch_validation_sync,
    summarize_batch_results,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
_PRIVATE_OUTPUT_ROOTS = (
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "live_runs",
    REPO_ROOT / "validation" / "local",
)


def _result_files(path: Path) -> list[Path]:
    """Return private batch-result files from one file or run directory."""
    if path.is_file():
        return [path]
    return sorted(path.rglob("results*.ndjson")) + sorted(path.rglob("results*.json"))


def _result_entries(result_file: Path) -> Iterator[dict[str, object]]:
    """Read a JSON array or streamed NDJSON result file."""
    try:
        text = result_file.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"Cannot read exclusion results file: {result_file}"
        raise ValueError(msg) from exc
    if result_file.suffix == ".ndjson":
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            if not raw_line.strip():
                continue
            try:
                entry = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                msg = f"Cannot read exclusion NDJSON line {line_number}: {result_file}"
                raise ValueError(msg) from exc
            if not isinstance(entry, dict):
                msg = f"Exclusion NDJSON entries must be objects: {result_file}"
                raise ValueError(msg)
            yield entry
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"Cannot read exclusion results file: {result_file}"
        raise ValueError(msg) from exc
    if not isinstance(payload, list) or not all(isinstance(entry, dict) for entry in payload):
        msg = f"Exclusion results must be a JSON array of objects: {result_file}"
        raise ValueError(msg)
    for entry in payload:
        if isinstance(entry, dict):
            yield entry


def _load_excluded_domains(paths: list[Path]) -> set[str]:
    """Load canonical queried namespaces without retaining result details."""
    from recon_tool.validator import validate_domain

    excluded: set[str] = set()
    for path in paths:
        files = _result_files(path)
        if not files:
            msg = f"No JSON or NDJSON result files found under exclusion path: {path}"
            raise ValueError(msg)
        for result_file in files:
            for entry in _result_entries(result_file):
                value = entry.get("queried_domain") or entry.get("domain")
                if not isinstance(value, str) or not value:
                    continue
                try:
                    excluded.add(validate_domain(value))
                except ValueError:
                    continue
    return excluded


def _write_filtered_manifest(
    corpus: Path,
    output_dir: Path,
    excluded: set[str],
    *,
    limit: int | None = None,
) -> tuple[Path, int, int]:
    """Write a normalized, deduplicated private manifest excluding prior work."""
    from recon_tool.cli.batch import read_batch_domains
    from recon_tool.validator import validate_domain

    try:
        with corpus.open(encoding="utf-8") as stream:
            raw_domains = read_batch_domains(stream)
    except (OSError, UnicodeError, ValueError) as exc:
        msg = f"Cannot prepare corpus manifest: {corpus}"
        raise ValueError(msg) from exc

    scheduled: list[str] = []
    seen: set[str] = set()
    excluded_rows = 0
    for row_number, raw_domain in enumerate(raw_domains, start=1):
        try:
            domain = validate_domain(raw_domain)
        except ValueError as exc:
            msg = f"Malformed domain in corpus row {row_number}"
            raise ValueError(msg) from exc
        if domain in excluded:
            excluded_rows += 1
            continue
        if domain in seen:
            continue
        seen.add(domain)
        scheduled.append(domain)

    if not scheduled:
        msg = "Corpus has no unobserved domains after exclusions"
        raise ValueError(msg)
    if limit is not None:
        scheduled = scheduled[:limit]

    manifest = output_dir / "input-manifest.txt"
    manifest.write_text("\n".join(scheduled) + "\n", encoding="utf-8")
    return manifest, len(scheduled), excluded_rows


def _default_output_dir(base: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%SZ")
    return base / "live_runs" / stamp


def _validate_output_dir(output_dir: Path) -> Path:
    """Keep in-repository live results under an ignored private workspace."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from validation.run_path_safety import validate_private_output_root

    return validate_private_output_root(
        output_dir,
        repo_root=REPO_ROOT,
        allowed_roots=_PRIVATE_OUTPUT_ROOTS,
    )


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
        help=(
            "Directory to write results.json, summary.json, and summary.md. "
            "Paths inside this checkout must be under a private validation workspace."
        ),
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
    parser.add_argument(
        "--exclude-results",
        type=Path,
        action="append",
        default=[],
        help=(
            "Prior JSON or NDJSON result file, or run directory, whose queried domains "
            "must be excluded. Repeat for multiple prior runs."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Run only the first N normalized, unobserved domains after exclusions.",
    )
    parser.add_argument(
        "--include-unclassified",
        action="store_true",
        help=("Include bounded typed catalog coverage and unmatched DNS values in each domain's private JSON output."),
    )
    parser.add_argument(
        "--no-ct",
        action="store_true",
        help=(
            "Skip cert-transparency providers (crt.sh, CertSpotter) for every "
            "domain in the corpus. Recommended for runs of 1000+ domains "
            "where you want zero load on public CT services."
        ),
    )
    args = parser.parse_args()

    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")

    try:
        output_dir = _validate_output_dir(args.output_dir or _default_output_dir(base))
    except ValueError as exc:
        parser.error(str(exc))
    output_dir.mkdir(parents=True, exist_ok=True)

    corpus = args.corpus
    if args.exclude_results or args.limit is not None:
        try:
            excluded = _load_excluded_domains(args.exclude_results)
            corpus, _, _ = _write_filtered_manifest(args.corpus, output_dir, excluded, limit=args.limit)
        except ValueError as exc:
            parser.error(str(exc))

    results = run_batch_validation_sync(
        corpus,
        concurrency=max(1, min(20, args.concurrency)),
        include_unclassified=args.include_unclassified,
        skip_ct=args.no_ct,
    )
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
