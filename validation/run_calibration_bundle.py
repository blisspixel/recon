"""Run the private calibration harness bundle and render a checked memo.

This is maintainer-local orchestration. It reads a gitignored real-apex corpus,
captures aggregate JSON without shell redirection, writes artifacts under
``validation/runs-private/``, and renders a memo through
``validation.render_calibration_memo`` before anything is reviewed for commit.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from validation.render_calibration_memo import load_public_payload, render_memo

REPO_ROOT = Path(__file__).resolve().parent.parent
VALIDATION_ROOT = REPO_ROOT / "validation"

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class BundleOutputs:
    run_dir: Path
    reference_json: Path
    tenancy_json: Path
    conformal_json: Path
    memo_md: Path
    meta_json: Path


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%SZ")


def _count_domains(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(
        1
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def _count_strata(directory: Path) -> int:
    if not directory.exists():
        return 0
    return sum(1 for path in directory.glob("*.txt") if path.is_file())


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - command argv is constructed locally.
        cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        check=False,
    )


def _write_json_from_command(
    *,
    cmd: list[str],
    output: Path,
    description: str,
    runner: CommandRunner,
    dry_run: bool,
) -> None:
    print(f"  {description} -> {output.name}", flush=True)
    if dry_run:
        print(f"    {' '.join(cmd)}")
        return
    result = runner(cmd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{description} failed: {detail}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{description} did not emit valid JSON: {exc}") from exc
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _command_base(module: str) -> list[str]:
    return [sys.executable, "-m", module]


def _render_checked_memo(
    *,
    reference_json: Path,
    tenancy_json: Path,
    conformal_json: Path,
    memo_md: Path,
    title: str,
    min_cell: int,
) -> None:
    reference = load_public_payload(reference_json, "reference", small_cell_threshold=min_cell)
    tenancy = load_public_payload(tenancy_json, "tenancy", small_cell_threshold=min_cell)
    conformal = load_public_payload(conformal_json, "conformal", small_cell_threshold=min_cell)
    memo = render_memo(
        title=title,
        reference=reference,
        tenancy=tenancy,
        conformal=conformal,
        small_cell_threshold=min_cell,
    )
    memo_md.write_text(f"{memo}\n", encoding="utf-8")


def run_bundle(
    *,
    stratify_dir: Path,
    consolidated: Path,
    output_root: Path,
    label: str,
    stamp: str | None = None,
    min_cell: int = 10,
    bins: int = 10,
    concurrency: int = 5,
    timeout: float = 120.0,
    alpha: float = 0.1,
    trials: int = 20,
    dry_run: bool = False,
    runner: CommandRunner = _default_runner,
) -> BundleOutputs:
    """Run all calibration harnesses and render the aggregate memo."""
    if not stratify_dir.is_dir():
        raise FileNotFoundError(f"stratify directory not found: {stratify_dir}")
    if not consolidated.is_file():
        raise FileNotFoundError(f"consolidated corpus not found: {consolidated}")

    run_stamp = stamp or _utc_stamp()
    run_dir = output_root / run_stamp
    outputs = BundleOutputs(
        run_dir=run_dir,
        reference_json=run_dir / "reference.json",
        tenancy_json=run_dir / "tenancy.json",
        conformal_json=run_dir / "conformal.json",
        memo_md=run_dir / "memo.md",
        meta_json=run_dir / "meta.json",
    )
    if dry_run:
        print(f"Dry run for calibration bundle {run_stamp}")
        print(f"Run directory would be: {run_dir}")
    else:
        run_dir.mkdir(parents=True, exist_ok=False)

    common_strata_args = [
        "--stratify-dir",
        str(stratify_dir),
        "--min-cell",
        str(min_cell),
        "--bins",
        str(bins),
        "--concurrency",
        str(concurrency),
        "--timeout",
        str(timeout),
        "--json",
    ]
    _write_json_from_command(
        cmd=[*_command_base("validation.reference_calibration"), *common_strata_args],
        output=outputs.reference_json,
        description="reference calibration",
        runner=runner,
        dry_run=dry_run,
    )
    _write_json_from_command(
        cmd=[*_command_base("validation.tenancy_reference_calibration"), *common_strata_args],
        output=outputs.tenancy_json,
        description="tenancy corroboration",
        runner=runner,
        dry_run=dry_run,
    )
    _write_json_from_command(
        cmd=[
            *_command_base("validation.conformal_coverage"),
            str(consolidated),
            "--alpha",
            str(alpha),
            "--trials",
            str(trials),
            "--concurrency",
            str(concurrency),
            "--timeout",
            str(timeout),
            "--json",
        ],
        output=outputs.conformal_json,
        description="conformal coverage",
        runner=runner,
        dry_run=dry_run,
    )

    if dry_run:
        print("  render memo -> memo.md")
        return outputs

    title = label or f"Aggregate Calibration Validation Memo {run_stamp}"
    _render_checked_memo(
        reference_json=outputs.reference_json,
        tenancy_json=outputs.tenancy_json,
        conformal_json=outputs.conformal_json,
        memo_md=outputs.memo_md,
        title=title,
        min_cell=min_cell,
    )
    meta = {
        "run_stamp": run_stamp,
        "label": label,
        "stratify_dir": str(stratify_dir),
        "consolidated_corpus": str(consolidated),
        "strata_count": _count_strata(stratify_dir),
        "consolidated_domain_count": _count_domains(consolidated),
        "min_cell": min_cell,
        "bins": bins,
        "concurrency": concurrency,
        "timeout": timeout,
        "alpha": alpha,
        "trials": trials,
        "artifacts": {
            "reference_json": str(outputs.reference_json),
            "tenancy_json": str(outputs.tenancy_json),
            "conformal_json": str(outputs.conformal_json),
            "memo_md": str(outputs.memo_md),
        },
        "disclosure": {
            "private_run_dir": True,
            "aggregate_json_only": True,
            "memo_rendered_with_disclosure_checks": True,
        },
    }
    outputs.meta_json.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return outputs


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run private calibration harnesses to aggregate JSON and render a checked memo."
    )
    parser.add_argument(
        "--stratify-dir",
        type=Path,
        default=VALIDATION_ROOT / "corpus-private" / "by-vertical",
        help="Directory of private per-stratum *.txt lists.",
    )
    parser.add_argument(
        "--consolidated",
        type=Path,
        default=VALIDATION_ROOT / "corpus-private" / "consolidated.txt",
        help="Private consolidated corpus for conformal coverage.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=VALIDATION_ROOT / "runs-private",
        help="Private output root for the timestamped run directory.",
    )
    parser.add_argument("--label", default="", help="Optional memo title and run label.")
    parser.add_argument("--stamp", default=None, help="Override the UTC run stamp.")
    parser.add_argument("--min-cell", type=int, default=10, help="Suppress or reject strata below this count.")
    parser.add_argument("--bins", type=int, default=10, help="Reliability bins for calibration harnesses.")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent resolves.")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-domain resolve timeout seconds.")
    parser.add_argument("--alpha", type=float, default=0.1, help="Conformal miscoverage level.")
    parser.add_argument("--trials", type=int, default=20, help="Conformal split count.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running network calls.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        outputs = run_bundle(
            stratify_dir=args.stratify_dir,
            consolidated=args.consolidated,
            output_root=args.output_root,
            label=args.label,
            stamp=args.stamp,
            min_cell=args.min_cell,
            bins=args.bins,
            concurrency=args.concurrency,
            timeout=args.timeout,
            alpha=args.alpha,
            trials=args.trials,
            dry_run=args.dry_run,
        )
    except (FileNotFoundError, FileExistsError, RuntimeError, ValueError) as exc:
        print(f"FAIL: {exc}")
        return 1

    if args.dry_run:
        return 0
    print()
    print(f"Calibration bundle complete: {outputs.run_dir}")
    print(f"  reference: {outputs.reference_json}")
    print(f"  tenancy:   {outputs.tenancy_json}")
    print(f"  conformal: {outputs.conformal_json}")
    print(f"  memo:      {outputs.memo_md}")
    print(f"  meta:      {outputs.meta_json}")
    print()
    print("Review memo.md before copying any aggregate result into a committed validation memo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
