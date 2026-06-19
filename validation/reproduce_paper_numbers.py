"""Run the public, no-private-data paper-number reproduction bundle.

This is the clean-checkout entry point for the paper's reproducible numbers.
It orchestrates existing validation harnesses, captures stdout/stderr into a
timestamped local run directory, and writes a manifest plus summary. It does not
read private corpora or emit target-specific data.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VALIDATION_ROOT = REPO_ROOT / "validation"
DEFAULT_OUTPUT_ROOT = VALIDATION_ROOT / "local" / "paper-numbers"

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class PaperStep:
    name: str
    description: str
    command: tuple[str, ...]
    artifact_name: str


@dataclass(frozen=True)
class StepResult:
    name: str
    description: str
    command: tuple[str, ...]
    returncode: int
    duration_seconds: float
    stdout_path: Path
    stderr_path: Path


@dataclass(frozen=True)
class ReproductionOutputs:
    run_dir: Path
    manifest_json: Path
    summary_md: Path
    results: tuple[StepResult, ...]


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%SZ")


def _module_cmd(module: str, *args: str) -> tuple[str, ...]:
    return (sys.executable, "-m", module, *args)


def _paper_steps() -> tuple[PaperStep, ...]:
    return (
        PaperStep(
            name="adversarial-properties",
            description="Suppression-monotonicity proof obligations over the shipped network.",
            command=_module_cmd("validation.adversarial_properties"),
            artifact_name="adversarial-properties.txt",
        ),
        PaperStep(
            name="differential-verification",
            description="Variable elimination against a naive full-joint reference.",
            command=_module_cmd("validation.differential_verification"),
            artifact_name="differential-verification.txt",
        ),
        PaperStep(
            name="interval-coverage",
            description="Synthetic 80 percent interval coverage under the CAL8 likelihood band.",
            command=_module_cmd("validation.interval_coverage", "--json"),
            artifact_name="interval-coverage.json",
        ),
        PaperStep(
            name="likelihood-sensitivity",
            description="Posterior and decision stability under plus-or-minus-20-percent likelihood perturbation.",
            command=_module_cmd("validation.likelihood_sensitivity"),
            artifact_name="likelihood-sensitivity.txt",
        ),
        PaperStep(
            name="layer-ablation",
            description="Synthetic Bayesian and graph-layer ablations.",
            command=_module_cmd("validation.layer_ablation"),
            artifact_name="layer-ablation.txt",
        ),
    )


def _smoke_steps() -> tuple[PaperStep, ...]:
    return (
        PaperStep(
            name="adversarial-properties",
            description="Suppression-monotonicity proof obligations over the shipped network.",
            command=_module_cmd("validation.adversarial_properties"),
            artifact_name="adversarial-properties.txt",
        ),
        PaperStep(
            name="differential-verification",
            description="Fast tricky-node differential-verification sweep.",
            command=_module_cmd("validation.differential_verification", "--tricky-only"),
            artifact_name="differential-verification.txt",
        ),
        PaperStep(
            name="interval-coverage",
            description="Small synthetic interval-coverage smoke sweep.",
            command=_module_cmd(
                "validation.interval_coverage",
                "--deltas",
                "0.2",
                "--worlds",
                "1",
                "--samples",
                "20",
                "--json",
            ),
            artifact_name="interval-coverage.json",
        ),
        PaperStep(
            name="likelihood-sensitivity",
            description="Small likelihood-sensitivity smoke sweep.",
            command=_module_cmd("validation.likelihood_sensitivity", "--samples", "50", "--trials", "1"),
            artifact_name="likelihood-sensitivity.txt",
        ),
        PaperStep(
            name="layer-ablation",
            description="Small Bayesian-only layer-ablation smoke sweep.",
            command=_module_cmd("validation.layer_ablation", "--samples", "50", "--skip-graph"),
            artifact_name="layer-ablation.txt",
        ),
    )


def steps_for_profile(profile: str) -> tuple[PaperStep, ...]:
    if profile == "paper":
        return _paper_steps()
    if profile == "smoke":
        return _smoke_steps()
    raise ValueError(f"unknown reproduction profile: {profile}")


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter + repo-local modules.
        cmd,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


def _command_display(command: Sequence[str]) -> str:
    return " ".join(command)


def _write_summary(
    *,
    output: Path,
    profile: str,
    generated_at: str,
    results: Sequence[StepResult],
    manifest_json: Path,
) -> None:
    lines = [
        "# Paper Number Reproduction Run",
        "",
        f"- Profile: `{profile}`",
        f"- Generated at: `{generated_at}`",
        "- Private corpora read: no",
        "- Network required by default: no",
        f"- Manifest: `{manifest_json.name}`",
        "",
        "## Results",
        "",
        "| Step | Status | Seconds | Output |",
        "|---|---:|---:|---|",
    ]
    for result in results:
        status = "pass" if result.returncode == 0 else f"fail ({result.returncode})"
        lines.append(
            f"| `{result.name}` | {status} | {result.duration_seconds:.2f} | `{result.stdout_path.name}` |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This bundle regenerates the public, no-private-data evidence rows used by",
            "the paper draft: suppression monotonicity, differential verification,",
            "synthetic interval coverage, likelihood sensitivity, and layer ablations.",
            "The private-corpus calibration rows remain maintainer-local and are not",
            "reproduced by this command.",
            "",
        ]
    )
    output.write_text("\n".join(lines), encoding="utf-8")


def run_reproduction(
    *,
    profile: str,
    output_root: Path,
    stamp: str | None = None,
    dry_run: bool = False,
    runner: CommandRunner = _default_runner,
) -> ReproductionOutputs:
    """Run the selected reproduction profile and write local artifacts."""
    generated_at = datetime.now(UTC).isoformat()
    run_stamp = stamp or _utc_stamp()
    run_dir = output_root / run_stamp
    steps = steps_for_profile(profile)
    manifest_json = run_dir / "manifest.json"
    summary_md = run_dir / "summary.md"

    if dry_run:
        for step in steps:
            print(_command_display(step.command))
        return ReproductionOutputs(run_dir=run_dir, manifest_json=manifest_json, summary_md=summary_md, results=())

    run_dir.mkdir(parents=True, exist_ok=False)
    results: list[StepResult] = []
    for step in steps:
        stdout_path = run_dir / step.artifact_name
        stderr_path = run_dir / step.artifact_name.replace(".", ".stderr.", 1)
        print(f"==> {step.name}", flush=True)
        start = time.monotonic()
        completed = runner(list(step.command))
        duration = time.monotonic() - start
        stdout_path.write_text(completed.stdout, encoding="utf-8")
        stderr_path.write_text(completed.stderr, encoding="utf-8")
        results.append(
            StepResult(
                name=step.name,
                description=step.description,
                command=step.command,
                returncode=completed.returncode,
                duration_seconds=duration,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
        )
        if completed.returncode != 0:
            break

    success = all(result.returncode == 0 for result in results) and len(results) == len(steps)
    manifest = {
        "generated_at": generated_at,
        "profile": profile,
        "run_dir": str(run_dir),
        "private_corpora_read": False,
        "network_required_by_default": False,
        "success": success,
        "steps": [
            {
                "name": result.name,
                "description": result.description,
                "command": list(result.command),
                "returncode": result.returncode,
                "duration_seconds": round(result.duration_seconds, 4),
                "stdout": str(result.stdout_path),
                "stderr": str(result.stderr_path),
            }
            for result in results
        ],
        "not_reproduced_here": [
            "maintainer-local private-corpus calibration bundle",
            "public-list calibration reruns without a committed frozen list",
            "posture distributions that require a caller-supplied domain list",
        ],
    }
    manifest_json.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_summary(
        output=summary_md,
        profile=profile,
        generated_at=generated_at,
        results=results,
        manifest_json=manifest_json,
    )
    if not success:
        failed = next((result for result in results if result.returncode != 0), None)
        detail = f"{failed.name} failed" if failed is not None else "not all steps ran"
        raise RuntimeError(f"paper-number reproduction failed: {detail}")
    return ReproductionOutputs(
        run_dir=run_dir,
        manifest_json=manifest_json,
        summary_md=summary_md,
        results=tuple(results),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Regenerate public, no-private-data paper-number artifacts.")
    parser.add_argument(
        "--profile",
        choices=("paper", "smoke"),
        default="paper",
        help="paper runs the full public bundle; smoke runs a fast orchestrator check.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="Root for timestamped local run artifacts.",
    )
    parser.add_argument("--stamp", default=None, help="Override the UTC run stamp.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        outputs = run_reproduction(
            profile=args.profile,
            output_root=args.output_root,
            stamp=args.stamp,
            dry_run=args.dry_run,
        )
    except (FileExistsError, RuntimeError, ValueError) as exc:
        print(f"FAIL: {exc}")
        return 1

    if args.dry_run:
        return 0
    print()
    print(f"Paper-number reproduction complete: {outputs.run_dir}")
    print(f"  summary:  {outputs.summary_md}")
    print(f"  manifest: {outputs.manifest_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
