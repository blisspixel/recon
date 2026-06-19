from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from validation.reproduce_paper_numbers import run_reproduction, steps_for_profile


def _completed(cmd: list[str], returncode: int = 0, stdout: str = "ok\n") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(cmd, returncode, stdout, "")


def test_smoke_profile_writes_manifest_summary_and_artifacts(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return _completed(cmd, stdout=f"stdout for {cmd[2]}\n")

    outputs = run_reproduction(
        profile="smoke",
        output_root=tmp_path,
        stamp="20260619-000000Z",
        runner=runner,
    )

    assert len(calls) == len(steps_for_profile("smoke"))
    assert outputs.run_dir == tmp_path / "20260619-000000Z"
    manifest = json.loads(outputs.manifest_json.read_text(encoding="utf-8"))
    assert manifest["success"] is True
    assert manifest["private_corpora_read"] is False
    assert manifest["network_required_by_default"] is False
    assert [step["name"] for step in manifest["steps"]] == [
        "adversarial-properties",
        "differential-verification",
        "interval-coverage",
        "likelihood-sensitivity",
        "layer-ablation",
    ]
    assert "--tricky-only" in manifest["steps"][1]["command"]
    assert "--samples" in manifest["steps"][2]["command"]
    assert all(Path(step["stdout"]).is_file() for step in manifest["steps"])

    summary = outputs.summary_md.read_text(encoding="utf-8")
    assert "Paper Number Reproduction Run" in summary
    assert "Private corpora read: no" in summary
    assert "`adversarial-properties`" in summary


def test_dry_run_prints_commands_without_creating_run_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        raise AssertionError(cmd)

    outputs = run_reproduction(
        profile="smoke",
        output_root=tmp_path,
        stamp="20260619-000000Z",
        dry_run=True,
        runner=runner,
    )

    assert not outputs.run_dir.exists()
    out = capsys.readouterr().out
    assert "validation.adversarial_properties" in out
    assert "validation.layer_ablation" in out


@pytest.mark.parametrize("stamp", ["", "../outside", "nested/stamp", "nested\\stamp", "bad stamp", "a" * 81])
def test_run_reproduction_rejects_unsafe_stamp(tmp_path: Path, stamp: str) -> None:
    with pytest.raises(ValueError, match="run stamp must be 1-80"):
        run_reproduction(profile="smoke", output_root=tmp_path, stamp=stamp, dry_run=True)


def test_run_reproduction_resolves_safe_stamp_under_output_root(tmp_path: Path) -> None:
    outputs = run_reproduction(
        profile="smoke",
        output_root=tmp_path,
        stamp="safe-run_20260619.1",
        dry_run=True,
    )

    assert outputs.run_dir == (tmp_path / "safe-run_20260619.1").resolve(strict=False)


def test_failure_stops_after_failed_step_and_keeps_manifest(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if len(calls) == 2:
            return _completed(cmd, returncode=2, stdout="failed\n")
        return _completed(cmd)

    with pytest.raises(RuntimeError, match="differential-verification failed"):
        run_reproduction(
            profile="smoke",
            output_root=tmp_path,
            stamp="20260619-000000Z",
            runner=runner,
        )

    assert len(calls) == 2
    manifest = json.loads((tmp_path / "20260619-000000Z" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["success"] is False
    assert [step["returncode"] for step in manifest["steps"]] == [0, 2]


def test_unknown_profile_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown reproduction profile"):
        steps_for_profile("full")
