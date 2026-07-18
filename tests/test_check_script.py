"""Canonical local-gate orchestration regressions."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts import check

_CI_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


def test_text_range_is_forwarded_only_to_text_hygiene(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        check,
        "_STAGES",
        [
            (check._CORE, "ruff", ["python", "-m", "ruff"]),
            (check._CORE, "text-hygiene", ["python", "scripts/check_text_hygiene.py"]),
        ],
    )

    def fake_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(check.subprocess, "run", fake_run)
    assert check.main(["--text-range", "v2.5.8..HEAD"]) == 0
    assert commands == [
        ["python", "-m", "ruff"],
        ["python", "scripts/check_text_hygiene.py", "--range", "v2.5.8..HEAD"],
    ]


@pytest.mark.parametrize("return_code", [0, 1])
def test_captured_gate_output_is_plain(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    return_code: int,
) -> None:
    monkeypatch.setattr(check, "_STAGES", [(check._CORE, "sample", ["python", "sample.py"])])

    def fake_run(_cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["python", "sample.py"], return_code, "", "")

    monkeypatch.setattr(check.subprocess, "run", fake_run)

    assert check.main(["--fast"]) == return_code
    output = capsys.readouterr().out
    assert "\x1b[" not in output
    assert ("All gate stages passed" if return_code == 0 else "1 stage(s) failed") in output


def test_color_capable_gate_output_retains_status_style(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(check, "_STAGES", [(check._CORE, "sample", ["python", "sample.py"])])
    monkeypatch.setattr(check, "_supports_color", lambda: True)

    def fake_run(_cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["python", "sample.py"], 0, "", "")

    monkeypatch.setattr(check.subprocess, "run", fake_run)

    assert check.main(["--fast"]) == 0
    assert "\x1b[" in capsys.readouterr().out


def test_pyright_scope_comes_only_from_pyproject() -> None:
    local_stage = next(command for _group, name, command in check._STAGES if name == "pyright")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert local_stage == [check._PY, "-m", "pyright"]
    assert "run: uv run pyright\n" in workflow
    assert "pyright src/recon_tool/ tests/" not in workflow


def test_ruff_scope_and_cache_policy_match_ci() -> None:
    local_stage = next(command for _group, name, command in check._STAGES if name == "ruff")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert local_stage == [check._PY, "-m", "ruff", "check", "--no-cache", "."]
    assert "run: uv run ruff check --no-cache .\n" in workflow


def test_ci_runs_the_interface_layout_guard() -> None:
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert "run: uv run python scripts/check_interface_layout.py" in workflow


def test_reproducible_build_smokes_built_wheel_entry_points() -> None:
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")
    build_commands = [line.strip() for line in workflow.splitlines() if line.strip().startswith("uv build")]

    assert "Smoke-test built wheel entry points" in workflow
    assert len(build_commands) == 2
    assert all("--build-constraints build-constraints.txt --require-hashes" in line for line in build_commands)
    assert 'uv build --sdist --out-dir "$out_dir"' in workflow
    assert 'uv build --wheel "${sdists[0]}" --out-dir "$out_dir"' in workflow
    assert 'uv tool run --isolated --from "$wheel" recon --version' in workflow
    assert 'uv run --no-project --isolated --with "$wheel" python -m recon_tool --version' in workflow
