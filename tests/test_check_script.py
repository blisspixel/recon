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


def test_pyright_scope_comes_only_from_pyproject() -> None:
    local_stage = next(command for _group, name, command in check._STAGES if name == "pyright")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert local_stage == [check._PY, "-m", "pyright"]
    assert "run: uv run pyright\n" in workflow
    assert "pyright src/recon_tool/ tests/" not in workflow


def test_ci_runs_the_interface_layout_guard() -> None:
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert "run: uv run python scripts/check_interface_layout.py" in workflow
