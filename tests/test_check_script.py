"""Canonical local-gate orchestration regressions."""

from __future__ import annotations

import subprocess

import pytest

from scripts import check


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
