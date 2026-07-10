"""Release-script regressions."""

from __future__ import annotations

import subprocess

from scripts import release


def test_release_script_points_at_src_layout_init() -> None:
    assert release.INIT_PY == release.ROOT / "src" / "recon_tool" / "__init__.py"
    assert release.INIT_PY.exists()


def test_release_script_version_consistency_reads_src_layout_init() -> None:
    assert release._check_version_consistency() == release._read_current_version()


def test_release_quality_gate_typechecks_tests(monkeypatch) -> None:
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(release, "_run", fake_run)

    release._run_quality_gate()

    pyright_cmd = next(cmd for cmd in commands if cmd[:3] == ["uv", "run", "pyright"])
    assert pyright_cmd == ["uv", "run", "pyright", "src/recon_tool/", "tests/"]


def test_release_push_command_names_only_the_reviewed_tag() -> None:
    assert release._release_push_command("2.3.7") == [
        "git",
        "push",
        "origin",
        "main",
        "refs/tags/v2.3.7:refs/tags/v2.3.7",
    ]
