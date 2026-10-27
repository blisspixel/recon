"""Ignored RECON_CONFIG_DIR values must not create a working-directory cache."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from recon_tool.cli.doctor import config_directory_check


def _run(tmp_path: Path, raw: str, script: str) -> subprocess.CompletedProcess[str]:
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    work.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["RECON_CONFIG_DIR"] = raw
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
        env.pop(name, None)
    return subprocess.run(  # noqa: S603 - fixed interpreter, argv list, test-owned script.
        [sys.executable, "-c", script],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


_CLI_SCRIPT = """
from pathlib import Path
cwd = Path.cwd()
from recon_tool.cli.doctor import config_directory_check
from recon_tool.paths import cache_root, state_dir
check = config_directory_check()
cache_root().mkdir(parents=True, exist_ok=True)
state_dir().mkdir(parents=True, exist_ok=True)
print(check.status if check is not None else "none")
print(check.detail if check is not None else "")
print("CHILDREN=" + ",".join(sorted(path.name for path in cwd.iterdir())))
"""

_MCP_SCRIPT = """
from pathlib import Path
cwd = Path.cwd()
import recon_tool.server
from recon_tool.paths import cache_root, state_dir
cache_root().mkdir(parents=True, exist_ok=True)
state_dir().mkdir(parents=True, exist_ok=True)
print("CHILDREN=" + ",".join(sorted(path.name for path in cwd.iterdir())))
"""


@pytest.mark.parametrize("raw", ["${PLUGIN_DATA}/recon", "cfg/recon"])
def test_cli_startup_does_not_write_the_working_directory(tmp_path: Path, raw: str) -> None:
    completed = _run(tmp_path, raw, _CLI_SCRIPT)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().splitlines()[-1] == "CHILDREN="
    if raw.startswith("${"):
        assert "unexpanded ${PLUGIN_DATA}" in completed.stderr
        assert "unexpanded ${PLUGIN_DATA}" in completed.stdout
    else:
        assert "not an absolute path" in completed.stderr
        assert "cfg/recon" not in completed.stderr
        assert "not an absolute path" in completed.stdout


def test_mcp_server_import_does_not_write_the_working_directory(tmp_path: Path) -> None:
    completed = _run(tmp_path, "${PLUGIN_DATA}/recon", _MCP_SCRIPT)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().splitlines()[-1] == "CHILDREN="
    assert "unexpanded ${PLUGIN_DATA}" in completed.stderr
    assert not (tmp_path / "work" / "${PLUGIN_DATA}").exists()


def test_doctor_row_names_the_placeholder_and_absolute_paths_stay_quiet(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RECON_CONFIG_DIR", "${PLUGIN_DATA}/recon")
    placeholder = config_directory_check()
    assert placeholder is not None
    assert placeholder.status == "warn"
    assert placeholder.detail == "ignoring RECON_CONFIG_DIR because it contains unexpanded ${PLUGIN_DATA}"
    assert "${PLUGIN_DATA}/recon" not in placeholder.detail

    monkeypatch.setenv("RECON_CONFIG_DIR", "cfg/recon")
    relative = config_directory_check()
    assert relative is not None
    assert relative.detail == "ignoring RECON_CONFIG_DIR because it is not an absolute path"
    assert "cfg/recon" not in relative.detail

    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    assert config_directory_check() is None
