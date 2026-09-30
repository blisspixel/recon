"""Updater subprocesses must ignore an implicit working-directory pip module."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from recon_tool import updater
from recon_tool.updater_windows import remove_wheelhouse

_STUB = """import json, os, sys
from pathlib import Path
Path(os.environ['RECON_TEST_PIP_RECEIPT']).write_text(
    json.dumps({'origin': ORIGIN, 'args': sys.argv[1:]}), encoding='utf-8')
if '--dest' in sys.argv:
    (Path(sys.argv[sys.argv.index('--dest') + 1]) / 'synthetic.whl').write_bytes(b'synthetic')
"""


def _write_pip(root: Path, origin: str, *, package: bool) -> None:
    source = _STUB.replace("ORIGIN", repr(origin))
    if package:
        (root / "pip").mkdir(parents=True)
        (root / "pip" / "__init__.py").write_text("", encoding="utf-8")
        (root / "pip" / "__main__.py").write_text(source, encoding="utf-8")
    else:
        root.mkdir(parents=True, exist_ok=True)
        (root / "pip.py").write_text(source, encoding="utf-8")


@pytest.mark.parametrize("package", [False, True])
@pytest.mark.parametrize("operation", ["upgrade", "reinstall", "offline", "download"])
def test_updater_ignores_workspace_pip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, package: bool, operation: str
) -> None:
    workspace, trusted = tmp_path / "workspace", tmp_path / "installed"
    _write_pip(workspace, "workspace", package=package)
    _write_pip(trusted, "installed", package=True)
    receipt = tmp_path / "receipt.json"
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("PYTHONPATH", str(trusted))
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    monkeypatch.setenv("RECON_TEST_PIP_RECEIPT", str(receipt))

    if operation == "download":
        wheelhouse = updater.stage_pip_wheelhouse("recon-tool==1.2.3")
        try:
            assert (wheelhouse / "synthetic.whl").is_file()
        finally:
            remove_wheelhouse(wheelhouse)
    else:
        commands = {
            "upgrade": updater.upgrade_command(updater.PIP, version="1.2.3"),
            "reinstall": updater.interpreter_reinstall_argv("1.2.3"),
            "offline": updater.offline_pip_command("recon-tool==1.2.3", tmp_path),
        }
        command = commands[operation]
        assert command is not None
        subprocess.run(command, check=True, timeout=15, capture_output=True)  # noqa: S603 - synthetic pip only.

    result = json.loads(receipt.read_text(encoding="utf-8"))
    assert result["origin"] == "installed"
    assert result["args"][-1] == "recon-tool==1.2.3"
    assert result["args"][0] == ("download" if operation == "download" else "install")


def test_pip_user_site_install_remains_available(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    interpreter = str(getattr(sys, "_base_executable", sys.executable))
    env = {key: value for key, value in os.environ.items() if not key.startswith("PYTHON")}
    env["PYTHONUSERBASE"] = str(tmp_path / "userbase")
    receipt = tmp_path / "receipt.json"
    env["RECON_TEST_PIP_RECEIPT"] = str(receipt)
    result = subprocess.run(  # noqa: S603 - current base interpreter and constant site query.
        [interpreter, "-P", "-c", "import site; print(site.getusersitepackages())"],
        env=env,
        check=True,
        timeout=15,
        capture_output=True,
        text=True,
    )
    _write_pip(Path(result.stdout.strip()), "user-site", package=True)
    workspace = tmp_path / "workspace"
    _write_pip(workspace, "workspace", package=False)
    monkeypatch.setattr(updater.sys, "executable", interpreter)
    command = updater.interpreter_reinstall_argv("1.2.3")
    subprocess.run(  # noqa: S603 - temporary user-site pip stub, no package installation.
        command, env=env, cwd=workspace, check=True, timeout=15, capture_output=True
    )
    assert json.loads(receipt.read_text(encoding="utf-8"))["origin"] == "user-site"
