"""Installer-script regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_INSTALL_SH = _ROOT / "scripts" / "install.sh"
_INSTALL_PS1 = _ROOT / "scripts" / "install.ps1"


def test_installers_do_not_bootstrap_pipx_with_unpinned_pip() -> None:
    script = _INSTALL_SH.read_text(encoding="utf-8")
    powershell = _INSTALL_PS1.read_text(encoding="utf-8")

    assert "sort -V" not in script
    assert "pip install" not in script
    assert "pip install" not in powershell
    assert "https://astral.sh/uv/install.sh" not in script
    assert "https://astral.sh/uv/install.ps1" not in powershell
    assert "install uv or pipx first" in script
    assert "install uv or pipx first" in powershell
    assert "Invoke-Expression (Invoke-RestMethod" not in powershell


def test_unix_installer_shell_syntax() -> None:
    if os.name == "nt":
        pytest.skip("checked on Unix runners")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")

    subprocess.run([bash, "-n", str(_INSTALL_SH)], check=True)  # noqa: S603
