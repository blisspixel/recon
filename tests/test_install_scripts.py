"""Installer-script regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_INSTALL_SH = _ROOT / "scripts" / "install.sh"


def test_unix_installer_uses_portable_python_version_check() -> None:
    script = _INSTALL_SH.read_text(encoding="utf-8")

    assert "sort -V" not in script
    assert "sys.version_info >= (3, 11)" in script


def test_unix_installer_shell_syntax() -> None:
    if os.name == "nt":
        pytest.skip("checked on Unix runners")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")

    subprocess.run([bash, "-n", str(_INSTALL_SH)], check=True)  # noqa: S603
