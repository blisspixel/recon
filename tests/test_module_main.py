"""Package module entry points used by operators and installers."""

from __future__ import annotations

import subprocess
import sys

import pytest


def test_package_main_module_imports() -> None:
    """``recon_tool.__main__`` must import cleanly for ``python -m recon_tool``."""
    import recon_tool.__main__ as package_main

    assert callable(package_main.run)


def test_python_m_recon_tool_version() -> None:
    """Live process check: module form reports the package version."""
    result = subprocess.run(
        [sys.executable, "-m", "recon_tool", "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    assert "recon" in combined.lower()
    assert any(ch.isdigit() for ch in combined)


@pytest.mark.parametrize("argv", [["-h"], ["--help"]])
def test_python_m_recon_tool_help_mentions_passive_scope(argv: list[str]) -> None:
    result = subprocess.run(  # noqa: S603 - argv list, no shell, no untrusted input.
        [sys.executable, "-m", "recon_tool", *argv],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    assert "Passive domain intelligence from public sources" in combined
