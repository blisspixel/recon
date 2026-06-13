"""Self-update support for the `recon update` command.

recon can be installed several ways (pipx, uv tool, plain pip, Homebrew, an
editable source checkout), and each upgrades differently. These pure helpers
detect how the running copy was installed and produce the right upgrade command,
plus a PyPI latest-version lookup so `recon update` can say whether an upgrade is
even needed. The CLI command in cli.py wires them together and runs the upgrade.

Network touches only pypi.org (the version check); the upgrade itself shells out
to the detected tool. Everything here is defensive — a failed lookup or unknown
install method degrades to a printed manual command, never a crash.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from recon_tool import __version__

_PACKAGE = "recon-tool"

# Install methods, in detection order of specificity.
PIPX = "pipx"
UV = "uv"
HOMEBREW = "homebrew"
EDITABLE = "editable"
PIP = "pip"


def current_version() -> str:
    return __version__


def _is_editable() -> bool:
    try:
        raw = distribution(_PACKAGE).read_text("direct_url.json")
    except (PackageNotFoundError, OSError):
        return False
    if not raw:
        return False
    try:
        return bool(json.loads(raw).get("dir_info", {}).get("editable"))
    except (ValueError, AttributeError):
        return False


def detect_install_method() -> str:
    """Best-effort guess of how the running recon was installed.

    Reads the interpreter prefix (pipx / uv / Homebrew live in distinctive
    paths) and the package's direct_url.json (editable installs). Falls back to
    ``pip`` — the safe default, since ``pip install -U`` works for a plain venv
    or user install.
    """
    if _is_editable():
        return EDITABLE
    prefix = str(Path(sys.prefix)).replace("\\", "/").lower()
    parts = prefix.split("/")
    if "pipx" in parts:
        return PIPX
    if "uv" in parts and "tools" in parts:
        return UV
    if "cellar" in parts or "homebrew" in prefix:
        return HOMEBREW
    return PIP


def upgrade_command(method: str) -> list[str] | None:
    """The argv to upgrade in place, or None when the user must act manually
    (Homebrew and editable installs are not safe to drive from here)."""
    if method == PIPX:
        return ["pipx", "upgrade", _PACKAGE]
    if method == UV:
        return ["uv", "tool", "upgrade", _PACKAGE]
    if method == PIP:
        return [sys.executable, "-m", "pip", "install", "-U", _PACKAGE]
    return None


def manual_hint(method: str) -> str:
    """The command to tell the user to run when we won't self-upgrade."""
    if method == HOMEBREW:
        return "brew upgrade recon"
    if method == EDITABLE:
        return "git pull  (editable install from a source checkout)"
    return "pip install -U recon-tool"


def fetch_latest_version(timeout: float = 10.0) -> str | None:
    """Return the latest recon-tool version on PyPI, or None on any failure."""
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{_PACKAGE}/json", timeout=timeout) as resp:
            return str(json.load(resp)["info"]["version"])
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError):
        return None


def _version_tuple(v: str) -> tuple[int, ...]:
    out: list[int] = []
    for part in v.split("."):
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        out.append(int(digits) if digits else 0)
    return tuple(out)


def compare_versions(current: str, latest: str) -> int:
    """-1 if current < latest (upgrade available), 0 if equal, 1 if current is
    ahead (a local/dev build). Falls back to string compare on parse trouble."""
    if current == latest:
        return 0
    ct, lt = _version_tuple(current), _version_tuple(latest)
    if ct == lt:
        return 0
    return -1 if ct < lt else 1
