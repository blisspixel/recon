"""Self-update support for the `recon update` command.

recon can be installed several ways (pipx, uv tool, plain pip, or an editable
source checkout), and each upgrades differently. These pure helpers detect how
the running copy was installed and produce the right upgrade command, plus a
PyPI latest-version lookup so `recon update` can say whether an upgrade is even
needed. The CLI command in cli.py wires them together and runs the upgrade.

Network touches only pypi.org for the version check; the upgrade itself shells
out to the detected tool. Everything here is defensive: a failed lookup or
unknown install method degrades to a printed manual command, never a crash.
"""

from __future__ import annotations

import json
import re
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

    Reads the interpreter prefix (pipx / uv live in distinctive paths) and the
    package's direct_url.json (editable installs). Falls back to
    ``pip``, the safe default, since ``pip install -U`` works for a plain venv
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
    (retired Homebrew installs and editable installs need manual action)."""
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
        return "Homebrew install is retired; reinstall with `uv tool install recon-tool` or `pipx install recon-tool`"
    if method == EDITABLE:
        return "git pull  (editable install from a source checkout)"
    return "pip install -U recon-tool"


def fetch_latest_version(timeout: float = 10.0) -> str | None:
    """Return the latest recon-tool version on PyPI, or None on any failure."""
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{_PACKAGE}/json", timeout=timeout) as resp:
            payload = json.load(resp)
        if not isinstance(payload, dict):
            return None
        info = payload.get("info")
        if not isinstance(info, dict):
            return None
        version = info.get("version")
        if not isinstance(version, str) or not version.strip():
            return None
        normalized = version.strip()
        return normalized if _version_key(normalized) is not None else None
    except (urllib.error.URLError, TimeoutError, TypeError, ValueError, OSError):
        return None


_VERSION_RE = re.compile(
    r"^v?(?P<release>\d+(?:\.\d+)*)"
    r"(?:(?:[-_.]?(?P<pre>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_num>\d*))"
    r"|(?:[-_.]?dev[-_.]?(?P<dev_num>\d*)))?"
    r"(?P<local>\+[0-9a-z]+(?:[-_.][0-9a-z]+)*)?$",
    re.IGNORECASE,
)
_PRECEDENCE = {
    "a": 0,
    "alpha": 0,
    "b": 1,
    "beta": 1,
    "c": 2,
    "pre": 2,
    "preview": 2,
    "rc": 2,
}


def _version_key(
    version: str,
) -> tuple[tuple[int, ...], int, int, int, tuple[tuple[int, int, str], ...]] | None:
    """Parse stable, prerelease, development, and local version forms.

    Release tuples drop insignificant trailing zeroes, while prereleases sort
    development, alpha, beta, release-candidate, final, then a local build of
    that final. This covers recon's update-check inputs without adding a
    packaging library to the runtime.
    """
    normalized = version.strip()
    if len(normalized) > 128:
        return None
    match = _VERSION_RE.fullmatch(normalized)
    if match is None:
        return None
    try:
        release = [int(part) for part in match.group("release").split(".")]
        phase_number = int(match.group("pre_num") or match.group("dev_num") or "0")
    except ValueError:
        return None
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = match.group("pre")
    if match.group("dev_num") is not None:
        phase = -1
    elif pre is not None:
        phase = _PRECEDENCE[pre.casefold()]
    else:
        phase = 3
    local = match.group("local")
    local_key: tuple[tuple[int, int, str], ...] = ()
    if local is not None:
        local_key = tuple(
            (1, int(segment), "") if segment.isdigit() else (0, 0, segment.casefold())
            for segment in re.split(r"[-_.]", local[1:])
        )
    return tuple(release), phase, phase_number, int(local is not None), local_key


def _release_prefix_key(version: str) -> tuple[int, ...] | None:
    """Return a bounded numeric release prefix for unsupported local forms."""
    normalized = version.strip()
    if len(normalized) > 128:
        return None
    match = re.match(r"^v?(\d+(?:\.\d+)*)", normalized)
    if match is None:
        return None
    try:
        release = [int(part) for part in match.group(1).split(".")]
    except ValueError:
        return None
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    return tuple(release)


def compare_versions(current: str, latest: str) -> int:
    """-1 if current < latest (upgrade available), 0 if equal, 1 if current is
    ahead (a local/dev build). Unsupported local spellings compare their
    numeric release prefixes before a final string fallback."""
    if current == latest:
        return 0
    current_key = _version_key(current)
    latest_key = _version_key(latest)
    if current_key is None or latest_key is None:
        current_release = _release_prefix_key(current)
        latest_release = _release_prefix_key(latest)
        if current_release is not None and latest_release is not None and current_release != latest_release:
            return -1 if current_release < latest_release else 1
        return -1 if current < latest else 1
    if current_key == latest_key:
        return 0
    return -1 if current_key < latest_key else 1
