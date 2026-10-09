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

import http.client
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from recon_tool import __version__
from recon_tool.json_limits import exceeds_json_nesting_limit

_PACKAGE = "recon-tool"
_MAX_PYPI_RESPONSE_BYTES = 5 * 1024 * 1024
_MAX_INSTALL_RECEIPT_BYTES = 64 * 1024

# Install methods, in detection order of specificity.
PIPX = "pipx"
UV = "uv"
HOMEBREW = "homebrew"
EDITABLE = "editable"
PIP = "pip"
UNKNOWN = "unverified"


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


def _read_install_receipt(path: Path) -> str | None:
    """Read bounded manager metadata, distinguishing absent from invalid."""
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("installation receipt is not a regular file")
        # Refuse links and avoid blocking on a FIFO substituted after lstat on
        # platforms that expose these flags. Recheck the opened descriptor.
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("installation receipt is not a regular file")
            raw = handle.read(_MAX_INSTALL_RECEIPT_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(raw) > _MAX_INSTALL_RECEIPT_BYTES:
        raise ValueError("installation receipt exceeds supported size")
    return raw.decode("utf-8-sig")


def _pipx_receipt_method(raw: str) -> str:
    if exceeds_json_nesting_limit(raw):
        return UNKNOWN
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("pipx_metadata_version"), str):
        return UNKNOWN
    package = data.get("main_package")
    if not isinstance(package, dict) or package.get("package") != _PACKAGE:
        return UNKNOWN
    return PIPX if not package.get("suffix") and not package.get("pinned") else UNKNOWN


def _uv_receipt_method(raw: str) -> str:
    tool = tomllib.loads(raw).get("tool")
    if not isinstance(tool, dict):
        return UNKNOWN
    requirements = tool.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        return UNKNOWN
    first = requirements[0]
    return UV if isinstance(first, dict) and first.get("name") == _PACKAGE else UNKNOWN


def _receipt_method(prefix: Path) -> str | None:
    """Identify the environment owner, not the installer of a dependency.

    pipx records its main package in pipx_metadata.json. uv records the tool
    as its first requirement in uv-receipt.toml, before any --with packages.
    Receipts work with custom manager directories without path-name guesses.
    Unknown receipt shapes deliberately require manual maintenance.
    """
    try:
        pipx_raw = _read_install_receipt(prefix / "pipx_metadata.json")
        uv_raw = _read_install_receipt(prefix / "uv-receipt.toml")
        if pipx_raw is not None and uv_raw is not None:
            return UNKNOWN
        if pipx_raw is not None:
            return _pipx_receipt_method(pipx_raw)
        if uv_raw is not None:
            return _uv_receipt_method(uv_raw)
    except (OSError, ValueError, RecursionError):
        return UNKNOWN
    return None


def detect_install_method() -> str:
    """Identify the running install from editable or manager metadata.

    Directory names alone never authorize a manager upgrade. A pip fallback
    requires package INSTALLER metadata; an unknown installer is manual-only.
    """
    if _is_editable():
        return EDITABLE
    receipt_method = _receipt_method(Path(sys.prefix))
    if receipt_method is not None:
        return receipt_method
    prefix_text = str(Path(sys.prefix)).replace("\\", "/").lower()
    parts = prefix_text.split("/")
    if "cellar" in parts or "homebrew" in prefix_text:
        return HOMEBREW
    if "pipx" in parts or ("uv" in parts and "tools" in parts):
        return UNKNOWN
    try:
        installer = distribution(_PACKAGE).read_text("INSTALLER")
    except (PackageNotFoundError, OSError):
        return UNKNOWN
    return PIP if installer is not None and installer.strip() == PIP else UNKNOWN


def _is_relative_lexical(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_relative_launcher_path(path: Path) -> bool:
    s = str(path)
    if not s or s == ".":
        return True
    if s.startswith((".", "..")):
        return True
    return not (path.is_absolute() or s.startswith(("/", "\\")))


def _target_in_ancestors(target: Path, current_directory: Path) -> bool:
    try:
        resolved_t = target.resolve()
    except OSError:
        return True
    if resolved_t.is_relative_to(current_directory) or _is_relative_lexical(target, current_directory):
        return True
    for ancestor in current_directory.parents:
        if ancestor == ancestor.parent or ancestor == Path.home():
            continue
        if resolved_t.is_relative_to(ancestor) or _is_relative_lexical(target, ancestor):
            return True
    return False


def _launcher_is_in_workspace(target: Path, *, lexical: Path | None = None) -> bool:
    """Return True if target or lexical is within the current workspace."""
    try:
        current_directory = Path.cwd().resolve()
        targets = [target]
        if lexical is not None:
            targets.append(lexical)
            if _is_relative_launcher_path(lexical):
                return True

        for candidate in (current_directory, *current_directory.parents):
            if (candidate / ".git").exists():
                return any(t.resolve().is_relative_to(candidate) or _is_relative_lexical(t, candidate) for t in targets)

        return any(_target_in_ancestors(t, current_directory) for t in targets)
    except OSError:
        return True


def _resolve_launcher(name: str) -> str | None:
    """Absolute path to a launcher outside the current workspace tree."""
    found = shutil.which(name)
    if found is None:
        return None
    lexical = Path(found)
    if _is_relative_launcher_path(lexical):
        return None
    try:
        resolved = lexical.resolve()
    except OSError:
        return None

    if _launcher_is_in_workspace(resolved, lexical=lexical):
        return None
    return str(resolved)


def _pip_command() -> list[str]:
    """Use installed pip without importing a module from the current directory.

    Safe-path mode preserves user-site installs, unlike isolated mode. Explicit
    interpreter configuration remains the operator's responsibility.
    """
    return [sys.executable, "-P", "-m", "pip"]


def upgrade_command(method: str, *, version: str | None = None) -> list[str] | None:
    """The argv to upgrade in place, or None when the user must act manually.

    Returns None for retired Homebrew and editable installs, and also when the
    detected launcher cannot be resolved to a trusted absolute path.
    """
    if version is not None and _version_key(version) is None:
        return None
    spec = f"{_PACKAGE}=={version}" if version is not None else _PACKAGE
    if method in (PIPX, UV):
        launcher = _resolve_launcher(method)
        if launcher is None or not _manager_targets_current_install(launcher, method):
            return None
        prefix = [launcher, "tool"] if method == UV else [launcher]
        # pipx's upgrade path already removes original version specifiers.
        if method == PIPX or version is None:
            return [*prefix, "upgrade", _PACKAGE]
        # A version-pinned installer receipt constrains `tool upgrade`.
        # Replace that requirement with the checked release through its owner.
        # Do not force-recreate a uv environment: its running interpreter is
        # locked on Windows. An ordinary install updates the requirement in place.
        return [*prefix, "install", "--upgrade", spec]
    if method == PIP:
        return [*_pip_command(), "install", "-U", spec]
    return None


def pinned_spec(version: str) -> str:
    """Return a version-pinned requirement, or raise when the version is unsafe."""
    if _version_key(version) is None:
        raise ValueError("unsupported release version")
    return f"{_PACKAGE}=={version}"


def interpreter_reinstall_argv(version: str) -> list[str]:
    """Pip reinstall through the current interpreter, without the recon launcher."""
    return [*_pip_command(), "install", "-U", pinned_spec(version)]


def offline_pip_command(spec: str, wheelhouse: Path) -> list[str]:
    """Install one already-downloaded release without contacting the index."""
    return [
        *_pip_command(),
        "install",
        "--disable-pip-version-check",
        "--upgrade",
        "--only-binary=:all:",
        "--no-index",
        f"--find-links={wheelhouse}",
        spec,
    ]


def format_argv(command: list[str]) -> str:
    """Render an argv for a person to copy, without invoking a shell."""
    if sys.platform == "win32":
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def _noninteractive_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PIP_NO_INPUT"] = "1"
    return env


def stage_pip_wheelhouse(spec: str) -> Path:
    """Download a pinned release before pip is allowed to replace the install.

    A failed download leaves the current files in place. The caller installs
    from the returned directory and then deletes it.
    """
    version = spec.split("==", 1)[1] if "==" in spec else ""
    if not spec.startswith(f"{_PACKAGE}==") or _version_key(version) is None:
        raise OSError("refusing to download an unpinned package")
    from recon_tool.updater_windows import WHEELHOUSE_PREFIX, remove_wheelhouse

    destination = Path(tempfile.mkdtemp(prefix=WHEELHOUSE_PREFIX))
    command = [
        *_pip_command(),
        "download",
        "--disable-pip-version-check",
        "--only-binary=:all:",
        "--dest",
        str(destination),
        spec,
    ]
    try:
        result = subprocess.run(  # noqa: S603 - interpreter, pip module, and pinned spec; no shell.
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=180,
            env=_noninteractive_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        remove_wheelhouse(destination)
        raise OSError(f"could not download {spec} ({exc})") from exc
    if result.returncode != 0 or not any(destination.iterdir()):
        remove_wheelhouse(destination)
        raise OSError(f"could not download {spec} (exit {result.returncode})")
    return destination


def _manager_targets_current_install(launcher: str, method: str) -> bool:
    """Verify the launcher's local destination before offering an upgrade.

    Custom UV_TOOL_DIR / PIPX_HOME settings may differ from those that created
    this environment. Query only the already-vetted launcher, with no package
    operation or network lookup, and compare its reported root to sys.prefix.
    """
    prefix = Path(sys.prefix)
    if prefix.name != _PACKAGE or _receipt_method(prefix) != method:
        return False
    query = ["tool", "dir"] if method == UV else ["environment", "--value", "PIPX_LOCAL_VENVS"]
    try:
        result = subprocess.run(  # noqa: S603
            [launcher, *query],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        root = result.stdout.strip()
        if result.returncode != 0 or not root or len(root) > 4096 or any(ord(char) < 32 for char in root):
            return False
        root_path = Path(root)
        return root_path.is_absolute() and (root_path / _PACKAGE).resolve() == prefix.resolve()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def manual_hint(method: str) -> str:
    """The command to tell the user to run when we won't self-upgrade."""
    if method == HOMEBREW:
        return "Homebrew install is retired; reinstall with `uv tool install recon-tool` or `pipx install recon-tool`"
    if method == EDITABLE:
        return "git pull  (editable install from a source checkout)"
    if method == PIPX:
        return (
            "verify `pipx environment --value PIPX_LOCAL_VENVS` contains this install, then `pipx upgrade recon-tool`"
        )
    if method == UV:
        return "verify `uv tool dir` contains this install, then `uv tool install --upgrade recon-tool`"
    if method == PIP:
        return "pip install -U recon-tool"
    return "installation owner could not be verified; use the original environment's package manager manually"


def fetch_latest_version(timeout: float = 10.0) -> str | None:
    """Return the latest recon-tool version on PyPI, or None on any failure."""
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{_PACKAGE}/json", timeout=timeout) as resp:
            raw = resp.read(_MAX_PYPI_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_PYPI_RESPONSE_BYTES:
            return None
        text = raw.decode("utf-8")
        if exceeds_json_nesting_limit(text):
            return None
        payload = json.loads(text)
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
    except (http.client.HTTPException, urllib.error.URLError, TimeoutError, TypeError, ValueError, OSError):
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


def non_upgrade_status_message(current: str, latest: str) -> str | None:
    """Return styled equal/ahead status, or None when an upgrade is available."""
    comparison = compare_versions(current, latest)
    if comparison < 0:
        return None
    if comparison == 0:
        return f"[green]recon {current} is up to date.[/green]"
    return (
        f"[cyan]Installed recon {current} is newer than the latest PyPI release ({latest}). "
        "No upgrade is offered.[/cyan]"
    )
