"""Startup guard against a working-directory copy of ``recon_tool``.

Python can import a package through the current working directory: ``-m`` and
``-c`` put the working directory (or ``''``) at the front of ``sys.path`` unless
``PYTHONSAFEPATH=1`` or ``-P`` is in effect, and any relative entry in
``sys.path`` (for example from ``PYTHONPATH=.``) is resolved against the working
directory. A workspace that contains its own ``recon_tool`` package can then
shadow the installed one.

The guard asks where the running ``recon_tool`` package was actually imported
from. It refuses only when that import location is the working directory, or a
relative ``sys.path`` entry that resolves to it, because only then does the
loaded code depend on which directory the client launched from. Mere ancestry
is not a signal: every per-user installation lives somewhere under the home
directory, and a filesystem root is an ancestor of every path, so refusing
whenever the package sat below the working directory blocked legitimate launches
from ``$HOME`` and ``/``.

Two exemptions are preserved. An import location that is one of the running
interpreter's own installation roots (``purelib``, ``platlib``, site-packages,
or user site-packages) holds the installed package by definition. A working
directory whose ``pyproject.toml`` names ``recon-tool`` is the supported source
checkout workflow that the earlier guard already accepted.

This guard is defense in depth. When a hostile shadow package is imported, its
own code runs instead of this guard. The primary control is the launcher that
``recon mcp install`` generates, which removes ``''`` and ``'.'`` from
``sys.path`` before importing ``recon_tool`` and sets ``PYTHONSAFEPATH=1``.
"""

from __future__ import annotations

import contextlib
import os
import site
import sys
import sysconfig
from collections.abc import Iterable
from pathlib import Path

# Each path interpolated into the refusal is capped so a hostile or deeply
# nested directory cannot flood the client's stderr capture.
_MAX_PATH_CHARS = 200


def _same_path(left: Path, right: Path) -> bool:
    """Return True when both paths name the same directory.

    ``os.path.samefile`` compares device and file identity, which is correct on
    case-insensitive filesystems (Windows, default macOS) and through symlinks.
    When either path cannot be stat'ed, fall back to a case-normalized string
    comparison of the already-resolved paths.
    """
    try:
        return os.path.samefile(left, right)
    except (OSError, ValueError):
        return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _installation_roots() -> list[Path]:
    """Return the running interpreter's absolute package installation roots."""
    candidates: list[str] = []
    for key in ("purelib", "platlib"):
        try:
            value = sysconfig.get_paths().get(key)
        except (KeyError, OSError, ValueError):
            value = None
        if value:
            candidates.append(value)
    # Embedded and frozen interpreters can lack these helpers or fail inside them.
    with contextlib.suppress(OSError, ValueError, AttributeError):
        candidates.extend(site.getsitepackages())
    if site.ENABLE_USER_SITE:
        with contextlib.suppress(OSError, ValueError, AttributeError):
            candidates.append(site.getusersitepackages())
    roots: list[Path] = []
    for candidate in candidates:
        # A relative root would itself depend on the working directory.
        if not os.path.isabs(candidate):
            continue
        try:
            roots.append(Path(candidate).resolve())
        except (OSError, RuntimeError, ValueError):
            continue
    return roots


def _cwd_dependent_entries(import_root: Path, cwd: Path, path_entries: Iterable[object]) -> bool:
    """Return True when ``import_root`` was reachable only through the cwd.

    That is the case when the import root is the working directory itself
    (``python -m`` prepends it as an absolute path), or when a relative
    ``sys.path`` entry such as ``''``, ``'.'`` or ``'src'`` resolves to it.
    """
    if _same_path(import_root, cwd):
        return True
    for entry in path_entries:
        if not isinstance(entry, str) or os.path.isabs(entry):
            continue
        try:
            resolved = (cwd / entry).resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        if _same_path(resolved, import_root):
            return True
    return False


def _is_source_checkout(cwd: Path) -> bool:
    """Return True for the supported recon source checkout at ``cwd``."""
    pyproject = cwd / "pyproject.toml"
    if not pyproject.is_file():
        return False
    try:
        content = pyproject.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    # Tolerate the common spacing variants without pulling in a TOML parser.
    return 'name = "recon-tool"' in content or 'name="recon-tool"' in content


def _bounded(path: Path) -> str:
    """Render ``path`` for stderr with a fixed upper length."""
    text = "".join(ch if ch.isprintable() else "?" for ch in str(path))
    if len(text) <= _MAX_PATH_CHARS:
        return text
    keep = (_MAX_PATH_CHARS - 3) // 2
    return f"{text[:keep]}...{text[-keep:]}"


def refusal_message(pkg_dir: Path, cwd: Path) -> str:
    """Return the bounded, actionable refusal written to stderr."""
    return (
        "recon mcp server: refusing to start. The recon_tool package was "
        f"imported from {_bounded(pkg_dir)}, which Python reached through the "
        f"current working directory ({_bounded(cwd)}) rather than through an "
        "installed location. A recon_tool package inside a workspace can "
        "shadow the installed one, so recon will not run it.\n"
        "\n"
        "To start the installed server:\n"
        "  * Use the launcher from `recon mcp install --client=<name>`; it "
        "removes the working directory from the import path.\n"
        "  * Remove '.', empty, or other relative entries from PYTHONPATH in "
        "the client environment.\n"
        "  * Or start the client from a directory that does not contain a "
        "recon_tool package.\n"
        "To run from a recon source checkout, start from the repository root "
        'whose pyproject.toml has name = "recon-tool".\n'
    )


def detect_cwd_shadow_install() -> str | None:
    """Return a refusal message when ``recon_tool`` was imported through the cwd.

    Returns ``None`` when the loaded package came from a location that does not
    depend on the working directory, from one of the interpreter's installation
    roots, or from the supported source checkout.
    """
    import recon_tool  # the actually-imported package is what must be verified

    try:
        pkg_dir = Path(recon_tool.__file__).resolve().parent
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        # No resolvable package location: there is no file path a working
        # directory could have supplied.
        return None

    try:
        cwd = Path.cwd().resolve()
    except (OSError, RuntimeError, ValueError):
        # No usable working directory, so nothing could be imported through it.
        return None

    import_root = pkg_dir.parent
    if not _cwd_dependent_entries(import_root, cwd, sys.path):
        return None
    if any(_same_path(import_root, root) for root in _installation_roots()):
        return None
    if _is_source_checkout(cwd):
        return None
    return refusal_message(pkg_dir, cwd)
