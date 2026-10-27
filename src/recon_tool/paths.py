"""Central resolution of recon's config / cache / state directories.

recon historically kept everything under ``~/.recon/`` (overridable with
an absolute ``RECON_CONFIG_DIR``). This module adds XDG Base Directory support
for *fresh* installs while preserving an absolute override and an existing
legacy directory, so nobody's existing data moves:

* ``RECON_CONFIG_DIR`` set to an absolute path with no ``${...}`` placeholder
  → single directory, every category under it
  (unchanged: cache→ ``$DIR/cache``, priors→ ``$DIR/priors.yaml``, …). Highest
  precedence; this is the test/CI seam. A relative value or an unexpanded
  ``${...}`` placeholder is ignored, with one stderr warning, so a client that
  leaves ``${PLUGIN_DATA}`` literal cannot create that directory in the
  working directory.
* ``~/.recon`` already exists → keep using it for everything (a legacy install;
  do not strand its data).
* otherwise (a fresh install) → XDG:
    - config → ``$XDG_CONFIG_HOME/recon`` (default ``~/.config/recon``)
    - cache  → ``$XDG_CACHE_HOME/recon``  (default ``~/.cache/recon``)
    - state  → ``$XDG_STATE_HOME/recon``  (default ``~/.local/state/recon``)

Per the XDG spec a relative value for an ``XDG_*`` variable is invalid and is
ignored (the default is used). Resolution reads the environment on every call,
so a test that sets ``RECON_CONFIG_DIR`` takes effect immediately.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Literal

_LEGACY_DIRNAME = ".recon"
_UNEXPANDED_PLACEHOLDER = re.compile(r"\$\{[^}]*\}")
_IGNORED_CONFIG_DIR_WARNED: set[str] = set()
IgnoredConfigDirKind = Literal["placeholder", "relative"]


def ignored_config_dir() -> tuple[IgnoredConfigDirKind, str] | None:
    """Why ``RECON_CONFIG_DIR`` is ignored, plus the unexpanded token.

    An absolute path with no ``${...}`` placeholder is honored and returns
    None. An empty or unset value also returns None. A placeholder result
    names the first ``${...}`` token and does not include the rest of the
    value. A relative path returns an empty token so the value itself is
    not echoed.
    """
    raw = os.environ.get("RECON_CONFIG_DIR")
    if not raw:
        return None
    match = _UNEXPANDED_PLACEHOLDER.search(raw)
    if match is not None:
        return ("placeholder", match.group(0))
    if not os.path.isabs(raw):
        return ("relative", "")
    return None


def _warn_ignored_config_dir(raw: str, kind: IgnoredConfigDirKind, token: str) -> None:
    """Warn once per process for one ignored raw value."""
    if raw in _IGNORED_CONFIG_DIR_WARNED:
        return
    _IGNORED_CONFIG_DIR_WARNED.add(raw)
    if kind == "placeholder":
        detail = f"because it contains unexpanded {token}"
    else:
        detail = "because it is not an absolute path"
    print(f"recon: ignoring RECON_CONFIG_DIR {detail}", file=sys.stderr)


def _legacy_base() -> Path | None:
    """The single-directory base for back-compat, or None to use XDG.

    Returns an absolute ``RECON_CONFIG_DIR`` with no unexpanded ``${...}``
    placeholder, else an existing ``~/.recon`` legacy directory, else None.
    A placeholder or relative override is ignored after one stderr warning.
    """
    raw = os.environ.get("RECON_CONFIG_DIR")
    if raw:
        ignored = ignored_config_dir()
        if ignored is None:
            return Path(raw)
        _warn_ignored_config_dir(raw, ignored[0], ignored[1])
    legacy = Path.home() / _LEGACY_DIRNAME
    if legacy.exists():
        return legacy
    return None


def _xdg(var: str, default: Path) -> Path:
    """Resolve an XDG base variable, honoring the spec's absolute-path rule."""
    val = os.environ.get(var)
    if val and os.path.isabs(val):  # a relative XDG path is invalid → ignore it
        return Path(val)
    return default


def config_dir() -> Path:
    """Directory for recon's config (priors / overlays / corpus)."""
    base = _legacy_base()
    if base is not None:
        return base
    return _xdg("XDG_CONFIG_HOME", Path.home() / ".config") / "recon"


def cache_root() -> Path:
    """Base directory for recon's caches (result cache, CT cache)."""
    base = _legacy_base()
    if base is not None:
        return base
    return _xdg("XDG_CACHE_HOME", Path.home() / ".cache") / "recon"


def state_dir() -> Path:
    """Base directory for recon's persistent runtime state (rate-limit state)."""
    base = _legacy_base()
    if base is not None:
        return base
    return _xdg("XDG_STATE_HOME", Path.home() / ".local" / "state") / "recon"
