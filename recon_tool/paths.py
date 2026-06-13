"""Central resolution of recon's config / cache / state directories.

recon historically kept everything under ``~/.recon/`` (overridable with
``RECON_CONFIG_DIR``). This module adds XDG Base Directory support for *fresh*
installs while preserving both legacy behaviors exactly, so nobody's existing
data moves:

* ``RECON_CONFIG_DIR`` set  → single directory, every category under it
  (unchanged: cache→ ``$DIR/cache``, priors→ ``$DIR/priors.yaml``, …). Highest
  precedence; this is the test/CI seam.
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
from pathlib import Path

_LEGACY_DIRNAME = ".recon"


def _legacy_base() -> Path | None:
    """The single-directory base for back-compat, or None to use XDG.

    Returns the ``RECON_CONFIG_DIR`` override if set, else an existing
    ``~/.recon`` legacy directory, else None.
    """
    env = os.environ.get("RECON_CONFIG_DIR")
    if env:
        return Path(env)
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
