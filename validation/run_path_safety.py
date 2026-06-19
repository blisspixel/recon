"""Path helpers for maintainer-local validation run directories."""

from __future__ import annotations

import re
from pathlib import Path

_SAFE_RUN_STAMP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")


def validate_run_stamp(stamp: str) -> str:
    """Return a path-segment-safe run stamp or raise."""
    if not _SAFE_RUN_STAMP_RE.fullmatch(stamp):
        raise ValueError("run stamp must be 1-80 letters, digits, dots, underscores, or hyphens")
    return stamp


def contained_child(parent: Path, child_name: str) -> Path:
    """Resolve ``child_name`` under ``parent`` and reject traversal."""
    base = parent.resolve(strict=False)
    child = (base / child_name).resolve(strict=False)
    if child != base and base in child.parents:
        return child
    raise ValueError(f"run directory escapes output root: {child_name}")
