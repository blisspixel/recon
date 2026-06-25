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


def _is_self_or_child(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return str(path)


def validate_private_output_root(
    output_root: Path,
    *,
    repo_root: Path,
    allowed_roots: tuple[Path, ...],
) -> Path:
    """Return a safe private-run output root or raise.

    Output roots outside the repository are operator-local and allowed. Output
    roots inside the repository must sit under one of the explicitly ignored
    private validation roots so private corpus artifacts cannot land in public
    paths by accident.
    """
    resolved_output = output_root.resolve(strict=False)
    resolved_repo = repo_root.resolve(strict=False)
    if not _is_self_or_child(resolved_output, resolved_repo):
        return resolved_output

    resolved_allowed = tuple(root.resolve(strict=False) for root in allowed_roots)
    if any(_is_self_or_child(resolved_output, root) for root in resolved_allowed):
        return resolved_output

    allowed_display = ", ".join(_display_path(root, resolved_repo) for root in resolved_allowed)
    raise ValueError(f"private validation output root inside repository must be under one of: {allowed_display}")
