"""Canonical containment checks shared by recon's disk caches."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from recon_tool.validator import validate_domain

_CACHE_DIRECTORY_NAMES = frozenset({"cache", "ct-cache"})


def _is_redirect(path: Path) -> bool:
    """Return whether a cache child is a symlink or Windows reparse point."""
    try:
        if path.is_symlink():
            return True
        if os.name != "nt":
            return False
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        return bool(attributes & reparse_flag)
    except OSError:
        return False


def resolve_cache_directory(directory_name: str = "cache", *, create: bool = False) -> Path | None:
    """Return a canonical cache directory within its configured root.

    An explicitly configured root may itself be a symlink, but its selected
    cache child must resolve to that root's direct child. This rejects a symlink
    or Windows junction that redirects only the destructive cache boundary.
    """
    from recon_tool.paths import cache_root

    if directory_name not in _CACHE_DIRECTORY_NAMES:
        return None
    configured_root = cache_root()
    requested = configured_root / directory_name
    try:
        if create:
            configured_root.mkdir(parents=True, exist_ok=True)
        resolved_root = configured_root.resolve(strict=False)
        if _is_redirect(requested):
            return None
        if create:
            requested.mkdir(exist_ok=True)
        if _is_redirect(requested):
            return None
        resolved_directory = requested.resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    if resolved_directory != resolved_root / directory_name:
        return None
    return resolved_directory


def validated_cache_path(directory: Path, domain: str) -> Path | None:
    """Return a validated domain cache path within a canonical directory."""
    try:
        normalized = validate_domain(domain, apex=False)
    except ValueError:
        return None
    path = directory / f"{normalized}.json"
    try:
        if not path.is_relative_to(directory):
            return None
    except (ValueError, OSError):
        return None
    return path


def resolve_result_cache_path(domain: str) -> Path | None:
    """Resolve one result-cache file path, rejecting traversal and redirects."""
    directory = resolve_cache_directory()
    if directory is None:
        return None
    return validated_cache_path(directory, domain)
