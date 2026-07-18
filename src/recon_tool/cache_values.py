"""Shared validation, inspection, and cleanup helpers for persisted cache data.

Cache files are untrusted local JSON. These helpers preserve legacy defaults
without coercing malformed values into plausible domain observations.
"""

from __future__ import annotations

import logging
import math
from bisect import insort
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, TypeVar

from recon_tool.models import ConfidenceLevel

logger = logging.getLogger("recon")
_MAX_CACHE_COUNT = 2_147_483_647
_T = TypeVar("_T")
DEFAULT_CACHE_OVERVIEW_LIMIT = 100
_CACHE_TEMP_NONCE_LENGTH = 8
_CACHE_TEMP_NONCE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")


@dataclass(frozen=True)
class CacheInspection(Generic[_T]):
    """Read-only inspection outcome that distinguishes absence from failure."""

    entry: _T | None = None
    failed: bool = False


@dataclass(frozen=True)
class CacheListing(Generic[_T]):
    """Validated cache metadata plus explicit inspection completeness."""

    entries: tuple[_T, ...] = ()
    failed: int = 0
    inspected: int = 0
    total: int = 0
    temporary_files: int = 0


@dataclass(frozen=True)
class CacheFileSelection:
    """Deterministic bounded cache candidates found without reading payloads."""

    stems: tuple[str, ...] = ()
    total: int = 0
    temporary_files: int = 0


@dataclass(frozen=True)
class CacheClearResult:
    """Non-raising outcome for one cache layer's destructive clear operation."""

    removed: int = 0
    temporary_removed: int = 0
    failed: bool = False


def _is_cache_temporary_name(name: str) -> bool:
    """Return whether a filename has the shape emitted by ``mkstemp`` writers."""
    try:
        domain, nonce, suffix = name.rsplit(".", 2)
    except ValueError:
        return False
    if (
        suffix != "tmp"
        or len(nonce) != _CACHE_TEMP_NONCE_LENGTH
        or any(character not in _CACHE_TEMP_NONCE_CHARS for character in nonce)
    ):
        return False
    try:
        from recon_tool.validator import validate_domain

        return validate_domain(domain, apex=False) == domain
    except ValueError:
        return False


def select_cache_file_stems(directory: Path, *, limit: int | None) -> CacheFileSelection:
    """Select the lexicographically first cache keys with bounded memory.

    Directory names are all enumerated so the overview can report an exact
    candidate and temporary-artifact count. With a finite limit, at most that
    many names are retained and later payload inspection is correspondingly
    bounded. ``None`` is the explicit complete-inspection mode.
    """
    if limit is not None and limit < 1:
        raise ValueError("Cache listing limit must be positive or None")

    stems: list[str] = []
    total = 0
    temporary_files = 0
    for path in directory.iterdir():
        name = path.name
        if _is_cache_temporary_name(name):
            temporary_files += 1
            continue
        if not name.endswith(".json"):
            continue
        total += 1
        stem = name[:-5]
        if limit is None:
            stems.append(stem)
            continue
        insort(stems, stem)
        if len(stems) > limit:
            stems.pop()
    if limit is None:
        stems.sort()
    return CacheFileSelection(stems=tuple(stems), total=total, temporary_files=temporary_files)


def clear_cache_directory(directory: Path, *, layer: str) -> CacheClearResult:
    """Remove completed entries and writer-shaped temporary artifacts."""
    removed = 0
    temporary_removed = 0
    failed = False
    try:
        for path in directory.iterdir():
            suffix = path.suffix
            is_temporary = _is_cache_temporary_name(path.name)
            if suffix != ".json" and not is_temporary:
                continue
            try:
                path.unlink()
                removed += int(suffix == ".json")
                temporary_removed += int(is_temporary)
            except FileNotFoundError:
                continue
            except OSError:
                failed = True
                logger.debug("%s cache file unlink failed: %s", layer, path, exc_info=True)
    except OSError:
        failed = True
        logger.debug("%s cache clear-all enumeration failed", layer, exc_info=True)
    return CacheClearResult(removed=removed, temporary_removed=temporary_removed, failed=failed)


def cache_count(
    value: Any,
    field: str,
    *,
    default: int = 0,
    maximum: int = _MAX_CACHE_COUNT,
) -> int:
    """Return a non-negative bounded JSON integer or reject the cache entry."""
    if value is None:
        return default
    if type(value) is not int or value < 0 or value > maximum:
        raise ValueError(f"Cache field {field!r} must be a bounded non-negative integer")
    return value


def cache_float(
    value: Any,
    field: str,
    *,
    default: float = 0.0,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """Return a finite JSON number or reject the cache entry."""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Cache field {field!r} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"Cache field {field!r} must be a finite number")
    if minimum is not None and result < minimum:
        raise ValueError(f"Cache field {field!r} must be at least {minimum}")
    if maximum is not None and result > maximum:
        raise ValueError(f"Cache field {field!r} must be at most {maximum}")
    return result


def required_cache_float(
    value: Any,
    field: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """Return a required finite JSON number or reject the cache entry."""
    if value is None:
        raise ValueError(f"Cache field {field!r} must be a finite number")
    return cache_float(value, field, minimum=minimum, maximum=maximum)


def cache_object_tuple(value: Any, field: str) -> tuple[dict[str, Any], ...]:
    """Return an array of JSON objects without dropping malformed members."""
    if not isinstance(value, list | tuple) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"Cache field {field!r} must be an array of objects")
    return tuple(value)


def cache_string_tuple(value: Any, field: str) -> tuple[str, ...]:
    """Return a JSON string array as a tuple without coercing corrupt values."""
    if value is None:
        return ()
    if not isinstance(value, list | tuple) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Cache field {field!r} must be an array of strings")
    return tuple(value)


def cache_string(value: Any, field: str, *, nonempty: bool = False) -> str:
    """Return a required JSON string without coercing corrupt scalar values."""
    if not isinstance(value, str) or (nonempty and not value):
        qualifier = "nonempty " if nonempty else ""
        raise ValueError(f"Cache field {field!r} must be a {qualifier}string")
    return value


def optional_cache_string(value: Any, field: str) -> str | None:
    """Return an optional JSON string without coercing other scalar types."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Cache field {field!r} must be a string or null")
    return value


def cache_bool(value: Any, field: str, *, default: bool = False) -> bool:
    """Return a strict JSON boolean or reject the cache entry."""
    if value is None:
        return default
    if type(value) is not bool:
        raise ValueError(f"Cache field {field!r} must be a boolean")
    return value


def optional_cache_count(value: Any, field: str, *, maximum: int = _MAX_CACHE_COUNT) -> int | None:
    """Return an optional bounded count."""
    return None if value is None else cache_count(value, field, maximum=maximum)


def parse_confidence(
    value: Any,
    field: str,
    fallback: ConfidenceLevel = ConfidenceLevel.MEDIUM,
) -> ConfidenceLevel:
    """Parse a cache confidence, defaulting only when the field is absent."""
    if value is None:
        return fallback
    if not isinstance(value, str):
        raise ValueError(f"Cache field {field!r} must be low, medium, or high")
    try:
        return ConfidenceLevel(value.lower())
    except ValueError as exc:
        raise ValueError(f"Cache field {field!r} must be low, medium, or high") from exc
