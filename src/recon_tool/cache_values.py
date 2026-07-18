"""Strict scalar and sequence decoders for persisted cache data.

Cache files are untrusted local JSON. These helpers preserve legacy defaults
without coercing malformed values into plausible domain observations.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from recon_tool.models import ConfidenceLevel

_MAX_CACHE_COUNT = 2_147_483_647


@dataclass(frozen=True)
class CacheClearResult:
    """Non-raising outcome for one cache layer's destructive clear operation."""

    removed: int = 0
    failed: bool = False


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
