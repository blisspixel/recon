"""Read-only, payload-free metadata inspection for the result cache."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from recon_tool.cache import tenant_info_from_dict
from recon_tool.cache_contract import (
    DEFAULT_TTL,
    MAX_RESULT_CACHE_FILE_BYTES,
    RESULT_CACHE_VERSION,
)
from recon_tool.cache_paths import resolve_cache_directory, resolve_result_cache_path
from recon_tool.cache_values import CacheInspection, CacheListing
from recon_tool.json_limits import load_bounded_json_file
from recon_tool.validator import validate_domain

logger = logging.getLogger("recon")


@dataclass(frozen=True)
class ResultCacheInfo:
    """Validated result-cache metadata without TenantInfo payload fields."""

    domain: str
    cached_at: str
    resolved_at: str
    age_seconds: float
    file_size_bytes: int
    reusable: bool


def inspect_result_cache(domain: str) -> CacheInspection[ResultCacheInfo]:
    """Inspect one result-cache entry while preserving missing/failure truth."""
    try:
        expected_domain = validate_domain(domain, apex=False)
        path = resolve_result_cache_path(expected_domain)
        if path is None:
            raise ValueError("Result cache path is outside its configured boundary")
        data, file_stat, age_seconds = load_bounded_json_file(
            path,
            maximum_bytes=MAX_RESULT_CACHE_FILE_BYTES,
        )
        if not isinstance(data, dict):
            raise ValueError("Result cache payload must be a JSON object")
        if data.get("_cache_version") != RESULT_CACHE_VERSION:
            raise ValueError("Result cache version does not match the current format")
        info = tenant_info_from_dict(data)
        if info.queried_domain != expected_domain:
            raise ValueError("Result cache payload domain does not match its cache key")

        cached_at = data.get("_cached_at")
        return CacheInspection(
            entry=ResultCacheInfo(
                domain=expected_domain,
                cached_at=cached_at if isinstance(cached_at, str) and cached_at else "unknown",
                resolved_at=info.resolved_at or "unknown",
                age_seconds=age_seconds,
                file_size_bytes=file_stat.st_size,
                reusable=age_seconds <= DEFAULT_TTL,
            )
        )
    except FileNotFoundError:
        return CacheInspection()
    except (OSError, OverflowError, TypeError, ValueError, json.JSONDecodeError, RecursionError):
        logger.debug("Result cache inspection failed for %s", domain, exc_info=True)
        return CacheInspection(failed=True)


def list_result_cache() -> CacheListing[ResultCacheInfo]:
    """List validated result-cache metadata and count unreadable entries."""
    try:
        directory = resolve_cache_directory()
        if directory is None:
            logger.debug("Result cache listing rejected its configured directory")
            return CacheListing(failed=1)
        if not directory.exists():
            return CacheListing()
        if not directory.is_dir():
            logger.debug("Result cache listing path is not a directory")
            return CacheListing(failed=1)

        entries: list[ResultCacheInfo] = []
        failed = 0
        for path in sorted(directory.glob("*.json")):
            inspection = inspect_result_cache(path.stem)
            if inspection.entry is not None:
                entries.append(inspection.entry)
            elif inspection.failed:
                failed += 1
        return CacheListing(entries=tuple(entries), failed=failed)
    except OSError:
        logger.debug("Result cache listing failed", exc_info=True)
        return CacheListing(failed=1)
