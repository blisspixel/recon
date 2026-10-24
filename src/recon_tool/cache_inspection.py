"""Read-only, payload-free metadata inspection for the result cache."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from recon_tool.cache_admission import ResultCacheAdmission, read_result_cache_entry
from recon_tool.cache_contract import DEFAULT_TTL
from recon_tool.cache_paths import resolve_cache_directory
from recon_tool.cache_values import CacheInspection, CacheListing, CachePolicyMismatch, select_cache_file_stems

logger = logging.getLogger("recon")


_ADMISSION_STATUS: dict[ResultCacheAdmission, str] = {
    "reusable": "reusable",
    "expired": "expired; next lookup refreshes",
    "lineage_invalid": "not reusable; generated-insight lineage does not validate",
    "collection_incomplete": "not reusable; previous collection had unavailable sources",
}
_ADMISSION_SHORT_STATUS: dict[ResultCacheAdmission, str] = {
    "reusable": "reusable",
    "expired": "expired",
    "lineage_invalid": "lineage",
    "collection_incomplete": "partial",
}


@dataclass(frozen=True)
class ResultCacheInfo:
    """Validated result-cache metadata without TenantInfo payload fields.

    ``admission`` is the same decision ``cache_get`` applies with the default
    TTL, so ``recon cache show`` agrees with what an ordinary lookup does.
    """

    domain: str
    cached_at: str
    resolved_at: str
    age_seconds: float
    file_size_bytes: int
    admission: ResultCacheAdmission

    @property
    def reusable(self) -> bool:
        """Whether an ordinary default-TTL lookup would serve this entry."""
        return self.admission == "reusable"

    @property
    def status(self) -> str:
        """Human status naming why a stored entry is or is not reused."""
        return _ADMISSION_STATUS[self.admission]

    @property
    def short_status(self) -> str:
        """Compact status for one-row listings."""
        return _ADMISSION_SHORT_STATUS[self.admission]


def inspect_result_cache(domain: str) -> CacheInspection[ResultCacheInfo]:
    """Inspect one result-cache entry while preserving missing/failure truth."""
    try:
        entry = read_result_cache_entry(domain, ttl=DEFAULT_TTL)
        return CacheInspection(
            entry=ResultCacheInfo(
                domain=entry.info.queried_domain,
                cached_at=entry.cached_at or "unknown",
                resolved_at=entry.info.resolved_at or "unknown",
                age_seconds=entry.age_seconds,
                file_size_bytes=entry.file_size_bytes,
                admission=entry.admission,
            )
        )
    except FileNotFoundError:
        return CacheInspection()
    except CachePolicyMismatch:
        return CacheInspection(other_policy=True)
    except (OSError, OverflowError, TypeError, ValueError, json.JSONDecodeError, RecursionError):
        logger.debug("Result cache inspection failed for %s", domain, exc_info=True)
        return CacheInspection(failed=True)


def list_result_cache(*, limit: int | None = None) -> CacheListing[ResultCacheInfo]:
    """List result-cache metadata with optional bounded payload inspection."""
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

        selection = select_cache_file_stems(directory, limit=limit)
        entries: list[ResultCacheInfo] = []
        failed = 0
        other_policy = 0
        for stem in selection.stems:
            inspection = inspect_result_cache(stem)
            if inspection.entry is not None:
                entries.append(inspection.entry)
            elif inspection.failed:
                failed += 1
            elif inspection.other_policy:
                other_policy += 1
        return CacheListing(
            entries=tuple(entries),
            failed=failed,
            inspected=len(selection.stems),
            total=selection.total,
            temporary_files=selection.temporary_files,
            other_policy=other_policy,
        )
    except OSError:
        logger.debug("Result cache listing failed", exc_info=True)
        return CacheListing(failed=1)
