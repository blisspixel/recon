"""In-process runtime state for the MCP server: the bounded TTL result cache,
the per-domain rate limiter, and structured JSON logging.

Extracted from ``server.py`` (docs/roadmap.md god-file track). A leaf: it holds
the shared ``_ServerRuntimeState`` plus the module-level accessor wrappers the
tools call, and depends only on the models and stdlib. ``server.py`` imports the
wrappers (re-bound to their original underscore names); the FastMCP instance,
resources, and tools stay there.
"""

from __future__ import annotations

import json as json_mod
import logging
import time
from dataclasses import dataclass, field

from recon_tool.models import SourceResult, TenantInfo

logger = logging.getLogger("recon")


CACHE_TTL = 120.0  # seconds


CACHE_MAX_SIZE = 1000


_CacheEntry = tuple[float, TenantInfo, tuple[SourceResult, ...]]


@dataclass(slots=True)
class _ServerRuntimeState:
    cache: dict[str, _CacheEntry] = field(default_factory=dict)
    rate_limit: dict[str, float] = field(default_factory=dict)

    def cache_evict_expired(self) -> None:
        now = time.monotonic()
        expired = [k for k, (ts, _, _) in self.cache.items() if now - ts > CACHE_TTL]
        for key in expired:
            del self.cache[key]

    def cache_get(self, domain: str) -> tuple[TenantInfo, tuple[SourceResult, ...]] | None:
        entry = self.cache.get(domain)
        if entry is None:
            return None
        ts, info, results = entry
        if time.monotonic() - ts > CACHE_TTL:
            del self.cache[domain]
            return None
        return info, results

    def cache_set(self, domain: str, info: TenantInfo, results: list[SourceResult]) -> None:
        if len(self.cache) >= CACHE_MAX_SIZE:
            self.cache_evict_expired()
        if len(self.cache) >= CACHE_MAX_SIZE:
            oldest_key = min(self.cache.items(), key=lambda item: item[1][0])[0]
            del self.cache[oldest_key]
        self.cache[domain] = (time.monotonic(), info, tuple(results))

    def cache_clear(self) -> None:
        self.cache.clear()

    def cache_refresh_info(
        self,
        domain: str,
        info: TenantInfo,
        results: tuple[SourceResult, ...],
    ) -> None:
        self.cache[domain] = (time.monotonic(), info, results)

    def remerge_cached_infos(self) -> None:
        from recon_tool.merger import merge_results

        for domain, (_ts, _info, results) in list(self.cache.items()):
            try:
                refreshed = merge_results(list(results), domain)
            except Exception:
                logger.exception("Failed to refresh cached TenantInfo for %s", domain)
                self.cache.pop(domain, None)
                continue
            self.cache_refresh_info(domain, refreshed, results)

    def rate_limit_evict_expired(self) -> None:
        now = time.monotonic()
        expired = [k for k, ts in self.rate_limit.items() if now - ts >= RATE_LIMIT_WINDOW]
        for key in expired:
            del self.rate_limit[key]

    def rate_limit_check(self, domain: str) -> bool:
        now = time.monotonic()
        last = self.rate_limit.get(domain, 0.0)
        return now - last >= RATE_LIMIT_WINDOW

    def rate_limit_record(self, domain: str) -> None:
        if len(self.rate_limit) >= RATE_LIMIT_MAX_SIZE:
            self.rate_limit_evict_expired()
        if len(self.rate_limit) >= RATE_LIMIT_MAX_SIZE:
            oldest_key = min(self.rate_limit.items(), key=lambda item: item[1])[0]
            del self.rate_limit[oldest_key]
        self.rate_limit[domain] = time.monotonic()

    def rate_limit_try_acquire(self, domain: str) -> bool:
        now = time.monotonic()
        last = self.rate_limit.get(domain)
        if last is not None and now - last < RATE_LIMIT_WINDOW:
            return False
        if len(self.rate_limit) >= RATE_LIMIT_MAX_SIZE and domain not in self.rate_limit:
            self.rate_limit_evict_expired()
        if len(self.rate_limit) >= RATE_LIMIT_MAX_SIZE and domain not in self.rate_limit:
            oldest_key = min(self.rate_limit.items(), key=lambda item: item[1])[0]
            del self.rate_limit[oldest_key]
        self.rate_limit[domain] = now
        return True

    def rate_limit_release(self, domain: str) -> None:
        self.rate_limit.pop(domain, None)

    def rate_limit_clear(self) -> None:
        self.rate_limit.clear()


_STATE = _ServerRuntimeState()


cache = _STATE.cache


def cache_evict_expired() -> None:
    _STATE.cache_evict_expired()


def cache_get(domain: str) -> tuple[TenantInfo, tuple[SourceResult, ...]] | None:
    return _STATE.cache_get(domain)


def cache_set(domain: str, info: TenantInfo, results: list[SourceResult]) -> None:
    _STATE.cache_set(domain, info, results)


def cache_clear() -> None:
    _STATE.cache_clear()


def cache_refresh_info(domain: str, info: TenantInfo, results: tuple[SourceResult, ...]) -> None:
    _STATE.cache_refresh_info(domain, info, results)


def remerge_cached_infos() -> None:
    _STATE.remerge_cached_infos()


RATE_LIMIT_WINDOW = 5.0  # seconds between lookups for the same domain


RATE_LIMIT_MAX_SIZE = 5000


rate_limit = _STATE.rate_limit


def rate_limit_evict_expired() -> None:
    _STATE.rate_limit_evict_expired()


def rate_limit_check(domain: str) -> bool:
    """Return True if the domain lookup should be allowed.

    Does NOT record the timestamp — call rate_limit_record() after a
    successful lookup so transient failures don't block retries.
    """
    return _STATE.rate_limit_check(domain)


def rate_limit_record(domain: str) -> None:
    _STATE.rate_limit_record(domain)


def rate_limit_try_acquire(domain: str) -> bool:
    return _STATE.rate_limit_try_acquire(domain)


def rate_limit_release(domain: str) -> None:
    _STATE.rate_limit_release(domain)


def rate_limit_clear() -> None:
    _STATE.rate_limit_clear()


def log_structured(level: int, msg: str, **fields: object) -> None:
    """Emit a structured log entry as JSON for machine-parseable logging.

    Falls back to standard logging format when JSON serialization fails.
    """
    entry = {"msg": msg, **fields}
    try:
        logger.log(level, json_mod.dumps(entry))
    except (TypeError, ValueError):
        logger.log(level, msg, extra=fields)
