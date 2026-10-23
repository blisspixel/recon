# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportUnknownVariableType=none
"""In-process runtime state for the MCP server: the bounded TTL result cache,
the per-domain rate limiter, and structured JSON logging.

Extracted from ``server.py`` (docs/roadmap.md god-file track). A leaf: it holds
the shared ``_ServerRuntimeState`` plus the module-level accessor wrappers the
tools call, and depends only on the models and stdlib. The server facade imports
the wrappers and re-binds them to their original underscore names; the FastMCP
instance, resources, and tools stay in the package-local tool modules.
"""

from __future__ import annotations

import json as json_mod
import logging
import time
from dataclasses import dataclass, field, replace

from recon_tool.models import SourceResult, TenantInfo
from recon_tool.network_policy import MCP_COLLECTION_POLICY

logger = logging.getLogger("recon")


CACHE_TTL = 120.0  # seconds


CACHE_MAX_SIZE = 1000


_CacheEntry = tuple[float, TenantInfo, tuple[SourceResult, ...]]


@dataclass(slots=True)
class _ServerRuntimeState:
    cache: dict[str, _CacheEntry] = field(default_factory=dict)
    cache_policies: dict[str, str] = field(default_factory=dict)
    rate_limit: dict[str, float] = field(default_factory=dict)

    def cache_evict_expired(self) -> None:
        now = time.monotonic()
        expired = [k for k, (ts, _, _) in self.cache.items() if now - ts > CACHE_TTL]
        for key in expired:
            del self.cache[key]
            self.cache_policies.pop(key, None)

    def cache_get(self, domain: str) -> tuple[TenantInfo, tuple[SourceResult, ...]] | None:
        entry = self.cache.get(domain)
        if entry is None:
            return None
        if self.cache_policies.get(domain) != MCP_COLLECTION_POLICY.identity:
            del self.cache[domain]
            self.cache_policies.pop(domain, None)
            return None
        ts, info, results = entry
        if time.monotonic() - ts > CACHE_TTL:
            del self.cache[domain]
            self.cache_policies.pop(domain, None)
            return None
        return info, results

    def cache_set(self, domain: str, info: TenantInfo, results: list[SourceResult]) -> None:
        if info.resolution_policy_id is not None and info.resolution_policy_id != MCP_COLLECTION_POLICY.identity:
            raise ValueError("Lookup result belongs to another collection policy")
        if len(self.cache) >= CACHE_MAX_SIZE:
            self.cache_evict_expired()
        if len(self.cache) >= CACHE_MAX_SIZE:
            oldest_key = min(self.cache.items(), key=lambda item: item[1][0])[0]
            del self.cache[oldest_key]
            self.cache_policies.pop(oldest_key, None)
        self.cache[domain] = (time.monotonic(), info, tuple(results))
        self.cache_policies[domain] = MCP_COLLECTION_POLICY.identity

    def cache_clear(self) -> None:
        self.cache.clear()
        self.cache_policies.clear()

    def cache_refresh_info(
        self,
        domain: str,
        info: TenantInfo,
        results: tuple[SourceResult, ...],
    ) -> None:
        if info.resolution_policy_id is not None and info.resolution_policy_id != MCP_COLLECTION_POLICY.identity:
            raise ValueError("Lookup result belongs to another collection policy")
        # Preserve the original fetch timestamp: a re-merge does no network
        # I/O (the raw results are unchanged), so the TTL must keep bounding
        # data freshness rather than resetting it to now.
        existing = self.cache.get(domain)
        if existing is not None and self.cache_policies.get(domain) != MCP_COLLECTION_POLICY.identity:
            raise ValueError("Cached source results belong to another collection policy")
        if existing is not None and existing[1].resolution_policy_id is not None:
            info = replace(
                info,
                resolution_vantage=existing[1].resolution_vantage,
                resolution_policy_id=existing[1].resolution_policy_id,
            )
        ts = existing[0] if existing is not None else time.monotonic()
        self.cache[domain] = (ts, info, results)
        self.cache_policies[domain] = MCP_COLLECTION_POLICY.identity

    def remerge_cached_infos(self) -> None:
        from recon_tool.merger import merge_results

        for domain, (_ts, _info, results) in list(self.cache.items()):
            if self.cache_get(domain) is None:
                continue
            try:
                refreshed = replace(
                    merge_results(list(results), domain),
                    resolution_vantage=_info.resolution_vantage,
                    resolution_policy_id=_info.resolution_policy_id,
                )
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

    Does NOT record the timestamp - call rate_limit_record() after a
    successful lookup so transient failures don't block retries.
    """
    return _STATE.rate_limit_check(domain)


def rate_limit_record(domain: str) -> None:
    _STATE.rate_limit_record(domain)


def rate_limit_try_acquire(domain: str) -> bool:
    return _STATE.rate_limit_try_acquire(domain)


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


def log_validation_failed(request_id: str) -> None:
    """Record one rejected domain without retaining the untrusted value."""
    log_structured(
        logging.WARNING,
        "validation_failed",
        request_id=request_id,
        error_type="invalid_domain",
    )
