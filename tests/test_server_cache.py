"""Tests for MCP server cache and rate limiter bounds."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from recon_tool.models import ConfidenceLevel, TenantInfo
from recon_tool.server import (
    CACHE_MAX_SIZE,
    _cache,
    _cache_clear,
    _cache_get,
    _cache_refresh_info,
    _cache_set,
    _rate_limit,
    _rate_limit_check,
    _rate_limit_clear,
    _rate_limit_record,
    _rate_limit_try_acquire,
)


def _make_info(domain: str) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.LOW,
    )


class TestBoundedCache:
    def setup_method(self):
        _cache_clear()

    def teardown_method(self):
        _cache_clear()

    def test_cache_set_and_get(self):
        info = _make_info("test.invalid")
        _cache_set("test.invalid", info, [])
        result = _cache_get("test.invalid")
        assert result is not None
        assert result[0].display_name == "test.invalid"

    def test_cache_miss(self):
        assert _cache_get("nonexistent.invalid") is None

    def test_cache_expiry(self):
        info = _make_info("test.invalid")
        _cache_set("test.invalid", info, [])
        # Manually expire the entry
        ts, i, r = _cache["test.invalid"]
        _cache["test.invalid"] = (ts - 999, i, r)
        assert _cache_get("test.invalid") is None

    def test_cache_bounded_size(self):
        """Cache should not grow beyond CACHE_MAX_SIZE."""
        for i in range(CACHE_MAX_SIZE + 50):
            _cache_set(f"domain-{i}.invalid", _make_info(f"domain-{i}.invalid"), [])
        assert len(_cache) <= CACHE_MAX_SIZE

    def test_cache_evicts_oldest_when_full(self):
        """When at capacity, oldest entry should be evicted."""
        # Fill cache
        for i in range(CACHE_MAX_SIZE):
            _cache_set(f"d{i}.invalid", _make_info(f"d{i}.invalid"), [])
        # Add one more — should evict the oldest
        _cache_set("new.invalid", _make_info("new.invalid"), [])
        assert len(_cache) <= CACHE_MAX_SIZE
        assert _cache_get("new.invalid") is not None

    def test_refresh_info_preserves_original_timestamp(self):
        """cache_refresh_info updates the merged info but keeps the original
        fetch timestamp: a re-merge does no network I/O, so it must not extend
        data freshness past the TTL window."""
        info1 = _make_info("test.invalid")
        _cache_set("test.invalid", info1, [])
        # Age the entry to a known older timestamp.
        old_ts, i, r = _cache["test.invalid"]
        aged_ts = old_ts - 60.0
        _cache["test.invalid"] = (aged_ts, i, r)
        # Re-merge with a fresh info object (as reevaluate_domain does).
        info2 = _make_info("test.invalid")
        _cache_refresh_info("test.invalid", info2, ())
        new_ts, new_info, _ = _cache["test.invalid"]
        assert new_ts == aged_ts
        assert new_info is info2


class TestBoundedRateLimiter:
    def setup_method(self):
        _rate_limit_clear()

    def teardown_method(self):
        _rate_limit_clear()

    def test_first_lookup_allowed(self):
        assert _rate_limit_check("test.invalid") is True

    def test_immediate_repeat_blocked(self):
        _rate_limit_check("test.invalid")
        _rate_limit_record("test.invalid")
        assert _rate_limit_check("test.invalid") is False

    def test_different_domains_allowed(self):
        _rate_limit_record("a.invalid")
        assert _rate_limit_check("b.invalid") is True

    def test_try_acquire_records_immediately(self):
        assert _rate_limit_try_acquire("test.invalid") is True
        assert _rate_limit_check("test.invalid") is False

    def test_rate_limit_bounded_size(self):
        """Rate limiter should not grow unbounded."""
        from recon_tool.server import _RATE_LIMIT_MAX_SIZE

        for i in range(_RATE_LIMIT_MAX_SIZE + 100):
            _rate_limit_record(f"domain-{i}.invalid")
        assert len(_rate_limit) <= _RATE_LIMIT_MAX_SIZE
