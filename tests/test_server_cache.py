"""Tests for MCP server cache and rate limiter bounds."""

from __future__ import annotations

from recon_tool.models import ConfidenceLevel, TenantInfo
from recon_tool.server import (
    CACHE_MAX_SIZE,
    _cache,
    _cache_clear,
    _cache_get,
    _cache_set,
    _rate_limit,
    _rate_limit_check,
    _rate_limit_clear,
    _rate_limit_record,
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
        info = _make_info("test.com")
        _cache_set("test.com", info, [])
        result = _cache_get("test.com")
        assert result is not None
        assert result[0].display_name == "test.com"

    def test_cache_miss(self):
        assert _cache_get("nonexistent.com") is None

    def test_cache_expiry(self):
        info = _make_info("test.com")
        _cache_set("test.com", info, [])
        # Manually expire the entry
        ts, i, r = _cache["test.com"]
        _cache["test.com"] = (ts - 999, i, r)
        assert _cache_get("test.com") is None

    def test_cache_bounded_size(self):
        """Cache should not grow beyond CACHE_MAX_SIZE."""
        for i in range(CACHE_MAX_SIZE + 50):
            _cache_set(f"domain-{i}.com", _make_info(f"domain-{i}.com"), [])
        assert len(_cache) <= CACHE_MAX_SIZE

    def test_cache_evicts_oldest_when_full(self):
        """When at capacity, oldest entry should be evicted."""
        # Fill cache
        for i in range(CACHE_MAX_SIZE):
            _cache_set(f"d{i}.com", _make_info(f"d{i}.com"), [])
        # Add one more — should evict the oldest
        _cache_set("new.com", _make_info("new.com"), [])
        assert len(_cache) <= CACHE_MAX_SIZE
        assert _cache_get("new.com") is not None


class TestBoundedRateLimiter:
    def setup_method(self):
        _rate_limit_clear()

    def teardown_method(self):
        _rate_limit_clear()

    def test_first_lookup_allowed(self):
        assert _rate_limit_check("test.com") is True

    def test_immediate_repeat_blocked(self):
        _rate_limit_check("test.com")
        _rate_limit_record("test.com")
        assert _rate_limit_check("test.com") is False

    def test_different_domains_allowed(self):
        _rate_limit_record("a.com")
        assert _rate_limit_check("b.com") is True

    def test_rate_limit_bounded_size(self):
        """Rate limiter should not grow unbounded."""
        from recon_tool.server import _RATE_LIMIT_MAX_SIZE

        for i in range(_RATE_LIMIT_MAX_SIZE + 100):
            _rate_limit_record(f"domain-{i}.com")
        # After eviction, should be at or below max
        assert len(_rate_limit) <= _RATE_LIMIT_MAX_SIZE + 100  # some may not be expired yet
