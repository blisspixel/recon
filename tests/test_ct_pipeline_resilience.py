"""Tests for the CT pipeline resilience changes.

Covers:
  - Global CT-call semaphore caps process-wide concurrency.
  - CertSpotter rate-limited empty response raises (so dns.py marks
    the provider as degraded, instead of silently soft-failing).
  - The cert-intel orchestrator consults the CT cache BEFORE hitting
    live providers, so corpus re-runs serve fresh entries from disk.

These behaviors were added to address the 2026-05-27 finding that
99.9% of a 5241-domain corpus run had crt.sh marked degraded and
98%+ of records had CertSpotter return empty (rate-limit-as-empty)
without any degradation marker, leaving the cert / cluster / lexical
layers blind despite ``--ct`` being passed.
"""

from __future__ import annotations

from datetime import UTC
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from recon_tool.rate_limit import AdaptiveRateLimiter, RateLimited
from recon_tool.sources.cert_providers import (
    _CT_GLOBAL_CONCURRENCY,
    CertSpotterProvider,
    _get_ct_semaphore,
    _parse_retry_after,
)


class TestGlobalCTSemaphore:
    @pytest.mark.asyncio
    async def test_semaphore_value_is_bounded(self) -> None:
        """The CT semaphore caps concurrent CT calls process-wide so
        batch concurrency cannot multiply rate-limit pressure."""
        sem = _get_ct_semaphore()
        # Acquire twice (should succeed because cap is 2)
        await sem.acquire()
        await sem.acquire()
        assert sem.locked(), (
            f"Semaphore should be exhausted after {_CT_GLOBAL_CONCURRENCY} acquires; got locked={sem.locked()}"
        )
        sem.release()
        sem.release()
        assert not sem.locked()

    @pytest.mark.asyncio
    async def test_semaphore_is_per_loop_singleton(self) -> None:
        """Two calls in the same loop return the same semaphore."""
        a = _get_ct_semaphore()
        b = _get_ct_semaphore()
        assert a is b


class TestCertSpotterRateLimitedRaises:
    @pytest.mark.asyncio
    async def test_429_with_no_pages_raises(self) -> None:
        """A 429 on the first page must raise so the orchestrator can
        mark CertSpotter as degraded. Without this fix, the provider
        returned ``([], None, None)`` and dns.py treated it as a soft
        success (no degradation marker on the result)."""
        provider = CertSpotterProvider()

        mock_resp_429 = MagicMock(spec=httpx.Response)
        mock_resp_429.status_code = 429
        mock_resp_429.headers = {}  # no Retry-After

        with (
            patch.object(provider, "_fetch_page", new=AsyncMock(return_value=mock_resp_429)),
            pytest.raises(httpx.HTTPError, match="rate-limited"),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_429_after_partial_pages_returns_partial(self) -> None:
        """When 429 fires AFTER at least one page succeeded, return the
        partial data instead of raising. The caller (dns.py) sees a
        successful (partial) result and counts the provider as fired."""
        provider = CertSpotterProvider()

        # First page: valid issuance
        first_resp = MagicMock(spec=httpx.Response)
        first_resp.status_code = 200
        first_resp.json = MagicMock(
            return_value=[
                {
                    "id": "1",
                    "dns_names": ["app.example.com"],
                    "issuer": {"friendly_name": "Test CA"},
                    "not_before": "2025-01-01T00:00:00Z",
                    "not_after": "2026-01-01T00:00:00Z",
                }
            ]
        )

        # Second page: rate-limited (with empty headers - no Retry-After)
        second_resp = MagicMock(spec=httpx.Response)
        second_resp.status_code = 429
        second_resp.headers = {}

        with patch.object(provider, "_fetch_page", new=AsyncMock(side_effect=[first_resp, second_resp])):
            subdomains, cert_summary, _ = await provider.query("example.com")

        assert "app.example.com" in subdomains, (
            f"Expected partial data from page 1 to survive the page-2 rate limit; got subdomains={subdomains}"
        )
        assert cert_summary is not None


class TestAdaptiveRateLimiter:
    @pytest.mark.asyncio
    async def test_first_request_does_not_wait(self) -> None:
        """A fresh limiter grants the first slot immediately."""
        import time

        lim = AdaptiveRateLimiter("t", min_interval_s=1.0, max_interval_s=60.0, persist=False)
        start = time.monotonic()
        await lim.acquire()
        assert time.monotonic() - start < 0.1, "first acquire should be immediate"

    @pytest.mark.asyncio
    async def test_max_wait_exceeded_raises(self) -> None:
        """A saturated limiter raises rather than blocking the run."""
        lim = AdaptiveRateLimiter(
            "t",
            min_interval_s=600.0,
            max_interval_s=600.0,
            start_interval_s=600.0,
            max_wait_s=0.1,
            persist=False,
        )
        await lim.acquire()  # consume the first slot
        with pytest.raises(RateLimited):
            await lim.acquire()

    @pytest.mark.asyncio
    async def test_on_rate_limited_increases_interval(self) -> None:
        """A 429 doubles the interval. Several in a row reach the cap."""
        lim = AdaptiveRateLimiter(
            "t",
            min_interval_s=1.0,
            max_interval_s=16.0,
            start_interval_s=1.0,
            failure_threshold=99,  # don't trip the breaker for this test
            persist=False,
        )
        snap0 = lim.snapshot()["interval_s"]
        lim.on_rate_limited()
        snap1 = lim.snapshot()["interval_s"]
        lim.on_rate_limited()
        snap2 = lim.snapshot()["interval_s"]
        assert snap1 == 2.0 * snap0
        assert snap2 == 2.0 * snap1

    @pytest.mark.asyncio
    async def test_retry_after_floors_the_interval(self) -> None:
        """Retry-After supplied to on_rate_limited is a hard floor."""
        lim = AdaptiveRateLimiter(
            "t",
            min_interval_s=1.0,
            max_interval_s=300.0,
            start_interval_s=2.0,
            failure_threshold=99,
            persist=False,
        )
        lim.on_rate_limited(retry_after_s=45.0)
        assert lim.snapshot()["interval_s"] == 45.0

    @pytest.mark.asyncio
    async def test_breaker_opens_after_consecutive_failures(self) -> None:
        """failure_threshold consecutive failures open the breaker."""
        lim = AdaptiveRateLimiter(
            "t",
            min_interval_s=1.0,
            max_interval_s=300.0,
            start_interval_s=1.0,
            failure_threshold=3,
            persist=False,
            cooldown_s=60.0,
        )
        lim.on_rate_limited()
        lim.on_rate_limited()
        assert not lim.snapshot()["breaker_open"]
        lim.on_rate_limited()
        assert lim.snapshot()["breaker_open"]
        # Acquire while open raises immediately.
        with pytest.raises(RateLimited, match="circuit breaker open"):
            await lim.acquire()

    @pytest.mark.asyncio
    async def test_success_resets_breaker(self) -> None:
        """A successful probe closes the breaker and resets cooldown."""
        lim = AdaptiveRateLimiter(
            "t",
            min_interval_s=1.0,
            max_interval_s=300.0,
            start_interval_s=1.0,
            failure_threshold=2,
            persist=False,
            cooldown_s=60.0,
        )
        lim.on_rate_limited()
        lim.on_rate_limited()
        assert lim.snapshot()["breaker_open"]
        lim.on_success()
        assert not lim.snapshot()["breaker_open"]
        assert lim.snapshot()["consecutive_failures"] == 0

    @pytest.mark.asyncio
    async def test_success_decreases_interval_toward_min(self) -> None:
        """Repeated successes ratchet the interval down toward min_interval.

        With success_decrease=0.9 and start=10.0, the interval halves
        roughly every seven successes. We do not require an exact
        clamp to min_interval here; we assert the floor never undershoots
        and the trend is monotonic-decreasing toward it.
        """
        lim = AdaptiveRateLimiter(
            "t",
            min_interval_s=1.0,
            max_interval_s=300.0,
            start_interval_s=10.0,
            persist=False,
        )
        prev = lim.snapshot()["interval_s"]
        for _ in range(30):
            lim.on_success()
            now = lim.snapshot()["interval_s"]
            assert now >= 1.0, f"interval undershot min_interval: {now}"
            assert now <= prev + 1e-9, f"interval went up after on_success: {prev} -> {now}"
            prev = now
        assert lim.snapshot()["interval_s"] == 1.0


class TestRetryAfterParsing:
    def test_numeric_seconds(self) -> None:
        from unittest.mock import MagicMock

        resp = MagicMock()
        resp.headers = {"retry-after": "12"}
        assert _parse_retry_after(resp) == 12.0

    def test_missing_header(self) -> None:
        from unittest.mock import MagicMock

        resp = MagicMock()
        resp.headers = {}
        assert _parse_retry_after(resp) is None

    def test_negative_value_ignored(self) -> None:
        from unittest.mock import MagicMock

        resp = MagicMock()
        resp.headers = {"retry-after": "-1"}
        assert _parse_retry_after(resp) is None

    def test_http_date_unparseable_returns_none(self) -> None:
        """HTTP-date form is not supported. Returning None means the
        caller falls back to the no-wait branch, which is acceptable
        because the rate limiter will pace the next call anyway."""
        from unittest.mock import MagicMock

        resp = MagicMock()
        resp.headers = {"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}
        assert _parse_retry_after(resp) is None


class TestAdaptiveRateLimiterPersistence:
    """Persistence carries breaker / interval state across process restarts.

    A fresh process should inherit "crt.sh tripped 10 minutes ago, still in
    cooldown" so the limiter does not burst on startup before learning. Stale
    state (older than `_PERSIST_MAX_AGE_SECONDS`) is ignored on load."""

    def test_state_round_trips(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        lim = AdaptiveRateLimiter(
            "round-trip",
            min_interval_s=5.0,
            max_interval_s=300.0,
            start_interval_s=30.0,
            failure_threshold=3,
            cooldown_s=60.0,
        )
        # Drive it into a known state: 2 rate-limits (interval doubles
        # twice), no breaker yet.
        lim.on_rate_limited()
        lim.on_rate_limited()
        # Force a persist write.
        lim._persist_state(force=True)

        # Construct a fresh instance with the same name -> should
        # load the persisted state.
        lim2 = AdaptiveRateLimiter(
            "round-trip",
            min_interval_s=5.0,
            max_interval_s=300.0,
            start_interval_s=30.0,
            failure_threshold=3,
            cooldown_s=60.0,
        )
        snap = lim2.snapshot()
        assert snap["interval_s"] >= 60.0, f"expected inherited >= 60s, got {snap['interval_s']}"
        assert snap["consecutive_failures"] == 2

    def test_stale_state_is_ignored(self, tmp_path, monkeypatch) -> None:
        """A persisted file with `saved_at` > 24h ago should not be honored.

        Inheriting day-old punishment would punish operators returning the
        next morning for yesterday's burst, which is the wrong behavior."""
        import json as _json
        from datetime import datetime, timedelta

        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        state_dir = tmp_path / "rate-limit-state"
        state_dir.mkdir(parents=True, exist_ok=True)
        old = datetime.now(UTC) - timedelta(hours=48)
        (state_dir / "stale.json").write_text(
            _json.dumps(
                {
                    "name": "stale",
                    "saved_at": old.isoformat().replace("+00:00", "Z"),
                    "interval_s": 300.0,
                    "current_cooldown_s": 600.0,
                    "consecutive_failures": 5,
                    "breaker_open": True,
                    "breaker_remaining_s": 300.0,
                }
            ),
            encoding="utf-8",
        )
        lim = AdaptiveRateLimiter(
            "stale",
            min_interval_s=5.0,
            max_interval_s=300.0,
            start_interval_s=30.0,
        )
        snap = lim.snapshot()
        assert snap["interval_s"] == 30.0, "stale state should not override start_interval_s"
        assert snap["consecutive_failures"] == 0
        assert not snap["breaker_open"]

    def test_persist_can_be_disabled(self, tmp_path, monkeypatch) -> None:
        """`persist=False` keeps the limiter entirely in memory."""
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        lim = AdaptiveRateLimiter(
            "no-persist",
            min_interval_s=1.0,
            max_interval_s=300.0,
            persist=False,
        )
        lim.on_rate_limited()
        # No state file should appear on disk.
        path = tmp_path / "rate-limit-state" / "no-persist.json"
        assert not path.exists()


class TestCertIntelCacheFirst:
    @pytest.fixture(autouse=True)
    def _mock_crtsh(self):
        """Override the conftest.py autouse fixture that patches
        ``_detect_cert_intel`` to a noop. This test needs the real
        implementation to verify the cache-first short-circuit."""
        return

    @pytest.mark.asyncio
    async def test_fresh_cache_short_circuits_providers(self) -> None:
        """A populated CT cache entry should serve as the result without
        hitting either live provider. Corpus re-runs of size 5000+ have
        no business re-hitting crt.sh for apexes that were just fetched.
        """
        from datetime import datetime

        from recon_tool.ct_cache import CTCacheEntry
        from recon_tool.models import CertSummary
        from recon_tool.sources.dns import _detect_cert_intel, _DetectionCtx

        ctx = _DetectionCtx()
        cached = CTCacheEntry(
            subdomains=("api.example.com", "id.example.com"),
            cert_summary=CertSummary(
                cert_count=10,
                issuer_diversity=2,
                issuance_velocity=3,
                newest_cert_age_days=1,
                oldest_cert_age_days=90,
                top_issuers=("Let's Encrypt",),
                wildcard_sibling_clusters=(),
                deployment_bursts=(),
            ),
            provider_used="crt.sh",
            cached_at=datetime.now(UTC).isoformat(),
            age_days=2,
        )

        crtsh_query = AsyncMock()
        certspotter_query = AsyncMock()

        with (
            patch("recon_tool.ct_cache.ct_cache_get", return_value=cached),
            patch("recon_tool.sources.cert_providers.CrtshProvider.query", crtsh_query),
            patch("recon_tool.sources.cert_providers.CertSpotterProvider.query", certspotter_query),
        ):
            await _detect_cert_intel(ctx, "example.com")

        crtsh_query.assert_not_called()
        certspotter_query.assert_not_called()
        assert ctx.ct_provider_used == "crt.sh (cached)"
        assert ctx.ct_subdomain_count == 2
        assert "api.example.com" in ctx.related_domains
        # ct_attempt_outcome must reflect the cache hit so the
        # operator can tell this record was served from cache and the
        # absence of live CT data was intentional, not a degradation.
        assert ctx.ct_attempt_outcome == "cache_hit"

    @pytest.mark.asyncio
    async def test_summary_only_cache_short_circuits_providers(self) -> None:
        from datetime import datetime

        from recon_tool.ct_cache import CTCacheEntry
        from recon_tool.models import CertSummary
        from recon_tool.sources.dns import _detect_cert_intel, _DetectionCtx

        ctx = _DetectionCtx()
        summary = CertSummary(1, 1, 0, 1, 1, ("Issuer",))
        cached = CTCacheEntry(
            subdomains=(),
            cert_summary=summary,
            infrastructure_clusters=None,
            provider_used="crt.sh",
            cached_at=datetime.now(UTC).isoformat(),
            age_days=1,
        )
        crtsh_query = AsyncMock()
        certspotter_query = AsyncMock()

        with (
            patch("recon_tool.ct_cache.ct_cache_get", return_value=cached),
            patch("recon_tool.sources.cert_providers.CrtshProvider.query", crtsh_query),
            patch("recon_tool.sources.cert_providers.CertSpotterProvider.query", certspotter_query),
        ):
            await _detect_cert_intel(ctx, "example.com")

        crtsh_query.assert_not_called()
        certspotter_query.assert_not_called()
        assert ctx.cert_summary == summary
        assert ctx.ct_attempt_outcome == "cache_hit"
