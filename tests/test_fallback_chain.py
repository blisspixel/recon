"""Unit tests for the CertIntel fallback chain in dns.py.

Covers: fallback ordering, CrtshProvider tried first, CertSpotterProvider
as fallback, both fail → both in degraded_sources.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from recon_tool.models import CertSummary
from recon_tool.sources.dns import _detect_cert_intel, _DetectionCtx


@pytest.mark.usefixtures("_enable_crtsh")
class TestFallbackChain:
    """Tests for _detect_cert_intel fallback behavior."""

    @pytest.fixture
    def _enable_crtsh(self):
        """Override conftest auto-mock so we can test the real fallback chain."""

    @pytest.mark.asyncio
    async def test_crtsh_tried_first(self):
        """CrtshProvider should be tried before CertSpotterProvider."""
        call_order: list[str] = []

        mock_crtsh = MagicMock()
        mock_crtsh.name = "crt.sh"

        async def _crtsh_ok(domain):
            call_order.append("crt.sh")
            return ["sub.example.com"], None, None

        mock_crtsh.query = _crtsh_ok

        mock_cs = MagicMock()
        mock_cs.name = "certspotter"

        async def _cs_ok(domain):
            call_order.append("certspotter")
            return [], None, None

        mock_cs.query = _cs_ok

        with (
            patch("recon_tool.sources.dns.CrtshProvider", return_value=mock_crtsh),
            patch("recon_tool.sources.dns.CertSpotterProvider", return_value=mock_cs),
        ):
            ctx = _DetectionCtx()
            await _detect_cert_intel(ctx, "example.com")

        # Only crt.sh should have been called (it succeeded)
        assert call_order == ["crt.sh"]
        assert "sub.example.com" in ctx.related_domains

    @pytest.mark.asyncio
    async def test_fallback_to_certspotter_on_crtsh_failure(self):
        """When CrtshProvider fails, CertSpotterProvider should be tried."""
        call_order: list[str] = []

        mock_crtsh = MagicMock()
        mock_crtsh.name = "crt.sh"

        async def _crtsh_fail(domain):
            call_order.append("crt.sh")
            raise Exception("crt.sh down")

        mock_crtsh.query = _crtsh_fail

        mock_cs = MagicMock()
        mock_cs.name = "certspotter"

        async def _cs_ok(domain):
            call_order.append("certspotter")
            return ["fallback.example.com"], None, None

        mock_cs.query = _cs_ok

        with (
            patch("recon_tool.sources.dns.CrtshProvider", return_value=mock_crtsh),
            patch("recon_tool.sources.dns.CertSpotterProvider", return_value=mock_cs),
        ):
            ctx = _DetectionCtx()
            await _detect_cert_intel(ctx, "example.com")

        assert call_order == ["crt.sh", "certspotter"]
        assert "fallback.example.com" in ctx.related_domains
        assert "crt.sh" in ctx.degraded_sources
        assert "certspotter" not in ctx.degraded_sources

    @pytest.mark.asyncio
    async def test_both_fail_both_in_degraded(self):
        """When both providers fail, both names should be in degraded_sources."""
        mock_crtsh = MagicMock()
        mock_crtsh.name = "crt.sh"

        async def _crtsh_fail(domain):
            raise Exception("crt.sh down")

        mock_crtsh.query = _crtsh_fail

        mock_cs = MagicMock()
        mock_cs.name = "certspotter"

        async def _cs_fail(domain):
            raise Exception("certspotter down")

        mock_cs.query = _cs_fail

        with (
            patch("recon_tool.sources.dns.CrtshProvider", return_value=mock_crtsh),
            patch("recon_tool.sources.dns.CertSpotterProvider", return_value=mock_cs),
        ):
            ctx = _DetectionCtx()
            await _detect_cert_intel(ctx, "example.com")

        assert "crt.sh" in ctx.degraded_sources
        assert "certspotter" in ctx.degraded_sources
        assert ctx.cert_summary is None

    @pytest.mark.asyncio
    async def test_successful_fallback_uses_certspotter_results(self):
        """When CrtshProvider fails and CertSpotterProvider succeeds,
        the cert_summary from CertSpotterProvider should be used."""
        mock_summary = CertSummary(
            cert_count=5,
            issuer_diversity=2,
            issuance_velocity=3,
            newest_cert_age_days=1,
            oldest_cert_age_days=100,
            top_issuers=("Let's Encrypt", "DigiCert"),
        )

        mock_crtsh = MagicMock()
        mock_crtsh.name = "crt.sh"

        async def _crtsh_fail(domain):
            raise Exception("crt.sh down")

        mock_crtsh.query = _crtsh_fail

        mock_cs = MagicMock()
        mock_cs.name = "certspotter"

        async def _cs_ok(domain):
            return ["api.example.com"], mock_summary, None

        mock_cs.query = _cs_ok

        with (
            patch("recon_tool.sources.dns.CrtshProvider", return_value=mock_crtsh),
            patch("recon_tool.sources.dns.CertSpotterProvider", return_value=mock_cs),
        ):
            ctx = _DetectionCtx()
            await _detect_cert_intel(ctx, "example.com")

        assert ctx.cert_summary is mock_summary
        assert "api.example.com" in ctx.related_domains

    @pytest.mark.asyncio
    async def test_crtsh_success_sets_cert_summary(self):
        """When CrtshProvider succeeds, its cert_summary should be used."""
        mock_summary = CertSummary(
            cert_count=10,
            issuer_diversity=3,
            issuance_velocity=5,
            newest_cert_age_days=0,
            oldest_cert_age_days=365,
            top_issuers=("LE",),
        )

        mock_crtsh = MagicMock()
        mock_crtsh.name = "crt.sh"

        async def _crtsh_ok(domain):
            return ["dev.example.com"], mock_summary, None

        mock_crtsh.query = _crtsh_ok

        with patch("recon_tool.sources.dns.CrtshProvider", return_value=mock_crtsh):
            ctx = _DetectionCtx()
            await _detect_cert_intel(ctx, "example.com")

        assert ctx.cert_summary is mock_summary
        assert len(ctx.degraded_sources) == 0

    @pytest.mark.asyncio
    async def test_empty_providers_falls_through_to_ct_cache(self, tmp_path, monkeypatch):
        """v1.8.1 regression — empty-but-not-error provider responses must
        not block the CT cache fallback.

        CertSpotter rate-limited responses look like a successful empty
        result (HTTP 200 with no issuances). Before v1.8.1, the loop in
        ``_detect_cert_intel`` returned on any successful response, so
        the CT cache fallback never fired and ``cert_summary`` stayed
        None even when a populated cache entry existed. The 10-domain
        validation dive found 7/10 targets in this state.
        """
        # Point the CT cache at a tmp dir and seed it.
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        from recon_tool.ct_cache import ct_cache_put

        cached_summary = CertSummary(
            cert_count=42,
            issuer_diversity=2,
            issuance_velocity=5,
            newest_cert_age_days=1,
            oldest_cert_age_days=120,
            top_issuers=("DigiCert",),
        )
        ct_cache_put("example.com", ["api.example.com", "auth.example.com"], cached_summary, "certspotter")

        # Both providers return empty success (no exception, no data).
        mock_crtsh = MagicMock()
        mock_crtsh.name = "crt.sh"

        async def _crtsh_empty(domain):
            return [], None, None

        mock_crtsh.query = _crtsh_empty

        mock_cs = MagicMock()
        mock_cs.name = "certspotter"

        async def _cs_empty(domain):
            return [], None, None

        mock_cs.query = _cs_empty

        with (
            patch("recon_tool.sources.dns.CrtshProvider", return_value=mock_crtsh),
            patch("recon_tool.sources.dns.CertSpotterProvider", return_value=mock_cs),
        ):
            ctx = _DetectionCtx()
            await _detect_cert_intel(ctx, "example.com")

        # Cache fallback must have populated the result. Round-trip
        # through the cache JSON serialiser produces an equal-but-
        # not-identical CertSummary instance.
        assert ctx.cert_summary == cached_summary
        assert "api.example.com" in ctx.related_domains
        assert ctx.ct_subdomain_count == 2
        assert ctx.ct_cache_age_days == 0  # just-cached
        # Soft-failure attribution: prefer the live provider name we
        # actually called over the historical cache provider, so the
        # panel reflects the current live attempt.
        assert ctx.ct_provider_used == "crt.sh (cached)"

    @pytest.mark.asyncio
    async def test_empty_providers_no_cache_records_soft_attribution(self, tmp_path, monkeypatch):
        """v1.8.1 — when all providers return empty AND no cache exists,
        the panel still attributes to the first provider that responded.
        Better than leaving ct_provider_used unset (which would suggest
        no provider was tried)."""
        # Isolate from any real ~/.recon/ct-cache/example.com.json that
        # may exist from prior runs.
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))

        mock_crtsh = MagicMock()
        mock_crtsh.name = "crt.sh"

        async def _crtsh_fail(domain):
            raise Exception("crt.sh down")

        mock_crtsh.query = _crtsh_fail

        mock_cs = MagicMock()
        mock_cs.name = "certspotter"

        async def _cs_empty(domain):
            return [], None, None

        mock_cs.query = _cs_empty

        with (
            patch("recon_tool.sources.dns.CrtshProvider", return_value=mock_crtsh),
            patch("recon_tool.sources.dns.CertSpotterProvider", return_value=mock_cs),
        ):
            ctx = _DetectionCtx()
            await _detect_cert_intel(ctx, "example.com")

        assert ctx.ct_provider_used == "certspotter"
        assert ctx.ct_subdomain_count == 0
        assert ctx.cert_summary is None
        assert "crt.sh" in ctx.degraded_sources
