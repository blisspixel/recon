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
