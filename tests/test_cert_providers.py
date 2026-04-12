"""Unit tests for CertIntelProvider protocol, CrtshProvider, CertSpotterProvider.

Covers: protocol conformance, provider names, HTTP error handling,
shared filtering helpers, CertSummary construction, CertSpotter request shape.

Requirements: 1.1, 1.2, 1.3, 2.1–2.7, 3.1–3.8, 11.5, 11.6
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from recon_tool.sources.cert_providers import (
    MAX_SUBDOMAINS,
    CertIntelProvider,
    CertSpotterProvider,
    CrtshProvider,
    build_cert_summary,
    filter_subdomains,
)

# ── Protocol conformance ────────────────────────────────────────────────


class TestProtocolConformance:
    def test_crtsh_implements_protocol(self):
        assert isinstance(CrtshProvider(), CertIntelProvider)

    def test_certspotter_implements_protocol(self):
        assert isinstance(CertSpotterProvider(), CertIntelProvider)


# ── Provider name properties ────────────────────────────────────────────


class TestProviderNames:
    def test_crtsh_name(self):
        assert CrtshProvider().name == "crt.sh"

    def test_certspotter_name(self):
        assert CertSpotterProvider().name == "certspotter"


# ── HTTP error handling ─────────────────────────────────────────────────


def _mock_http_context(mock_client):
    """Build a patched http_client context manager returning mock_client."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


@pytest.mark.usefixtures("_enable_crtsh")
class TestCrtshHttpErrors:
    @pytest.fixture
    def _enable_crtsh(self):
        """Override conftest auto-mock for these tests."""

    @pytest.mark.asyncio
    async def test_raises_on_400(self):
        provider = CrtshProvider()
        resp = MagicMock(status_code=400, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_500(self):
        provider = CrtshProvider()
        resp = MagicMock(status_code=500, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_503(self):
        provider = CrtshProvider()
        resp = MagicMock(status_code=503, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self):
        provider = CrtshProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.TimeoutException),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_connect_error(self):
        provider = CrtshProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.ConnectError),
        ):
            await provider.query("example.com")


@pytest.mark.usefixtures("_enable_crtsh")
class TestCertSpotterHttpErrors:
    @pytest.fixture
    def _enable_crtsh(self):
        """Override conftest auto-mock for these tests."""

    @pytest.mark.asyncio
    async def test_raises_on_400(self):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=400, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_503(self):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=503, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self):
        provider = CertSpotterProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.TimeoutException),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_connect_error(self):
        provider = CertSpotterProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.ConnectError),
        ):
            await provider.query("example.com")


# ── Shared filtering helpers ────────────────────────────────────────────


class TestFilterSubdomains:
    def test_removes_wildcards(self):
        raw = ["*.example.com", "app.example.com"]
        result = filter_subdomains(raw, "example.com")
        assert "app.example.com" in result
        assert all("*" not in r for r in result)

    def test_removes_noise_prefixes(self):
        raw = ["www.example.com", "mail.example.com", "ftp.example.com", "api.example.com"]
        result = filter_subdomains(raw, "example.com")
        assert "api.example.com" in result
        for prefix in ("www.", "mail.", "ftp."):
            assert not any(r.startswith(prefix) for r in result)

    def test_validates_subdomain_of_domain(self):
        raw = ["app.example.com", "app.other.com", "notexample.com"]
        result = filter_subdomains(raw, "example.com")
        assert "app.example.com" in result
        assert "app.other.com" not in result
        assert "notexample.com" not in result

    def test_excludes_domain_itself(self):
        raw = ["example.com", "sub.example.com"]
        result = filter_subdomains(raw, "example.com")
        assert "example.com" not in result
        assert "sub.example.com" in result

    def test_caps_at_max_subdomains(self):
        raw = [f"sub{i}.example.com" for i in range(200)]
        result = filter_subdomains(raw, "example.com")
        assert len(result) <= MAX_SUBDOMAINS

    def test_case_insensitive(self):
        raw = ["APP.EXAMPLE.COM", "Dev.Example.Com"]
        result = filter_subdomains(raw, "example.com")
        assert "app.example.com" in result
        assert "dev.example.com" in result

    def test_empty_input(self):
        assert filter_subdomains([], "example.com") == []

    def test_high_signal_prefixes_sorted_first(self):
        raw = ["zzz.example.com", "auth.example.com", "aaa.example.com"]
        result = filter_subdomains(raw, "example.com")
        auth_idx = result.index("auth.example.com")
        zzz_idx = result.index("zzz.example.com")
        assert auth_idx < zzz_idx


# ── CertSummary construction ────────────────────────────────────────────


class TestBuildCertSummary:
    def test_basic_construction(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            {
                "issuer_id": "1",
                "issuer_name": "Let's Encrypt",
                "not_before": "2024-03-01T00:00:00",
                "not_after": "2024-06-01T00:00:00",
            },
            {
                "issuer_id": "2",
                "issuer_name": "DigiCert",
                "not_before": "2024-01-01T00:00:00",
                "not_after": "2024-12-01T00:00:00",
            },
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert cs.cert_count == 2
        assert cs.issuer_diversity == 2
        assert cs.newest_cert_age_days >= 0
        assert cs.oldest_cert_age_days >= cs.newest_cert_age_days
        assert len(cs.top_issuers) <= 3

    def test_returns_none_for_empty(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        assert build_cert_summary([], now) is None

    def test_returns_none_for_invalid_entries(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [{"issuer_id": None, "issuer_name": None, "not_before": None, "not_after": None}]
        assert build_cert_summary(entries, now) is None

    def test_issuance_velocity_counts_recent(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            {
                "issuer_id": "1",
                "issuer_name": "LE",
                "not_before": "2024-05-01T00:00:00",
                "not_after": "2024-08-01T00:00:00",
            },
            {
                "issuer_id": "1",
                "issuer_name": "LE",
                "not_before": "2023-01-01T00:00:00",
                "not_after": "2024-01-01T00:00:00",
            },
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert cs.issuance_velocity == 1

    def test_top_issuers_capped_at_3(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            {
                "issuer_id": str(i),
                "issuer_name": f"CA{i}",
                "not_before": "2024-01-01T00:00:00",
                "not_after": "2025-01-01T00:00:00",
            }
            for i in range(10)
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert len(cs.top_issuers) <= 3


# ── CertSpotter request shape ───────────────────────────────────────────


@pytest.mark.usefixtures("_enable_crtsh")
class TestCertSpotterRequestShape:
    @pytest.fixture
    def _enable_crtsh(self):
        """Override conftest auto-mock."""

    @pytest.mark.asyncio
    async def test_correct_url_and_params(self):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=200)
        resp.json.return_value = []
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            await provider.query("example.com")

        client.get.assert_called_once()
        call_args = client.get.call_args
        url = call_args[0][0]
        params = call_args[1].get("params")

        assert "api.certspotter.com" in url
        assert params["domain"] == "example.com"
        assert params["include_subdomains"] == "true"

    @pytest.mark.asyncio
    async def test_no_auth_headers(self):
        """CertSpotter requests must not include Authorization headers."""
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=200)
        resp.json.return_value = []
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            await provider.query("example.com")

        call_kwargs = client.get.call_args[1]
        headers = call_kwargs.get("headers", {})
        assert "Authorization" not in headers
        assert "authorization" not in headers
