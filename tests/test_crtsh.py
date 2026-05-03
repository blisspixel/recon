"""Tests for certificate transparency integration (CrtshProvider via cert_providers)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from recon_tool.sources.cert_providers import MAX_SUBDOMAINS, CrtshProvider, filter_subdomains


@pytest.fixture
def _enable_crtsh():
    """Override the conftest auto-mock to allow real cert intel in these tests."""


@pytest.mark.usefixtures("_enable_crtsh")
class TestCrtshProvider:
    @pytest.mark.asyncio
    async def test_discovers_subdomains(self):
        """crt.sh results should return discovered subdomains."""
        provider = CrtshProvider()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "dev.example.com"},
            {"name_value": "staging.example.com"},
            {"name_value": "api.example.com"},
        ]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("recon_tool.sources.cert_providers.http_client") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            subdomains, _, _ = await provider.query("example.com")

        assert "dev.example.com" in subdomains
        assert "staging.example.com" in subdomains
        assert "api.example.com" in subdomains

    @pytest.mark.asyncio
    async def test_filters_wildcards(self):
        """Wildcard entries should be filtered out."""
        provider = CrtshProvider()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "*.example.com"},
            {"name_value": "real.example.com"},
        ]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("recon_tool.sources.cert_providers.http_client") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            subdomains, _, _ = await provider.query("example.com")

        assert "real.example.com" in subdomains
        assert len([d for d in subdomains if "*" in d]) == 0

    @pytest.mark.asyncio
    async def test_filters_noise_prefixes(self):
        """Common noise subdomains (www, mail, ftp, etc.) should be filtered."""
        provider = CrtshProvider()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "www.example.com"},
            {"name_value": "mail.example.com"},
            {"name_value": "ftp.example.com"},
            {"name_value": "webmail.example.com"},
            {"name_value": "app.example.com"},
        ]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("recon_tool.sources.cert_providers.http_client") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            subdomains, _, _ = await provider.query("example.com")

        assert "app.example.com" in subdomains
        assert "www.example.com" not in subdomains
        assert "mail.example.com" not in subdomains

    @pytest.mark.asyncio
    async def test_excludes_queried_domain(self):
        """The queried domain itself should not appear in subdomains."""
        provider = CrtshProvider()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "example.com"},
            {"name_value": "sub.example.com"},
        ]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("recon_tool.sources.cert_providers.http_client") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            subdomains, _, _ = await provider.query("example.com")

        assert "example.com" not in subdomains
        assert "sub.example.com" in subdomains

    @pytest.mark.asyncio
    async def test_caps_at_max_subdomains(self):
        """Should not return more than MAX_SUBDOMAINS."""
        provider = CrtshProvider()
        entries = [{"name_value": f"sub{i}.example.com"} for i in range(150)]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = entries

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("recon_tool.sources.cert_providers.http_client") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            subdomains, _, _ = await provider.query("example.com")

        assert len(subdomains) <= 100

    @pytest.mark.asyncio
    async def test_large_response_is_bounded_before_filtering(self):
        """Large crt.sh payloads should not force unbounded local parsing."""
        provider = CrtshProvider()
        entries = [
            {
                "name_value": f"sub{i}.example.com",
                "issuer_ca_id": i,
                "issuer_name": "Example CA",
                "not_before": "2024-01-01T00:00:00",
                "not_after": "2025-01-01T00:00:00",
            }
            for i in range(MAX_SUBDOMAINS * 30)
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = entries

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("recon_tool.sources.cert_providers.http_client") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            subdomains, cert_summary, _clusters = await provider.query("example.com")

        assert len(subdomains) <= MAX_SUBDOMAINS
        assert "sub2500.example.com" not in subdomains
        assert cert_summary is not None
        assert cert_summary.cert_count == MAX_SUBDOMAINS * 10

    @pytest.mark.asyncio
    async def test_handles_http_error(self):
        """HTTP errors should raise an exception."""
        provider = CrtshProvider()
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.request = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("recon_tool.sources.cert_providers.http_client") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(httpx.HTTPStatusError):
                await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_handles_timeout(self):
        """Timeouts should raise an exception."""
        provider = CrtshProvider()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with patch("recon_tool.sources.cert_providers.http_client") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(httpx.TimeoutException):
                await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_handles_multiline_name_value(self):
        """crt.sh sometimes returns multiple names separated by newlines."""
        provider = CrtshProvider()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "a.example.com\nb.example.com\n*.example.com"},
        ]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("recon_tool.sources.cert_providers.http_client") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            subdomains, _, _ = await provider.query("example.com")

        assert "a.example.com" in subdomains
        assert "b.example.com" in subdomains
        # Wildcard should be filtered
        assert len([d for d in subdomains if "*" in d]) == 0

    def test_name_property(self):
        """Provider name should be 'crt.sh'."""
        assert CrtshProvider().name == "crt.sh"


class TestFilterSubdomains:
    def test_basic_filtering(self):
        raw = ["app.example.com", "*.example.com", "www.example.com", "api.example.com"]
        result = filter_subdomains(raw, "example.com")
        assert "app.example.com" in result
        assert "api.example.com" in result
        assert "*.example.com" not in result
        assert "www.example.com" not in result
