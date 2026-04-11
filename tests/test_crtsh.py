"""Tests for crt.sh certificate transparency integration."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from recon_tool.sources.dns import _detect_crtsh, _DetectionCtx


@pytest.fixture()
def _enable_crtsh():
    """Override the conftest auto-mock to allow real _detect_crtsh in these tests."""


class TestCrtshDetector:
    @pytest.mark.asyncio
    async def test_discovers_subdomains(self, _enable_crtsh):
        """crt.sh results should add subdomains to related_domains."""
        ctx = _DetectionCtx()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "dev.example.com"},
            {"name_value": "staging.example.com"},
            {"name_value": "api.example.com"},
        ]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns.httpx.AsyncClient", return_value=mock_client):
            await _detect_crtsh(ctx, "example.com")

        assert "dev.example.com" in ctx.related_domains
        assert "staging.example.com" in ctx.related_domains
        assert "api.example.com" in ctx.related_domains

    @pytest.mark.asyncio
    async def test_filters_wildcards(self, _enable_crtsh):
        """Wildcard entries should be filtered out."""
        ctx = _DetectionCtx()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "*.example.com"},
            {"name_value": "real.example.com"},
        ]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns.httpx.AsyncClient", return_value=mock_client):
            await _detect_crtsh(ctx, "example.com")

        assert "real.example.com" in ctx.related_domains
        assert len([d for d in ctx.related_domains if "*" in d]) == 0

    @pytest.mark.asyncio
    async def test_filters_noise_prefixes(self, _enable_crtsh):
        """Common noise subdomains (www, mail, ftp, etc.) should be filtered."""
        ctx = _DetectionCtx()
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
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns.httpx.AsyncClient", return_value=mock_client):
            await _detect_crtsh(ctx, "example.com")

        assert "app.example.com" in ctx.related_domains
        assert "www.example.com" not in ctx.related_domains
        assert "mail.example.com" not in ctx.related_domains

    @pytest.mark.asyncio
    async def test_excludes_queried_domain(self, _enable_crtsh):
        """The queried domain itself should not appear in related_domains."""
        ctx = _DetectionCtx()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "example.com"},
            {"name_value": "sub.example.com"},
        ]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns.httpx.AsyncClient", return_value=mock_client):
            await _detect_crtsh(ctx, "example.com")

        assert "example.com" not in ctx.related_domains
        assert "sub.example.com" in ctx.related_domains

    @pytest.mark.asyncio
    async def test_caps_at_max_subdomains(self, _enable_crtsh):
        """Should not return more than _CRTSH_MAX_SUBDOMAINS."""
        ctx = _DetectionCtx()
        entries = [{"name_value": f"sub{i}.example.com"} for i in range(100)]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = entries

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns.httpx.AsyncClient", return_value=mock_client):
            await _detect_crtsh(ctx, "example.com")

        assert len(ctx.related_domains) <= 20

    @pytest.mark.asyncio
    async def test_handles_http_error_gracefully(self, _enable_crtsh):
        """HTTP errors should be silently ignored."""
        ctx = _DetectionCtx()
        mock_response = MagicMock()
        mock_response.status_code = 503

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns.httpx.AsyncClient", return_value=mock_client):
            await _detect_crtsh(ctx, "example.com")

        assert len(ctx.related_domains) == 0

    @pytest.mark.asyncio
    async def test_handles_timeout_gracefully(self, _enable_crtsh):
        """Timeouts should be silently ignored."""
        import httpx
        ctx = _DetectionCtx()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns.httpx.AsyncClient", return_value=mock_client):
            await _detect_crtsh(ctx, "example.com")

        assert len(ctx.related_domains) == 0

    @pytest.mark.asyncio
    async def test_handles_multiline_name_value(self, _enable_crtsh):
        """crt.sh sometimes returns multiple names separated by newlines."""
        ctx = _DetectionCtx()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "a.example.com\nb.example.com\n*.example.com"},
        ]

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns.httpx.AsyncClient", return_value=mock_client):
            await _detect_crtsh(ctx, "example.com")

        assert "a.example.com" in ctx.related_domains
        assert "b.example.com" in ctx.related_domains
        # Wildcard should be filtered
        assert len([d for d in ctx.related_domains if "*" in d]) == 0
