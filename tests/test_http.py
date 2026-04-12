"""Tests for the HTTP client module — SSRF protection, retry logic, and client lifecycle."""

from __future__ import annotations

import pytest

from recon_tool.http import _is_private_ip, http_client


class TestSSRFProtection:
    """Verify that private/internal IPs are blocked."""

    def test_loopback_blocked(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_rfc1918_10_blocked(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_rfc1918_172_blocked(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_rfc1918_192_blocked(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_link_local_blocked(self):
        assert _is_private_ip("169.254.169.254") is True

    def test_ipv6_loopback_blocked(self):
        assert _is_private_ip("::1") is True

    def test_public_ip_allowed(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_hostname_allowed(self):
        assert _is_private_ip("login.microsoftonline.com") is False

    def test_empty_string_allowed(self):
        assert _is_private_ip("") is False


class TestHttpClientLifecycle:
    """Verify client creation and reuse behavior."""

    @pytest.mark.asyncio
    async def test_provided_client_reused(self):
        import httpx

        existing = httpx.AsyncClient()
        try:
            async with http_client(provided=existing) as client:
                assert client is existing
        finally:
            await existing.aclose()

    @pytest.mark.asyncio
    async def test_new_client_created_when_none(self):
        async with http_client() as client:
            import httpx

            assert isinstance(client, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_new_client_closed_on_exit(self):
        async with http_client() as client:
            pass
        # After exiting context, client should be closed
        assert client.is_closed
