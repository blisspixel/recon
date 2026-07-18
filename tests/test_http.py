"""Tests for the HTTP client module — SSRF protection, retry logic, and client lifecycle."""

from __future__ import annotations

import socket
from collections.abc import AsyncGenerator

import httpx
import pytest

from recon_tool.http import _is_private_ip, _MaxBytesStream, http_client


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

    @pytest.mark.parametrize(
        "addr",
        [
            "0.0.0.0",  # noqa: S104 - test fixture for unspecified-address SSRF blocking
            "100.64.0.1",
            "224.0.0.1",
            "192.0.2.1",
            "2001:db8::1",
        ],
    )
    def test_special_use_blocked(self, addr: str):
        assert _is_private_ip(addr) is True

    def test_ipv6_loopback_blocked(self):
        assert _is_private_ip("::1") is True

    def test_public_ip_allowed(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_hostname_allowed(self, monkeypatch: pytest.MonkeyPatch):
        def resolve_public(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]

        monkeypatch.setattr("recon_tool.http.socket.getaddrinfo", resolve_public)
        assert _is_private_ip("login.microsoftonline.com") is False

    def test_hostname_resolution_failure_is_blocked(self, monkeypatch: pytest.MonkeyPatch):
        def fail_resolution(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
            raise socket.gaierror("synthetic DNS failure")

        monkeypatch.setattr("recon_tool.http.socket.getaddrinfo", fail_resolution)
        assert _is_private_ip("unresolved.example") is True

    def test_empty_hostname_is_blocked(self):
        assert _is_private_ip("") is True


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
            assert client.is_closed is False
        # After exiting context, client should be closed
        assert client.is_closed


class _FakeStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncGenerator[bytes]:
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        return None


async def _consume_stream(stream: httpx.AsyncByteStream) -> None:
    async for _chunk in stream:
        continue


class TestResponseBodyCap:
    """_MaxBytesStream aborts an oversized response body during the read, so
    a hostile or decompression-bomb endpoint cannot force recon to buffer
    an unbounded body into memory."""

    @pytest.mark.asyncio
    async def test_aborts_oversized_body(self):
        wrapped = _MaxBytesStream(_FakeStream([b"x" * 4096] * 4), max_bytes=8192)
        with pytest.raises(httpx.ReadError):
            await _consume_stream(wrapped)

    @pytest.mark.asyncio
    async def test_allows_body_within_cap(self):
        wrapped = _MaxBytesStream(_FakeStream([b"hello", b"world"]), max_bytes=1024)
        out = b""
        async for chunk in wrapped:
            out += chunk
        assert out == b"helloworld"
