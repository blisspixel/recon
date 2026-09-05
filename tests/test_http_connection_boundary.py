"""Socket-boundary admission, TLS identity, and connection lifecycle checks."""

from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import Callable, Iterable
from unittest.mock import AsyncMock

import httpcore
import httpx
import pytest

from recon_tool.http import _public_addresses_async, _SSRFSafeTransport
from recon_tool.http_backend import PublicNetworkBackend

_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


class _Stream(httpcore.AsyncMockStream):
    def __init__(self) -> None:
        super().__init__([_OK, _OK])
        self.tls_hosts: list[str | None] = []
        self.writes: list[bytes] = []
        self.closed = False

    async def start_tls(
        self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None
    ) -> httpcore.AsyncNetworkStream:
        assert ssl_context.check_hostname
        assert ssl_context.verify_mode == ssl.CERT_REQUIRED
        self.tls_hosts.append(server_hostname)
        return self

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.writes.append(buffer)

    async def aclose(self) -> None:
        self.closed = True


def _answers(*addresses: str) -> list[tuple[object, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443)) for address in addresses]


def _resolver(*addresses: str) -> Callable[..., list[tuple[object, ...]]]:
    def resolve(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return _answers(*addresses)

    return resolve


@pytest.mark.asyncio
async def test_numeric_dial_preserves_tls_host_header_and_origin_pooling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("recon_tool.http.socket.getaddrinfo", _resolver("8.8.8.8"))
    streams: list[_Stream] = []
    destinations: list[str] = []

    async def dial(_self, host: str, _port: int, **_kwargs) -> httpcore.AsyncNetworkStream:
        destinations.append(host)
        stream = _Stream()
        streams.append(stream)
        return stream

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", dial)
    async with httpx.AsyncClient(transport=_SSRFSafeTransport()) as client:
        assert (await client.get("https://one.invalid/first")).text == "ok"
        assert (await client.get("https://one.invalid/second")).text == "ok"
        assert (await client.get("https://two.invalid/third")).text == "ok"
    assert destinations == ["8.8.8.8", "8.8.8.8"]
    assert [stream.tls_hosts for stream in streams] == [["one.invalid"], ["two.invalid"]]
    assert b"Host: one.invalid\r\n" in b"".join(streams[0].writes)
    assert b"Host: two.invalid\r\n" in b"".join(streams[1].writes)
    assert all(stream.closed for stream in streams)


@pytest.mark.asyncio
async def test_changed_dns_answer_cannot_reach_a_private_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def resolve(*_args, **_kwargs) -> list[tuple[object, ...]]:
        nonlocal calls
        calls += 1
        return _answers("8.8.8.8" if calls == 1 else "127.0.0.1")

    dial = AsyncMock(side_effect=AssertionError("private destination reached socket dialing"))
    monkeypatch.setattr("recon_tool.http.socket.getaddrinfo", resolve)
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", dial)
    async with httpx.AsyncClient(transport=_SSRFSafeTransport()) as client:
        with pytest.raises(httpx.ConnectError, match="SSRF blocked"):
            await client.get("https://changing.invalid/")
    assert calls == 2
    dial.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("addresses", [(), ("8.8.8.8", "127.0.0.1"), ("not-an-address",), ("::ffff:127.0.0.1",)])
async def test_complete_answer_must_be_public(monkeypatch: pytest.MonkeyPatch, addresses: tuple[str, ...]) -> None:
    monkeypatch.setattr("recon_tool.http.socket.getaddrinfo", _resolver(*addresses))
    assert await _public_addresses_async("synthetic.invalid") == ()


@pytest.mark.asyncio
async def test_literals_and_duplicate_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("recon_tool.http.socket.getaddrinfo", _resolver("8.8.8.8", "8.8.8.8"))
    assert await _public_addresses_async("synthetic.invalid") == ("8.8.8.8",)
    assert await _public_addresses_async("8.8.8.8") == ("8.8.8.8",)
    assert await _public_addresses_async("2001:4860:4860::8888") == ("2001:4860:4860::8888",)
    assert await _public_addresses_async("127.0.0.1") == ()
    assert await _public_addresses_async("") == ()


@pytest.mark.asyncio
async def test_connect_deadline_covers_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def stalled(_host: str) -> tuple[str, ...]:
        await asyncio.Event().wait()
        return ()

    with pytest.raises(httpcore.ConnectTimeout):
        await PublicNetworkBackend(stalled).connect_tcp("synthetic.invalid", 443, timeout=0.01)


@pytest.mark.asyncio
async def test_request_validation_has_a_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    async def stalled(_host: str) -> bool:
        await asyncio.Event().wait()
        return False

    monkeypatch.setattr("recon_tool.http._is_private_ip_async", stalled)
    async with httpx.AsyncClient(transport=_SSRFSafeTransport(), timeout=0.01) as client:
        with pytest.raises(httpx.ConnectTimeout):
            await client.get("https://synthetic.invalid/")


@pytest.mark.asyncio
async def test_address_fallback_cancels_stalled_dial(monkeypatch: pytest.MonkeyPatch) -> None:
    cancelled = asyncio.Event()
    winner = _Stream()

    async def resolve(_host: str) -> tuple[str, ...]:
        return ("2001:4860:4860::8888", "8.8.8.8")

    async def dial(_self, host: str, _port: int, **_kwargs) -> httpcore.AsyncNetworkStream:
        if ":" in host:
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
        return winner

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", dial)
    monkeypatch.setattr("recon_tool.http_backend._CONNECT_STAGGER_SECONDS", 0)
    selected = await PublicNetworkBackend(resolve).connect_tcp("synthetic.invalid", 443, timeout=1)
    assert cancelled.is_set()
    assert not winner.closed
    await selected.aclose()
    assert winner.closed


@pytest.mark.asyncio
async def test_unused_successful_sockets_are_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    streams: list[_Stream] = []

    async def resolve(_host: str) -> tuple[str, ...]:
        return ("8.8.8.8", "1.1.1.1")

    async def dial(_self, _host: str, _port: int, **_kwargs) -> httpcore.AsyncNetworkStream:
        stream = _Stream()
        streams.append(stream)
        return stream

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", dial)
    monkeypatch.setattr("recon_tool.http_backend._CONNECT_STAGGER_SECONDS", 0)
    selected = await PublicNetworkBackend(resolve).connect_tcp("synthetic.invalid", 443, timeout=1)
    assert len(streams) == 2
    assert sum(stream.closed for stream in streams) == 1
    await selected.aclose()
    assert all(stream.closed for stream in streams)


@pytest.mark.asyncio
async def test_connection_errors_keep_httpx_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("recon_tool.http.socket.getaddrinfo", _resolver("8.8.8.8"))

    async def dial(
        _self,
        _host: str,
        _port: int,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
        **_kwargs,
    ) -> httpcore.AsyncNetworkStream:
        assert socket_options is None
        raise httpcore.ConnectError("synthetic failure")

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", dial)
    async with httpx.AsyncClient(transport=_SSRFSafeTransport()) as client:
        with pytest.raises(httpx.ConnectError, match="synthetic failure"):
            await client.get("https://synthetic.invalid/")


@pytest.mark.asyncio
async def test_cancellation_during_cleanup_closes_the_selected_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    streams: list[_Stream] = []
    cleanup_started = asyncio.Event()
    finish_cleanup = asyncio.Event()

    class SlowCloseStream(_Stream):
        async def aclose(self) -> None:
            cleanup_started.set()
            try:
                await finish_cleanup.wait()
            finally:
                self.closed = True

    async def resolve(_host: str) -> tuple[str, ...]:
        return ("8.8.8.8", "1.1.1.1")

    async def dial(_self, _host: str, _port: int, **_kwargs) -> httpcore.AsyncNetworkStream:
        stream = SlowCloseStream() if streams else _Stream()
        streams.append(stream)
        return stream

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", dial)
    monkeypatch.setattr("recon_tool.http_backend._CONNECT_STAGGER_SECONDS", 0)
    task = asyncio.create_task(PublicNetworkBackend(resolve).connect_tcp("synthetic.invalid", 443, timeout=1))
    await asyncio.wait_for(cleanup_started.wait(), timeout=1)
    task.cancel()
    finish_cleanup.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(streams) == 2
    assert all(stream.closed for stream in streams)


@pytest.mark.asyncio
async def test_ipv4_fallback_survives_a_full_ipv6_answer_set(monkeypatch: pytest.MonkeyPatch) -> None:
    attempted: list[str] = []

    async def resolve(_host: str) -> tuple[str, ...]:
        return (*(f"2001:4860::{index}" for index in range(16)), "8.8.8.8")

    async def dial(_self, host: str, _port: int, **_kwargs) -> httpcore.AsyncNetworkStream:
        attempted.append(host)
        if ":" in host:
            raise httpcore.ConnectError("synthetic IPv6 route failure")
        return _Stream()

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", dial)
    selected = await PublicNetworkBackend(resolve).connect_tcp("synthetic.invalid", 443, timeout=1)
    assert attempted[:2] == ["2001:4860::0", "8.8.8.8"]
    await selected.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["cancel", "timeout", "error"])
async def test_failed_tls_handshake_closes_unowned_socket(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    handshake_started = asyncio.Event()

    class HandshakeStream(_Stream):
        async def start_tls(
            self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None
        ) -> httpcore.AsyncNetworkStream:
            handshake_started.set()
            if failure == "timeout":
                raise httpcore.ConnectTimeout("synthetic handshake timeout")
            if failure == "error":
                raise httpcore.ConnectError("synthetic handshake failure")
            await asyncio.Event().wait()
            return self

    stream = HandshakeStream()
    monkeypatch.setattr("recon_tool.http.socket.getaddrinfo", _resolver("8.8.8.8"))
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", AsyncMock(return_value=stream))
    async with httpx.AsyncClient(transport=_SSRFSafeTransport()) as client:
        task = asyncio.create_task(client.get("https://synthetic.invalid/"))
        await asyncio.wait_for(handshake_started.wait(), timeout=1)
        if failure == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif failure == "timeout":
            with pytest.raises(httpx.ConnectTimeout, match="synthetic handshake timeout"):
                await task
        else:
            with pytest.raises(httpx.ConnectError, match="synthetic handshake failure"):
                await task
        assert stream.closed
