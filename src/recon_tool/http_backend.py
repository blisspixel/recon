"""HTTP connection adapter with destination admission at the socket boundary."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable, Generator, Iterable
from contextlib import contextmanager
from itertools import zip_longest
from typing import cast

import httpcore
import httpx

_MAX_CONNECTION_ADDRESSES = 16
_CONNECT_STAGGER_SECONDS = 0.25
_CLOSE_TIMEOUT_SECONDS = 1.0
_CORE_ERRORS = (httpcore.TimeoutException, httpcore.NetworkError, httpcore.ProtocolError, httpcore.UnsupportedProtocol)


def _connection_candidates(addresses: tuple[str, ...]) -> tuple[str, ...]:
    """Alternate IP families before capping attempts, retaining DNS preference."""
    ipv6_first = ":" in addresses[0]
    preferred = [address for address in addresses if (":" in address) == ipv6_first]
    alternate = [address for address in addresses if (":" in address) != ipv6_first]
    interleaved = (address for pair in zip_longest(preferred, alternate) for address in pair if address is not None)
    return tuple(interleaved)[:_MAX_CONNECTION_ADDRESSES]


async def _close_stream(stream: httpcore.AsyncNetworkStream) -> None:
    async with asyncio.timeout(_CLOSE_TIMEOUT_SECONDS):
        await stream.aclose()


async def _finish_dials(
    tasks: list[asyncio.Task[httpcore.AsyncNetworkStream]], selected: httpcore.AsyncNetworkStream | None
) -> None:
    for task in tasks:
        task.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    await asyncio.gather(
        *(
            _close_stream(result)
            for result in results
            if isinstance(result, httpcore.AsyncNetworkStream) and result is not selected
        )
    )


@contextmanager
def _map_errors() -> Generator[None]:
    """Preserve the HTTPX errors consumed by collectors and retry handling."""
    try:
        yield
    except _CORE_ERRORS as exc:
        error_type = getattr(httpx, type(exc).__name__, httpx.NetworkError)
        raise error_type(str(exc)) from exc


class _TLSGuardStream(httpcore.AsyncNetworkStream):
    """Retain socket ownership until the TLS handshake has succeeded.

    The pool does not yet own an HTTP connection during start_tls. Explicitly
    close the raw stream on cancellation as well as ordinary handshake errors.
    """

    def __init__(self, stream: httpcore.AsyncNetworkStream) -> None:
        self._stream = stream

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._stream.read(max_bytes, timeout=timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._stream.write(buffer, timeout=timeout)

    async def aclose(self) -> None:
        await self._stream.aclose()

    def get_extra_info(self, info: str) -> object:
        return self._stream.get_extra_info(info)

    async def start_tls(
        self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None
    ) -> httpcore.AsyncNetworkStream:
        try:
            stream = await self._stream.start_tls(ssl_context, server_hostname=server_hostname, timeout=timeout)
        except BaseException:
            # Return cleanup errors as values so they do not mask the original
            # failure. Shielding also lets bounded cleanup survive a second
            # cancellation while the caller is already unwinding.
            cleanup = asyncio.gather(_close_stream(self._stream), return_exceptions=True)
            await asyncio.shield(cleanup)
            raise
        return _TLSGuardStream(stream)


class PublicNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect only to numeric addresses returned by the admission callback.

    HTTP origins, Host headers, TLS SNI, and certificate verification continue
    to use the original hostname in the connection pool. Only socket dialing
    uses the validated address, so another DNS answer cannot change its target.
    """

    def __init__(self, resolve: Callable[[str], Awaitable[tuple[str, ...]]]) -> None:
        self._resolve = resolve
        # HTTPCore's optional-import fallback omits backend type information.
        # The direct asyncio extra guarantees the real implementation exists.
        self._backend = cast(httpcore.AsyncNetworkBackend, httpcore.AnyIOBackend())

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            async with asyncio.timeout(timeout):
                addresses = await self._resolve(host)
                if not addresses:
                    raise httpcore.ConnectError("SSRF blocked: destination could not be validated")
                stream = await self._connect_addresses(addresses, port, timeout, local_address, socket_options)
                return _TLSGuardStream(stream)
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout("Timed out resolving or connecting to a public destination") from exc

    async def _connect_addresses(
        self,
        addresses: tuple[str, ...],
        port: int,
        timeout: float | None,
        local_address: str | None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None,
    ) -> httpcore.AsyncNetworkStream:
        """Race bounded, staggered numeric dials and close every unused socket."""
        options = tuple(socket_options) if socket_options is not None else None

        async def dial(index: int, address: str) -> httpcore.AsyncNetworkStream:
            await asyncio.sleep(index * _CONNECT_STAGGER_SECONDS)
            return await self._backend.connect_tcp(
                address, port, timeout=timeout, local_address=local_address, socket_options=options
            )

        tasks = [
            asyncio.create_task(dial(index, address)) for index, address in enumerate(_connection_candidates(addresses))
        ]
        selected: httpcore.AsyncNetworkStream | None = None
        error: Exception = httpcore.ConnectError("No public address accepted the connection")
        try:
            for completed in asyncio.as_completed(tasks):
                try:
                    selected = await completed
                    return selected
                except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                    error = exc
            raise error
        finally:
            cleanup = asyncio.create_task(_finish_dials(tasks, selected))
            try:
                await asyncio.shield(cleanup)
            except BaseException:
                # Ownership transfers only after cleanup completes. A caller
                # cancellation or cleanup failure must also close the winner.
                pending: list[Awaitable[object]] = [cleanup]
                if selected is not None:
                    pending.append(_close_stream(selected))
                await asyncio.gather(*pending, return_exceptions=True)
                raise

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("SSRF blocked: Unix socket destinations are not supported")


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, response: httpcore.Response) -> None:
        self._response = response

    async def __aiter__(self) -> AsyncIterator[bytes]:
        with _map_errors():
            async for chunk in self._response.aiter_stream():
                yield chunk

    async def aclose(self) -> None:
        with _map_errors():
            await self._response.aclose()


class CoreHTTPTransport(httpx.AsyncBaseTransport):
    """Use public transport and pool interfaces to install the guarded backend."""

    def __init__(self, resolve: Callable[[str], Awaitable[tuple[str, ...]]]) -> None:
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(),
            max_connections=100,
            max_keepalive_connections=20,
            keepalive_expiry=5.0,
            network_backend=PublicNetworkBackend(resolve),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with _map_errors():
            response = await self._pool.handle_async_request(core_request)
        return httpx.Response(
            response.status,
            headers=response.headers,
            stream=_ResponseStream(response),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        with _map_errors():
            await self._pool.aclose()
