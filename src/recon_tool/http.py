"""Shared HTTP client context manager for lookup sources.

Includes SSRF protection with DNS rebinding defense: both literal IP addresses
and resolved hostnames are validated against a public-unicast policy before
connecting.

Includes retry logic for transient failures (429, 503) with exponential backoff.

SECURITY NOTE (TOCTOU): The SSRF check resolves the hostname and validates the
IP, then httpx resolves it again independently for the actual connection. A
sophisticated attacker with a short-TTL DNS record could pass the check with a
public IP, then resolve to 169.254.169.254 when httpx connects. Full mitigation
would require pinning the resolved IP and connecting to it directly, which httpx
does not natively support. This defense-in-depth layer catches the vast majority
of SSRF attempts (literal IPs, stable DNS, open redirects) but is not proof
against active DNS rebinding with sub-second TTLs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import socket
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import httpx

logger = logging.getLogger("recon")

DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 5

# Retry configuration for transient HTTP errors (429 Too Many Requests, 503 Service Unavailable).
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 1.0  # seconds — doubles each retry (1s, 2s, 4s)
RETRYABLE_STATUS_CODES = frozenset({429, 503})

# Cumulative cap on retry sleeping for a single request. The per-attempt
# Retry-After is capped at 30s, but three attempts could otherwise stack
# to ~90s and consume most of the 120s aggregate resolve budget when an
# attacker-influenced endpoint returns 429 repeatedly. Bound the total.
_MAX_TOTAL_RETRY_SLEEP = 30.0

# Hard ceiling on a single HTTP response body. Several endpoints recon
# fetches have a host influenced by the looked-up domain owner
# (cse.<domain>, mta-sts.<domain>, the BIMI a= VMC URL, autodiscover
# redirects), and CT providers are third parties. resp.json() / resp.text
# buffer the whole body into memory, so without a cap a multi-GB response
# could OOM the process (or the MCP server). 10 MB is far above any
# legitimate response recon reads (CT JSON pages are bounded by their own
# entry caps; policy/config files are tiny).
#
# _MaxBytesStream counts the bytes recon reads off the wire, which are the
# COMPRESSED transfer bytes: httpx decodes Content-Encoding downstream of
# the transport stream, so the byte cap alone does NOT bound a gzip
# decompression bomb (a few MB of gzip expand to many GB after decode).
# recon defends that separately: it requests ``Accept-Encoding: identity``
# so a cooperating server sends the body uncompressed (making the raw cap
# the decoded cap), and refuses any response that still carries a
# compressing Content-Encoding via _RefusingStream, since an attacker-
# controlled host that ignores the identity request is the bomb vector.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# Content-Encoding values whose decoded body can be far larger than the
# transfer. recon requests identity and refuses a response carrying any of
# these rather than let httpx decode an attacker-sized payload past the cap.
_COMPRESSING_ENCODINGS = frozenset({"gzip", "x-gzip", "deflate", "br", "compress", "zstd"})

# IP networks that must never be reached via redirects (SSRF protection).
# Kept for explicit high-signal ranges and as a readability anchor; the
# predicate below also blocks all non-global or special-use IP literals.
# Covers loopback, private RFC1918, link-local, and cloud metadata ranges.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


def _addr_is_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True for any IP that is not globally routable unicast."""
    return (
        any(addr in net for net in _BLOCKED_NETWORKS)
        or not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _is_blocked_ip(addr_str: str) -> bool:
    """Check if an IP address string is private, internal, or special-use."""
    addr = _parse_ip_address(addr_str)
    if addr is None:
        return False
    return _addr_is_blocked(addr)


def _parse_ip_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return a parsed IP literal, or None when *host* is a hostname."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


async def _is_private_ip_async(host: str) -> bool:
    """Async check if a host must be refused by destination validation.

    Two-layer defense against SSRF and DNS rebinding:
    1. If the host is a literal IP address, check it directly.
    2. If the host is a hostname, resolve it via getaddrinfo in a thread pool
       (non-blocking) and check all returned addresses.

    Returns True if the host is non-public or cannot be resolved and therefore
    cannot be validated safely.
    """
    # Layer 1: literal IP check (fast path, no I/O)
    addr = _parse_ip_address(host)
    if addr is not None:
        return _addr_is_blocked(addr)

    # Layer 2: resolve hostname in thread pool and check all returned IPs
    if not host:
        logger.warning("SSRF validation refused: request has no hostname")
        return True
    try:
        loop = asyncio.get_running_loop()
        addrinfos = await loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        if not addrinfos:
            logger.warning("SSRF validation refused: hostname %s resolved to no addresses", host)
            return True
        for _family, _type, _proto, _canonname, sockaddr in addrinfos:
            ip_str = str(sockaddr[0])
            resolved = _parse_ip_address(ip_str)
            if resolved is None or _is_blocked_ip(ip_str):
                logger.warning(
                    "SSRF blocked: hostname %s resolves to non-public IP %s",
                    host,
                    ip_str,
                )
                return True
    except (socket.gaierror, OSError):
        logger.warning("SSRF validation refused: hostname %s could not be resolved", host)
        return True
    return False


def _is_private_ip(host: str) -> bool:  # pyright: ignore[reportUnusedFunction]
    """Synchronous check if a host must be refused by destination validation.

    Called only by tests/test_http.py (which is why pyright flags it unused
    from the production scan). Production uses the async variant via
    _SSRFSafeTransport; tests need a sync form to exercise the blocklist
    without an event loop. Kept colocated with _BLOCKED_NETWORKS so the two
    can't drift apart.
    """
    # Layer 1: literal IP check (fast path)
    addr = _parse_ip_address(host)
    if addr is not None:
        return _addr_is_blocked(addr)

    # Layer 2: resolve hostname and check all returned IPs
    if not host:
        logger.warning("SSRF validation refused: request has no hostname")
        return True
    try:
        addrinfos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addrinfos:
            logger.warning("SSRF validation refused: hostname %s resolved to no addresses", host)
            return True
        for _family, _type, _proto, _canonname, sockaddr in addrinfos:
            ip_str = str(sockaddr[0])
            resolved = _parse_ip_address(ip_str)
            if resolved is None or _is_blocked_ip(ip_str):
                logger.warning(
                    "SSRF blocked: hostname %s resolves to non-public IP %s",
                    host,
                    ip_str,
                )
                return True
    except (socket.gaierror, OSError):
        logger.warning("SSRF validation refused: hostname %s could not be resolved", host)
        return True
    return False


class _MaxBytesStream(httpx.AsyncByteStream):
    """Wrap a response byte stream and abort once it exceeds *max_bytes*.

    Counts bytes as the client reads the body (resp.json() / resp.text /
    resp.aread() all iterate this stream) and raises once the cap is
    exceeded, so a hostile endpoint cannot force recon to buffer an
    unbounded body into memory. Closing delegates to the wrapped stream.
    """

    def __init__(self, stream: httpx.AsyncByteStream, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes

    async def __aiter__(self) -> AsyncGenerator[bytes]:
        total = 0
        async for chunk in self._stream:
            total += len(chunk)
            if total > self._max_bytes:
                raise httpx.ReadError(f"response body exceeded {self._max_bytes}-byte cap")
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class _RefusingStream(httpx.AsyncByteStream):
    """A response stream that refuses to yield a body, raising on first read.

    Installed when a response carries a compressing Content-Encoding despite
    recon's ``Accept-Encoding: identity`` request. Reading the body would let
    httpx decode an attacker-controlled payload whose decoded size the transfer
    cap does not bound (a decompression bomb), so we refuse before any decode.
    The caller's body read raises httpx.ReadError and the source degrades
    cleanly, exactly like any other transport failure.
    """

    def __init__(self, encoding: str) -> None:
        self._encoding = encoding

    async def __aiter__(self) -> AsyncGenerator[bytes]:
        msg = f"refusing {self._encoding!r}-encoded response (identity requested; possible decompression bomb)"
        raise httpx.ReadError(msg)
        yield b""  # pragma: no cover - unreachable; makes this an async generator

    async def aclose(self) -> None:
        return None


class _SSRFSafeTransport(httpx.AsyncHTTPTransport):
    """Transport wrapper that blocks requests to private/internal IPs.

    Intercepts each request before it hits the network and rejects any
    whose host resolves to a blocked IP range. This prevents SSRF via
    open redirects on upstream endpoints, including DNS rebinding attacks
    where a hostname resolves to an internal IP.

    It also bounds the response body two ways: an oversized identity body is
    aborted mid-read by _MaxBytesStream, and a response that carries a
    compressing Content-Encoding (despite recon's ``Accept-Encoding: identity``
    request) is refused outright by _RefusingStream, since the byte cap counts
    compressed transfer bytes and cannot bound a decompression bomb. Uses async
    DNS resolution to avoid blocking the event loop. See module docstring for
    TOCTOU limitations.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host or ""
        if await _is_private_ip_async(host):
            raise httpx.ConnectError(
                f"SSRF blocked: request destination is non-public or could not be validated: {host}",
                request=request,
            )
        response = await super().handle_async_request(request)
        if isinstance(response.stream, httpx.AsyncByteStream):
            stream = response.stream
            encodings = {e.strip() for e in response.headers.get("content-encoding", "").lower().split(",")}
            compressing = encodings & _COMPRESSING_ENCODINGS
            if compressing:
                # Server compressed despite our identity request. Decoding could
                # be a decompression bomb (the byte cap counts compressed bytes),
                # so release the original transport stream immediately and
                # refuse the body instead of buffering the decode.
                await stream.aclose()
                response.stream = _RefusingStream(", ".join(sorted(compressing)))
            else:
                response.stream = _MaxBytesStream(stream, _MAX_RESPONSE_BYTES)
        return response


class _RetryTransport(httpx.AsyncHTTPTransport):
    """Transport wrapper that retries on 429/503 with exponential backoff.

    Wraps another transport (typically _SSRFSafeTransport) and adds retry
    logic for transient server errors. Respects Retry-After headers when present.

    NOTE: Only safe for requests with non-streaming bodies (bytes content).
    Streaming request bodies would be consumed on the first attempt and empty
    on retry. All current callers use content= (bytes), not stream=.
    """

    def __init__(self, wrapped: httpx.AsyncHTTPTransport) -> None:
        super().__init__()
        self._wrapped = wrapped

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        last_response: httpx.Response | None = None
        total_slept = 0.0
        for attempt in range(MAX_RETRIES + 1):
            response = await self._wrapped.handle_async_request(request)
            if response.status_code not in RETRYABLE_STATUS_CODES:
                return response
            last_response = response
            if attempt < MAX_RETRIES:
                # Respect Retry-After header if present, otherwise exponential backoff.
                # Retry-After can be seconds (numeric) or HTTP-date (string).
                # We only parse numeric values; date-format falls through to backoff.
                # Headers are buffered, so reading them before any aclose() is safe.
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        parsed_delay = float(retry_after)
                        if not math.isfinite(parsed_delay) or parsed_delay < 0.0:
                            raise ValueError("Retry-After must be finite and non-negative")
                        delay = min(parsed_delay, 30.0)
                    except ValueError:
                        delay = RETRY_BACKOFF_BASE * (2**attempt)
                else:
                    delay = RETRY_BACKOFF_BASE * (2**attempt)
                # Bound cumulative sleeping so repeated 429s on an
                # attacker-influenced endpoint cannot stack toward the
                # aggregate resolve budget. Once the total cap is reached,
                # stop retrying and return this response with its body still
                # readable: do not close the response we are about to return.
                remaining_sleep = max(0.0, _MAX_TOTAL_RETRY_SLEEP - total_slept)
                if remaining_sleep <= 0.0:
                    break
                delay = min(delay, remaining_sleep)
                # A retry will follow, so close this intermediate response's
                # stream to avoid a resource leak before fetching the next one.
                await response.aclose()
                total_slept += delay
                logger.debug(
                    "HTTP %d from %s, retrying in %.1fs (attempt %d/%d)",
                    response.status_code,
                    request.url.host,
                    delay,
                    attempt + 1,
                    MAX_RETRIES,
                )
                if delay > 0.0:
                    await asyncio.sleep(delay)
        # Exhausted retries — return the last response so caller sees the status code.
        # last_response is guaranteed non-None here because MAX_RETRIES >= 1 means
        # the loop body executes at least twice, and last_response is set on every
        # iteration that reaches the retryable branch.
        if last_response is None:  # pragma: no cover — defensive, should never happen
            raise httpx.ConnectError("Retry loop completed without a response")
        return last_response

    async def aclose(self) -> None:
        await self._wrapped.aclose()


def _user_agent() -> str:
    """Build User-Agent string with the actual package version."""
    from recon_tool import __version__

    return f"recon-tool/{__version__} (domain-intelligence; +https://github.com/recon-tool)"


@asynccontextmanager
async def http_client(
    provided: httpx.AsyncClient | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    retry_transient: bool = True,
) -> AsyncGenerator[httpx.AsyncClient]:
    """Yield an httpx.AsyncClient — reuses the provided one or creates a new one.

    If a client is provided, it is yielded as-is (caller owns lifecycle).
    If no client is provided, a new one is created with SSRF-safe defaults and closed on exit.

    When ``retry_transient`` is False, the _RetryTransport wrapper is skipped.
    Use this for callers whose own application code handles 429 / 503 — the
    CT providers (CertSpotter) are the primary example: they break the
    pagination loop on 429 and return partial data, so the transport-level
    retry (3 × 30s backoff = 90s) only adds pure latency and burns the
    aggregate resolve budget on rate-limited targets.
    """
    if provided is not None:
        yield provided
    else:
        base_transport: httpx.AsyncHTTPTransport = _SSRFSafeTransport()
        transport: httpx.AsyncHTTPTransport = (
            _RetryTransport(wrapped=base_transport) if retry_transient else base_transport
        )
        client = httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            # Request identity (uncompressed) so a cooperating server's body is
            # bounded by the same _MAX_RESPONSE_BYTES cap that counts wire bytes.
            # A host that ignores this and compresses anyway is refused by the
            # transport (decompression-bomb guard); see _SSRFSafeTransport.
            headers={"User-Agent": _user_agent(), "Accept-Encoding": "identity"},
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        )
        try:
            yield client
        finally:
            await client.aclose()
