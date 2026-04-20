"""Shared HTTP client context manager for lookup sources.

Includes SSRF protection with DNS rebinding defense: both literal IP addresses
and resolved hostnames are validated against a blocklist of private/link-local/
loopback IP ranges before connecting.

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
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

logger = logging.getLogger("recon")

DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 5

# Retry configuration for transient HTTP errors (429 Too Many Requests, 503 Service Unavailable).
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 1.0  # seconds — doubles each retry (1s, 2s, 4s)
RETRYABLE_STATUS_CODES = frozenset({429, 503})

# IP networks that must never be reached via redirects (SSRF protection).
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


def _is_blocked_ip(addr_str: str) -> bool:
    """Check if an IP address string falls within a blocked network."""
    try:
        addr = ipaddress.ip_address(addr_str)
        return any(addr in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return False


async def _is_private_ip_async(host: str) -> bool:
    """Async check if a host resolves to a blocked IP address.

    Two-layer defense against SSRF and DNS rebinding:
    1. If the host is a literal IP address, check it directly.
    2. If the host is a hostname, resolve it via getaddrinfo in a thread pool
       (non-blocking) and check all returned addresses.

    Returns True if the host should be blocked.
    """
    # Layer 1: literal IP check (fast path, no I/O)
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        pass  # Not an IP literal — fall through to DNS resolution

    # Layer 2: resolve hostname in thread pool and check all returned IPs
    if not host:
        return False
    try:
        loop = asyncio.get_running_loop()
        addrinfos = await loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        for _family, _type, _proto, _canonname, sockaddr in addrinfos:
            ip_str = sockaddr[0]
            if _is_blocked_ip(ip_str):
                logger.warning(
                    "SSRF blocked: hostname %s resolves to private IP %s",
                    host,
                    ip_str,
                )
                return True
    except (socket.gaierror, OSError):
        # DNS resolution failed — allow the request through so httpx
        # can produce a proper connection error downstream.
        pass
    return False


def _is_private_ip(host: str) -> bool:  # pyright: ignore[reportUnusedFunction]
    """Synchronous check if a host resolves to a blocked IP address.

    Exists as a test-facing API for the SSRF blocklist logic. The async
    variant (_is_private_ip_async) is used in production by _SSRFSafeTransport,
    but tests need a sync version to validate the blocklist without running
    an event loop. Keeping this here (rather than in tests/) ensures it stays
    in sync with _BLOCKED_NETWORKS and _is_blocked_ip.
    """
    # Layer 1: literal IP check (fast path)
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        pass

    # Layer 2: resolve hostname and check all returned IPs
    if not host:
        return False
    try:
        addrinfos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _family, _type, _proto, _canonname, sockaddr in addrinfos:
            ip_str = str(sockaddr[0])
            if _is_blocked_ip(ip_str):
                logger.warning(
                    "SSRF blocked: hostname %s resolves to private IP %s",
                    host,
                    ip_str,
                )
                return True
    except (socket.gaierror, OSError):
        pass
    return False


class _SSRFSafeTransport(httpx.AsyncHTTPTransport):
    """Transport wrapper that blocks requests to private/internal IPs.

    Intercepts each request before it hits the network and rejects any
    whose host resolves to a blocked IP range. This prevents SSRF via
    open redirects on upstream endpoints, including DNS rebinding attacks
    where a hostname resolves to an internal IP.

    Uses async DNS resolution to avoid blocking the event loop.
    See module docstring for TOCTOU limitations.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host or ""
        if await _is_private_ip_async(host):
            raise httpx.ConnectError(f"SSRF blocked: request to private/internal IP {host}")
        return await super().handle_async_request(request)


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
        for attempt in range(MAX_RETRIES + 1):
            response = await self._wrapped.handle_async_request(request)
            if response.status_code not in RETRYABLE_STATUS_CODES:
                return response
            last_response = response
            if attempt < MAX_RETRIES:
                # Close the intermediate response stream before retrying
                # to avoid resource leaks. The final response (after exhausting
                # retries) is returned to the caller unclosed.
                await response.aclose()
            if attempt < MAX_RETRIES:
                # Respect Retry-After header if present, otherwise exponential backoff.
                # Retry-After can be seconds (numeric) or HTTP-date (string).
                # We only parse numeric values; date-format falls through to backoff.
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = min(float(retry_after), 30.0)
                    except ValueError:
                        delay = RETRY_BACKOFF_BASE * (2**attempt)
                else:
                    delay = RETRY_BACKOFF_BASE * (2**attempt)
                logger.debug(
                    "HTTP %d from %s — retrying in %.1fs (attempt %d/%d)",
                    response.status_code,
                    request.url.host,
                    delay,
                    attempt + 1,
                    MAX_RETRIES,
                )
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
) -> AsyncIterator[httpx.AsyncClient]:
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
            headers={"User-Agent": _user_agent()},
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        )
        try:
            yield client
        finally:
            await client.aclose()
