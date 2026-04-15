"""Source-level retry helper for transient network failures.

The HTTP client layer (``recon_tool.http``) handles retries on HTTP 429 and
503 status codes, but it does not retry on lower-level transport failures
(timeouts, connection resets, DNS hiccups). Those failures can cause a
single source (OIDC discovery, Google Identity, DNS lookup) to return an
empty result, which then cascades up to ``merge_results`` and produces a
false "No information found" response on a domain that would have resolved
fine on a retry.

This module adds a thin ``@retry_on_transient`` wrapper for async source
``lookup`` methods. It retries a small number of times on a narrow set of
exception types with exponential backoff, and leaves semantic failures
(``ReconLookupError``, HTTP 4xx other than 429) untouched so they propagate
normally.

The design is deliberately minimal:

- Retry only the exception classes we've observed flaking in real traffic.
- Cap attempts low (3 total: original + 2 retries) so a truly-down source
  fails fast instead of blocking the aggregate timeout.
- Use short base delay (0.5s, then 1.5s) so the total added latency is
  bounded to ~2s in the worst case.
- Make the retry transparent to the caller — the decorated coroutine still
  returns a ``SourceResult`` on success, and returns whatever the original
  would have returned on final failure.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar

import httpx

logger = logging.getLogger("recon")

# Exception classes considered transient — worth retrying.
# Deliberately narrow: we retry only on transport/timeout failures, never on
# HTTP status errors (the HTTP client layer handles 429/503), never on semantic
# errors (ReconLookupError, ValueError, JSONDecodeError, etc.).
_TRANSIENT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadError,
    httpx.ReadTimeout,
    httpx.WriteError,
    httpx.WriteTimeout,
    httpx.RemoteProtocolError,
    httpx.NetworkError,
    asyncio.TimeoutError,
    OSError,  # covers socket.gaierror and friends in some stdlib paths
)

# Default retry configuration. Total attempts = 1 original + RETRY_ATTEMPTS.
# Keep this small: source failures already compete against the aggregate
# resolver timeout, and a stuck source shouldn't burn it.
RETRY_ATTEMPTS = 2
# Exponential backoff delays in seconds, one per retry. Length must match
# RETRY_ATTEMPTS.
RETRY_DELAYS = (0.5, 1.5)

P = ParamSpec("P")
T = TypeVar("T")


def retry_on_transient(
    attempts: int = RETRY_ATTEMPTS,
    delays: tuple[float, ...] = RETRY_DELAYS,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:  # type: ignore[reportInvalidTypeVarUse]
    """Decorator: retry an async callable on transient transport failures.

    Retries up to ``attempts`` times (so ``attempts + 1`` total tries) when
    the wrapped coroutine raises one of ``_TRANSIENT_EXCEPTIONS``. Between
    attempts, sleeps for the corresponding entry in ``delays``.

    Args:
        attempts: Number of retries after the initial call. Default 2.
        delays: Tuple of sleep durations between retries. Must have at least
            ``attempts`` entries. Extra entries are ignored.

    Returns:
        A decorator that wraps the original async callable.

    Example:
        ::

            @retry_on_transient()
            async def lookup(self, domain: str) -> SourceResult:
                ...

    Non-transient exceptions and success paths pass through unchanged.
    ``ReconLookupError`` is never retried — it signals a semantic failure
    that will not improve on a retry.
    """
    if attempts < 0:
        raise ValueError("attempts must be >= 0")
    if len(delays) < attempts:
        raise ValueError(
            f"delays tuple ({len(delays)} entries) shorter than attempts ({attempts})"
        )

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exc: BaseException | None = None
            for attempt_idx in range(attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except _TRANSIENT_EXCEPTIONS as exc:
                    last_exc = exc
                    if attempt_idx >= attempts:
                        # Out of retries — re-raise so the source's own
                        # exception handler can convert it to a SourceResult.
                        raise
                    delay = delays[attempt_idx]
                    logger.debug(
                        "transient %s in %s (attempt %d/%d) — retrying in %.1fs",
                        type(exc).__name__,
                        func.__qualname__,
                        attempt_idx + 1,
                        attempts + 1,
                        delay,
                    )
                    await asyncio.sleep(delay)
            # Unreachable: the loop either returns or raises above. Present
            # only to satisfy static checkers that expect a terminal statement.
            if last_exc is not None:
                raise last_exc  # pragma: no cover
            raise RuntimeError("retry_on_transient: impossible state")  # pragma: no cover

        return wrapper

    return decorator


__all__ = ["retry_on_transient", "RETRY_ATTEMPTS", "RETRY_DELAYS"]
