"""MCP progress notifications for long-running tools.

Collection stays free of the MCP SDK. Tools translate chain snapshots and
collection events into ``notifications/progress`` here. Messages are stage
names and counts. They never carry a domain, a resolver address, or any other
caller-supplied string.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Protocol, cast

from recon_tool.collection_progress import ProgressEvent, progress_listener

logger = logging.getLogger("recon")

_MIN_INTERVAL_SECONDS = 0.5
_MESSAGE = re.compile(
    r"\A(?:"
    r"depth [0-3]: [1-9][0-9]{0,2} of [1-9][0-9]{0,2}"
    r"|domain [1-9][0-9]{0,2} of [1-9][0-9]{0,2}"
    r"|(?:dns|certificate transparency|mta-sts|oidc discovery|user realm|"
    r"google identity|google workspace|collection): (?:started|done)"
    r")\Z"
)
_SOURCE_LABELS = {
    "dns_records": "dns",
    "ct": "certificate transparency",
    "mta_sts": "mta-sts",
    "oidc_discovery": "oidc discovery",
    "user_realm": "user realm",
    "google_identity": "google identity",
    "google_workspace": "google workspace",
}


class _ProgressReporter(Protocol):
    async def report_progress(
        self,
        progress: float,
        total: float | None = None,
        message: str | None = None,
    ) -> None: ...


def chain_message(depth: int, completed: int, known: int) -> str:
    """One chain-traversal line. The numbers are the only variable text."""
    return f"depth {depth}: {completed} of {known}"


def domain_message(index: int, total: int) -> str:
    """One multi-domain tool line. The names stay out of the notification."""
    return f"domain {index} of {total}"


def source_message(unit: str, phase: str) -> str:
    """One collector stage. Unknown unit names collapse to a fixed label."""
    label = _SOURCE_LABELS.get(unit, "collection")
    state = "done" if phase == "done" else "started"
    return f"{label}: {state}"


class ToolProgress:
    """Rate-limited progress for one tool call.

    The first update is sent immediately. Later updates within the interval
    are dropped rather than delayed, so nothing fires after the tool returns.
    ``report_progress`` on the SDK is a no-op when the request has no token.
    """

    def __init__(self, sink: _ProgressReporter | None, *, min_interval: float = _MIN_INTERVAL_SECONDS) -> None:
        self._sink = sink
        self._min_interval = min_interval
        self._last_at = 0.0
        self._high = 0.0
        self._closed = False

    @classmethod
    def from_context(cls, ctx: object | None) -> ToolProgress:
        """Use a tool context when it can report progress, else stay silent."""
        report = getattr(ctx, "report_progress", None) if ctx is not None else None
        if not callable(report):
            return cls(None)
        return cls(cast(_ProgressReporter, ctx))

    def close(self) -> None:
        """Refuse any further notification."""
        self._closed = True

    def reserve(
        self, progress: float, message: str, total: float | None = None
    ) -> tuple[float, float | None, str] | None:
        """Accept one increasing update now, or drop it.

        The decision is synchronous so a burst of collector events cannot all
        pass the interval check before the first send starts.
        """
        if self._closed or self._sink is None or progress <= self._high or _MESSAGE.fullmatch(message) is None:
            return None
        now = time.monotonic()
        if self._high > 0 and now - self._last_at < self._min_interval:
            return None
        self._high = progress
        self._last_at = now
        return (progress, total, message)

    async def send(self, progress: float, total: float | None, message: str) -> None:
        """Deliver one update already accepted by ``reserve``."""
        if self._sink is None:
            return
        try:
            await self._sink.report_progress(progress, total, message)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.debug("mcp progress notification failed", exc_info=True)

    async def advance(self, progress: float, message: str, total: float | None = None) -> None:
        """Reserve and send one update from an async tool."""
        reserved = self.reserve(progress, message, total)
        if reserved is not None:
            await self.send(*reserved)


@asynccontextmanager
async def source_progress(progress: ToolProgress) -> AsyncGenerator[None, None]:
    """Forward collector start and done events until the lookup returns.

    Nested related-domain work uses ``collection_progress.suppressed`` and
    does not reach this listener. Accepted notifications finish before this
    context exits, which is still before the tool result.
    """
    tasks: list[asyncio.Task[None]] = []
    sequence = 0

    def on_event(event: ProgressEvent) -> None:
        nonlocal sequence
        sequence += 1
        reserved = progress.reserve(float(sequence), source_message(event.unit, event.phase))
        if reserved is None:
            return
        tasks.append(asyncio.get_running_loop().create_task(progress.send(*reserved)))

    try:
        with progress_listener(on_event):
            yield
    finally:
        if tasks:
            await asyncio.gather(*tasks)
        progress.close()


def bind_domains(progress: ToolProgress) -> Callable[[int, int], Awaitable[None]]:
    """Return the per-domain callback multi-domain tools pass to resolution."""

    async def on_domain(index: int, total: int) -> None:
        await progress.advance(float(index), domain_message(index, total), total=float(total))

    return on_domain
