"""Throttled progress reporting for the long maintainer-local resolve sweeps.

The calibration and distribution harnesses resolve thousands of domains over the
network, so a run can take hours. Without a heartbeat it looks hung. This helper
wraps ``asyncio.gather`` and emits a throttled completion count to a stream,
stderr by default, leaving stdout reserved for the aggregate JSON payload.

Disclosure: the helper sees only the coroutines and a running count. It never
receives or prints a domain, so the progress line carries aggregates only, the
same rule the harness outputs already follow (docs/data-handling-policy.md).
"""

from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import Awaitable, Sequence
from typing import TextIO, TypeVar

T = TypeVar("T")


async def gather_with_progress(
    coros: Sequence[Awaitable[T]],
    *,
    label: str,
    stream: TextIO | None = None,
    min_interval: float = 2.0,
) -> list[T]:
    """Gather ``coros``, emitting a throttled completion count.

    Results are returned in input order, exactly like ``asyncio.gather``. A line
    (``label: done/total (pct) Ns elapsed``) is written to ``stream`` (default
    ``sys.stderr``) at most once per ``min_interval`` seconds, with a final line
    on completion. Counts only; no per-item data crosses the boundary.
    """
    out = sys.stderr if stream is None else stream
    total = len(coros)
    if total == 0:
        return []
    start = time.monotonic()
    done = 0
    last = start

    async def _tick(coro: Awaitable[T]) -> T:
        nonlocal done, last
        result = await coro
        done += 1
        now = time.monotonic()
        if done == total or now - last >= min_interval:
            last = now
            pct = 100.0 * done / total
            print(f"  {label}: {done}/{total} ({pct:.0f}%) {now - start:.0f}s elapsed", file=out, flush=True)
        return result

    return await asyncio.gather(*(_tick(coro) for coro in coros))
