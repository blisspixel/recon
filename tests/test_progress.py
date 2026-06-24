"""Unit tests for the resolve-sweep progress helper (no network)."""

from __future__ import annotations

import asyncio
import io

from validation.progress import gather_with_progress


async def _value(x: int) -> int:
    return x


def test_returns_results_in_input_order() -> None:
    out = io.StringIO()
    results = asyncio.run(
        gather_with_progress([_value(i) for i in range(5)], label="x", stream=out, min_interval=0.0)
    )
    assert results == [0, 1, 2, 3, 4]


def test_empty_returns_empty_and_emits_nothing() -> None:
    out = io.StringIO()
    results = asyncio.run(gather_with_progress([], label="x", stream=out))
    assert results == []
    assert out.getvalue() == ""


def test_final_line_reports_full_count_and_no_per_item_data() -> None:
    out = io.StringIO()
    asyncio.run(
        gather_with_progress([_value(i) for i in range(3)], label="resolving", stream=out, min_interval=0.0)
    )
    text = out.getvalue()
    assert "resolving: 3/3 (100%)" in text
    # Counts only: a domain-like token must never reach the progress stream.
    assert ".com" not in text


def test_large_interval_emits_only_the_completion_line() -> None:
    out = io.StringIO()
    asyncio.run(
        gather_with_progress([_value(i) for i in range(10)], label="x", stream=out, min_interval=1e9)
    )
    lines = [line for line in out.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
    assert "x: 10/10 (100%)" in lines[0]
