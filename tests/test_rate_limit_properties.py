"""Hypothesis-based property tests for the adaptive rate limiter.

Verify invariants the AIMD + breaker design must hold across arbitrary
sequences of success / rate-limit / other-failure events:

- ``interval_s`` stays bounded in ``[min_interval_s, max_interval_s]``
  regardless of how many on_rate_limited / on_success calls land.
- The breaker opens iff ``consecutive_failures >= failure_threshold``
  and the last operation was a failure.
- ``on_success`` always resets ``consecutive_failures`` to 0 and
  clears any open breaker.
- ``Retry-After`` values supplied to ``on_rate_limited`` are honored
  as a floor (the interval never drops below them as the immediate
  effect of that call).
- ``snapshot()`` returns plain JSON-serialisable types (so the
  end-of-run budget summary can write the file).

These tests catch regressions where someone "simplifies" the math.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recon_tool.rate_limit import AdaptiveRateLimiter, RateLimited

# Disable Hypothesis's "function may be slow" health check for the
# event-sequence strategies; each example is fast in absolute terms
# but the per-test setup adds enough that the default threshold
# flagged spurious slowness.
_HYP_OPTS = {"suppress_health_check": [HealthCheck.too_slow]}


def _fresh(failure_threshold: int = 3, max_interval: float = 1000.0) -> AdaptiveRateLimiter:
    return AdaptiveRateLimiter(
        name="hyp",
        min_interval_s=1.0,
        max_interval_s=max_interval,
        start_interval_s=10.0,
        failure_threshold=failure_threshold,
        cooldown_s=10.0,
        max_cooldown_s=600.0,
        persist=False,
    )


# Strategy: arbitrary sequences of three operations.
# 0 = on_success, 1 = on_rate_limited (no retry-after), 2 = on_other_failure.
_op_strategy = st.lists(
    st.integers(min_value=0, max_value=2),
    min_size=0,
    max_size=50,
)


@given(ops=_op_strategy)
@settings(**_HYP_OPTS)
def test_interval_stays_within_bounds(ops: list[int]) -> None:
    lim = _fresh()
    for op in ops:
        if op == 0:
            lim.on_success()
        elif op == 1:
            lim.on_rate_limited()
        else:
            lim.on_other_failure()
        snap = lim.snapshot()
        assert lim.min_interval_s <= snap["interval_s"] <= lim.max_interval_s, (
            f"interval out of bounds after op={op}: {snap['interval_s']} "
            f"not in [{lim.min_interval_s}, {lim.max_interval_s}]"
        )


@given(ops=_op_strategy)
@settings(**_HYP_OPTS)
def test_breaker_state_matches_consecutive_failures(ops: list[int]) -> None:
    lim = _fresh(failure_threshold=3)
    for op in ops:
        if op == 0:
            lim.on_success()
        elif op == 1:
            lim.on_rate_limited()
        else:
            lim.on_other_failure()
    snap = lim.snapshot()
    if snap["breaker_open"]:
        # If the breaker is currently open, the most recent op must have
        # been a failure (success would have closed it).
        assert ops, f"breaker open with no ops: {snap}"
        assert ops[-1] != 0, f"breaker open with last op = success: ops={ops!r}"
        # And we must have crossed the threshold at least once.
        assert snap["consecutive_failures"] >= lim._failure_threshold, (
            f"breaker open without crossing threshold: {snap}"
        )


@given(ops=_op_strategy)
@settings(**_HYP_OPTS)
def test_success_after_anything_resets_failure_state(ops: list[int]) -> None:
    lim = _fresh()
    for op in ops:
        if op == 0:
            lim.on_success()
        elif op == 1:
            lim.on_rate_limited()
        else:
            lim.on_other_failure()
    lim.on_success()
    snap = lim.snapshot()
    assert snap["consecutive_failures"] == 0
    assert not snap["breaker_open"]


@given(
    retry_after_s=st.floats(min_value=1.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
)
@settings(**_HYP_OPTS)
def test_retry_after_acts_as_a_floor(retry_after_s: float) -> None:
    """A Retry-After supplied to on_rate_limited is honored as a floor.

    The resulting interval is ``min(max_interval_s, max(prev * factor,
    retry_after_s))``. The invariant we check is the floor: the new
    interval is never less than ``retry_after_s`` (clamped to the
    configured max).
    """
    lim = _fresh(max_interval=10000.0)
    lim.on_rate_limited(retry_after_s=retry_after_s)
    snap = lim.snapshot()
    expected_floor = min(retry_after_s, lim.max_interval_s)
    # snapshot() rounds to 2 decimals; tolerance of 0.011 covers that
    # rounding plus IEEE float noise.
    assert snap["interval_s"] >= expected_floor - 0.011, (
        f"retry_after={retry_after_s} but interval={snap['interval_s']} (max={lim.max_interval_s})"
    )


@given(ops=_op_strategy)
@settings(**_HYP_OPTS)
def test_snapshot_is_json_serializable(ops: list[int]) -> None:
    """``snapshot()`` must be JSON-serializable so the corpus runner can
    persist it to ``ct_budget_summary.json``. A regression that returned
    a non-JSON type (asyncio.Lock, set, datetime) would silently break
    that file."""
    lim = _fresh()
    for op in ops:
        if op == 0:
            lim.on_success()
        elif op == 1:
            lim.on_rate_limited()
        else:
            lim.on_other_failure()
    # Round-trip through json.dumps / loads as the real assertion.
    serialised = json.dumps(lim.snapshot())
    decoded = json.loads(serialised)
    assert isinstance(decoded, dict)


@given(
    cap=st.integers(min_value=1, max_value=20),
    drains=st.integers(min_value=1, max_value=20),
)
@settings(**_HYP_OPTS)
def test_acquire_max_wait_raises_synchronously(cap: int, drains: int) -> None:
    """An acquire that would wait beyond ``max_wait_s`` raises
    RateLimited rather than blocking. This is the corpus-scale
    fall-through-to-cache property — without it, a saturated limiter
    would stall a 5000-domain run indefinitely.
    """
    import asyncio

    async def _drive() -> None:
        lim = AdaptiveRateLimiter(
            "hyp-drain",
            min_interval_s=cap * 100.0,
            max_interval_s=cap * 100.0,
            start_interval_s=cap * 100.0,
            max_wait_s=0.01,
            failure_threshold=99,
            persist=False,
        )
        # First acquire consumes the initial slot. Subsequent acquires
        # cannot land within max_wait_s and must raise.
        await lim.acquire()
        for _ in range(drains):
            try:
                await lim.acquire()
            except RateLimited:
                return
            else:
                raise AssertionError("acquire should have raised RateLimited")

    asyncio.run(_drive())
