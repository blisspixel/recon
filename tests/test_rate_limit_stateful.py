"""Stateful (model-based) tests for the adaptive rate limiter + breaker.

The existing `test_rate_limit_properties.py` exercises single operations.
This adds a Hypothesis `RuleBasedStateMachine` that drives *arbitrary
sequences* of success / rate-limited / other-failure outcomes and asserts
the limiter's invariants hold after every step. Sequence-level bugs (a
breaker that opens without enough failures, an interval that escapes its
bounds after a particular run, a consecutive-failure counter that drifts)
are exactly the class a single-shot property test cannot reach.

The machine models the synchronous outcome-reporting methods
(`on_success`, `on_rate_limited`, `on_other_failure`); `acquire()` is
async and sleeps, so its timing behavior stays with the dedicated async
tests. Persistence is disabled so the machine never touches the
filesystem.
"""

from __future__ import annotations

from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from recon_tool.rate_limit import AdaptiveRateLimiter

_MIN = 0.5
_MAX = 60.0
_THRESHOLD = 3
_COOLDOWN = 60.0
_MAX_COOLDOWN = 600.0


class RateLimiterMachine(RuleBasedStateMachine):
    """Drive outcome sequences and assert the limiter's invariants.

    A parallel ``expected_consecutive`` counter mirrors the limiter's own
    consecutive-failure tracking, so a drift between the model and the
    implementation fails the run.
    """

    def __init__(self) -> None:
        super().__init__()
        self.limiter = AdaptiveRateLimiter(
            name="stateful-test",
            min_interval_s=_MIN,
            max_interval_s=_MAX,
            failure_threshold=_THRESHOLD,
            cooldown_s=_COOLDOWN,
            max_cooldown_s=_MAX_COOLDOWN,
            persist=False,
        )
        self.expected_consecutive = 0

    @rule()
    def success(self) -> None:
        self.limiter.on_success()
        self.expected_consecutive = 0

    @rule(retry_after=st.one_of(st.none(), st.floats(min_value=0.1, max_value=120.0)))
    def rate_limited(self, retry_after: float | None) -> None:
        self.limiter.on_rate_limited(retry_after_s=retry_after)
        self.expected_consecutive += 1

    @rule()
    def other_failure(self) -> None:
        self.limiter.on_other_failure()
        self.expected_consecutive += 1

    @invariant()
    def interval_stays_in_bounds(self) -> None:
        assert _MIN <= self.limiter._interval_s <= _MAX

    @invariant()
    def consecutive_tracks_model(self) -> None:
        # The implementation's counter must match the model exactly, and
        # never go negative.
        assert self.limiter._consecutive_failures == self.expected_consecutive
        assert self.limiter._consecutive_failures >= 0

    @invariant()
    def cooldown_stays_bounded(self) -> None:
        assert _COOLDOWN <= self.limiter._current_cooldown_s <= _MAX_COOLDOWN

    @invariant()
    def open_breaker_implies_threshold_crossed(self) -> None:
        # The breaker may only be open if at least `failure_threshold`
        # failures have accumulated since the last success. (No real time
        # elapses during the run, so a tripped breaker stays open until a
        # success closes it.)
        is_open, _ = self.limiter._breaker_state()
        if is_open:
            assert self.limiter._consecutive_failures >= _THRESHOLD


# Hypothesis turns the machine into a unittest-style TestCase.
TestRateLimiterStateful = RateLimiterMachine.TestCase
