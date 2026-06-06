"""Property tests for the v2.0.1 posterior-backed confidence dot fill.

The dot fill is a pure function of where a node's 80% credible interval sits
relative to the present/absent decision threshold. Pinned here so the panel
renderer cannot drift or recalibrate the meaning of the dots through the UI.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from recon_tool.formatter import _POSTERIOR_DECISION_THRESHOLD, _posterior_dot_fill
from recon_tool.models import PosteriorObservation


def _obs(posterior: float, interval_low: float, interval_high: float, *, sparse: bool = False) -> PosteriorObservation:
    return PosteriorObservation(
        name="n",
        description="d",
        posterior=posterior,
        interval_low=interval_low,
        interval_high=interval_high,
        evidence_used=(),
        n_eff=1.0,
        sparse=sparse,
    )


def test_threshold_is_one_half() -> None:
    assert _POSTERIOR_DECISION_THRESHOLD == 0.5


def test_interval_fully_above_threshold_is_three() -> None:
    assert _posterior_dot_fill(_obs(0.95, 0.84, 0.99)) == 3
    # exactly at the threshold counts as above
    assert _posterior_dot_fill(_obs(0.70, 0.50, 0.90)) == 3


def test_mode_above_interval_dips_below_is_two() -> None:
    assert _posterior_dot_fill(_obs(0.62, 0.41, 0.78)) == 2
    assert _posterior_dot_fill(_obs(0.55, 0.30, 0.80)) == 2


def test_mode_below_threshold_is_one() -> None:
    assert _posterior_dot_fill(_obs(0.38, 0.19, 0.61)) == 1
    assert _posterior_dot_fill(_obs(0.10, 0.02, 0.30)) == 1


_p = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)


@given(post=_p, lo=_p, hi=_p)
def test_output_always_one_to_three_and_deterministic(post: float, lo: float, hi: float) -> None:
    fill = _posterior_dot_fill(_obs(post, lo, hi))
    assert fill in (1, 2, 3)
    assert _posterior_dot_fill(_obs(post, lo, hi)) == fill  # deterministic


@given(post=_p, lo1=_p, lo2=_p)
def test_monotone_in_interval_low(post: float, lo1: float, lo2: float) -> None:
    a, b = sorted((lo1, lo2))
    assert _posterior_dot_fill(_obs(post, b, 1.0)) >= _posterior_dot_fill(_obs(post, a, 1.0))


@given(lo=_p, p1=_p, p2=_p)
def test_monotone_in_posterior(lo: float, p1: float, p2: float) -> None:
    low = min(lo, 0.49)  # keep interval_low below threshold so posterior decides 1 vs 2
    a, b = sorted((p1, p2))
    assert _posterior_dot_fill(_obs(b, low, 1.0)) >= _posterior_dot_fill(_obs(a, low, 1.0))
