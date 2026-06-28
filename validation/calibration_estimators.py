"""Calibration estimators shared by validation harnesses.

The older validation memos report fixed-width-bin ECE using each bin midpoint as
the representative confidence. That is useful for continuity, but it blends two
things: model error and estimator error from arbitrary bin placement. This module
adds the paper-facing estimator:

1. Sort predictions into equal-mass bins, so sparse tails do not dominate by
   occupying many empty fixed-width intervals.
2. Use the in-bin mean confidence, not the bin midpoint.
3. Bootstrap the estimator to expose sampling uncertainty.

All functions are pure and aggregate-only. They receive already de-identified
posterior and label lists and never know domain names.
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class EqualMassBin:
    """One equal-mass reliability bin."""

    bin_low: float
    bin_high: float
    mean_confidence: float
    empirical_rate: float
    count: int


@dataclass(frozen=True)
class EceBootstrapSummary:
    """ECE point estimate plus percentile bootstrap interval."""

    estimate: float
    ci_low: float
    ci_high: float
    confidence_level: float
    bootstrap_samples: int
    bins: int


def _validate_inputs(predicted: list[float], outcome: list[int], bins: int) -> None:
    if bins < 1:
        raise ValueError("bins must be a positive integer")
    if len(predicted) != len(outcome):
        raise ValueError("predicted and outcome must have the same length")
    for p in predicted:
        if not 0.0 <= p <= 1.0:
            raise ValueError("predicted probabilities must be in [0, 1]")
    for o in outcome:
        if o not in (0, 1):
            raise ValueError("outcomes must be binary 0 or 1")


def equal_mass_reliability_bins(
    predicted: list[float], outcome: list[int], bins: int = 10
) -> list[EqualMassBin]:
    """Return reliability bins with near-equal counts.

    Bins are sorted by posterior and divided into at most ``bins`` non-empty
    contiguous groups. When there are fewer records than requested bins, each
    record becomes its own bin.
    """
    _validate_inputs(predicted, outcome, bins)
    n = len(predicted)
    if n == 0:
        return []

    pairs = sorted(zip(predicted, outcome, strict=True), key=lambda item: item[0])
    bin_count = min(bins, n)
    out: list[EqualMassBin] = []
    for idx in range(bin_count):
        start = idx * n // bin_count
        end = (idx + 1) * n // bin_count
        chunk = pairs[start:end]
        if not chunk:
            continue
        confidences = [p for p, _label in chunk]
        labels = [label for _p, label in chunk]
        out.append(
            EqualMassBin(
                bin_low=confidences[0],
                bin_high=confidences[-1],
                mean_confidence=sum(confidences) / len(confidences),
                empirical_rate=sum(labels) / len(labels),
                count=len(chunk),
            )
        )
    return out


def mean_confidence_ece(predicted: list[float], outcome: list[int], bins: int = 10) -> float:
    """Equal-mass ECE using the in-bin mean confidence."""
    table = equal_mass_reliability_bins(predicted, outcome, bins=bins)
    total = len(predicted)
    if total == 0:
        return 0.0
    return sum((row.count / total) * abs(row.mean_confidence - row.empirical_rate) for row in table)


def percentile(values: list[float], q: float) -> float:
    """Linear-interpolation percentile, with ``q`` in ``[0, 1]``."""
    if not values:
        raise ValueError("percentile of empty list")
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be in [0, 1]")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = q * (len(ordered) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def bootstrap_mean_confidence_ece(
    predicted: list[float],
    outcome: list[int],
    *,
    bins: int = 10,
    samples: int = 400,
    confidence_level: float = 0.80,
    seed: int = 1729,
) -> EceBootstrapSummary:
    """Bootstrap the equal-mass, mean-confidence ECE estimator.

    Returns a deterministic percentile interval under the supplied seed. Empty
    input returns a zero-width zero estimate; callers should still report ``n``.
    """
    _validate_inputs(predicted, outcome, bins)
    if samples < 1:
        raise ValueError("samples must be a positive integer")
    if not 0.0 < confidence_level < 1.0:
        raise ValueError("confidence_level must be in (0, 1)")

    estimate = mean_confidence_ece(predicted, outcome, bins=bins)
    n = len(predicted)
    if n == 0:
        return EceBootstrapSummary(
            estimate=0.0,
            ci_low=0.0,
            ci_high=0.0,
            confidence_level=confidence_level,
            bootstrap_samples=samples,
            bins=bins,
        )

    rng = random.Random(seed)  # noqa: S311 - deterministic validation bootstrap.
    draws: list[float] = []
    for _ in range(samples):
        indices = [rng.randrange(n) for _sample_idx in range(n)]
        draws.append(
            mean_confidence_ece(
                [predicted[i] for i in indices],
                [outcome[i] for i in indices],
                bins=bins,
            )
        )
    tail = (1.0 - confidence_level) / 2.0
    return EceBootstrapSummary(
        estimate=estimate,
        ci_low=percentile(draws, tail),
        ci_high=percentile(draws, 1.0 - tail),
        confidence_level=confidence_level,
        bootstrap_samples=samples,
        bins=bins,
    )
