"""Credible interval arithmetic for the Bayesian inference layer."""

from __future__ import annotations

import math

import deal


def interval_is_ordered(interval: tuple[float, float]) -> bool:
    """Return true when an interval is valid and inside the unit range."""
    low, high = interval
    return 0.0 <= low <= high <= 1.0


@deal.post(interval_is_ordered)  # pyright: ignore[reportUntypedFunctionDecorator]
def credible_interval(posterior: float, n_eff: float, width: float = 0.80) -> tuple[float, float]:
    """Return the evidence-responsive interval for a posterior.

    Unimodal moment-matched Betas use the exact central quantile via a
    local incomplete-beta inversion. Boundary-shaped Betas keep the
    mean-centered fallback so the interval continues to contain the
    reported posterior and the CAL8 coverage contract remains valid.
    """
    if n_eff <= 0:
        return (0.0, 1.0)
    p = _clamp_probability(posterior)
    if width <= 0:
        return (p, p)
    if width >= 1:
        return (0.0, 1.0)
    if p <= 0.0:
        return (0.0, 0.0)
    if p >= 1.0:
        return (1.0, 1.0)
    alpha = p * n_eff
    beta = (1.0 - p) * n_eff
    if alpha < 1.0 or beta < 1.0:
        return _mean_centered_interval(p, n_eff, width)
    tail = (1.0 - width) / 2.0
    low = beta_ppf(tail, alpha, beta)
    high = beta_ppf(1.0 - tail, alpha, beta)
    if not low <= p <= high:
        return _mean_centered_interval(p, n_eff, width)
    return (low, high)


def _clamp_probability(value: float) -> float:
    if value <= 0.0:
        return 0.0
    if value >= 1.0:
        return 1.0
    return value


def beta_ppf(q: float, alpha: float, beta: float) -> float:
    """Return the quantile of Beta(alpha, beta) by monotone bisection."""
    if q <= 0.0:
        return 0.0
    if q >= 1.0:
        return 1.0
    lo = 0.0
    hi = 1.0
    for _ in range(64):
        mid = (lo + hi) / 2.0
        if _regularized_incomplete_beta(alpha, beta, mid) < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def _regularized_incomplete_beta(alpha: float, beta: float, x: float) -> float:
    """Evaluate I_x(alpha, beta) for positive alpha and beta."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_beta_density = (
        math.lgamma(alpha + beta)
        - math.lgamma(alpha)
        - math.lgamma(beta)
        + alpha * math.log(x)
        + beta * math.log1p(-x)
    )
    beta_density = math.exp(log_beta_density)
    threshold = (alpha + 1.0) / (alpha + beta + 2.0)
    if x < threshold:
        return beta_density * _beta_continued_fraction(alpha, beta, x) / alpha
    return 1.0 - beta_density * _beta_continued_fraction(beta, alpha, 1.0 - x) / beta


def _beta_continued_fraction(alpha: float, beta: float, x: float) -> float:
    """Evaluate the continued fraction used by the incomplete beta."""
    min_float = 1e-300
    qab = alpha + beta
    qap = alpha + 1.0
    qam = alpha - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < min_float:
        d = min_float
    d = 1.0 / d
    h = d
    for iteration in range(1, 200):
        double_iteration = 2 * iteration
        aa = iteration * (beta - iteration) * x / ((qam + double_iteration) * (alpha + double_iteration))
        d = 1.0 + aa * d
        if abs(d) < min_float:
            d = min_float
        c = 1.0 + aa / c
        if abs(c) < min_float:
            c = min_float
        d = 1.0 / d
        h *= d * c

        aa = -((alpha + iteration) * (qab + iteration) * x) / (
            (alpha + double_iteration) * (qap + double_iteration)
        )
        d = 1.0 + aa * d
        if abs(d) < min_float:
            d = min_float
        c = 1.0 + aa / c
        if abs(c) < min_float:
            c = min_float
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-14:
            break
    return h


def _mean_centered_interval(posterior: float, n_eff: float, width: float) -> tuple[float, float]:
    if abs(width - 0.80) < 1e-6:
        z = 1.2816
    elif abs(width - 0.95) < 1e-6:
        z = 1.96
    else:
        z = math.sqrt(2.0) * _erfinv(width)
    se = math.sqrt(posterior * (1.0 - posterior) / n_eff)
    low = max(0.0, posterior - z * se)
    high = min(1.0, posterior + z * se)
    return (low, high)


def _erfinv(y: float) -> float:
    """Inverse error function via Winitzki's elementary approximation."""
    a = 0.147
    ln = math.log(1.0 - y * y)
    first = 2.0 / (math.pi * a) + ln / 2.0
    return math.copysign(math.sqrt(math.sqrt(first * first - ln / a) - first), y)
