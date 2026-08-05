"""Power analysis for the product-quality baseline paired decision rule.

Reproduces every number in
``docs/quality-baseline-preregistration.md`` section 9. Pure arithmetic: no
network, no corpus, no private data, no third-party dependency.

The decision rule under analysis is defined in
``docs/roadmap.md`` track 3. Within each label stratum, count candidate-only
supported decisions ``b``, baseline-only supported decisions ``c``, and unique
domains ``n``. Bound ``(b - c) / n`` by combining Bonferroni-adjusted one-sided
Clopper-Pearson bounds for the two discordance proportions:

    benefit lower = CP_lower(b_pos, n_pos) - CP_upper(c_pos, n_pos)   must be > 0
    safety upper  = CP_upper(b_neg, n_neg) - CP_lower(c_neg, n_neg)   must be < delta

Clopper-Pearson bounds are computed exactly, by bisection on the binomial CDF,
rather than through a normal or bootstrap approximation. The construction has to
stay valid at zero discordance, which is the boundary case the safety gate cares
about most and the one a percentile bootstrap gets wrong.

Run with::

    uv run python validation/quality_power_analysis.py
"""

from __future__ import annotations

from math import comb

# Two discordance proportions are bounded per stratum, so a one-sided 95 percent
# statement per stratum needs each proportion at half that tail.
ALPHA = 0.05 / 2

_BISECTION_STEPS = 200


def binom_cdf(k: int, n: int, p: float) -> float:
    """Return ``P(X <= k)`` for ``X`` distributed Binomial(``n``, ``p``)."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    return sum(comb(n, i) * p**i * (1.0 - p) ** (n - i) for i in range(k + 1))


def cp_upper(k: int, n: int, alpha: float = ALPHA) -> float:
    """Return the one-sided Clopper-Pearson upper bound on a proportion.

    The smallest ``p`` for which ``P(X <= k | n, p) == alpha``. Equals 1 when
    every trial succeeded, which is the correct vacuous bound.
    """
    if k >= n:
        return 1.0
    low, high = 0.0, 1.0
    for _ in range(_BISECTION_STEPS):
        mid = (low + high) / 2.0
        if binom_cdf(k, n, mid) > alpha:
            low = mid
        else:
            high = mid
    return (low + high) / 2.0


def cp_lower(k: int, n: int, alpha: float = ALPHA) -> float:
    """Return the one-sided Clopper-Pearson lower bound on a proportion.

    The largest ``p`` for which ``P(X >= k | n, p) == alpha``. Equals 0 when no
    trial succeeded, which is what makes the zero-discordance case well defined.
    """
    if k <= 0:
        return 0.0
    low, high = 0.0, 1.0
    for _ in range(_BISECTION_STEPS):
        mid = (low + high) / 2.0
        if 1.0 - binom_cdf(k - 1, n, mid) < alpha:
            low = mid
        else:
            high = mid
    return (low + high) / 2.0


def benefit_lower(b: int, c: int, n: int) -> float:
    """Return the conservative one-sided lower bound on ``(b - c) / n``."""
    return cp_lower(b, n) - cp_upper(c, n)


def safety_upper(b: int, c: int, n: int) -> float:
    """Return the conservative one-sided upper bound on ``(b - c) / n``."""
    return cp_upper(b, n) - cp_lower(c, n)


def min_n_for_benefit(b_rate: float, c_rate: float, n_max: int = 4000) -> int | None:
    """Return the smallest positive-stratum ``n`` whose benefit bound clears zero."""
    for n in range(10, n_max + 1):
        if benefit_lower(round(b_rate * n), round(c_rate * n), n) > 0.0:
            return n
    return None


def min_n_for_safety(delta: float, c_rate: float = 0.0, n_max: int = 4000) -> int | None:
    """Return the smallest negative-stratum ``n`` whose safety bound falls below ``delta``.

    Assumes the frozen zero-regression safeguard ``b_negative == 0``.
    """
    for n in range(10, n_max + 1):
        if safety_upper(0, round(c_rate * n), n) < delta:
            return n
    return None


def _print_safety_floor() -> None:
    print("Safety bound achievable with a perfect negative-stratum record (b=0, c=0)")
    print(f"  {'n_neg':>6}  {'safety upper bound':>18}")
    for n in (30, 50, 100, 183, 200, 300, 500):
        print(f"  {n:>6}  {safety_upper(0, 0, n):>18.4f}")


def _print_safety_requirements() -> None:
    print("Required reference-negative n by margin, given b_negative == 0")
    print(f"  {'delta':>6}  {'c=0':>6}  {'c=1%':>6}  {'c=5%':>6}")
    for delta in (0.01, 0.02, 0.03, 0.05, 0.10):
        cells = (min_n_for_safety(delta, rate) for rate in (0.0, 0.01, 0.05))
        rendered = "  ".join(f"{(n if n is not None else '>4000')!s:>6}" for n in cells)
        print(f"  {delta:>6.2f}  {rendered}")


def _print_benefit_requirements() -> None:
    print("Required reference-positive n by discordance rate")
    print(f"  {'b rate':>7}  {'c rate':>7}  {'net':>6}  {'min n_pos':>9}")
    for b_rate, c_rate in ((0.20, 0.05), (0.10, 0.00), (0.15, 0.05), (0.10, 0.02), (0.05, 0.00), (0.05, 0.01)):
        n = min_n_for_benefit(b_rate, c_rate)
        print(f"  {b_rate:>7.2f}  {c_rate:>7.2f}  {b_rate - c_rate:>+6.2f}  {(n if n is not None else '>4000')!s:>9}")


def _print_roadmap_floor_check() -> None:
    print("Benefit bound at the roadmap's nominal n_pos = 30 floor")
    for b, c in ((6, 0), (9, 0), (12, 1)):
        print(f"  b={b:>2} c={c}  benefit lower bound = {benefit_lower(b, c, 30):>+8.4f}")


def main() -> int:
    """Print every table cited by the preregistration."""
    sections = (
        _print_safety_floor,
        _print_safety_requirements,
        _print_benefit_requirements,
        _print_roadmap_floor_check,
    )
    for index, section in enumerate(sections):
        if index:
            print()
        section()
    print()
    print("Frozen minimum sample: n_pos >= 155, n_neg >= 183 at delta = 0.02.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
