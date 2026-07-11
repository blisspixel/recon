"""Split-conformal diagnostics for the labelable email-policy node.

The reference-comparison harness (validation/reference_calibration.py) reports
reliability and proper scores against the public DMARC declaration. This harness
asks a different question: given a calibration slice of score-label pairs, what
binary prediction sets result on held-out points?

The pure rank-quantile helper implements the ordinary split-conformal theorem:
for a scorer fixed independently of calibration and exchangeable future data,
it gives marginal finite-sample coverage of at least ``1 - alpha``. This
experiment has not established that recon's scorer development or tuning was
disjoint from the evaluated cohort. It therefore does not invoke that theorem
for recon and makes no future-point coverage claim.

The repeated seeded splits reuse one selected list. Their empirical label-
inclusion, minimum, and set-composition rates are dependent re-split
diagnostics only. They are not independent replications or coverage estimates.
A deliberately shifted unit-test split demonstrates one failure mode.

This construction does not validate recon's model-relative uncertainty band.
The full email-policy score also consumes the DMARC declaration that defines the
label, so its conformal result is overlap-aware selected-list corroboration. It
does not establish independent predictive evidence or transfer to a different
target population.

Scope. Only nodes with a defined public comparison label can use this harness.
The email-policy node currently supplies one through the DMARC declaration.

Data handling. Like the reference-calibration harness, a real run reads apex
domains and stays maintainer-local against the gitignored corpus, printing
aggregates only (docs/data-handling-policy.md). The pure functions below carry no
target data and are unit-tested (tests/test_conformal_coverage.py); the network
orchestration reuses the reference-calibration collector.

Run (maintainer-local, network):

    python -m validation.conformal_coverage domains.txt
    python -m validation.conformal_coverage domains.txt --alpha 0.1 --trials 50
    python -m validation.conformal_coverage domains.txt --json
"""

# Reuses the reference-calibration collector and its tested ``_read_domains``
# helper (the single source for resolve+label+drop-apex); same cross-harness
# allowance the other validation scripts take.
# pyright: reportPrivateUsage=false
from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def binary_nonconformity(posterior: float, label: int) -> float:
    """The split-conformal nonconformity score for a binary label.

    The score of a point under its true label is one minus the probability the
    model assigned to that label: low when the model was confident and right,
    high when it was confident and wrong. With ``p`` the posterior for the
    positive class, the positive-class probability is ``p`` and the negative is
    ``1 - p``.
    """
    p_label = posterior if label == 1 else 1.0 - posterior
    return 1.0 - p_label


def _validate_alpha(alpha: float) -> None:
    """Reject miscoverage levels outside the open unit interval."""
    if not math.isfinite(alpha) or not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be finite and strictly between 0 and 1")


def conformal_quantile(cal_scores: list[float], alpha: float) -> float:
    """The split-conformal threshold from calibration nonconformity scores.

    Returns the ``k``-th smallest score where ``k = ceil((n + 1) * (1 - alpha))``,
    the level that gives finite-sample marginal coverage of at least ``1 - alpha``
    for a future point exchangeable with the calibration observations. The
    probability is marginal over calibration data and the future point, not a
    conditional guarantee for this realized sample. When ``k`` exceeds ``n``
    (too few calibration points for the requested level) the threshold is
    ``+inf``, so the prediction set contains both labels.
    """
    _validate_alpha(alpha)
    n = len(cal_scores)
    if n == 0:
        return math.inf
    k = math.ceil((n + 1) * (1.0 - alpha))
    if k > n:
        return math.inf
    ordered = sorted(cal_scores)
    return ordered[k - 1]


def prediction_set(posterior: float, q_hat: float) -> tuple[int, ...]:
    """The conformal prediction set for one point given the threshold.

    A label is included when its nonconformity score is within the threshold.
    The result is one of: ``(1,)`` or ``(0,)`` (a singleton call), ``(0, 1)``
    (multi-label abstention), or ``()`` (an empty set). An empty set counts as a
    miss rather than being hidden.
    """
    included: list[int] = []
    if binary_nonconformity(posterior, 0) <= q_hat:
        included.append(0)
    if binary_nonconformity(posterior, 1) <= q_hat:
        included.append(1)
    return tuple(included)


def evaluate_explicit(
    cal_posteriors: list[float],
    cal_labels: list[int],
    test_posteriors: list[float],
    test_labels: list[int],
    alpha: float,
) -> dict[str, float]:
    """Empirical label-inclusion and set-composition for one explicit split.

    Calibrate the threshold on the calibration pairs, form a prediction set for
    each test point, and report the empirical label-inclusion rate (historical
    key ``coverage``) against the nominal ``1 - alpha`` reference, plus the
    singleton, multi-label, and empty-set rates. ``mean_set_size`` remains in the
    returned mapping for compatibility with recorded validation artifacts. It is
    only a shape diagnostic and cannot identify those three rates by itself. All
    output is aggregate; no per-point data is returned.
    """
    cal_scores = [binary_nonconformity(p, y) for p, y in zip(cal_posteriors, cal_labels, strict=True)]
    q_hat = conformal_quantile(cal_scores, alpha)
    n_test = len(test_posteriors)
    if n_test == 0:
        return {
            "target_coverage": round(1.0 - alpha, 4),
            "coverage": 0.0,
            "mean_set_size": 0.0,
            "singleton_rate": 0.0,
            "multi_label_rate": 0.0,
            "empty_set_rate": 0.0,
            "n_cal": float(len(cal_scores)),
            "n_test": 0.0,
            "q_hat": q_hat,
        }
    covered = 0
    total_size = 0
    singleton = 0
    multi_label = 0
    empty_set = 0
    for p, y in zip(test_posteriors, test_labels, strict=True):
        s = prediction_set(p, q_hat)
        total_size += len(s)
        if y in s:
            covered += 1
        if len(s) == 1:
            singleton += 1
        elif len(s) == 2:
            multi_label += 1
        elif len(s) == 0:
            empty_set += 1
    return {
        "target_coverage": round(1.0 - alpha, 4),
        "coverage": round(covered / n_test, 4),
        "mean_set_size": round(total_size / n_test, 4),
        "singleton_rate": round(singleton / n_test, 4),
        "multi_label_rate": round(multi_label / n_test, 4),
        "empty_set_rate": round(empty_set / n_test, 4),
        "n_cal": float(len(cal_scores)),
        "n_test": float(n_test),
        "q_hat": q_hat,
    }


def evaluate_split(posteriors: list[float], labels: list[int], alpha: float, seed: int) -> dict[str, float]:
    """One random half/half calibration/test split, seeded for reproducibility."""
    n = len(posteriors)
    idx = list(range(n))
    random.Random(seed).shuffle(idx)  # noqa: S311 - reproducible split, not security-sensitive.
    half = n // 2
    cal, test = idx[:half], idx[half:]
    return evaluate_explicit(
        [posteriors[i] for i in cal],
        [labels[i] for i in cal],
        [posteriors[i] for i in test],
        [labels[i] for i in test],
        alpha,
    )


def evaluate_cv(
    posteriors: list[float], labels: list[int], alpha: float, trials: int = 20, seed: int = 1729
) -> dict[str, float]:
    """Describe several seeded re-splits of one selected labeled list.

    The splits are dependent because they reuse observations. Their averages and
    minimum summarize empirical stability; they do not create independent
    samples, establish scorer-development disjointness, or establish the
    marginal coverage theorem for this experiment. Legacy ``mean_coverage``,
    ``min_coverage``, and ``mean_set_size`` keys are retained for recorded JSON
    compatibility. Set composition must be read from the three explicit rates.
    """
    _validate_alpha(alpha)
    n = len(posteriors)
    if n < 4:
        return {"n": float(n), "insufficient": 1.0}
    if trials < 1:
        raise ValueError("trials must be at least 1")
    coverages: list[float] = []
    sizes: list[float] = []
    singleton_rates: list[float] = []
    multi_label_rates: list[float] = []
    empty_set_rates: list[float] = []
    for t in range(trials):
        r = evaluate_split(posteriors, labels, alpha, seed + t)
        coverages.append(r["coverage"])
        sizes.append(r["mean_set_size"])
        singleton_rates.append(r["singleton_rate"])
        multi_label_rates.append(r["multi_label_rate"])
        empty_set_rates.append(r["empty_set_rate"])
    return {
        "n": float(n),
        "trials": float(trials),
        "target_coverage": round(1.0 - alpha, 4),
        "mean_coverage": round(sum(coverages) / trials, 4),
        "min_coverage": round(min(coverages), 4),
        "mean_set_size": round(sum(sizes) / trials, 4),
        "mean_singleton_rate": round(sum(singleton_rates) / trials, 4),
        "mean_multi_label_rate": round(sum(multi_label_rates) / trials, 4),
        "mean_empty_set_rate": round(sum(empty_set_rates) / trials, 4),
    }


def _print_summary(summary: dict[str, float]) -> None:
    if summary.get("insufficient"):
        print(f"Only {int(summary['n'])} labeled domains; need at least 4 to split. Nothing to report.")
        return
    print(f"\nConformal re-split diagnostics (n={int(summary['n'])}, {int(summary['trials'])} dependent re-splits)")
    print(f"  nominal reference: {summary['target_coverage']}")
    print(f"  mean inclusion:    {summary['mean_coverage']}")
    print(f"  minimum inclusion: {summary['min_coverage']}")
    print(f"  singleton rate:    {summary['mean_singleton_rate']}")
    print(f"  multi-label rate:  {summary['mean_multi_label_rate']}")
    print(f"  empty-set rate:    {summary['mean_empty_set_rate']}")


def json_payload(summary: dict[str, float], *, alpha: float, trials: int) -> dict[str, object]:
    """Machine-readable aggregate output for private-run memo generation."""
    return {
        "mode": "single",
        "node": "email_security_policy_enforcing",
        "construction": "split_conformal",
        "alpha": alpha,
        "trials_requested": trials,
        "summary": summary,
        "interpretation": {
            "coverage_scope": "dependent empirical re-split diagnostics only; no future-point coverage claim",
            "scorer_disjointness": "not established between scorer development and this evaluation cohort",
            "repeated_splits": "dependent descriptive re-splits of one selected list",
            "legacy_summary_keys": {
                "target_coverage": "nominal 1-alpha reference, not an established coverage target for this run",
                "mean_coverage": "descriptive mean across re-splits",
                "min_coverage": "descriptive minimum across re-splits",
                "mean_set_size": "compatibility diagnostic; does not identify set composition",
            },
            "set_composition_keys": {
                "mean_singleton_rate": "mean singleton-set rate",
                "mean_multi_label_rate": "mean two-label-set rate",
                "mean_empty_set_rate": "mean empty-set rate",
            },
        },
        "disclosure": {
            "aggregate_only": True,
            "contains_target_rows": False,
            "small_cell_threshold": 10,
        },
    }


_TRAILER = (
    "\nThe rank-quantile helper has the ordinary split-conformal theorem only for a\n"
    "scorer fixed independently of calibration and exchangeable future data. This\n"
    "run has not established scorer-development disjointness and repeatedly splits\n"
    "one selected list, so it reports dependent empirical diagnostics only. No\n"
    "future-point marginal coverage claim is made.\n"
    "The result does not validate recon's model-relative uncertainty band."
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Dependent conformal re-split diagnostics against the DMARC record."
    )
    parser.add_argument("domains", type=Path, help="File with one apex per line (gitignored; local).")
    parser.add_argument("--alpha", type=float, default=0.1, help="Miscoverage level; target is 1-alpha (default 0.1).")
    parser.add_argument("--trials", type=int, default=20, help="Dependent re-splits to summarize (default 20).")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent resolves (default 5).")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-domain resolve timeout seconds.")
    parser.add_argument("--json", action="store_true", help="Emit aggregate coverage as JSON.")
    args = parser.parse_args(argv)

    try:
        _validate_alpha(args.alpha)
    except ValueError as exc:
        parser.error(str(exc))

    if not args.domains.is_file():
        print(f"FAIL: domains file not found: {args.domains}")
        return 1

    # Reuse the reference-calibration collector: it pairs each domain's policy
    # posterior with the DMARC reference label and drops the apex. It returns a
    # CalibrationPair per domain (``.full`` = the shipped posterior, ``.held_out``
    # = the dmarc-masked residual). The historical conformal artifact evaluates
    # ``.full``. Because that score consumes the label-defining declaration, the
    # resulting empirical diagnostics are overlap-aware corroboration.
    from validation.reference_calibration import _read_domains, collect

    domains = _read_domains(args.domains)
    if not args.json:
        print(f"Resolving {len(domains)} domains against the DMARC record (aggregates only, no apex printed)...")
    pairs = asyncio.run(collect(domains, timeout=args.timeout, skip_ct=True, concurrency=args.concurrency))
    posteriors = [p.full.posterior for p in pairs]
    labels = [p.full.label for p in pairs]
    summary = evaluate_cv(posteriors, labels, alpha=args.alpha, trials=args.trials)
    if args.json:
        print(json.dumps(json_payload(summary, alpha=args.alpha, trials=args.trials), indent=2, sort_keys=True))
    else:
        _print_summary(summary)
        print(_TRAILER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
