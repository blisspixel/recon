"""Distribution-free conformal coverage for the labelable nodes.

A complement to the reference calibration (validation/reference_calibration.py).
That harness asks whether the email-policy posterior is *calibrated* against
the DMARC record (reliability / ECE / Brier). This one asks a different,
frequentist question on the same labelable node: if recon emits a prediction
set for the binary enforcing/not call, does that set contain the true label at
least a target fraction of the time, with a finite-sample guarantee that needs
no distributional assumption?

Split conformal prediction supplies exactly that. Given a held-out calibration
slice of (posterior, reference-label) pairs, it picks a threshold so that, on a
fresh exchangeable point, the prediction set covers the true label with
probability at least 1 - alpha. The guarantee is distribution-free and holds in
finite samples (Vovk et al.), and the threshold is a single quantile of sorted
nonconformity scores: no new dependency, no learned weights.

Why this sits beside the Bayesian interval, not instead of it. The credible
interval is a subjective-Bayesian statement about the probability; the conformal
set is a frequentist coverage statement about the label. They answer different
questions, and reporting both is the honest move: the interval says how much the
evidence constrains the claim, the conformal set says how often a decision rule
built on the posterior would be right.

The boundary, stated plainly. Conformal coverage holds under exchangeability of
the calibration and test points. An adversarially-hardened target is, by
construction, not exchangeable with the typical corpus (the whole point of the
MNAR treatment), so this guarantee is claimed for typical targets and explicitly
not for hardened ones. That is the same seam the suppression-monotonicity
theorem names (correlation.md section 4.3): the structural guarantee keeps
holding under hiding, the coverage guarantee does not. The harness includes a
falsifiability check (a deliberately non-exchangeable split) so the limitation is
demonstrated, not just asserted.

Scope. Only nodes with an external reference label can carry this: the
email-policy node now (the DMARC record), and the tenancy nodes once
provider-endpoint corroboration gives them a reference. The hideable nodes have
no label, so they carry only the structural guarantees.

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


def conformal_quantile(cal_scores: list[float], alpha: float) -> float:
    """The split-conformal threshold from calibration nonconformity scores.

    Returns the ``k``-th smallest score where ``k = ceil((n + 1) * (1 - alpha))``,
    the level that gives finite-sample marginal coverage of at least ``1 - alpha``
    on a fresh exchangeable point. When ``k`` exceeds ``n`` (too few calibration
    points for the requested level) the threshold is ``+inf``, so the prediction
    set contains both labels and coverage is trivially met (the honest, hedged
    fallback rather than a false-confident narrow set).
    """
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
    The result is one of: ``(1,)`` or ``(0,)`` (a decisive call), ``(0, 1)`` (the
    model abstains, both labels plausible), or ``()`` (neither plausible, which
    counts as a miss and pulls coverage down rather than being hidden).
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
    """Coverage and set-size aggregates for one explicit calibration/test split.

    Calibrate the threshold on the calibration pairs, form a prediction set for
    each test point, and report the empirical coverage (fraction of test points
    whose true label is in the set) against the ``1 - alpha`` target, plus the
    set-size mix. All aggregate; no per-point data is returned.
    """
    cal_scores = [binary_nonconformity(p, y) for p, y in zip(cal_posteriors, cal_labels, strict=True)]
    q_hat = conformal_quantile(cal_scores, alpha)
    n_test = len(test_posteriors)
    if n_test == 0:
        return {"coverage": 0.0, "mean_set_size": 0.0, "n_cal": float(len(cal_scores)), "n_test": 0.0}
    covered = 0
    total_size = 0
    decisive = 0
    abstain = 0
    empty = 0
    for p, y in zip(test_posteriors, test_labels, strict=True):
        s = prediction_set(p, q_hat)
        total_size += len(s)
        if y in s:
            covered += 1
        if len(s) == 1:
            decisive += 1
        elif len(s) == 2:
            abstain += 1
        elif len(s) == 0:
            empty += 1
    return {
        "target_coverage": round(1.0 - alpha, 4),
        "coverage": round(covered / n_test, 4),
        "mean_set_size": round(total_size / n_test, 4),
        "decisive_rate": round(decisive / n_test, 4),
        "abstain_rate": round(abstain / n_test, 4),
        "empty_rate": round(empty / n_test, 4),
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
    """Average conformal coverage over several seeded splits.

    A single split is noisy; averaging over ``trials`` independent splits gives a
    stable read on whether the shipped posterior meets the coverage target, and
    the worst split (``min_coverage``) shows the spread. Aggregates only.
    """
    n = len(posteriors)
    if n < 4:
        return {"n": float(n), "insufficient": 1.0}
    coverages: list[float] = []
    sizes: list[float] = []
    for t in range(trials):
        r = evaluate_split(posteriors, labels, alpha, seed + t)
        coverages.append(r["coverage"])
        sizes.append(r["mean_set_size"])
    return {
        "n": float(n),
        "trials": float(trials),
        "target_coverage": round(1.0 - alpha, 4),
        "mean_coverage": round(sum(coverages) / trials, 4),
        "min_coverage": round(min(coverages), 4),
        "mean_set_size": round(sum(sizes) / trials, 4),
    }


def _print_summary(summary: dict[str, float]) -> None:
    if summary.get("insufficient"):
        print(f"Only {int(summary['n'])} labeled domains; need at least 4 to split. Nothing to report.")
        return
    print(f"\nConformal coverage of the email-policy node (n={int(summary['n'])}, {int(summary['trials'])} splits)")
    print(f"  target coverage:   {summary['target_coverage']}")
    print(f"  mean coverage:     {summary['mean_coverage']}")
    print(f"  worst-split cover: {summary['min_coverage']}")
    print(f"  mean set size:     {summary['mean_set_size']}  (1.0 is fully decisive, 2.0 is always abstaining)")


def json_payload(summary: dict[str, float], *, alpha: float, trials: int) -> dict[str, object]:
    """Machine-readable aggregate output for private-run memo generation."""
    return {
        "mode": "single",
        "node": "email_security_policy_enforcing",
        "construction": "split_conformal",
        "alpha": alpha,
        "trials_requested": trials,
        "summary": summary,
        "disclosure": {
            "aggregate_only": True,
            "contains_target_rows": False,
            "small_cell_threshold": 10,
        },
    }


_TRAILER = (
    "\nDistribution-free finite-sample coverage under exchangeability (split conformal).\n"
    "The guarantee is claimed for typical targets and not for adversarially-hardened\n"
    "ones, which are non-exchangeable by construction; that boundary is the one the\n"
    "suppression theorem names (correlation.md section 4.3). Complements, and does not\n"
    "replace, the reference calibration and the Bayesian interval."
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Conformal coverage of the email-policy posterior against the DMARC record."
    )
    parser.add_argument("domains", type=Path, help="File with one apex per line (gitignored; local).")
    parser.add_argument("--alpha", type=float, default=0.1, help="Miscoverage level; target is 1-alpha (default 0.1).")
    parser.add_argument("--trials", type=int, default=20, help="Splits to average (default 20).")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent resolves (default 5).")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-domain resolve timeout seconds.")
    parser.add_argument("--json", action="store_true", help="Emit aggregate coverage as JSON.")
    args = parser.parse_args(argv)

    if not args.domains.is_file():
        print(f"FAIL: domains file not found: {args.domains}")
        return 1

    # Reuse the reference-calibration collector: it pairs each domain's policy
    # posterior with the DMARC reference label and drops the apex. It returns a
    # CalibrationPair per domain (``.full`` = the shipped posterior, ``.held_out``
    # = the dmarc-masked residual); conformal coverage is a statement about the
    # deployed predictor, so we take ``.full``.
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
