"""Pin the conformal-coverage harness's pure logic.

`validation/conformal_coverage.py` adds a distribution-free finite-sample
coverage check on the labelable email-policy node, complementary to the
reference calibration. The network orchestration is maintainer-local, but the
nonconformity score, the split-conformal quantile, the prediction set, and the
coverage aggregation are pure functions whose correctness any reported number
depends on. These tests pin them with hand-computed values and synthetic data
(no network, no real apex), including the coverage guarantee on calibrated data
and a falsifiability case proving the check can fail when exchangeability is
violated.
"""

from __future__ import annotations

import math
import random

import pytest

from validation.conformal_coverage import (
    binary_nonconformity,
    conformal_quantile,
    evaluate_cv,
    evaluate_explicit,
    prediction_set,
)


class TestNonconformity:
    def test_confident_and_right_scores_low(self) -> None:
        assert binary_nonconformity(0.9, 1) == pytest.approx(0.1)
        assert binary_nonconformity(0.1, 0) == pytest.approx(0.1)

    def test_confident_and_wrong_scores_high(self) -> None:
        assert binary_nonconformity(0.9, 0) == pytest.approx(0.9)
        assert binary_nonconformity(0.1, 1) == pytest.approx(0.9)

    def test_in_unit_interval(self) -> None:
        for p in (0.0, 0.25, 0.5, 0.75, 1.0):
            for y in (0, 1):
                assert 0.0 <= binary_nonconformity(p, y) <= 1.0


class TestConformalQuantile:
    def test_hand_computed_level(self) -> None:
        # n=4, k = ceil(5 * 0.8) = 4, so the 4th smallest score (1-based) is 0.4.
        assert conformal_quantile([0.1, 0.2, 0.3, 0.4], alpha=0.2) == pytest.approx(0.4)

    def test_unsorted_input_is_sorted(self) -> None:
        # n=3, k = ceil(4 * 0.75) = 3, so the 3rd smallest of {0.1,0.3,0.5} is 0.5.
        assert conformal_quantile([0.5, 0.1, 0.3], alpha=0.25) == pytest.approx(0.5)

    def test_too_few_points_for_level_is_inf(self) -> None:
        # n=2, k = ceil(3 * 0.99) = 3 > 2, so the threshold is +inf (hedge to
        # the full set rather than a false-confident narrow one).
        assert math.isinf(conformal_quantile([0.1, 0.2], alpha=0.01))

    def test_empty_is_inf(self) -> None:
        assert math.isinf(conformal_quantile([], alpha=0.1))


class TestPredictionSet:
    def test_decisive_positive(self) -> None:
        assert prediction_set(0.9, q_hat=0.15) == (1,)

    def test_decisive_negative(self) -> None:
        assert prediction_set(0.1, q_hat=0.15) == (0,)

    def test_abstains_when_threshold_is_loose(self) -> None:
        assert prediction_set(0.5, q_hat=0.6) == (0, 1)

    def test_empty_when_threshold_is_tight(self) -> None:
        assert prediction_set(0.5, q_hat=0.05) == ()

    def test_infinite_threshold_includes_both(self) -> None:
        assert prediction_set(0.99, q_hat=math.inf) == (0, 1)


class TestEvaluateExplicit:
    def test_confident_correct_is_decisive_and_covered(self) -> None:
        # Calibration scores are all 0.1, so any reasonable level puts the
        # threshold at 0.1; confident-correct test points get decisive sets that
        # contain the true label.
        out = evaluate_explicit(
            cal_posteriors=[0.9, 0.9, 0.1, 0.1],
            cal_labels=[1, 1, 0, 0],
            test_posteriors=[0.95, 0.05],
            test_labels=[1, 0],
            alpha=0.5,
        )
        assert out["coverage"] == pytest.approx(1.0)
        assert out["decisive_rate"] == pytest.approx(1.0)
        assert out["mean_set_size"] == pytest.approx(1.0)

    def test_empty_test_is_handled(self) -> None:
        out = evaluate_explicit([0.9], [1], [], [], alpha=0.1)
        assert out["n_test"] == 0.0


class TestCoverageGuaranteeOnCalibratedData:
    def _calibrated_bimodal(self, n: int, seed: int) -> tuple[list[float], list[int]]:
        # A calibrated, bimodal generator that mimics the email-policy node:
        # posteriors cluster near 0 or near 1, and the label is Bernoulli(p), so
        # the model is calibrated by construction and the points are exchangeable.
        rng = random.Random(seed)  # noqa: S311 - reproducible synthetic test data, not security-sensitive.
        posteriors: list[float] = []
        labels: list[int] = []
        for _ in range(n):
            p = rng.uniform(0.82, 0.98) if rng.random() < 0.6 else rng.uniform(0.02, 0.18)
            posteriors.append(p)
            labels.append(1 if rng.random() < p else 0)
        return posteriors, labels

    def test_meets_nominal_coverage(self) -> None:
        posteriors, labels = self._calibrated_bimodal(600, seed=20260611)
        out = evaluate_cv(posteriors, labels, alpha=0.1, trials=20, seed=1729)
        # Split conformal guarantees marginal coverage at or above 1 - alpha; on
        # calibrated exchangeable data the averaged coverage lands at nominal.
        assert out["mean_coverage"] >= 0.88
        assert out["min_coverage"] >= 0.80
        # The sets are not trivially "always abstain": a calibrated bimodal node
        # is usually decisive, so the mean set size sits well below 2.
        assert out["mean_set_size"] < 1.9

    def test_insufficient_data_is_flagged(self) -> None:
        out = evaluate_cv([0.9, 0.1], [1, 0], alpha=0.1)
        assert out.get("insufficient") == 1.0


class TestExchangeabilityIsLoadBearing:
    def test_non_exchangeable_split_breaks_coverage(self) -> None:
        # Calibrate where the model is confidently correct, then test where it is
        # confidently wrong: the two halves are not exchangeable, and coverage
        # collapses far below the 0.9 target. This is the falsifiability case; it
        # demonstrates the exchangeability caveat is real, not decorative.
        out = evaluate_explicit(
            cal_posteriors=[0.95] * 50 + [0.05] * 50,
            cal_labels=[1] * 50 + [0] * 50,
            test_posteriors=[0.95] * 50,
            test_labels=[0] * 50,
            alpha=0.1,
        )
        assert out["coverage"] < 0.9
        assert out["coverage"] == pytest.approx(0.0)


class TestAggregatesOnly:
    def test_cv_output_is_aggregate_numbers(self) -> None:
        rng = random.Random(7)  # noqa: S311 - reproducible synthetic test data, not security-sensitive.
        posteriors = [rng.uniform(0.0, 1.0) for _ in range(40)]
        labels = [rng.randint(0, 1) for _ in range(40)]
        out = evaluate_cv(posteriors, labels, alpha=0.1, trials=5)
        allowed = {
            "n",
            "trials",
            "target_coverage",
            "mean_coverage",
            "min_coverage",
            "mean_set_size",
        }
        assert set(out) <= allowed
        assert all(isinstance(v, int | float) for v in out.values())
