from __future__ import annotations

import pytest

from validation.calibration_estimators import (
    bootstrap_mean_confidence_ece,
    equal_mass_reliability_bins,
    mean_confidence_ece,
    percentile,
)


class TestEqualMassReliabilityBins:
    def test_bins_have_balanced_counts_and_mean_confidence(self) -> None:
        predicted = [0.9, 0.1, 0.8, 0.2, 0.7, 0.3]
        outcome = [1, 0, 1, 0, 1, 0]

        rows = equal_mass_reliability_bins(predicted, outcome, bins=3)

        assert [row.count for row in rows] == [2, 2, 2]
        assert rows[0].bin_low == 0.1
        assert rows[0].bin_high == 0.2
        assert rows[0].mean_confidence == pytest.approx(0.15)
        assert rows[0].empirical_rate == 0.0
        assert rows[2].mean_confidence == pytest.approx(0.85)
        assert rows[2].empirical_rate == 1.0

    def test_more_bins_than_records_uses_non_empty_bins_only(self) -> None:
        rows = equal_mass_reliability_bins([0.2, 0.8], [0, 1], bins=10)

        assert len(rows) == 2
        assert [row.count for row in rows] == [1, 1]

    def test_empty_input_returns_empty_table(self) -> None:
        assert equal_mass_reliability_bins([], [], bins=10) == []


class TestMeanConfidenceEce:
    def test_hand_computed_mean_confidence_ece(self) -> None:
        # Two equal-mass bins:
        # [0.1, 0.2] with empirical 0.0 gives |0.15 - 0.0| * 1/2.
        # [0.8, 0.9] with empirical 1.0 gives |0.85 - 1.0| * 1/2.
        assert mean_confidence_ece([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1], bins=2) == pytest.approx(0.15)

    def test_perfect_probability_rows_are_zero(self) -> None:
        assert mean_confidence_ece([0.0, 1.0], [0, 1], bins=2) == 0.0

    def test_validates_inputs(self) -> None:
        with pytest.raises(ValueError, match="same length"):
            mean_confidence_ece([0.1], [0, 1])
        with pytest.raises(ValueError, match="positive integer"):
            mean_confidence_ece([0.1], [0], bins=0)
        with pytest.raises(ValueError, match=r"\[0, 1\]"):
            mean_confidence_ece([1.2], [1])
        with pytest.raises(ValueError, match="binary"):
            mean_confidence_ece([0.2], [2])


class TestBootstrapMeanConfidenceEce:
    def test_bootstrap_summary_is_deterministic_and_bounds_estimate(self) -> None:
        predicted = [0.1, 0.2, 0.8, 0.9, 0.7, 0.6]
        outcome = [0, 0, 1, 1, 1, 0]

        first = bootstrap_mean_confidence_ece(predicted, outcome, bins=3, samples=50, seed=7)
        second = bootstrap_mean_confidence_ece(predicted, outcome, bins=3, samples=50, seed=7)

        assert first == second
        assert first.estimate == pytest.approx(mean_confidence_ece(predicted, outcome, bins=3))
        assert 0.0 <= first.ci_low <= first.ci_high <= 1.0
        assert first.bootstrap_samples == 50
        assert first.confidence_level == 0.80

    def test_empty_input_is_zero_width_zero(self) -> None:
        summary = bootstrap_mean_confidence_ece([], [], bins=10, samples=5)

        assert summary.estimate == 0.0
        assert summary.ci_low == 0.0
        assert summary.ci_high == 0.0


class TestPercentile:
    def test_interpolates(self) -> None:
        assert percentile([0.0, 1.0], 0.5) == pytest.approx(0.5)
        assert percentile([0.0, 10.0, 20.0], 0.25) == pytest.approx(5.0)

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            percentile([], 0.5)
