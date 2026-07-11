"""Pin the scoring math the validation diagnostics rest on.

The historical synthetic ECE, CAL8 sensitivity deviations, and Brier scores in
validation memos are computed by `validation/synthetic_calibration.py`
and `validation/likelihood_sensitivity.py`. Their Brier and ECE helpers
are pure functions with no test of their own, so a subtle error would
silently corrupt the numbers the assurance story quotes. These tests
pin each helper to hand-computed values and cross-check that the two
harnesses' independent implementations agree, so the diagnostic calculations
rest on verified arithmetic.
"""

from __future__ import annotations

from validation.likelihood_sensitivity import _brier as ls_brier
from validation.likelihood_sensitivity import _ece as ls_ece
from validation.synthetic_calibration import (
    _brier as sc_brier,
)
from validation.synthetic_calibration import (
    _expected_calibration_error,
    _reliability_table,
)


class TestBrier:
    def test_hand_computed(self) -> None:
        # ((0.8 - 1)^2 + (0.3 - 0)^2) / 2 = (0.04 + 0.09) / 2 = 0.065
        assert abs(sc_brier([0.8, 0.3], [1, 0]) - 0.065) < 1e-12
        assert abs(ls_brier([0.8, 0.3], [1, 0]) - 0.065) < 1e-12

    def test_perfect_prediction_is_zero(self) -> None:
        assert sc_brier([1.0, 0.0, 1.0], [1, 0, 1]) == 0.0
        assert ls_brier([1.0, 0.0, 1.0], [1, 0, 1]) == 0.0

    def test_empty_is_zero(self) -> None:
        assert sc_brier([], []) == 0.0
        assert ls_brier([], []) == 0.0

    def test_two_implementations_agree(self) -> None:
        preds = [0.1, 0.42, 0.6, 0.88, 0.5, 0.05, 0.95]
        outs = [0, 1, 0, 1, 1, 0, 1]
        assert abs(sc_brier(preds, outs) - ls_brier(preds, outs)) < 1e-12


class TestReliabilityTableAndEce:
    def test_reliability_table_single_bucket(self) -> None:
        # Both predictions fall in the [0.2, 0.3) bin (idx 2 at width 0.1);
        # empirical freq is 1 of 2 = 0.5, count 2.
        table = _reliability_table([0.2, 0.2], [1, 0], bins=10)
        assert len(table) == 1
        low, high, freq, count = table[0]
        assert abs(low - 0.2) < 1e-9
        assert abs(high - 0.3) < 1e-9
        assert freq == 0.5
        assert count == 2

    def test_expected_calibration_error_hand_computed(self) -> None:
        # midpoint 0.25, freq 0.5, |0.25 - 0.5| = 0.25, full weight.
        table = _reliability_table([0.2, 0.2], [1, 0], bins=10)
        assert abs(_expected_calibration_error(table, 2) - 0.25) < 1e-12

    def test_likelihood_ece_hand_computed(self) -> None:
        # Same case via the other harness: midpoint (2 + 0.5)*0.1 = 0.25.
        assert abs(ls_ece([0.2, 0.2], [1, 0], bins=10) - 0.25) < 1e-12

    def test_perfectly_calibrated_bucket_is_zero(self) -> None:
        # Four predictions of 0.25 with one positive: empirical freq 0.25
        # equals the bin midpoint 0.25, so the calibration error is zero.
        preds = [0.25, 0.25, 0.25, 0.25]
        outs = [1, 0, 0, 0]
        table = _reliability_table(preds, outs, bins=10)
        assert _expected_calibration_error(table, 4) == 0.0
        assert ls_ece(preds, outs, bins=10) == 0.0

    def test_empty_is_zero(self) -> None:
        assert _expected_calibration_error([], 0) == 0.0
        assert ls_ece([], [], bins=10) == 0.0

    def test_two_ece_implementations_agree(self) -> None:
        # The reliability-table ECE and the single-pass ECE use the same
        # binning and the same (idx + 0.5) * width midpoint, so they must
        # agree on any dataset.
        preds = [0.05, 0.18, 0.22, 0.49, 0.51, 0.77, 0.93, 0.31, 0.66]
        outs = [0, 0, 1, 0, 1, 1, 1, 0, 1]
        sc = _expected_calibration_error(_reliability_table(preds, outs, bins=10), len(preds))
        ls = ls_ece(preds, outs, bins=10)
        assert abs(sc - ls) < 1e-12
