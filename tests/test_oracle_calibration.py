"""Pin the oracle-calibration harness's pure logic.

`validation/oracle_calibration.py` calibrates the email-policy posterior
against the DMARC oracle (the record that is its own ground truth). The
network orchestration is maintainer-local, but the label derivation, the
Wilson interval, and the aggregate calibration are pure functions whose
correctness the published number depends on. These tests pin them with
hand-computed values and synthetic records (no network, no real apex).
"""

from __future__ import annotations

import pytest

from validation.oracle_calibration import (
    OracleRecord,
    calibration_summary,
    oracle_label_email_policy,
    wilson_interval,
)


class TestOracleLabel:
    @pytest.mark.parametrize("policy", ["reject", "quarantine", "Reject", "  QUARANTINE  "])
    def test_enforcing_policies_label_one(self, policy: str) -> None:
        assert oracle_label_email_policy(policy) == 1

    def test_none_policy_labels_zero(self) -> None:
        assert oracle_label_email_policy("none") == 0
        assert oracle_label_email_policy("NONE") == 0

    def test_absent_or_unknown_policy_has_no_label(self) -> None:
        # No DMARC record, or an unrecognized value, carries no oracle
        # truth and is excluded rather than guessed.
        assert oracle_label_email_policy(None) is None
        assert oracle_label_email_policy("") is None
        assert oracle_label_email_policy("p=reject") is None  # raw token, not the parsed level


class TestWilsonInterval:
    def test_hand_computed_95(self) -> None:
        # Wilson 95% interval for 8 of 10 is approximately (0.490, 0.943),
        # a standard reference value.
        lo, hi = wilson_interval(8, 10, z=1.96)
        assert abs(lo - 0.4901) < 1e-3
        assert abs(hi - 0.9434) < 1e-3

    def test_is_inside_unit_interval_at_extremes(self) -> None:
        lo, hi = wilson_interval(10, 10, z=1.96)
        assert 0.0 <= lo <= hi <= 1.0
        lo0, hi0 = wilson_interval(0, 10, z=1.96)
        assert 0.0 <= lo0 <= hi0 <= 1.0

    def test_zero_n_is_vacuous(self) -> None:
        assert wilson_interval(0, 0) == (0.0, 1.0)

    def test_narrows_as_n_grows(self) -> None:
        lo_small, hi_small = wilson_interval(8, 10, z=1.96)
        lo_big, hi_big = wilson_interval(800, 1000, z=1.96)
        assert (hi_big - lo_big) < (hi_small - lo_small)


class TestCalibrationSummary:
    def test_empty_is_n_zero(self) -> None:
        assert calibration_summary([]) == {"n": 0}

    def test_base_rate_and_agreement(self) -> None:
        # Three enforcing (posterior high, label 1), one not (posterior low,
        # label 0): base rate 0.75, all four agree on the 0.5 threshold.
        records = [
            OracleRecord(posterior=0.9, label=1),
            OracleRecord(posterior=0.85, label=1),
            OracleRecord(posterior=0.7, label=1),
            OracleRecord(posterior=0.2, label=0),
        ]
        s = calibration_summary(records)
        assert s["n"] == 4
        assert s["base_rate_enforcing"] == 0.75
        assert s["agreement_rate"] == 1.0

    def test_disagreement_lowers_agreement_rate(self) -> None:
        # One miscalibrated domain: high posterior but the DMARC oracle says
        # not enforcing (the exact case oracle calibration is meant to catch).
        records = [
            OracleRecord(posterior=0.9, label=1),
            OracleRecord(posterior=0.88, label=0),  # over-confident vs the oracle
        ]
        s = calibration_summary(records)
        assert s["agreement_rate"] == 0.5
        # Brier penalizes the confident miss: ((0.9-1)^2 + (0.88-0)^2)/2.
        assert abs(s["brier"] - ((0.9 - 1) ** 2 + 0.88**2) / 2) < 1e-9

    def test_reliability_rows_are_aggregate_only(self) -> None:
        records = [OracleRecord(posterior=0.05 + 0.1 * i, label=i % 2) for i in range(10)]
        s = calibration_summary(records)
        for row in s["reliability"]:  # type: ignore[attr-defined]
            assert set(row) == {"bin_low", "bin_high", "enforcing_rate", "count"}
            assert all(isinstance(v, int | float) for v in row.values())
