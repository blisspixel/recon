"""Pin the reference-calibration harness's pure logic.

`validation/reference_calibration.py` calibrates the email-policy posterior
against the DMARC record (the record that is its own ground truth). The
network orchestration is maintainer-local, but the label derivation, the
Wilson interval, and the aggregate calibration are pure functions whose
correctness the published number depends on. These tests pin them with
hand-computed values and synthetic records (no network, no real apex).
"""

from __future__ import annotations

import json

import pytest

from validation import reference_calibration as refcal
from validation.reference_calibration import (
    CalibrationPair,
    CalibrationRecord,
    calibration_summary,
    held_out_policy_posterior,
    main,
    mean_log_score,
    reference_label_email_policy,
    stratified_summary,
    wilson_interval,
)


class TestReferenceLabel:
    @pytest.mark.parametrize("policy", ["reject", "quarantine", "Reject", "  QUARANTINE  "])
    def test_enforcing_policies_label_one(self, policy: str) -> None:
        assert reference_label_email_policy(policy) == 1

    def test_none_policy_labels_zero(self) -> None:
        assert reference_label_email_policy("none") == 0
        assert reference_label_email_policy("NONE") == 0

    def test_absent_or_unknown_policy_has_no_label(self) -> None:
        # No DMARC record, or an unrecognized value, carries no reference
        # truth and is excluded rather than guessed.
        assert reference_label_email_policy(None) is None
        assert reference_label_email_policy("") is None
        assert reference_label_email_policy("p=reject") is None  # raw token, not the parsed level


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
            CalibrationRecord(posterior=0.9, label=1),
            CalibrationRecord(posterior=0.85, label=1),
            CalibrationRecord(posterior=0.7, label=1),
            CalibrationRecord(posterior=0.2, label=0),
        ]
        s = calibration_summary(records)
        assert s["n"] == 4
        assert s["base_rate_enforcing"] == 0.75
        assert s["agreement_rate"] == 1.0

    def test_disagreement_lowers_agreement_rate(self) -> None:
        # One miscalibrated domain: high posterior but the DMARC Reference says
        # not enforcing (the exact case Reference calibration is meant to catch).
        records = [
            CalibrationRecord(posterior=0.9, label=1),
            CalibrationRecord(posterior=0.88, label=0),  # over-confident vs the Reference
        ]
        s = calibration_summary(records)
        assert s["agreement_rate"] == 0.5
        # Brier penalizes the confident miss: ((0.9-1)^2 + (0.88-0)^2)/2.
        assert abs(s["brier"] - ((0.9 - 1) ** 2 + 0.88**2) / 2) < 1e-9

    def test_reliability_rows_are_aggregate_only(self) -> None:
        records = [CalibrationRecord(posterior=0.05 + 0.1 * i, label=i % 2) for i in range(10)]
        s = calibration_summary(records)
        for row in s["reliability"]:  # type: ignore[attr-defined]
            assert set(row) == {"bin_low", "bin_high", "enforcing_rate", "count"}
            assert all(isinstance(v, int | float) for v in row.values())


class TestMeanLogScore:
    def test_hand_computed(self) -> None:
        # -[ln(0.9) + ln(1 - 0.2)] / 2 = (0.10536 + 0.22314) / 2 = 0.16425
        records = [
            CalibrationRecord(posterior=0.9, label=1),
            CalibrationRecord(posterior=0.2, label=0),
        ]
        assert mean_log_score(records) == pytest.approx(0.16425, abs=1e-5)

    def test_uninformative_predictor_scores_ln2(self) -> None:
        records = [CalibrationRecord(posterior=0.5, label=i % 2) for i in range(10)]
        import math

        assert mean_log_score(records) == pytest.approx(math.log(2.0), abs=1e-9)

    def test_confident_miss_is_finite_and_dominant(self) -> None:
        # A posterior of exactly 1.0 against label 0 must clamp, not inf.
        records = [CalibrationRecord(posterior=1.0, label=0)]
        score = mean_log_score(records)
        assert score == pytest.approx(13.8155, abs=1e-3)

    def test_empty_is_zero(self) -> None:
        assert mean_log_score([]) == 0.0

    def test_summary_carries_it(self) -> None:
        records = [CalibrationRecord(posterior=0.9, label=1)]
        assert "log_score" in calibration_summary(records)


class TestHeldOutPolicyPosterior:
    """The residual predictor masks the dmarc_policy unit, so the DMARC
    signal must not influence it in either direction. Hand values use the
    shipped network (prior 0.62) with priors_override={} so a local
    ~/.recon/priors.yaml cannot leak in; see
    tests/test_bayesian_masked_units.py for the arithmetic."""

    def test_invariant_to_the_dmarc_signal(self) -> None:
        with_dmarc = held_out_policy_posterior(set(), {"dmarc_reject", "spf_strict"}, priors_override={})
        without_dmarc = held_out_policy_posterior(set(), {"spf_strict"}, priors_override={})
        assert with_dmarc == without_dmarc

    def test_hand_computed_spf_only_residual(self) -> None:
        # 0.62*0.53*0.94 / (0.62*0.53*0.94 + 0.38*0.27*0.99) = 0.7525
        p = held_out_policy_posterior(set(), {"spf_strict"}, priors_override={})
        assert p == pytest.approx(0.7525, abs=1e-4)

    def test_hand_computed_no_signal_residual(self) -> None:
        # Strict SPF genuinely absent (declarative complement [0.47, 0.73]),
        # MTA-STS absent (near-neutral complement [0.94, 0.99]):
        # 0.62*0.47*0.94 / (0.62*0.47*0.94 + 0.38*0.73*0.99) = 0.4994
        p = held_out_policy_posterior(set(), set(), priors_override={})
        assert p == pytest.approx(0.4994, abs=1e-4)


class TestStratifiedSummary:
    def test_small_cells_are_suppressed(self) -> None:
        strata = {
            "big": [CalibrationRecord(posterior=0.9, label=1) for _ in range(12)],
            "tiny": [CalibrationRecord(posterior=0.9, label=1) for _ in range(3)],
        }
        out = stratified_summary(strata, min_cell=10)
        assert out["strata"]["tiny"] == {"n": 3, "suppressed": True}
        assert out["strata"]["big"]["n"] == 12
        assert "ece" in out["strata"]["big"]

    def test_pooled_includes_suppressed_records(self) -> None:
        # Suppression hides a stratum's row but its records still count in the
        # pooled total, so the headline number is over the whole set.
        strata = {
            "a": [CalibrationRecord(posterior=0.9, label=1) for _ in range(8)],
            "b": [CalibrationRecord(posterior=0.1, label=0) for _ in range(8)],
        }
        out = stratified_summary(strata, min_cell=10)
        assert out["strata"]["a"]["suppressed"] is True
        assert out["strata"]["b"]["suppressed"] is True
        assert out["pooled"]["n"] == 16

    def test_strata_keys_carry_no_apex(self) -> None:
        strata = {"banking": [CalibrationRecord(posterior=0.9, label=1) for _ in range(10)]}
        out = stratified_summary(strata, min_cell=10)
        assert all("." not in name for name in out["strata"])


class TestJsonMain:
    """Pin the --json orchestration (the maintainer / PV2-drift surface).

    Like the conformal collector contract, main()'s glue is otherwise only
    exercised by a live run. The collector is monkeypatched so no network is
    touched; the test asserts main() emits one valid JSON object carrying the
    full and held-out aggregates, and nothing that looks like an apex.
    """

    @staticmethod
    def _pairs(n: int) -> list[CalibrationPair]:
        return [
            CalibrationPair(
                full=CalibrationRecord(posterior=0.9 if i % 2 else 0.1, label=i % 2),
                held_out=CalibrationRecord(posterior=0.45, label=i % 2),
            )
            for i in range(n)
        ]

    def test_single_json_is_parseable_aggregate(self, tmp_path, monkeypatch, capsys) -> None:
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("contoso.com\nfabrikam.com\n", encoding="utf-8")

        async def _fake_collect(domains, *, timeout, skip_ct, concurrency, label="resolving"):
            return self._pairs(20)

        monkeypatch.setattr(refcal, "collect", _fake_collect)
        rc = main([str(domains_file), "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        doc = json.loads(out)
        assert doc["mode"] == "single"
        assert doc["n"] == 20
        assert doc["full"]["n"] == 20
        assert doc["held_out"]["n"] == 20
        # No apex leaks into the structured output.
        assert "contoso" not in out
        assert "fabrikam" not in out

    def test_single_json_empty_is_clean(self, tmp_path, monkeypatch, capsys) -> None:
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("contoso.com\n", encoding="utf-8")

        async def _fake_collect(domains, *, timeout, skip_ct, concurrency, label="resolving"):
            return []

        monkeypatch.setattr(refcal, "collect", _fake_collect)
        rc = main([str(domains_file), "--json"])
        assert rc == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc == {"mode": "single", "n": 0, "full": {"n": 0}, "held_out": {"n": 0}}

    def test_stratified_json_carries_both_constructions(self, tmp_path, monkeypatch, capsys) -> None:
        (tmp_path / "alpha.txt").write_text("contoso.com\n", encoding="utf-8")
        (tmp_path / "beta.txt").write_text("fabrikam.com\n", encoding="utf-8")

        async def _fake_collect(domains, *, timeout, skip_ct, concurrency, label="resolving"):
            return self._pairs(12)

        monkeypatch.setattr(refcal, "collect", _fake_collect)
        rc = main(["--stratify-dir", str(tmp_path), "--json"])
        assert rc == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["mode"] == "stratified"
        assert doc["full"]["pooled"]["n"] == 24
        assert doc["held_out"]["pooled"]["n"] == 24
        assert set(doc["full"]["strata"]) == {"alpha", "beta"}
