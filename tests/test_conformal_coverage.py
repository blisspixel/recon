"""Pin the conformal-coverage harness's pure logic.

`validation/conformal_coverage.py` adds dependent empirical re-split
diagnostics on the labelable email-policy node, complementary to the reference
comparison. The network orchestration is maintainer-local, but the
nonconformity score, the split-conformal quantile, the prediction set, and the
coverage aggregation are pure functions whose correctness any reported number
depends on. These tests pin them with hand-computed values and synthetic data
(no network, no real apex). The pure quantile helper retains its correctly
scoped theorem for an independently fixed scorer and exchangeable future point;
the current recon experiment does not claim those prerequisites.
"""

from __future__ import annotations

import json
import math
import random

import pytest

import validation.reference_calibration as refcal
from validation.conformal_coverage import (
    binary_nonconformity,
    conformal_quantile,
    evaluate_cv,
    evaluate_explicit,
    json_payload,
    prediction_set,
)
from validation.conformal_coverage import (
    main as conformal_main,
)
from validation.reference_calibration import CalibrationPair, CalibrationRecord


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

    @pytest.mark.parametrize("alpha", [0.0, 1.0, -0.1, 1.1, math.nan, math.inf, -math.inf])
    def test_invalid_alpha_is_rejected(self, alpha: float) -> None:
        with pytest.raises(ValueError, match="finite and strictly between 0 and 1"):
            conformal_quantile([0.1, 0.2], alpha=alpha)


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
        assert out["singleton_rate"] == pytest.approx(1.0)
        assert out["multi_label_rate"] == pytest.approx(0.0)
        assert out["empty_set_rate"] == pytest.approx(0.0)
        assert out["mean_set_size"] == pytest.approx(1.0)

    def test_empty_test_is_handled(self) -> None:
        out = evaluate_explicit([0.9], [1], [], [], alpha=0.1)
        assert out["n_test"] == 0.0


class TestEmpiricalBehaviorOnExchangeableSyntheticData:
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

    def test_repeated_split_diagnostics_are_nontrivial(self) -> None:
        posteriors, labels = self._calibrated_bimodal(600, seed=20260611)
        out = evaluate_cv(posteriors, labels, alpha=0.1, trials=20, seed=1729)
        # This seeded simulation is a regression check, not proof of the marginal
        # theorem. The dependent re-splits land near the nominal reference here.
        assert out["mean_coverage"] >= 0.88
        assert out["min_coverage"] >= 0.80
        assert out["mean_singleton_rate"] > 0.5
        assert out["mean_multi_label_rate"] < 0.5
        assert out["mean_empty_set_rate"] < 0.5
        rate_sum = out["mean_singleton_rate"] + out["mean_multi_label_rate"] + out["mean_empty_set_rate"]
        assert rate_sum == pytest.approx(1.0, abs=2e-4)

    def test_insufficient_data_is_flagged(self) -> None:
        out = evaluate_cv([0.9, 0.1], [1, 0], alpha=0.1)
        assert out.get("insufficient") == 1.0

    def test_invalid_alpha_is_rejected_before_small_sample_shortcut(self) -> None:
        with pytest.raises(ValueError, match="finite and strictly between 0 and 1"):
            evaluate_cv([0.9, 0.1], [1, 0], alpha=math.nan)

    def test_zero_trials_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="trials must be at least 1"):
            evaluate_cv([0.9, 0.1, 0.8, 0.2], [1, 0, 1, 0], alpha=0.1, trials=0)


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


class TestCollectorContract:
    """Guard the cross-harness contract this harness reuses.

    `conformal_coverage.main` consumes `reference_calibration.collect`, which
    returns a `CalibrationPair` per domain. A 2026-06 change to the collector
    (adding the held-out residual, so it returns pairs not bare records) broke
    this orchestration, and only a live run caught it because the network path
    is otherwise untested. This pins the contract — main() must read the full
    posterior off each pair and run to completion — with the collector
    monkeypatched so no network is touched.
    """

    def test_main_runs_against_paired_collector(self, tmp_path, monkeypatch, capsys) -> None:
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("contoso.com\nnorthwindtraders.com\nfabrikam.com\n", encoding="utf-8")

        pairs = [
            CalibrationPair(
                full=CalibrationRecord(posterior=0.9 if i % 2 else 0.1, label=i % 2),
                held_out=CalibrationRecord(posterior=0.45, label=i % 2),
            )
            for i in range(40)
        ]

        async def _fake_collect(domains, *, timeout, skip_ct, concurrency):
            return pairs

        # Patch on the source module: conformal imports the names inside main(),
        # so the binding resolves at call time against this attribute.
        monkeypatch.setattr(refcal, "collect", _fake_collect)

        rc = conformal_main([str(domains_file)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "coverage" in out.lower()
        assert "singleton rate" in out.lower()
        assert "multi-label rate" in out.lower()
        assert "empty-set rate" in out.lower()

    def test_main_rejects_invalid_alpha_before_collection(self, tmp_path, capsys) -> None:
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("contoso.com\n", encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            conformal_main([str(domains_file), "--alpha", "nan"])

        assert exc_info.value.code == 2
        assert "alpha must be finite and strictly between 0 and 1" in capsys.readouterr().err

    def test_main_json_is_aggregate_only(self, tmp_path, monkeypatch, capsys) -> None:
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("contoso.com\nnorthwindtraders.com\nfabrikam.com\n", encoding="utf-8")

        pairs = [
            CalibrationPair(
                full=CalibrationRecord(posterior=0.9 if i % 2 else 0.1, label=i % 2),
                held_out=CalibrationRecord(posterior=0.45, label=i % 2),
            )
            for i in range(40)
        ]

        async def _fake_collect(domains, *, timeout, skip_ct, concurrency):
            return pairs

        monkeypatch.setattr(refcal, "collect", _fake_collect)

        rc = conformal_main([str(domains_file), "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["mode"] == "single"
        assert payload["construction"] == "split_conformal"
        assert payload["disclosure"]["aggregate_only"] is True
        assert payload["summary"]["n"] == 40.0
        assert payload["interpretation"]["coverage_scope"].startswith("dependent empirical")
        assert payload["interpretation"]["scorer_disjointness"].startswith("not established")
        assert "no future-point coverage claim" in payload["interpretation"]["coverage_scope"]
        assert "mean_set_size" in payload["interpretation"]["legacy_summary_keys"]
        rendered = json.dumps(payload)
        assert "contoso" not in rendered
        assert "fabrikam" not in rendered


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
            "mean_singleton_rate",
            "mean_multi_label_rate",
            "mean_empty_set_rate",
        }
        assert set(out) <= allowed
        assert all(isinstance(v, int | float) for v in out.values())

    def test_json_payload_carries_no_target_fields(self) -> None:
        payload = json_payload({"n": 4.0, "insufficient": 1.0}, alpha=0.1, trials=20)
        assert payload["disclosure"] == {
            "aggregate_only": True,
            "contains_target_rows": False,
            "small_cell_threshold": 10,
        }
        assert "domain" not in json.dumps(payload).lower()
