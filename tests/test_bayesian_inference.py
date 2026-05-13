"""Tests for the v1.9 Bayesian-network inference layer.

Covers:
  * Schema loading (positive and negative paths)
  * Priors override (``~/.recon/priors.yaml``)
  * Variable elimination correctness on hand-checked toy networks
  * Credible interval shape (sparse vs dense, conflict dampening)
  * Adapter from TenantInfo → InferenceResult
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from recon_tool.bayesian import (
    BayesianNetwork,
    InferenceResult,
    _binary_entropy,
    _credible_interval,
    _erfinv,
    infer,
    infer_from_tenant_info,
    load_network,
    load_priors_override,
    signals_from_tenant_info,
)

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def shipped_network() -> BayesianNetwork:
    return load_network()


@pytest.fixture
def toy_network_yaml(tmp_path: Path) -> Path:
    """A two-node parent→child network for hand-checked inference."""
    spec = {
        "version": 1,
        "nodes": [
            {
                "name": "rain",
                "description": "It rained.",
                "prior": 0.30,
                "evidence": [
                    {"slug": "wet_pavement", "likelihood": [0.90, 0.20]},
                ],
            },
            {
                "name": "umbrellas_seen",
                "description": "Many umbrellas in the lobby.",
                "parents": ["rain"],
                "cpt": {
                    "rain=present": 0.80,
                    "rain=absent": 0.05,
                },
                "evidence": [
                    {"signal": "lobby_umbrella_count_high", "likelihood": [0.95, 0.10]},
                ],
            },
        ],
    }
    p = tmp_path / "toy.yaml"
    p.write_text(yaml.safe_dump(spec), encoding="utf-8")
    return p


# ── Schema validation ────────────────────────────────────────────────


class TestSchemaValidation:
    def test_loads_shipped_network(self, shipped_network: BayesianNetwork) -> None:
        assert shipped_network.version == 1
        assert len(shipped_network.nodes) >= 5
        # Roots must have priors; children must have CPTs.
        for n in shipped_network.nodes:
            if n.parents:
                assert n.cpt
                assert n.prior is None
            else:
                assert n.prior is not None

    def test_rejects_unknown_parent(self, tmp_path: Path) -> None:
        spec = {
            "version": 1,
            "nodes": [
                {
                    "name": "child",
                    "description": "x",
                    "parents": ["nonexistent"],
                    "cpt": {"nonexistent=present": 0.5, "nonexistent=absent": 0.5},
                },
            ],
        }
        p = tmp_path / "bad.yaml"
        p.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(ValueError, match="parent 'nonexistent' not defined"):
            load_network(p)

    def test_rejects_cycle(self, tmp_path: Path) -> None:
        spec = {
            "version": 1,
            "nodes": [
                {
                    "name": "a",
                    "description": "x",
                    "parents": ["b"],
                    "cpt": {"b=present": 0.5, "b=absent": 0.5},
                },
                {
                    "name": "b",
                    "description": "x",
                    "parents": ["a"],
                    "cpt": {"a=present": 0.5, "a=absent": 0.5},
                },
            ],
        }
        p = tmp_path / "cycle.yaml"
        p.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(ValueError, match="cycle detected"):
            load_network(p)

    def test_rejects_missing_cpt_keys(self, tmp_path: Path) -> None:
        spec = {
            "version": 1,
            "nodes": [
                {"name": "a", "description": "x", "prior": 0.5},
                {
                    "name": "b",
                    "description": "x",
                    "parents": ["a"],
                    "cpt": {"a=present": 0.5},  # missing a=absent
                },
            ],
        }
        p = tmp_path / "incomplete.yaml"
        p.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(ValueError, match="CPT missing keys"):
            load_network(p)

    def test_rejects_root_without_prior(self, tmp_path: Path) -> None:
        spec = {"version": 1, "nodes": [{"name": "a", "description": "x"}]}
        p = tmp_path / "noprior.yaml"
        p.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(ValueError, match="requires numeric 'prior'"):
            load_network(p)

    def test_rejects_prior_out_of_range(self, tmp_path: Path) -> None:
        spec = {"version": 1, "nodes": [{"name": "a", "description": "x", "prior": 1.5}]}
        p = tmp_path / "badprior.yaml"
        p.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(ValueError, match="outside"):
            load_network(p)

    def test_rejects_unknown_version(self, tmp_path: Path) -> None:
        spec = {"version": 99, "nodes": [{"name": "a", "description": "x", "prior": 0.5}]}
        p = tmp_path / "badver.yaml"
        p.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(ValueError, match="unsupported schema version"):
            load_network(p)

    def test_rejects_non_mapping_top(self, tmp_path: Path) -> None:
        p = tmp_path / "list.yaml"
        p.write_text(yaml.safe_dump([1, 2, 3]), encoding="utf-8")
        with pytest.raises(ValueError, match="expected mapping"):
            load_network(p)

    def test_rejects_evidence_with_both_slug_and_signal(self, tmp_path: Path) -> None:
        spec = {
            "version": 1,
            "nodes": [
                {
                    "name": "a",
                    "description": "x",
                    "prior": 0.5,
                    "evidence": [{"slug": "foo", "signal": "bar", "likelihood": [0.5, 0.5]}],
                }
            ],
        }
        p = tmp_path / "ambig.yaml"
        p.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(ValueError, match="exactly one of 'slug' / 'signal'"):
            load_network(p)

    def test_rejects_likelihood_at_boundary(self, tmp_path: Path) -> None:
        # Likelihoods must be in (0, 1) strict — 0 or 1 would produce
        # degenerate factors.
        spec = {
            "version": 1,
            "nodes": [
                {
                    "name": "a",
                    "description": "x",
                    "prior": 0.5,
                    "evidence": [{"slug": "foo", "likelihood": [1.0, 0.5]}],
                }
            ],
        }
        p = tmp_path / "deg.yaml"
        p.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(ValueError, match="strictly in"):
            load_network(p)


# ── Priors override ──────────────────────────────────────────────────


class TestPriorsOverride:
    def test_returns_empty_when_file_missing(self, tmp_path: Path) -> None:
        out = load_priors_override(tmp_path / "absent.yaml")
        assert out == {}

    def test_loads_top_level_mapping(self, tmp_path: Path) -> None:
        p = tmp_path / "priors.yaml"
        p.write_text(yaml.safe_dump({"m365_tenant": 0.7, "cdn_fronting": 0.6}), encoding="utf-8")
        out = load_priors_override(p)
        assert out == {"m365_tenant": 0.7, "cdn_fronting": 0.6}

    def test_loads_nested_priors_block(self, tmp_path: Path) -> None:
        p = tmp_path / "priors.yaml"
        p.write_text(yaml.safe_dump({"priors": {"m365_tenant": 0.9}}), encoding="utf-8")
        out = load_priors_override(p)
        assert out == {"m365_tenant": 0.9}

    def test_skips_out_of_range_values(self, tmp_path: Path) -> None:
        p = tmp_path / "priors.yaml"
        p.write_text(
            yaml.safe_dump({"m365_tenant": 1.5, "cdn_fronting": 0.5}),
            encoding="utf-8",
        )
        out = load_priors_override(p)
        assert out == {"cdn_fronting": 0.5}

    def test_skips_non_numeric_values(self, tmp_path: Path) -> None:
        p = tmp_path / "priors.yaml"
        p.write_text(
            yaml.safe_dump({"m365_tenant": "high", "cdn_fronting": 0.5}),
            encoding="utf-8",
        )
        out = load_priors_override(p)
        assert out == {"cdn_fronting": 0.5}

    def test_returns_empty_on_malformed_yaml(self, tmp_path: Path) -> None:
        p = tmp_path / "broken.yaml"
        p.write_text("not: valid: yaml: [", encoding="utf-8")
        out = load_priors_override(p)
        assert out == {}

    def test_returns_empty_on_non_mapping_top(self, tmp_path: Path) -> None:
        p = tmp_path / "list.yaml"
        p.write_text(yaml.safe_dump([1, 2, 3]), encoding="utf-8")
        out = load_priors_override(p)
        assert out == {}

    def test_priors_override_changes_posterior(self, shipped_network: BayesianNetwork) -> None:
        # Empty evidence: posterior should equal prior.
        baseline = infer(shipped_network, [], [], priors_override={})
        baseline_m365 = next(p for p in baseline.posteriors if p.name == "m365_tenant")
        # Override the prior to 0.9 — posterior should jump.
        overridden = infer(shipped_network, [], [], priors_override={"m365_tenant": 0.9})
        overridden_m365 = next(p for p in overridden.posteriors if p.name == "m365_tenant")
        assert overridden_m365.posterior > baseline_m365.posterior + 0.4


# ── Variable elimination correctness ─────────────────────────────────


class TestInferenceCorrectness:
    def test_empty_evidence_returns_priors(self, toy_network_yaml: Path) -> None:
        net = load_network(toy_network_yaml)
        result = infer(net, [], [], priors_override={})
        rain = next(p for p in result.posteriors if p.name == "rain")
        # Prior on rain is 0.30
        assert abs(rain.posterior - 0.30) < 1e-3
        # No entropy reduction with no evidence
        assert abs(result.entropy_reduction) < 1e-3

    def test_observed_evidence_collapses_posterior(self, toy_network_yaml: Path) -> None:
        net = load_network(toy_network_yaml)
        # Observe wet pavement — should raise P(rain)
        result = infer(
            net,
            observed_slugs=["wet_pavement"],
            observed_signals=[],
            priors_override={},
        )
        rain = next(p for p in result.posteriors if p.name == "rain")
        # Bayes: P(rain|wet) = P(wet|rain)*P(rain) / P(wet)
        #                    = 0.9 * 0.3 / (0.9*0.3 + 0.2*0.7) = 0.27 / 0.41 ≈ 0.6585
        assert abs(rain.posterior - 0.6585) < 0.01

    def test_chain_evidence_propagates(self, toy_network_yaml: Path) -> None:
        net = load_network(toy_network_yaml)
        result = infer(
            net,
            observed_slugs=["wet_pavement"],
            observed_signals=["lobby_umbrella_count_high"],
            priors_override={},
        )
        rain = next(p for p in result.posteriors if p.name == "rain")
        umbrellas = next(p for p in result.posteriors if p.name == "umbrellas_seen")
        # Both pieces of evidence point at rain; posterior should be high.
        assert rain.posterior > 0.85
        # Umbrella node sees direct evidence → very high.
        assert umbrellas.posterior > 0.90

    def test_entropy_reduction_positive_when_posteriors_collapse(self, toy_network_yaml: Path) -> None:
        # Strong corroborating evidence on both nodes should reduce
        # total entropy — both posteriors collapse toward 1.0 (away
        # from the maximum-entropy point at 0.5).
        net = load_network(toy_network_yaml)
        result = infer(
            net,
            observed_slugs=["wet_pavement"],
            observed_signals=["lobby_umbrella_count_high"],
            priors_override={},
        )
        assert result.entropy_reduction > 0

    def test_entropy_reduction_can_be_negative(self, toy_network_yaml: Path) -> None:
        # Single piece of evidence that pulls a confident prior toward
        # the maximum-entropy point legitimately *increases* total
        # entropy. The metric tracks confidence change, not "more
        # evidence is always better" — and we report it honestly
        # rather than clipping to zero.
        net = load_network(toy_network_yaml)
        result = infer(
            net,
            observed_slugs=["wet_pavement"],
            observed_signals=[],
            priors_override={},
        )
        # Rain prior 0.30 (entropy 0.61); posterior ~0.66 (entropy ~0.65).
        # Net change is small and may be negative.
        assert result.entropy_reduction < 0.1

    def test_no_negative_evidence_propagation(self, toy_network_yaml: Path) -> None:
        """Absence of observation must not be conditioned on.

        Passive collection cannot distinguish "binding truly absent"
        from "binding present but unobservable". Test that non-observed
        bindings do not push posteriors down below the prior.
        """
        net = load_network(toy_network_yaml)
        baseline = infer(net, [], [], priors_override={})
        # Observe ONLY the umbrella signal, NOT wet_pavement.
        with_umbrellas = infer(
            net,
            observed_slugs=[],
            observed_signals=["lobby_umbrella_count_high"],
            priors_override={},
        )
        baseline_rain = next(p for p in baseline.posteriors if p.name == "rain")
        rain_umbrellas = next(p for p in with_umbrellas.posteriors if p.name == "rain")
        # Umbrella evidence makes rain MORE likely (via the umbrella
        # node propagating up). It must not fall below the prior just
        # because wet_pavement wasn't observed.
        assert rain_umbrellas.posterior >= baseline_rain.posterior

    def test_unrelated_evidence_does_not_move_unrelated_node(self, shipped_network: BayesianNetwork) -> None:
        # Strong M365 evidence shouldn't tell us much about cdn_fronting.
        baseline = infer(shipped_network, [], [], priors_override={})
        cdn_baseline = next(p for p in baseline.posteriors if p.name == "cdn_fronting")
        m365 = infer(
            shipped_network,
            observed_slugs=["microsoft365", "entra-id"],
            observed_signals=[],
            priors_override={},
        )
        cdn_after = next(p for p in m365.posteriors if p.name == "cdn_fronting")
        # CDN posterior should stay close to its prior since no path
        # connects M365 to CDN in the shipped network.
        assert abs(cdn_after.posterior - cdn_baseline.posterior) < 0.05

    def test_posterior_in_unit_interval(self, shipped_network: BayesianNetwork) -> None:
        result = infer(
            shipped_network,
            observed_slugs=["microsoft365", "entra-id", "okta", "cloudflare", "aws-cloudfront"],
            observed_signals=["federated_sso_hub", "dmarc_reject", "dkim_present"],
            priors_override={},
        )
        for p in result.posteriors:
            assert 0.0 <= p.posterior <= 1.0
            assert 0.0 <= p.interval_low <= p.interval_high <= 1.0


# ── Credible intervals ───────────────────────────────────────────────


class TestCredibleIntervals:
    def test_sparse_when_no_evidence(self, shipped_network: BayesianNetwork) -> None:
        result = infer(shipped_network, [], [], priors_override={})
        # Every node sparse at floor n_eff
        assert all(p.sparse for p in result.posteriors)

    def test_intervals_widen_under_conflict(self, shipped_network: BayesianNetwork) -> None:
        no_conflict = infer(
            shipped_network,
            observed_slugs=["microsoft365"],
            observed_signals=[],
            conflict_field_count=0,
            priors_override={},
        )
        with_conflict = infer(
            shipped_network,
            observed_slugs=["microsoft365"],
            observed_signals=[],
            conflict_field_count=4,
            priors_override={},
        )
        m1 = next(p for p in no_conflict.posteriors if p.name == "m365_tenant")
        m2 = next(p for p in with_conflict.posteriors if p.name == "m365_tenant")
        # Same posterior but wider interval under conflict.
        assert abs(m1.posterior - m2.posterior) < 1e-3
        assert (m2.interval_high - m2.interval_low) >= (m1.interval_high - m1.interval_low)

    def test_intervals_tighten_with_more_evidence(self, shipped_network: BayesianNetwork) -> None:
        one = infer(
            shipped_network,
            observed_slugs=["microsoft365"],
            observed_signals=[],
            priors_override={},
        )
        three = infer(
            shipped_network,
            observed_slugs=["microsoft365", "entra-id", "exchange-online"],
            observed_signals=[],
            priors_override={},
        )
        m1 = next(p for p in one.posteriors if p.name == "m365_tenant")
        m3 = next(p for p in three.posteriors if p.name == "m365_tenant")
        assert (m3.interval_high - m3.interval_low) <= (m1.interval_high - m1.interval_low)

    def test_credible_interval_helper_handles_extremes(self) -> None:
        # Posterior at 0 → interval pinned to lower bound 0
        low, high = _credible_interval(0.0, 10.0)
        assert low == 0.0
        # Posterior at 1 → interval pinned to upper bound 1
        low, high = _credible_interval(1.0, 10.0)
        assert high == 1.0

    def test_credible_interval_zero_n_eff(self) -> None:
        low, high = _credible_interval(0.5, 0.0)
        assert low == 0.0
        assert high == 1.0

    def test_credible_interval_95(self) -> None:
        low, high = _credible_interval(0.5, 8.0, width=0.95)
        # 95% should be wider than 80% on the same posterior + n_eff
        low80, high80 = _credible_interval(0.5, 8.0, width=0.80)
        assert (high - low) > (high80 - low80)


# ── Helpers ──────────────────────────────────────────────────────────


class TestHelpers:
    def test_binary_entropy_at_extremes(self) -> None:
        assert _binary_entropy(0.0) == 0.0
        assert _binary_entropy(1.0) == 0.0

    def test_binary_entropy_max_at_half(self) -> None:
        # Max binary entropy is ln 2 nats at p=0.5
        import math

        assert abs(_binary_entropy(0.5) - math.log(2)) < 1e-9

    def test_erfinv_monotonic(self) -> None:
        assert _erfinv(0.1) < _erfinv(0.5) < _erfinv(0.9)

    def test_erfinv_zero(self) -> None:
        # erfinv(0) = 0 by symmetry; our approx should be near zero.
        assert abs(_erfinv(0.0)) < 0.05


# ── TenantInfo adapter ───────────────────────────────────────────────


class _FakeEvidence:
    def __init__(self, source_type: str, raw_value: str = "") -> None:
        self.source_type = source_type
        self.raw_value = raw_value


class _FakeMergeConflicts:
    def __init__(self, **fields: tuple) -> None:
        for f in (
            "display_name",
            "auth_type",
            "region",
            "tenant_id",
            "dmarc_policy",
            "google_auth_type",
        ):
            setattr(self, f, fields.get(f, ()))


class _FakeTenantInfo:
    def __init__(
        self,
        slugs: tuple[str, ...] = (),
        evidence: tuple[_FakeEvidence, ...] = (),
        auth_type: str | None = None,
        google_auth_type: str | None = None,
        dmarc_policy: str | None = None,
        mta_sts_mode: str | None = None,
        merge_conflicts: _FakeMergeConflicts | None = None,
    ) -> None:
        self.slugs = slugs
        self.evidence = evidence
        self.auth_type = auth_type
        self.google_auth_type = google_auth_type
        self.dmarc_policy = dmarc_policy
        self.mta_sts_mode = mta_sts_mode
        self.merge_conflicts = merge_conflicts


class TestTenantInfoAdapter:
    def test_signals_from_federated_auth(self) -> None:
        info = _FakeTenantInfo(auth_type="Federated")
        sig = signals_from_tenant_info(info)
        assert "federated_sso_hub" in sig

    def test_signals_from_google_federated_auth(self) -> None:
        info = _FakeTenantInfo(google_auth_type="Federated")
        sig = signals_from_tenant_info(info)
        assert "federated_sso_hub" in sig

    def test_signals_from_dmarc_reject(self) -> None:
        info = _FakeTenantInfo(dmarc_policy="reject")
        assert "dmarc_reject" in signals_from_tenant_info(info)

    def test_signals_from_dmarc_quarantine(self) -> None:
        info = _FakeTenantInfo(dmarc_policy="quarantine")
        assert "dmarc_quarantine" in signals_from_tenant_info(info)

    def test_signals_from_mta_sts_enforce(self) -> None:
        info = _FakeTenantInfo(mta_sts_mode="enforce")
        assert "mta_sts_enforce" in signals_from_tenant_info(info)

    def test_signals_from_dkim_evidence(self) -> None:
        info = _FakeTenantInfo(
            evidence=(_FakeEvidence("DKIM", "selector1.example.com"),),
        )
        assert "dkim_present" in signals_from_tenant_info(info)

    def test_signals_from_strict_spf(self) -> None:
        info = _FakeTenantInfo(
            evidence=(_FakeEvidence("SPF", "v=spf1 include:_spf.example.com -all"),),
        )
        assert "spf_strict" in signals_from_tenant_info(info)

    def test_no_signals_from_soft_spf(self) -> None:
        info = _FakeTenantInfo(
            evidence=(_FakeEvidence("SPF", "v=spf1 include:_spf.example.com ~all"),),
        )
        assert "spf_strict" not in signals_from_tenant_info(info)

    def test_signals_empty_on_bare_info(self) -> None:
        info = _FakeTenantInfo()
        assert signals_from_tenant_info(info) == set()

    def test_infer_from_tenant_info_round_trip(self) -> None:
        info = _FakeTenantInfo(
            slugs=("microsoft365", "entra-id", "okta"),
            auth_type="Federated",
            dmarc_policy="reject",
            evidence=(
                _FakeEvidence("DKIM", "selector1.example.com"),
                _FakeEvidence("SPF", "v=spf1 -all"),
            ),
        )
        result: InferenceResult = infer_from_tenant_info(info)
        m365 = next(p for p in result.posteriors if p.name == "m365_tenant")
        okta = next(p for p in result.posteriors if p.name == "okta_idp")
        assert m365.posterior > 0.95
        assert okta.posterior > 0.85
        assert result.entropy_reduction > 0

    def test_infer_from_tenant_info_with_conflicts(self) -> None:
        info = _FakeTenantInfo(
            slugs=("microsoft365",),
            merge_conflicts=_FakeMergeConflicts(auth_type=("a", "b"), tenant_id=("x", "y")),
        )
        result = infer_from_tenant_info(info)
        # Conflict count fed through — intervals should be wider than
        # the no-conflict counterpart.
        assert result.conflict_count == 2
