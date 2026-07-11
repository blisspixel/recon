"""Tests for the 2.2.0 evidence-semantics diagnostics.

Three additive diagnostics ship together as the 2.2 surface:

1. Per-node ``entropy_reduction_nats`` — the node-level breakdown of the
   result-level information-recovered total (CAL10).
2. ``unit_counterfactuals`` — exact leave-one-unit-out re-inference per
   informative evidence unit, the masked-units primitive applied per unit.
3. ``partition_stability`` — Louvain seed-sweep consensus (mean pairwise
   adjusted Rand index) on the CT co-occurrence graph (CAL11).

The load-bearing pin is the cross-check: every reported counterfactual
must EQUAL the posterior of an actual ``infer(..., masked_units={unit})``
run, tying the diagnostic to the independently-pinned mask semantics
(tests/test_bayesian_masked_units.py) rather than to its own arithmetic.

All inference runs pass ``priors_override={}`` for hermeticity.
"""

from __future__ import annotations

import pytest

from recon_tool.bayesian import BayesianNetwork, infer, load_network
from recon_tool.infra_graph import adjusted_rand_index, build_infrastructure_clusters

_POLICY = "email_security_policy_enforcing"


@pytest.fixture
def network() -> BayesianNetwork:
    return load_network()


def _node(result: object, name: str) -> object:
    return next(p for p in result.posteriors if p.name == name)


class TestUnitCounterfactuals:
    def test_counterfactual_equals_masked_run(self, network: BayesianNetwork) -> None:
        # The defining property: each unit's posterior_without is exactly
        # the posterior of the same inference with that unit masked.
        slugs: set[str] = set()
        signals = {
            "m365_tenant_observed",
            "google_workspace_tenant_observed",
            "federated_sso_hub",
            "okta_idp_observed",
            "email_gateway_mx_observed",
            "dmarc_reject",
            "spf_strict",
            "cdn_cname_observed",
            "aws_endpoint_cname_observed",
        }
        result = infer(network, slugs, signals, priors_override={})
        checked = 0
        for p in result.posteriors:
            for cf in p.unit_counterfactuals:
                masked = infer(network, slugs, signals, priors_override={}, masked_units=(cf.unit,))
                assert cf.posterior_without == _node(masked, p.name).posterior, (p.name, cf.unit)
                assert cf.delta == pytest.approx(p.posterior - cf.posterior_without, abs=2e-4)
                checked += 1
        assert checked >= 9  # every evidence-bound node contributed at least one

    def test_hand_computed_policy_counterfactuals(self, network: BayesianNetwork) -> None:
        # DMARC reject + strict SPF fired. By hand (see
        # test_bayesian_masked_units for the arithmetic):
        #   full 0.9859; without dmarc_policy 0.7525 (delta 0.2334);
        #   without spf_strict 0.9727 (delta 0.0132).
        result = infer(network, set(), {"dmarc_reject", "spf_strict"}, priors_override={})
        cfs = {c.unit: c for c in _node(result, _POLICY).unit_counterfactuals}
        assert cfs["dmarc_policy"].observed == "fired"
        assert cfs["dmarc_policy"].posterior_without == pytest.approx(0.7525, abs=1e-4)
        assert cfs["dmarc_policy"].delta == pytest.approx(0.2334, abs=1e-4)
        assert cfs["spf_strict"].posterior_without == pytest.approx(0.9727, abs=1e-4)
        assert cfs["spf_strict"].delta == pytest.approx(0.0132, abs=1e-4)

    def test_informative_absence_gets_a_negative_delta_counterfactual(self, network: BayesianNetwork) -> None:
        # Only strict SPF fired: the DMARC group is an informative absence
        # on the declarative node. Its counterfactual removes the
        # disconfirming absence, so posterior_without RISES above the
        # posterior and delta is negative.
        result = infer(network, set(), {"spf_strict"}, priors_override={})
        node = _node(result, _POLICY)
        cfs = {c.unit: c for c in node.unit_counterfactuals}
        dmarc = cfs["dmarc_policy"]
        assert dmarc.observed == "absent"
        assert dmarc.posterior_without == pytest.approx(0.7525, abs=1e-4)
        assert dmarc.delta == pytest.approx(0.1517 - 0.7525, abs=1e-4)
        assert dmarc.delta < 0
        # MTA-STS absence is weak but non-neutral, so it must remain visible
        # whenever its factor is applied.
        mta_sts = cfs["mta_sts_enforce"]
        assert mta_sts.observed == "absent"
        assert mta_sts.delta < 0

    def test_dag_flow_survives_the_mask(self, network: BayesianNetwork) -> None:
        # With a federation signal observed, masking the M365 observation must
        # NOT drop m365_tenant to its prior: support still flows backward
        # through the federated_identity CPT. The counterfactual exposes
        # exactly that.
        result = infer(
            network,
            set(),
            {"m365_tenant_observed", "federated_sso_hub"},
            priors_override={},
        )
        cf = _node(result, "m365_tenant").unit_counterfactuals[0]
        assert cf.unit == "m365_tenant_observed"
        assert cf.posterior_without > 0.31  # strictly above the 0.30 prior

    def test_sorted_by_absolute_delta_descending(self, network: BayesianNetwork) -> None:
        result = infer(network, set(), {"dmarc_reject", "spf_strict"}, priors_override={})
        deltas = [abs(c.delta) for c in _node(result, _POLICY).unit_counterfactuals]
        assert deltas == sorted(deltas, reverse=True)

    def test_no_informative_units_means_empty(self, network: BayesianNetwork) -> None:
        result = infer(network, set(), set(), priors_override={})
        for p in result.posteriors:
            if p.name == _POLICY:
                # Every applied non-neutral absence is visible, including the
                # weak MTA-STS non-fire.
                units = {c.unit for c in p.unit_counterfactuals}
                assert units == {"dmarc_policy", "mta_sts_enforce", "spf_strict"}
                assert all(c.observed == "absent" for c in p.unit_counterfactuals)
            else:
                assert p.unit_counterfactuals == ()

    def test_caller_mask_excludes_unit_from_enumeration(self, network: BayesianNetwork) -> None:
        result = infer(
            network,
            set(),
            {"dmarc_reject", "spf_strict"},
            priors_override={},
            masked_units=("dmarc_policy",),
        )
        units = {c.unit for c in _node(result, _POLICY).unit_counterfactuals}
        assert "dmarc_policy" not in units


class TestPerNodeEntropyReduction:
    def test_sums_to_the_result_total(self, network: BayesianNetwork) -> None:
        result = infer(
            network,
            set(),
            {"m365_tenant_observed", "cdn_cname_observed", "dmarc_reject", "federated_sso_hub"},
            priors_override={},
        )
        total = sum(p.entropy_reduction_nats for p in result.posteriors)
        assert total == pytest.approx(result.entropy_reduction, abs=5e-3)

    def test_hand_computed_m365_share(self, network: BayesianNetwork) -> None:
        # With the role-scoped M365 observation fired the posterior is
        # 0.3*0.95 / (0.3*0.95 + 0.7*0.03) = 0.93137 -> 0.9314.
        # H(0.30) = 0.6109 nats, H(0.9314) = 0.2500; reduction = 0.3608.
        result = infer(network, set(), {"m365_tenant_observed"}, priors_override={})
        node = _node(result, "m365_tenant")
        assert node.posterior == pytest.approx(0.9314, abs=1e-4)
        assert node.entropy_reduction_nats == pytest.approx(0.3608, abs=2e-3)

    def test_zero_when_no_evidence_moves_a_root_node(self, network: BayesianNetwork) -> None:
        result = infer(network, set(), set(), priors_override={})
        assert _node(result, "cdn_fronting").entropy_reduction_nats == pytest.approx(0.0, abs=1e-9)


def _entry(names: list[str], issuer: str = "Test CA") -> dict:
    return {
        "dns_names": names,
        "issuer_name": issuer,
        "not_before": "2025-01-01T00:00:00",
        "not_after": "2026-01-01T00:00:00",
    }


class TestAdjustedRandIndex:
    def test_identical_partitions_are_one(self) -> None:
        p = [{"a", "b"}, {"c", "d"}]
        assert adjusted_rand_index(p, [set(s) for s in p]) == pytest.approx(1.0)

    def test_label_permutation_is_still_one(self) -> None:
        assert adjusted_rand_index([{"a", "b"}, {"c"}], [{"c"}, {"a", "b"}]) == pytest.approx(1.0)

    def test_degenerate_identical_trivial_partitions_are_one(self) -> None:
        # All-singletons vs all-singletons: expected == maximum; identical
        # partitions read as stable, by convention.
        p1 = [{"a"}, {"b"}, {"c"}]
        assert adjusted_rand_index(p1, [{"a"}, {"b"}, {"c"}]) == pytest.approx(1.0)

    def test_known_disagreement_value(self) -> None:
        # Hubert-Arabie worked example shape: one element moved between
        # blocks. ARI must be strictly between 0 and 1.
        p1 = [{"a", "b", "c"}, {"d", "e", "f"}]
        p2 = [{"a", "b"}, {"c", "d", "e", "f"}]
        score = adjusted_rand_index(p1, p2)
        assert 0.0 < score < 1.0

    def test_independent_partitions_score_near_zero(self) -> None:
        # Crossing partitions of a 2x2 grid: agreement is at chance level.
        p1 = [{"a", "b"}, {"c", "d"}]
        p2 = [{"a", "c"}, {"b", "d"}]
        assert adjusted_rand_index(p1, p2) <= 0.0


class TestPartitionStability:
    def test_clean_two_clique_graph_is_fully_stable(self) -> None:
        # Two well-separated cliques: every seed must land on the same
        # partition, so the consensus is exactly 1.0.
        entries = [
            _entry(["a.example.com", "b.example.com", "c.example.com"]),
            _entry(["a.example.com", "b.example.com", "c.example.com"]),
            _entry(["x.example.com", "y.example.com", "z.example.com"]),
            _entry(["x.example.com", "y.example.com", "z.example.com"]),
        ]
        report = build_infrastructure_clusters(entries)
        assert report.algorithm == "louvain"
        assert report.partition_stability == pytest.approx(1.0)
        assert report.stability_runs == 8

    def test_skipped_path_has_no_stability(self) -> None:
        report = build_infrastructure_clusters([])
        assert report.partition_stability is None
        assert report.stability_runs == 0

    def test_reported_clusters_stay_seed_deterministic(self) -> None:
        # The sweep must not change the reported partition: two identical
        # calls still produce identical cluster output.
        entries = [
            _entry(["a.example.com", "b.example.com", "c.example.com"]),
            _entry(["x.example.com", "y.example.com", "z.example.com"]),
            _entry(["a.example.com", "x.example.com"]),
        ]
        r1 = build_infrastructure_clusters(entries)
        r2 = build_infrastructure_clusters(entries)
        assert r1.clusters == r2.clusters
        assert r1.partition_stability == r2.partition_stability
