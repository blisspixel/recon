"""Hand-computed unit anchors for the inference-core math helpers.

The 2026-06 mutation baseline (validation/mutation-gate.md) showed the
surviving mutants clustering in helpers the behavior suites exercise
only indirectly: the credible-interval arithmetic and its inverse-erf
approximation, the CAL14 declarative evidence counting, the evidence
influence ranking, the correlation-group reduction, the priors-override
loader, and the TenantInfo adapters. Each test here pins one of those
helpers to values computed by hand (or to a documented approximation
band), so a subtle arithmetic change fails a named assertion instead of
slipping through. This file runs first in the mutation kill-set
(mutation.toml); keep it fast and dependency-light.
"""

from __future__ import annotations

import math
from types import SimpleNamespace

import pytest

from recon_tool.bayesian import (
    _CONFLICT_N_EFF_PENALTY,
    _conflict_provenance,
    _contributing_evidence,
    _credible_interval,
    _declarative_evidence_count,
    _erfinv,
    _Evidence,
    _factor_is_probabilities,
    _factor_is_strictly_positive,
    _interval_is_ordered,
    _marginal_in_unit_range,
    _Node,
    _rank_evidence,
    infer,
    infer_from_tenant_info,
    load_network,
    load_priors_override,
    signals_from_tenant_info,
)


def _ev(name: str, lp: float, la: float, group: str | None = None, kind: str = "slug") -> _Evidence:
    return _Evidence(kind=kind, name=name, likelihood_present=lp, likelihood_absent=la, group=group)


# ── _credible_interval ─────────────────────────────────────────────────


class TestCredibleInterval:
    def test_default_width_hand_computed(self) -> None:
        # p=0.5, n_eff=4: se = sqrt(0.25/4) = 0.25; z = 1.2816 for the
        # 80% branch, so the half-width is 0.3204 by hand.
        low, high = _credible_interval(0.5, 4.0, 0.80)
        assert abs(low - (0.5 - 1.2816 * 0.25)) < 1e-9
        assert abs(high - (0.5 + 1.2816 * 0.25)) < 1e-9

    def test_95_branch_hand_computed(self) -> None:
        # Same se; z = 1.96 exactly on the 0.95 branch: half-width 0.49.
        low, high = _credible_interval(0.5, 4.0, 0.95)
        assert abs(low - 0.01) < 1e-9
        assert abs(high - 0.99) < 1e-9

    def test_width_narrows_with_n_eff(self) -> None:
        # n_eff=16 halves the standard error versus n_eff=4.
        low4, high4 = _credible_interval(0.5, 4.0, 0.80)
        low16, high16 = _credible_interval(0.5, 16.0, 0.80)
        assert abs((high16 - low16) - (high4 - low4) / 2) < 1e-9

    def test_general_width_uses_erfinv(self) -> None:
        # width=0.5 takes the general branch: z = sqrt(2) * erfinv(0.5).
        # True erfinv(0.5) = 0.4769363; the Winitzki approximation is
        # within ~5e-4 here, so the half-width is 0.16864 +/- 5e-4.
        low, high = _credible_interval(0.5, 4.0, 0.5)
        assert abs((high - low) / 2 - 0.16864) < 5e-4

    def test_clamps_to_unit_interval(self) -> None:
        low, high = _credible_interval(0.02, 4.0, 0.80)
        assert low == 0.0
        assert abs(high - (0.02 + 1.2816 * math.sqrt(0.02 * 0.98 / 4.0))) < 1e-9
        assert _credible_interval(0.98, 4.0, 0.80)[1] == 1.0

    def test_nonpositive_n_eff_is_vacuous(self) -> None:
        assert _credible_interval(0.7, 0.0) == (0.0, 1.0)
        assert _credible_interval(0.7, -1.0) == (0.0, 1.0)


class TestErfinv:
    def test_anchor_values(self) -> None:
        # True values: erfinv(0.8) = 0.9061938, erfinv(0.5) = 0.4769363.
        # Winitzki's approximation is documented to ~5e-3; measured error
        # at these anchors is ~1e-4, so 2e-3 leaves slack without letting
        # a sign or operator mutation through.
        assert abs(_erfinv(0.8) - 0.9061938) < 2e-3
        assert abs(_erfinv(0.5) - 0.4769363) < 2e-3

    def test_odd_symmetry_and_zero(self) -> None:
        assert _erfinv(-0.8) == -_erfinv(0.8)
        assert _erfinv(0.0) == 0.0

    def test_monotonic(self) -> None:
        assert 0.0 < _erfinv(0.2) < _erfinv(0.5) < _erfinv(0.9)


# ── CAL14 declarative evidence counting ────────────────────────────────


class TestDeclarativeEvidenceCount:
    def _node(self, evidence: tuple[_Evidence, ...], group_absence: tuple[tuple[str, float, float], ...]) -> _Node:
        return _Node(
            name="n",
            description="d",
            parents=(),
            prior=0.5,
            cpt={},
            evidence=evidence,
            missingness="declarative",
            group_absence=group_absence,
        )

    def test_counts_fired_strong_absent_and_informative_groups(self) -> None:
        # By hand: fired A contributes 1. Absent B has
        # |log(0.1/0.7)| = 1.95 > 0.2 (counts). Absent C has
        # |log(0.5/0.45)| = 0.105 < 0.2 (does not). The fully-absent
        # group g has |log(0.2/0.8)| = 1.39 > 0.2 (counts once for two
        # members). The fully-absent group h has |log(0.5/0.55)| = 0.095
        # (does not). Total: 3.
        node = self._node(
            evidence=(
                _ev("a", 0.9, 0.1),
                _ev("b", 0.9, 0.3),
                _ev("c", 0.5, 0.55),
                _ev("g1", 0.8, 0.2, group="g"),
                _ev("g2", 0.7, 0.2, group="g"),
                _ev("h1", 0.6, 0.3, group="h"),
            ),
            group_absence=(("g", 0.2, 0.8), ("h", 0.5, 0.55)),
        )
        fired = [node.evidence[0]]
        assert _declarative_evidence_count(node, fired) == 3

    def test_fired_group_not_double_counted_as_absent(self) -> None:
        node = self._node(
            evidence=(_ev("g1", 0.8, 0.2, group="g"), _ev("g2", 0.7, 0.2, group="g")),
            group_absence=(("g", 0.2, 0.8),),
        )
        fired = [node.evidence[0]]
        assert _declarative_evidence_count(node, fired) == 1

    def test_absent_group_without_pair_does_not_count(self) -> None:
        node = self._node(
            evidence=(_ev("g1", 0.8, 0.2, group="g"),),
            group_absence=(),
        )
        assert _declarative_evidence_count(node, []) == 0


# ── Correlation-group reduction ────────────────────────────────────────


class TestContributingEvidence:
    def test_group_reduces_to_strongest_member(self) -> None:
        # |LLR|: m1 = log(9) = 2.20, m2 = log(2) = 0.69; m1 wins.
        m1 = _ev("m1", 0.9, 0.1, group="g")
        m2 = _ev("m2", 0.6, 0.3, group="g")
        u1 = _ev("u1", 0.7, 0.4)
        out = _contributing_evidence([m2, m1, u1])
        assert {e.name for e in out} == {"m1", "u1"}

    def test_ungrouped_pass_through(self) -> None:
        evs = [_ev("a", 0.9, 0.1), _ev("b", 0.6, 0.3)]
        assert _contributing_evidence(evs) == evs


# ── Evidence influence ranking ─────────────────────────────────────────


class TestRankEvidence:
    def test_hand_computed_llr_and_shares(self) -> None:
        # a: log(0.9/0.1) = log 9 = 2.1972; b: log(0.6/0.3) = log 2 =
        # 0.6931. abs_sum = 2.8904, so a carries 76.02% and b 23.98%.
        ranked = _rank_evidence([_ev("b", 0.6, 0.3), _ev("a", 0.9, 0.1)])
        assert [c.name for c in ranked] == ["a", "b"]
        assert ranked[0].llr == round(math.log(9), 4)
        assert ranked[1].llr == round(math.log(2), 4)
        assert ranked[0].influence_pct == 76.02
        assert ranked[1].influence_pct == 23.98

    def test_tie_breaks_on_kind_then_name(self) -> None:
        a = _ev("zzz", 0.9, 0.1, kind="signal")
        b = _ev("aaa", 0.9, 0.1, kind="slug")
        ranked = _rank_evidence([b, a])
        assert [(c.kind, c.name) for c in ranked] == [("signal", "zzz"), ("slug", "aaa")]

    def test_empty_is_empty(self) -> None:
        assert _rank_evidence([]) == ()


# ── Priors override loader ─────────────────────────────────────────────


class TestLoadPriorsOverride:
    def test_missing_file_is_empty(self, tmp_path) -> None:
        assert load_priors_override(tmp_path / "absent.yaml") == {}

    def test_priors_mapping_with_invalid_values_filtered(self, tmp_path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text("priors:\n  m365_tenant: 0.5\n  out_of_range: 1.5\n  not_a_number: x\n", encoding="utf-8")
        assert load_priors_override(f) == {"m365_tenant": 0.5}

    def test_top_level_mapping_form(self, tmp_path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text("aws_hosting: 0.25\n", encoding="utf-8")
        assert load_priors_override(f) == {"aws_hosting": 0.25}

    def test_non_mapping_yaml_is_empty(self, tmp_path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text("- 1\n- 2\n", encoding="utf-8")
        assert load_priors_override(f) == {}

    def test_malformed_yaml_is_empty(self, tmp_path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text("{unclosed", encoding="utf-8")
        assert load_priors_override(f) == {}


# ── Network lookup ─────────────────────────────────────────────────────


class TestNetworkGet:
    def test_get_known_node(self) -> None:
        net = load_network()
        assert net.get("m365_tenant").name == "m365_tenant"

    def test_get_unknown_node_raises(self) -> None:
        net = load_network()
        with pytest.raises(KeyError):
            net.get("no_such_node")


# ── n_eff arithmetic, pinned exactly ───────────────────────────────────


class TestNEffExactValues:
    # n_eff is an exposed NodePosterior field, so the arithmetic
    # (_MIN_N_EFF + count * _EVIDENCE_N_EFF_CONTRIB - conflicts *
    # _CONFLICT_N_EFF_PENALTY, floored at _MIN_N_EFF) can be pinned to
    # exact values. The values depend on the shipped network's bindings;
    # a deliberate network change that moves them shows up here next to
    # the drift-gate baseline it also has to update.

    def test_two_ungrouped_bindings(self) -> None:
        net = load_network()
        result = infer(net, ["cloudflare", "akamai"], [], priors_override={})
        post = {p.name: p for p in result.posteriors}
        assert post["cdn_fronting"].n_eff == 6.0

    def test_conflict_subtracts_exactly_its_penalty(self) -> None:
        net = load_network()
        result = infer(net, ["cloudflare", "akamai"], [], conflict_field_count=1, priors_override={})
        post = {p.name: p for p in result.posteriors}
        assert post["cdn_fronting"].n_eff == 6.0 - _CONFLICT_N_EFF_PENALTY

    def test_floor_holds_for_evidence_free_node_under_conflict(self) -> None:
        net = load_network()
        result = infer(net, [], [], conflict_field_count=1, priors_override={})
        post = {p.name: p for p in result.posteriors}
        assert post["cdn_fronting"].n_eff == 4.0

    def test_declarative_informative_absences_count(self) -> None:
        # With nothing fired, the declarative policy node still earns
        # n_eff from its informative absences: the absent dmarc_policy
        # group (|LLR| 2.8) and the absent spf_strict complement (|LLR|
        # 0.44) count; the near-neutral mta_sts complement does not.
        net = load_network()
        result = infer(net, [], [], priors_override={})
        post = {p.name: p for p in result.posteriors}
        assert post["email_security_policy_enforcing"].n_eff == 6.0


# ── Contract predicates ────────────────────────────────────────────────


class TestContractPredicates:
    # The deal contracts only fire on violation, so on correct code a
    # weakened predicate is invisible to the behavior suites. Pinning
    # the predicates directly keeps the contracts meaning what they say.

    def test_factor_is_probabilities_rejects_out_of_range(self) -> None:
        assert _factor_is_probabilities({frozenset((("n", "present"),)): 0.5})
        assert not _factor_is_probabilities({frozenset((("n", "present"),)): -0.5})
        assert not _factor_is_probabilities({frozenset((("n", "present"),)): 1.5})

    def test_factor_is_strictly_positive_rejects_zero(self) -> None:
        assert _factor_is_strictly_positive(None)
        assert _factor_is_strictly_positive({frozenset((("n", "present"),)): 1e-9})
        assert not _factor_is_strictly_positive({frozenset((("n", "present"),)): 0.0})

    def test_marginal_in_unit_range(self) -> None:
        assert _marginal_in_unit_range({"present": 0.4, "absent": 0.6})
        assert not _marginal_in_unit_range({"present": -0.1})
        assert not _marginal_in_unit_range({"present": 1.1})

    def test_interval_is_ordered(self) -> None:
        assert _interval_is_ordered((0.2, 0.8))
        assert not _interval_is_ordered((0.8, 0.2))
        assert not _interval_is_ordered((-0.1, 0.5))
        assert not _interval_is_ordered((0.5, 1.1))


# ── Output rounding granularity ────────────────────────────────────────


class TestOutputRounding:
    def test_posteriors_and_intervals_round_to_four_decimals(self) -> None:
        # ``infer`` rounds posterior and interval bounds to exactly four
        # decimals. Both directions are pinned: every value must already
        # be at 4-decimal granularity (a 5-decimal emission fails the
        # equality), and at least one value across the nodes must carry a
        # nonzero fourth decimal (a 3-decimal emission fails the any()).
        net = load_network()
        result = infer(net, ["microsoft365", "okta"], ["dmarc_reject", "spf_strict"], priors_override={})
        values = [v for p in result.posteriors for v in (p.posterior, p.interval_low, p.interval_high)]
        assert all(v == round(v, 4) for v in values)
        assert any(round(v, 3) != v for v in values)


# ── TenantInfo adapters ────────────────────────────────────────────────


class TestSignalsFromTenantInfo:
    def test_field_derived_signals(self) -> None:
        info = SimpleNamespace(
            auth_type="Federated",
            dmarc_policy="reject",
            mta_sts_mode="enforce",
            evidence=(
                SimpleNamespace(source_type="DKIM", raw_value="v=DKIM1"),
                SimpleNamespace(source_type="SPF", raw_value="v=spf1 include:x.example -all"),
            ),
        )
        assert signals_from_tenant_info(info) == {
            "federated_sso_hub",
            "dmarc_reject",
            "mta_sts_enforce",
            "dkim_present",
            "spf_strict",
        }

    def test_quarantine_and_google_federation(self) -> None:
        info = SimpleNamespace(google_auth_type="Federated", dmarc_policy="quarantine")
        assert signals_from_tenant_info(info) == {"federated_sso_hub", "dmarc_quarantine"}

    def test_spf_strict_requires_standalone_token(self) -> None:
        info = SimpleNamespace(
            evidence=(SimpleNamespace(source_type="SPF", raw_value="v=spf1 include:foo-all.example ~all"),)
        )
        assert signals_from_tenant_info(info) == set()

    def test_spf_value_matching_is_case_insensitive(self) -> None:
        info = SimpleNamespace(evidence=(SimpleNamespace(source_type="SPF", raw_value="V=SPF1 -ALL"),))
        assert signals_from_tenant_info(info) == {"spf_strict"}

    def test_empty_info_yields_nothing(self) -> None:
        assert signals_from_tenant_info(SimpleNamespace()) == set()


class TestConflictProvenance:
    def test_no_conflicts(self) -> None:
        assert _conflict_provenance(SimpleNamespace()) == ()
        assert _conflict_provenance(SimpleNamespace(merge_conflicts=None)) == ()

    def test_dedupes_sources_and_carries_penalty(self) -> None:
        conflicts = SimpleNamespace(
            display_name=(),
            auth_type=(
                SimpleNamespace(source="dns"),
                SimpleNamespace(source="oidc"),
                SimpleNamespace(source="dns"),
            ),
            region=(),
            tenant_id=(),
            dmarc_policy=(),
            google_auth_type=(),
        )
        out = _conflict_provenance(SimpleNamespace(merge_conflicts=conflicts))
        assert len(out) == 1
        assert out[0].field == "auth_type"
        assert out[0].sources == ("dns", "oidc")
        assert out[0].magnitude == _CONFLICT_N_EFF_PENALTY


class TestInferFromTenantInfo:
    def test_slug_raises_posterior_and_counts_conflicts(self) -> None:
        net = load_network()
        empty = infer_from_tenant_info(SimpleNamespace(), network=net, priors_override={})
        base = {p.name: p for p in empty.posteriors}
        info = SimpleNamespace(slugs=("microsoft365",))
        result = infer_from_tenant_info(info, network=net, priors_override={})
        post = {p.name: p for p in result.posteriors}
        assert post["m365_tenant"].posterior > base["m365_tenant"].posterior
        assert result.conflict_count == 0

        conflicted = SimpleNamespace(
            slugs=("microsoft365",),
            merge_conflicts=SimpleNamespace(
                display_name=(),
                auth_type=(SimpleNamespace(source="dns"), SimpleNamespace(source="oidc")),
                region=(),
                tenant_id=(),
                dmarc_policy=(),
                google_auth_type=(),
            ),
        )
        result2 = infer_from_tenant_info(conflicted, network=net, priors_override={})
        assert result2.conflict_count == 1
        post2 = {p.name: p for p in result2.posteriors}
        # The conflict dampens n_eff, so the interval widens relative to
        # the unconflicted run of the same evidence.
        width = post["m365_tenant"].interval_high - post["m365_tenant"].interval_low
        width2 = post2["m365_tenant"].interval_high - post2["m365_tenant"].interval_low
        assert width2 > width
