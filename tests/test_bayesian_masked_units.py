"""Tests for the ``masked_units`` leave-one-unit-out inference primitive.

``infer(..., masked_units=...)`` treats an evidence unit (a correlation
group, or an ungrouped binding) as *structurally unobserved*: no firing
contribution, no informative-absence contribution, no n_eff contribution.
This is the primitive under the held-out reference calibration (mask the
unit that defines the label so predictor and label are disjoint) and the
evidence-semantics counterfactual diagnostics.

The semantics are pinned three ways:

1. Hand-computed posteriors on the shipped policy node, which is isolated
   in the DAG (no parents, no children), so its posterior is an odds
   product checkable on paper.
2. An equivalence property: masking a unit must give exactly the result of
   running the unmasked engine on a network with that unit's bindings (and
   its ``group_absence`` entry) deleted. This is the definition of
   "structurally unobserved" — the unit does not exist for this query.
3. The hideable shortcut: on a hideable node, masking a unit must equal
   simply not observing its bindings (the MNAR absence rule already
   contributes LR=1), while on a declarative node the two must differ,
   because there absence is informative and unobserved is not.

All runs pass ``priors_override={}`` so a developer's local
``~/.recon/priors.yaml`` cannot leak into the assertions.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from recon_tool.bayesian import (
    BayesianNetwork,
    infer,
    infer_from_tenant_info,
    load_network,
)

_POLICY = "email_security_policy_enforcing"


@pytest.fixture
def network() -> BayesianNetwork:
    return load_network()


def _posterior(result: object, node: str) -> float:
    return next(p.posterior for p in result.posteriors if p.name == node)


def _node_posterior(result: object, node: str) -> object:
    return next(p for p in result.posteriors if p.name == node)


def _without_units(network: BayesianNetwork, units: set[str]) -> BayesianNetwork:
    """A copy of the network with the named evidence units deleted.

    Deleting a unit removes its bindings (every binding whose group, or
    name when ungrouped, is in ``units``) and its ``group_absence`` entry.
    Running the unmasked engine on this network is the reference semantics
    that ``masked_units`` must reproduce exactly.
    """
    new_nodes = []
    for node in network.nodes:
        evidence = tuple(ev for ev in node.evidence if (ev.group or ev.name) not in units)
        group_absence = tuple(entry for entry in node.group_absence if entry[0] not in units)
        new_nodes.append(replace(node, evidence=evidence, group_absence=group_absence))
    return BayesianNetwork(version=network.version, nodes=tuple(new_nodes))


class TestDefaultUnchanged:
    def test_empty_mask_is_identity(self, network: BayesianNetwork) -> None:
        slugs = {"microsoft365", "cloudflare", "okta"}
        signals = {"dmarc_reject", "spf_strict", "federated_sso_hub"}
        base = infer(network, slugs, signals, priors_override={})
        masked = infer(network, slugs, signals, priors_override={}, masked_units=())
        assert base == masked

    def test_unknown_unit_is_noop(self, network: BayesianNetwork) -> None:
        slugs = {"microsoft365"}
        signals = {"dmarc_reject"}
        base = infer(network, slugs, signals, priors_override={})
        masked = infer(network, slugs, signals, priors_override={}, masked_units=("no_such_unit",))
        assert base == masked


class TestHideableMasking:
    def test_masking_group_equals_not_observing_it(self, network: BayesianNetwork) -> None:
        # On a hideable node the MNAR rule already gives a non-firing binding
        # LR=1, so masking the m365_indicators group must be exactly the same
        # as never observing the three M365 slugs.
        with_mask = infer(
            network,
            {"microsoft365", "entra-id", "cloudflare"},
            set(),
            priors_override={},
            masked_units=("m365_indicators",),
        )
        without_slugs = infer(network, {"cloudflare"}, set(), priors_override={})
        assert with_mask == without_slugs

    def test_masking_ungrouped_binding_equals_not_observing_it(self, network: BayesianNetwork) -> None:
        with_mask = infer(
            network,
            {"okta"},
            {"federated_sso_hub"},
            priors_override={},
            masked_units=("okta",),
        )
        without_slug = infer(network, set(), {"federated_sso_hub"}, priors_override={})
        assert with_mask == without_slug

    def test_masked_fired_binding_leaves_evidence_used(self, network: BayesianNetwork) -> None:
        result = infer(
            network,
            {"microsoft365"},
            set(),
            priors_override={},
            masked_units=("m365_indicators",),
        )
        node = _node_posterior(result, "m365_tenant")
        assert node.evidence_used == ()
        assert node.evidence_ranked == ()


class TestDeclarativeMasking:
    """The policy node is the seam: there, absent and unobserved differ."""

    def test_hand_computed_full_masked_and_unfired(self, network: BayesianNetwork) -> None:
        # Evidence: DMARC reject fired, strict SPF fired, MTA-STS not fired.
        # Policy node is isolated, prior 0.62. By hand:
        #   full:    0.62*0.92*0.53*0.94 / (... + 0.38*0.04*0.27*0.99) = 0.9859
        #   masked:  0.62*0.53*0.94      / (... + 0.38*0.27*0.99)      = 0.7525
        #   unfired: 0.62*0.05*0.53*0.94 / (... + 0.38*0.85*0.27*0.99) = 0.1517
        # (likelihoods from bayesian_network.yaml; unfired applies the
        # dmarc_policy group_absence pair [0.05, 0.85]).
        signals = {"dmarc_reject", "spf_strict"}
        full = infer(network, set(), signals, priors_override={})
        masked = infer(network, set(), signals, priors_override={}, masked_units=("dmarc_policy",))
        unfired = infer(network, set(), {"spf_strict"}, priors_override={})

        assert _posterior(full, _POLICY) == pytest.approx(0.9859, abs=1e-4)
        assert _posterior(masked, _POLICY) == pytest.approx(0.7525, abs=1e-4)
        assert _posterior(unfired, _POLICY) == pytest.approx(0.1517, abs=1e-4)

    def test_masked_sits_between_unfired_and_fired(self, network: BayesianNetwork) -> None:
        # Unobserved must be weaker than observed-present and stronger than
        # observed-absent: hiding the strong DMARC group from the engine's
        # view must not let the informative-absence rule punish the domain
        # for a record it actually published.
        signals = {"dmarc_reject", "spf_strict"}
        p_full = _posterior(infer(network, set(), signals, priors_override={}), _POLICY)
        p_masked = _posterior(
            infer(network, set(), signals, priors_override={}, masked_units=("dmarc_policy",)),
            _POLICY,
        )
        p_unfired = _posterior(infer(network, set(), {"spf_strict"}, priors_override={}), _POLICY)
        assert p_unfired < p_masked < p_full

    def test_masking_differs_from_not_firing_on_declarative(self, network: BayesianNetwork) -> None:
        # The whole point of the primitive: on a declarative node, masking a
        # unit is NOT the same as the unit not firing.
        signals = {"spf_strict"}
        masked = infer(network, set(), signals, priors_override={}, masked_units=("dmarc_policy",))
        unfired = infer(network, set(), signals, priors_override={})
        assert _posterior(masked, _POLICY) != _posterior(unfired, _POLICY)

    def test_masked_unit_does_not_count_toward_n_eff(self, network: BayesianNetwork) -> None:
        # Full: dmarc unit fired (1) + spf fired (1) = 2 -> n_eff 6.0.
        # Masked dmarc: spf fired (1) only -> n_eff 5.0 (the masked unit is
        # neither fired evidence nor an informative absence).
        # Unfired dmarc: spf fired (1) + dmarc informative absence (1) -> 6.0.
        signals = {"dmarc_reject", "spf_strict"}
        full = _node_posterior(infer(network, set(), signals, priors_override={}), _POLICY)
        masked = _node_posterior(
            infer(network, set(), signals, priors_override={}, masked_units=("dmarc_policy",)),
            _POLICY,
        )
        unfired = _node_posterior(infer(network, set(), {"spf_strict"}, priors_override={}), _POLICY)
        assert full.n_eff == pytest.approx(6.0)
        assert masked.n_eff == pytest.approx(5.0)
        assert unfired.n_eff == pytest.approx(6.0)


class TestNetworkDeletionEquivalence:
    """Masking == running the unmasked engine on a unit-deleted network."""

    @pytest.mark.parametrize(
        ("units", "slugs", "signals"),
        [
            ({"dmarc_policy"}, set(), {"dmarc_reject", "spf_strict"}),
            ({"dmarc_policy"}, set(), {"spf_strict"}),
            ({"spf_strict"}, set(), {"dmarc_reject", "spf_strict"}),
            ({"m365_indicators"}, {"microsoft365", "entra-id", "okta"}, {"federated_sso_hub"}),
            ({"okta"}, {"okta", "cloudflare"}, set()),
            (
                {"dmarc_policy", "m365_indicators"},
                {"microsoft365", "aws"},
                {"dmarc_quarantine", "mta_sts_enforce"},
            ),
        ],
    )
    def test_masked_equals_deleted(
        self,
        network: BayesianNetwork,
        units: set[str],
        slugs: set[str],
        signals: set[str],
    ) -> None:
        masked = infer(network, slugs, signals, priors_override={}, masked_units=units)
        deleted = infer(_without_units(network, units), slugs, signals, priors_override={})
        assert masked == deleted


class TestTenantInfoPassthrough:
    def test_infer_from_tenant_info_threads_mask(self, network: BayesianNetwork) -> None:
        info = SimpleNamespace(
            slugs=("microsoft365",),
            auth_type=None,
            google_auth_type=None,
            dmarc_policy="reject",
            mta_sts_mode=None,
            evidence=(),
            merge_conflicts=None,
        )
        full = infer_from_tenant_info(info, network=network, priors_override={})
        masked = infer_from_tenant_info(
            info,
            network=network,
            priors_override={},
            masked_units=("dmarc_policy",),
        )
        assert _posterior(full, _POLICY) != _posterior(masked, _POLICY)
        # The mask must leave every other node untouched.
        for name in ("m365_tenant", "cdn_fronting", "aws_hosting"):
            assert _posterior(full, name) == _posterior(masked, name)
