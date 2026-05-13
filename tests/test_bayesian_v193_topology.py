"""Regression tests for the v1.9.3 topology surgery.

The v1.9.3 bridge milestone (docs/roadmap.md §v1.9.3) replaced the
v1.9.0 ``email_security_strong`` node with two separate nodes that
make different claims:

  * ``email_security_modern_provider`` — provider-presence claim,
    parameterized on M365 / GWS / gateway parents, no evidence
    bindings (pure CPT propagation).
  * ``email_security_policy_enforcing`` — policy-enforcement claim,
    root node with a base-rate prior and policy-signal evidence
    bindings (DMARC / DKIM / SPF / MTA-STS).

The same milestone expanded ``federated_identity`` to take both
``m365_tenant`` and ``google_workspace_tenant`` as parents, fixing
the v1.9.0 under-attribution of federation on GWS-only tenants.

These tests pin the topology so future schema or engine changes
cannot silently revert the surgery.
"""

from __future__ import annotations

import pytest

from recon_tool.bayesian import infer, load_network


@pytest.fixture(scope="module")
def network():
    return load_network()


# ── Network shape ────────────────────────────────────────────────────


def test_email_security_strong_is_gone(network):
    """The v1.9.0 node must not be re-added by accident."""
    names = {n.name for n in network.nodes}
    assert "email_security_strong" not in names


def test_two_new_email_security_nodes_present(network):
    names = {n.name for n in network.nodes}
    assert "email_security_modern_provider" in names
    assert "email_security_policy_enforcing" in names


def test_modern_provider_has_three_parents_and_no_evidence(network):
    node = next(n for n in network.nodes if n.name == "email_security_modern_provider")
    assert set(node.parents) == {"m365_tenant", "google_workspace_tenant", "email_gateway_present"}
    assert len(node.evidence) == 0, (
        "modern_provider must remain pure CPT propagation; provider presence is fully captured by parent slugs"
    )


def test_policy_enforcing_is_root_with_policy_signals(network):
    node = next(n for n in network.nodes if n.name == "email_security_policy_enforcing")
    assert node.parents == (), "policy enforcement must be provider-independent"
    bindings = {ev.name for ev in node.evidence}
    # The four policy-enforcement signals after v1.9.6 removed
    # ``dkim_present`` (DKIM publication is a deliverability hygiene
    # signal, not a policy-enforcement signal — see the YAML concept
    # comment on this node and CONTRIBUTING.md "CPT-change discipline
    # → Worked example 2").
    assert bindings == {
        "dmarc_reject",
        "dmarc_quarantine",
        "mta_sts_enforce",
        "spf_strict",
    }


def test_federated_identity_has_both_provider_parents(network):
    node = next(n for n in network.nodes if n.name == "federated_identity")
    assert set(node.parents) == {"m365_tenant", "google_workspace_tenant"}


# ── Behavioural: nodes respond to the right evidence ────────────────


def test_modern_provider_responds_to_provider_evidence(network):
    """The modern_provider posterior moves up when M365 / GWS / gateway
    slugs fire, and stays flat when only policy signals fire."""
    no_evidence = _posterior(network, [], [], "email_security_modern_provider")
    with_m365 = _posterior(network, ["microsoft365"], [], "email_security_modern_provider")
    with_gws = _posterior(network, ["google-workspace"], [], "email_security_modern_provider")
    with_gateway = _posterior(network, ["proofpoint"], [], "email_security_modern_provider")

    # Each parent slug should lift modern_provider materially.
    assert with_m365 > no_evidence + 0.10
    assert with_gws > no_evidence + 0.10
    assert with_gateway > no_evidence + 0.05


def test_modern_provider_does_not_move_on_policy_signals(network):
    """Independence: policy signals must not influence modern_provider."""
    no_evidence = _posterior(network, [], [], "email_security_modern_provider")
    with_dmarc = _posterior(network, [], ["dmarc_reject"], "email_security_modern_provider")
    with_dkim = _posterior(network, [], ["dkim_present"], "email_security_modern_provider")
    with_spf = _posterior(network, [], ["spf_strict"], "email_security_modern_provider")

    # Pure structural propagation; no path from policy signals to this node.
    assert abs(with_dmarc - no_evidence) < 0.005
    assert abs(with_dkim - no_evidence) < 0.005
    assert abs(with_spf - no_evidence) < 0.005


def test_policy_enforcing_responds_to_policy_signals(network):
    """The policy_enforcing posterior moves up when DMARC / SPF / MTA-STS
    fire, and stays at baseline when only ``dkim_present`` fires (no
    longer a binding as of v1.9.6).
    """
    no_evidence = _posterior(network, [], [], "email_security_policy_enforcing")
    with_dmarc_reject = _posterior(network, [], ["dmarc_reject"], "email_security_policy_enforcing")
    with_dkim = _posterior(network, [], ["dkim_present"], "email_security_policy_enforcing")
    with_mta_sts = _posterior(network, [], ["mta_sts_enforce"], "email_security_policy_enforcing")
    with_spf = _posterior(network, [], ["spf_strict"], "email_security_policy_enforcing")

    assert with_dmarc_reject > no_evidence + 0.30
    assert with_mta_sts > no_evidence + 0.10
    assert with_spf > no_evidence + 0.05
    # v1.9.6: dkim_present is no longer a binding — it now acts as
    # unrelated evidence for policy_enforcing, so the posterior must
    # stay at baseline within numerical tolerance.
    assert abs(with_dkim - no_evidence) < 1e-9


def test_policy_enforcing_does_not_move_on_provider_slugs(network):
    """Independence: provider presence must not influence policy_enforcing.

    This is the key v1.9.3 invariant — the v1.9.0 node entangled the
    two and produced 52.6% disagreement on the corpus."""
    no_evidence = _posterior(network, [], [], "email_security_policy_enforcing")
    with_m365 = _posterior(network, ["microsoft365"], [], "email_security_policy_enforcing")
    with_gws = _posterior(network, ["google-workspace"], [], "email_security_policy_enforcing")
    with_gateway = _posterior(network, ["proofpoint"], [], "email_security_policy_enforcing")

    # Root node with no parents: provider slugs cannot reach it.
    assert abs(with_m365 - no_evidence) < 0.005
    assert abs(with_gws - no_evidence) < 0.005
    assert abs(with_gateway - no_evidence) < 0.005


def test_federated_identity_lifts_on_gws_evidence(network):
    """The v1.9.0 single-parent network had federated_identity tied to
    M365 only; a GWS-only tenant could not lift the posterior. v1.9.3
    fixes this — the GWS path must materially lift the posterior in
    the absence of M365 evidence."""
    no_evidence = _posterior(network, [], [], "federated_identity")
    gws_only = _posterior(network, ["google-workspace"], [], "federated_identity")
    # 0.35 (GWS-only CPT) should beat 0.08 (neither) by a clear margin.
    assert gws_only > no_evidence + 0.10


def test_federated_identity_old_m365_path_preserved(network):
    """The M365 path numbers were preserved (0.45). Adding GWS as a
    parent should not regress M365-driven federation attribution."""
    m365_only = _posterior(network, ["microsoft365"], [], "federated_identity")
    # 0.45 CPT entry, propagated through M365 prior 0.30 → marginal
    # should land in the 0.30 range when only M365 fires (no
    # federated_sso_hub signal). Exact value depends on inference,
    # but the M365 path must still lift above the no-evidence baseline.
    no_evidence = _posterior(network, [], [], "federated_identity")
    assert m365_only > no_evidence + 0.05


# ── helpers ──────────────────────────────────────────────────────────


def _posterior(network, slugs, signals, node_name) -> float:
    result = infer(network, slugs, signals, priors_override={})
    p = next(p for p in result.posteriors if p.name == node_name)
    return p.posterior
