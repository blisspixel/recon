"""v1.9 validation rounds — properties that must hold across the
engine. These are not unit tests of single functions; they exercise
the whole inference pipeline with a variety of evidence shapes and
assert structural invariants.

If any of these fail, the network or the inference engine has
regressed in a way that would damage downstream consumers.
"""

from __future__ import annotations

import math

import pytest

from recon_tool.bayesian import infer, load_network


@pytest.fixture(scope="module")
def network():
    return load_network()


# ── Invariant 1: posteriors are valid probabilities ──────────────────


@pytest.mark.parametrize(
    ("slugs", "signals"),
    [
        ([], []),
        (["microsoft365"], []),
        (["microsoft365", "entra-id", "exchange-online"], ["dmarc_reject"]),
        (["okta"], ["federated_sso_hub"]),
        (["cloudflare", "akamai", "fastly"], []),
        (["aws", "aws-cloudfront", "aws-route53"], []),
        (
            ["microsoft365", "entra-id", "okta", "cloudflare"],
            ["federated_sso_hub", "dmarc_reject", "dkim_present", "spf_strict"],
        ),
        (["unknown-slug-not-in-network"], ["unknown-signal-not-in-network"]),
    ],
)
def test_posteriors_are_valid_probabilities(network, slugs, signals):
    result = infer(network, slugs, signals, priors_override={})
    for p in result.posteriors:
        assert 0.0 <= p.posterior <= 1.0, f"{p.name} posterior out of range: {p.posterior}"
        assert 0.0 <= p.interval_low <= p.interval_high <= 1.0, (
            f"{p.name} interval malformed: [{p.interval_low}, {p.interval_high}]"
        )
        # Posterior should lie inside its credible interval.
        assert p.interval_low - 1e-6 <= p.posterior <= p.interval_high + 1e-6


# ── Invariant 2: empty evidence → marginal priors hold ───────────────


def test_empty_evidence_recovers_marginal_priors(network):
    """With no evidence, every posterior should equal the network's
    marginal prior on that node (computed by inference with no
    factors from observation)."""
    result = infer(network, [], [], priors_override={})
    for p in result.posteriors:
        node = network.get(p.name)
        if node.prior is not None:
            # Root node — posterior must equal prior to within rounding.
            assert abs(p.posterior - node.prior) < 1e-3, (
                f"{p.name}: posterior {p.posterior} != prior {node.prior} on empty evidence"
            )


# ── Invariant 3: monotonicity of evidence ────────────────────────────


def test_more_corroborating_evidence_does_not_decrease_posterior(network):
    """Adding a corroborating slug should never decrease P(node) for
    that slug's bound node."""
    result_one = infer(network, ["microsoft365"], [], priors_override={})
    result_two = infer(network, ["microsoft365", "entra-id"], [], priors_override={})
    p1 = next(p for p in result_one.posteriors if p.name == "m365_tenant")
    p2 = next(p for p in result_two.posteriors if p.name == "m365_tenant")
    assert p2.posterior >= p1.posterior - 1e-6


def test_unrelated_evidence_does_not_change_unrelated_posterior(network):
    """Cloudflare evidence should not move the M365 posterior."""
    baseline = infer(network, [], [], priors_override={})
    cdn = infer(network, ["cloudflare"], [], priors_override={})
    m1 = next(p for p in baseline.posteriors if p.name == "m365_tenant")
    m2 = next(p for p in cdn.posteriors if p.name == "m365_tenant")
    assert abs(m1.posterior - m2.posterior) < 1e-3


# ── Invariant 4: interval width inversely correlates with n_eff ─────


def test_interval_width_strictly_decreases_with_evidence(network):
    """Adding evidence to a node should never widen its interval (as
    long as there are no conflicts to dampen it)."""
    e0 = infer(network, [], [], priors_override={})
    e1 = infer(network, ["microsoft365"], [], priors_override={})
    e2 = infer(network, ["microsoft365", "entra-id"], [], priors_override={})

    def width(p):
        return p.interval_high - p.interval_low

    w0 = width(next(p for p in e0.posteriors if p.name == "m365_tenant"))
    w1 = width(next(p for p in e1.posteriors if p.name == "m365_tenant"))
    w2 = width(next(p for p in e2.posteriors if p.name == "m365_tenant"))

    assert w2 <= w1 <= w0 + 1e-6, f"intervals not narrowing: w0={w0:.4f}, w1={w1:.4f}, w2={w2:.4f}"


# ── Invariant 5: conflicts widen intervals ───────────────────────────


def test_conflicts_widen_intervals(network):
    no_conflict = infer(network, ["microsoft365"], [], conflict_field_count=0, priors_override={})
    with_conflict = infer(network, ["microsoft365"], [], conflict_field_count=3, priors_override={})

    def width(result, name):
        p = next(p for p in result.posteriors if p.name == name)
        return p.interval_high - p.interval_low

    assert width(with_conflict, "m365_tenant") >= width(no_conflict, "m365_tenant")


# ── Invariant 6: sparse flag set when no evidence ────────────────────


def test_sparse_flag_set_under_no_evidence(network):
    result = infer(network, [], [], priors_override={})
    assert all(p.sparse for p in result.posteriors)


def test_sparse_flag_clears_with_sufficient_evidence(network):
    # Two pieces of evidence on m365_tenant clear the sparse flag.
    result = infer(network, ["microsoft365", "entra-id"], [], priors_override={})
    m365 = next(p for p in result.posteriors if p.name == "m365_tenant")
    assert not m365.sparse


# ── Invariant 7: entropy-reduction is bounded by ln 2 per node ──────


def test_entropy_reduction_per_node_bounded(network):
    """Maximum binary entropy is ln 2 nats. Per-node reduction can be
    at most ln 2 (going from p=0.5 to p∈{0,1}). Total reduction across
    N nodes is at most N · ln 2."""
    result = infer(
        network,
        ["microsoft365", "entra-id", "okta", "cloudflare", "aws"],
        ["federated_sso_hub", "dmarc_reject", "dkim_present", "spf_strict"],
        priors_override={},
    )
    max_possible = len(network.nodes) * math.log(2.0)
    assert result.entropy_reduction <= max_possible + 1e-6


# ── Invariant 8: priors override actually flows ──────────────────────


def test_override_changes_root_posterior(network):
    baseline = infer(network, [], [], priors_override={})
    overridden = infer(network, [], [], priors_override={"m365_tenant": 0.9})
    b = next(p for p in baseline.posteriors if p.name == "m365_tenant")
    o = next(p for p in overridden.posteriors if p.name == "m365_tenant")
    assert o.posterior > b.posterior + 0.4


def test_override_flows_to_children(network):
    """Raising the M365 prior should also lift federated_identity (a
    child) because the CPT puts $P(\\text{fed}|\\text{M365})$ above
    the unconditional rate."""
    baseline = infer(network, [], [], priors_override={})
    overridden = infer(network, [], [], priors_override={"m365_tenant": 0.9})
    b_fed = next(p for p in baseline.posteriors if p.name == "federated_identity")
    o_fed = next(p for p in overridden.posteriors if p.name == "federated_identity")
    assert o_fed.posterior > b_fed.posterior


def test_override_on_child_node_is_ignored(network):
    """Override on a node-with-parents must not corrupt inference. The
    loader applies override only to root nodes."""
    # federated_identity has parents; override is silently ignored.
    overridden = infer(network, [], [], priors_override={"federated_identity": 0.9})
    p = next(p for p in overridden.posteriors if p.name == "federated_identity")
    # Posterior should still be derived from CPT, not pinned to 0.9.
    # Without evidence, the marginal will not be 0.9.
    assert abs(p.posterior - 0.9) > 0.05


# ── Invariant 9: entropy reduction >= 0 on dense corroborating evidence ──


@pytest.mark.parametrize(
    ("slugs", "signals"),
    [
        (["microsoft365", "entra-id", "exchange-online"], ["federated_sso_hub", "dmarc_reject"]),
        (["okta"], ["federated_sso_hub"]),
        (["proofpoint"], ["dmarc_reject", "dkim_present", "spf_strict"]),
    ],
)
def test_dense_corroborating_evidence_reduces_total_entropy(network, slugs, signals):
    result = infer(network, slugs, signals, priors_override={})
    assert result.entropy_reduction > 0


# ── Invariant 10: n_eff floor never violated ─────────────────────────


def test_n_eff_never_below_floor(network):
    # Even with many conflicts, n_eff floor must hold.
    result = infer(network, [], [], conflict_field_count=100, priors_override={})
    for p in result.posteriors:
        assert p.n_eff >= 4.0  # _MIN_N_EFF


# ── Invariant 11: evidence count round-trips ─────────────────────────


def test_evidence_count_in_inference_result(network):
    result = infer(
        network,
        ["microsoft365", "entra-id"],
        ["dmarc_reject"],
        priors_override={},
    )
    # 2 slugs + 1 signal = 3 fired bindings; but only those that bind
    # to a node count. microsoft365 and entra-id both bind to
    # m365_tenant; dmarc_reject binds to email_security_policy_enforcing
    # (post-v1.9.3 split).
    assert result.evidence_count == 3
    assert result.conflict_count == 0
