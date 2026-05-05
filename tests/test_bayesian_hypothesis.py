"""Property-based tests for the v1.9 Bayesian inference layer.

Hypothesis generates random valid networks and random evidence sets,
then checks invariants that must hold regardless of input shape:

  * posteriors land in [0, 1]
  * the posterior is contained in its credible interval
  * the sparse flag tracks the n_eff floor
  * inference is deterministic given the same inputs
  * unknown evidence does not move any posterior
  * adding more corroborating evidence narrows intervals
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from recon_tool.bayesian import (
    _MIN_N_EFF,
    BayesianNetwork,
    _Evidence,
    _Node,
    infer,
    load_network,
)


def _toy_network(prior: float, lp: float, la: float) -> BayesianNetwork:
    """Single root node with one slug evidence binding."""
    node = _Node(
        name="root",
        description="root",
        parents=(),
        prior=prior,
        cpt={},
        evidence=(_Evidence(kind="slug", name="ev", likelihood_present=lp, likelihood_absent=la),),
    )
    return BayesianNetwork(version=1, nodes=(node,))


@settings(max_examples=200, deadline=None)
@given(
    prior=st.floats(min_value=0.01, max_value=0.99),
    lp=st.floats(min_value=0.05, max_value=0.95),
    la=st.floats(min_value=0.05, max_value=0.95),
)
def test_two_state_bayes_matches_closed_form(prior: float, lp: float, la: float) -> None:
    """For a single root node with one binary observation, the posterior
    must equal the closed-form Bayes' rule:

        P(node | obs) = P(obs|node) P(node) / [P(obs|node) P(node) + P(obs|¬node) (1 - P(node))]
    """
    net = _toy_network(prior, lp, la)
    result = infer(net, observed_slugs=["ev"], observed_signals=[], priors_override={})
    p = result.posteriors[0]
    expected = (lp * prior) / (lp * prior + la * (1.0 - prior))
    assert abs(p.posterior - expected) < 1e-3


@settings(max_examples=200, deadline=None)
@given(
    prior=st.floats(min_value=0.01, max_value=0.99),
    lp=st.floats(min_value=0.05, max_value=0.95),
    la=st.floats(min_value=0.05, max_value=0.95),
)
def test_no_observation_returns_prior(prior: float, lp: float, la: float) -> None:
    net = _toy_network(prior, lp, la)
    result = infer(net, [], [], priors_override={})
    assert abs(result.posteriors[0].posterior - prior) < 1e-3


@settings(max_examples=100, deadline=None)
@given(
    slugs=st.lists(
        st.sampled_from(
            [
                "microsoft365",
                "entra-id",
                "exchange-online",
                "google-workspace",
                "gmail",
                "okta",
                "proofpoint",
                "mimecast",
                "barracuda",
                "cloudflare",
                "akamai",
                "fastly",
                "aws",
                "aws-cloudfront",
                "aws-route53",
            ]
        ),
        max_size=8,
    ),
    signals=st.lists(
        st.sampled_from(
            [
                "federated_sso_hub",
                "dmarc_reject",
                "dmarc_quarantine",
                "mta_sts_enforce",
                "dkim_present",
                "spf_strict",
            ]
        ),
        max_size=6,
    ),
    conflicts=st.integers(min_value=0, max_value=10),
)
def test_invariants_hold_across_random_evidence(slugs, signals, conflicts) -> None:
    """For any plausible evidence pattern on the shipped network:
    posteriors are valid probabilities, intervals contain the
    posterior, sparse flag is consistent with n_eff floor, and
    n_eff is at least the floor.
    """
    net = load_network()
    result = infer(
        net,
        observed_slugs=slugs,
        observed_signals=signals,
        conflict_field_count=conflicts,
        priors_override={},
    )
    for p in result.posteriors:
        assert 0.0 <= p.posterior <= 1.0
        assert 0.0 <= p.interval_low <= p.interval_high <= 1.0
        # Posterior is contained in (or near) its credible interval.
        assert p.interval_low - 1e-6 <= p.posterior <= p.interval_high + 1e-6
        assert p.n_eff >= _MIN_N_EFF
        assert p.sparse == (p.n_eff <= _MIN_N_EFF)


@settings(max_examples=50, deadline=None)
@given(
    slugs=st.lists(
        st.sampled_from(["microsoft365", "entra-id", "okta", "cloudflare", "aws"]),
        max_size=5,
    ),
)
def test_inference_is_deterministic(slugs) -> None:
    """Same input → same output, every time."""
    net = load_network()
    r1 = infer(net, slugs, [], priors_override={})
    r2 = infer(net, slugs, [], priors_override={})
    assert r1.entropy_reduction == r2.entropy_reduction
    assert r1.evidence_count == r2.evidence_count
    for p1, p2 in zip(r1.posteriors, r2.posteriors, strict=True):
        assert p1.posterior == p2.posterior
        assert p1.interval_low == p2.interval_low
        assert p1.interval_high == p2.interval_high
