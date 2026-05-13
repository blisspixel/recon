"""Per-node stability criterion (a) — evidence-response correctness.

Implements the criterion-(a) test from ``docs/roadmap.md`` §v1.9.5:

    "The node's posterior moves in the predicted direction when
    relevant evidence is added or removed, and *does not* move when
    irrelevant evidence is varied. This validates the network
    propagation works as designed for that node, not just that the
    engine runs Bayes."

For every node in the v1.9.3+ topology, this module asserts two
properties against the bundled ``bayesian_network.yaml``:

1. **Bound-evidence sensitivity.** Adding any one of the node's
   evidence bindings (slug or signal) strictly raises that node's
   marginal posterior above the no-evidence baseline.

2. **Unrelated-evidence inertia.** Adding the binding of a node that
   is *d-separated* from the node under test (in the marginal — no
   other nodes observed) leaves the node's posterior at the
   no-evidence baseline within numerical tolerance.

For pure-propagation nodes (``email_security_modern_provider`` has
no direct bindings by design), the bound-sensitivity test uses each
*parent's* evidence — observing a parent's slug must move the
child's posterior through the CPT, even though the child itself
has no direct evidence.

This test exists as a regression signal: a future topology change
that breaks propagation for any node fails here before it can reach
a release tag.
"""

from __future__ import annotations

import pytest

from recon_tool.bayesian import (
    InferenceResult,
    infer,
    load_network,
)

# Tolerance for "posterior didn't move" comparisons. The Bayesian
# inference is exact (variable elimination), so identical inputs
# produce bit-identical outputs; we keep a tiny epsilon only to be
# defensive against any future numerical-noise refactor (e.g. log-
# space arithmetic).
EPSILON_NO_MOVE = 1e-9

# Minimum upward shift required for "bound evidence moves the
# posterior". Looser than EPSILON_NO_MOVE — even the weakest binding
# (``signal:dkim_present`` with likelihood [0.85, 0.30]) lifts its
# node's posterior by ≥ 0.1 from the prior. 0.01 is a comfortable
# floor that catches a propagation failure without hand-tuning per
# binding.
MIN_BOUND_LIFT = 0.01


# ── Per-node evidence directory ────────────────────────────────────
#
# Each entry lists the node's direct evidence bindings as
# ("slug" | "signal", name) pairs. Synced manually from
# ``recon_tool/data/bayesian_network.yaml`` — if a future patch adds
# or removes a binding there, this directory must be updated to match.
# The test verifies the directory is in sync by asserting each listed
# binding actually moves its node's posterior; a typo here surfaces
# as a real failure, not silent skip.
_NODE_BINDINGS: dict[str, list[tuple[str, str]]] = {
    "m365_tenant": [
        ("slug", "microsoft365"),
        ("slug", "entra-id"),
        ("slug", "exchange-online"),
    ],
    "google_workspace_tenant": [
        ("slug", "google-workspace"),
        ("slug", "gmail"),
    ],
    "federated_identity": [
        ("signal", "federated_sso_hub"),
    ],
    "okta_idp": [
        ("slug", "okta"),
    ],
    "email_gateway_present": [
        ("slug", "proofpoint"),
        ("slug", "mimecast"),
        ("slug", "barracuda"),
    ],
    "email_security_policy_enforcing": [
        ("signal", "dmarc_reject"),
        ("signal", "dmarc_quarantine"),
        ("signal", "mta_sts_enforce"),
        ("signal", "dkim_present"),
        ("signal", "spf_strict"),
    ],
    "cdn_fronting": [
        ("slug", "cloudflare"),
        ("slug", "akamai"),
        ("slug", "fastly"),
    ],
    "aws_hosting": [
        ("slug", "aws"),
        ("slug", "aws-cloudfront"),
        ("slug", "aws-route53"),
    ],
}

# Pure-propagation nodes have no direct bindings; the criterion-(a)
# upward-movement test exercises each parent's evidence instead.
_PURE_PROPAGATION_NODES: dict[str, list[tuple[str, str]]] = {
    "email_security_modern_provider": [
        # Parent: m365_tenant — any m365 slug observation must move
        # modern_provider via the CPT.
        ("slug", "microsoft365"),
        # Parent: google_workspace_tenant.
        ("slug", "google-workspace"),
        # Parent: email_gateway_present.
        ("slug", "proofpoint"),
    ],
}

# "Unrelated" bindings — d-separated from the node under test in the
# marginal. ``cloudflare`` activates only ``cdn_fronting``, which is a
# root with no children; its evidence cannot reach any other node
# through the marginal. For the cdn_fronting test itself, use a
# different isolated root's binding.
_UNRELATED_BINDING_FOR_NODE: dict[str, tuple[str, str]] = {
    "m365_tenant": ("slug", "cloudflare"),
    "google_workspace_tenant": ("slug", "cloudflare"),
    "federated_identity": ("slug", "cloudflare"),
    "okta_idp": ("slug", "cloudflare"),
    "email_gateway_present": ("slug", "cloudflare"),
    "email_security_modern_provider": ("slug", "cloudflare"),
    "email_security_policy_enforcing": ("slug", "cloudflare"),
    "cdn_fronting": ("slug", "proofpoint"),  # gateway is isolated; doesn't touch cdn
    "aws_hosting": ("slug", "cloudflare"),
}


# ── Inference helpers ──────────────────────────────────────────────


_network = load_network()


def _posterior_for(node_name: str, result: InferenceResult) -> float:
    for p in result.posteriors:
        if p.name == node_name:
            return p.posterior
    raise AssertionError(f"node {node_name!r} missing from InferenceResult")


def _infer_with(slugs: set[str], signals: set[str]) -> InferenceResult:
    return infer(
        _network,
        observed_slugs=slugs,
        observed_signals=signals,
        conflict_field_count=0,
        priors_override={},  # bypass operator override; test against shipped CPTs
    )


_BASELINE = _infer_with(set(), set())


def _baseline_posterior(node_name: str) -> float:
    return _posterior_for(node_name, _BASELINE)


# ── Tests ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "node_name,bindings",
    [
        pytest.param(n, b, id=n)
        for n, b in {**_NODE_BINDINGS, **_PURE_PROPAGATION_NODES}.items()
    ],
)
def test_bound_evidence_raises_posterior(
    node_name: str, bindings: list[tuple[str, str]]
) -> None:
    """Adding any bound binding (or parent binding, for
    pure-propagation nodes) strictly raises the node's posterior
    above the no-evidence baseline by at least ``MIN_BOUND_LIFT``.

    Criterion (a) — evidence-response correctness, upward direction.
    """
    baseline = _baseline_posterior(node_name)
    for kind, name in bindings:
        if kind == "slug":
            result = _infer_with({name}, set())
        else:
            result = _infer_with(set(), {name})
        posterior = _posterior_for(node_name, result)
        assert posterior > baseline + MIN_BOUND_LIFT, (
            f"{node_name}: posterior with {kind}:{name} = {posterior:.4f}, "
            f"baseline = {baseline:.4f}, lift = {posterior - baseline:.4f} "
            f"(expected > {MIN_BOUND_LIFT})"
        )


@pytest.mark.parametrize(
    "node_name",
    list({**_NODE_BINDINGS, **_PURE_PROPAGATION_NODES}.keys()),
)
def test_unrelated_evidence_is_inert(node_name: str) -> None:
    """Adding an unrelated (d-separated) binding leaves the node's
    posterior at the no-evidence baseline within
    ``EPSILON_NO_MOVE``.

    Criterion (a) — evidence-response correctness, inertia direction.
    A propagation regression that lets unrelated evidence bleed
    into a node fails here.
    """
    baseline = _baseline_posterior(node_name)
    kind, name = _UNRELATED_BINDING_FOR_NODE[node_name]
    if kind == "slug":
        result = _infer_with({name}, set())
    else:
        result = _infer_with(set(), {name})
    posterior = _posterior_for(node_name, result)
    drift = abs(posterior - baseline)
    assert drift < EPSILON_NO_MOVE, (
        f"{node_name}: unrelated {kind}:{name} drifted posterior by "
        f"{drift:.6g} (baseline = {baseline:.4f}, with-unrelated = "
        f"{posterior:.4f}; expected drift < {EPSILON_NO_MOVE})"
    )


def test_baseline_root_posteriors_equal_priors() -> None:
    """Sanity check: under no evidence, every root node's marginal
    posterior equals its prior to within numerical noise. Guards
    against future ``infer`` refactors that accidentally inject
    nonzero "default" evidence.
    """
    for node in _network.nodes:
        if node.parents:
            continue  # descendants have CPT-propagated marginals, not prior
        baseline = _posterior_for(node.name, _BASELINE)
        assert node.prior is not None, f"{node.name} is rootless but no prior"
        assert abs(baseline - node.prior) < 1e-9, (
            f"{node.name}: baseline {baseline:.6f} != prior {node.prior:.6f}"
        )


def test_node_bindings_directory_is_complete() -> None:
    """Every node in the shipped network appears in either the
    direct-bindings or pure-propagation directory. Catches the case
    where a future v1.9.x patch adds a node but forgets to extend
    this test.
    """
    declared = set(_NODE_BINDINGS) | set(_PURE_PROPAGATION_NODES)
    actual = {node.name for node in _network.nodes}
    missing = actual - declared
    extra = declared - actual
    assert not missing, (
        f"node(s) {sorted(missing)} present in bayesian_network.yaml but "
        "not declared in test_node_stability_criteria — add them to "
        "_NODE_BINDINGS or _PURE_PROPAGATION_NODES with their evidence."
    )
    assert not extra, (
        f"node(s) {sorted(extra)} declared in test but not in "
        "bayesian_network.yaml — clean up the test directory."
    )
