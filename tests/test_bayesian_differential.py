"""Differential verification of the Bayesian inference core.

The shipped engine answers ``P(node = present | E)`` by variable
elimination over factors. These tests cross-check that machinery against
a second, independent implementation that does no factor algebra at all:
``validation.differential_verification.reference_posteriors`` enumerates
the full 512-state joint and reads each marginal off the normalized sum.

The cross-check is non-circular in two steps:

1. ``test_reference_anchored_to_hand_computation`` pins the independent
   reference to closed-form values a human can verify by hand (the
   no-evidence root and descendant marginals), so the oracle is
   known-correct, not merely self-consistent with the engine.
2. The remaining tests hold variable elimination to that oracle across
   the no-evidence prior, the exhaustive per-node subset sweep for the
   factor-construction-heavy nodes (correlation groups, declarative
   absence), and a seeded sample of the full none/one/all cross product.

The full enumerable sweep (every node at none/one/all, ~2.9k configs)
runs in ``validation/differential_verification.py``; the sampled subset
here keeps the default suite fast while still exercising every branch.
"""

from __future__ import annotations

import pytest

from recon_tool.bayesian import infer, load_network
from validation.differential_verification import (
    _DEFAULT_TOL,
    iter_structured_configs,
    iter_tricky_configs,
    prior_joint,
    reference_posteriors,
)

# Half a unit in the engine's fourth-decimal rounding, plus slack. A real
# factor-construction defect moves a posterior far past this.
_TOL = _DEFAULT_TOL


@pytest.fixture(scope="module")
def network():
    return load_network()


def _ve_posteriors(network, slugs: set[str], signals: set[str]) -> dict[str, float]:
    """Engine posteriors, pinned to shipped priors (ignore any ~/.recon override)."""
    result = infer(network, slugs, signals, priors_override={})
    return {p.name: p.posterior for p in result.posteriors}


# ── 1. Anchor the independent reference to hand computation ─────────────


def test_reference_anchored_to_hand_computation(network):
    """The reference must be correct, not just consistent with the engine.

    With no evidence every marginal is fixed by the priors and CPTs alone:

      * ``m365_tenant`` is a root: P = its prior, 0.30.
      * ``federated_identity`` marginalizes over its two roots:
          .30*.25*.50 + .30*.75*.45 + .70*.25*.35 + .70*.75*.08 = 0.242.
      * ``okta_idp`` then folds that through its CPT:
          0.242*0.30 + 0.758*0.005 = 0.076390.

    These are computed independently of the engine and of the reference's
    own enumeration logic, so agreement validates the oracle itself.
    """
    ref = reference_posteriors(network, set(), set())
    assert ref["m365_tenant"] == pytest.approx(0.30, abs=1e-9)
    assert ref["google_workspace_tenant"] == pytest.approx(0.25, abs=1e-9)
    assert ref["federated_identity"] == pytest.approx(0.242, abs=1e-9)
    assert ref["okta_idp"] == pytest.approx(0.242 * 0.30 + 0.758 * 0.005, abs=1e-9)


# ── 2. Hold variable elimination to the anchored reference ──────────────


def test_ve_matches_reference_no_evidence(network):
    """Prior marginals from the engine match naive enumeration on every node."""
    ve = _ve_posteriors(network, set(), set())
    ref = reference_posteriors(network, set(), set())
    for name, ref_p in ref.items():
        assert abs(ve[name] - ref_p) <= _TOL, f"{name}: VE={ve[name]} ref={ref_p}"


def test_ve_matches_reference_tricky_nodes_exhaustive(network):
    """Exhaustive local subset sweep for the factor-construction-heavy nodes.

    Walks the full power set of bindings for each correlation-group node and
    the declarative policy node, under both a sparse and a dense background,
    so group reduction (CAL7) and declarative absence conditioning (CAL14) are
    verified on every combination, not just none/one/all.
    """
    joint = prior_joint(network)
    checked = 0
    for slugs, signals in iter_tricky_configs(network):
        ve = _ve_posteriors(network, slugs, signals)
        ref = reference_posteriors(network, slugs, signals, joint=joint)
        for name, ref_p in ref.items():
            gap = abs(ve[name] - ref_p)
            assert gap <= _TOL, (
                f"{name}: gap={gap:.2e} slugs={sorted(slugs)} signals={sorted(signals)}"
            )
        checked += 1
    assert checked > 0


def test_ve_matches_reference_sampled_full_sweep(network):
    """A seeded sample of the full none/one/all cross product agrees everywhere.

    The complete ~2.9k-config sweep lives in the validation harness; here an
    evenly-strided deterministic sample keeps the default suite fast while still
    spanning the joint evidence space across all nine nodes.
    """
    joint = prior_joint(network)
    configs = list(iter_structured_configs(network))
    assert len(configs) > 2000  # the enumerable cross product is large
    stride = max(1, len(configs) // 400)
    sample = configs[::stride]
    worst = 0.0
    for slugs, signals in sample:
        ve = _ve_posteriors(network, slugs, signals)
        ref = reference_posteriors(network, slugs, signals, joint=joint)
        for name, ref_p in ref.items():
            gap = abs(ve[name] - ref_p)
            worst = max(worst, gap)
            assert gap <= _TOL, (
                f"{name}: gap={gap:.2e} slugs={sorted(slugs)} signals={sorted(signals)}"
            )
    # Sanity: the only gap should be the engine's 4-dp rounding, never structural.
    assert worst <= 5.05e-5


def test_declarative_absence_moves_posterior_down(network):
    """A focused, human-legible case the differential sweep also covers.

    The declarative policy node should read a genuinely-absent DMARC group as
    disconfirming: with no email-policy signals at all its posterior sits below
    its 0.62 prior, and the reference agrees with the engine on the exact value.
    """
    ve = _ve_posteriors(network, set(), set())
    ref = reference_posteriors(network, set(), set())
    node = "email_security_policy_enforcing"
    assert ve[node] < 0.62  # absence of the public declaration pulls it down
    assert abs(ve[node] - ref[node]) <= _TOL
