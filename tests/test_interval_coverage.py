"""Uncertainty-band perturbation-containment regressions.

``validation/interval_coverage.py`` measures how often the shipped 80%
uncertainty band contains the conditional probability a perturbed model would
report, in synthetic worlds whose
evidence likelihoods differ from the shipped values by a multiplicative
band. At the recorded CAL8 scenario (``delta = 0.2``), the second test
preserves a sampled containment floor for every node, both over all draws and
over the selected fired-evidence subset. This is a deterministic regression for
the fixed seed and sample design, not nominal coverage or general assurance.
The remaining tests anchor the reference path to hand computation and show that
the check can detect a sufficiently large perturbation.

Everything here is synthetic and offline: no network, no real domains,
aggregate numbers only.
"""

from __future__ import annotations

import random

from recon_tool.bayesian import _Evidence, _Node, infer, load_network
from validation.differential_verification import _reference_node_likelihood, prior_joint
from validation.interval_coverage import (
    _fully_observed_node_likelihood,
    _posteriors_from_likelihoods,
    perturb_world,
    run_coverage,
)

# Sized for CI: enough samples to detect drift in the recorded scenario, while
# staying within a few seconds. The full sweep (10 worlds x
# 300 samples x 6 deltas) runs locally; see validation/interval-coverage.md.
_WORLDS = 3
_SAMPLES = 80
_SEED = 1729


def test_consistency_total_coverage_at_zero_delta() -> None:
    # delta=0: the world equals the model and the reference equals the
    # engine (differential verification, v2.1.7), so the interval always
    # contains the truth. A failure here means the truth path or the
    # containment logic broke, not that the network drifted.
    results = run_coverage(deltas=(0.0,), worlds=2, samples=60, seed=_SEED)
    for name, row in results["deltas"]["0.00"]["nodes"].items():
        assert row["coverage"] == 1.0, f"{name}: delta=0 coverage {row['coverage']} (truth path broken)"
        assert row["fired_coverage"] in (None, 1.0), f"{name}: delta=0 fired coverage {row['fired_coverage']}"


def test_cal8_sampled_containment_meets_recorded_floor() -> None:
    # Preserve the finite CAL8 scenario recorded by the validation artifact.
    # The threshold applies only to this fixed generator, seed, and sample
    # design. It is not a nominal interval-coverage guarantee.
    results = run_coverage(deltas=(0.2,), worlds=_WORLDS, samples=_SAMPLES, seed=_SEED)
    for name, row in results["deltas"]["0.20"]["nodes"].items():
        assert row["coverage"] is not None, f"{name}: no samples tallied"
        assert row["coverage"] >= 0.80, (
            f"{name}: sampled containment {row['coverage']} fell below the recorded 0.80 floor"
        )
        if row["fired_coverage"] is not None:
            assert row["fired_coverage"] >= 0.80, (
                f"{name}: fired-subset containment {row['fired_coverage']} fell below the recorded 0.80 floor"
            )


def test_gross_misspecification_is_detectable() -> None:
    # Falsifiability: the check must be able to fail. At delta=1.0 the
    # worlds are far outside the recorded CAL8 scenario, and
    # with this seed at least one node's coverage drops below 1.0. If a
    # change ever makes coverage total even here, the check has lost its
    # discriminating power and needs re-examination.
    results = run_coverage(deltas=(1.0,), worlds=2, samples=150, seed=_SEED)
    coverages = [row["coverage"] for row in results["deltas"]["1.00"]["nodes"].values()]
    assert any(c is not None and c < 1.0 for c in coverages), (
        "no node's coverage dropped under delta=1.0; the coverage check can no longer fail"
    )


def test_fully_observed_likelihood_hand_computed() -> None:
    # Anchor the fully observed Bernoulli path: two bindings, one fired. By hand:
    #   P(pattern | present) = 0.7 * (1 - 0.4) = 0.42
    #   P(pattern | absent)  = 0.1 * (1 - 0.2) = 0.08
    node = _Node(
        name="anchor",
        description="hand-computed anchor",
        parents=(),
        prior=0.5,
        cpt={},
        evidence=(
            _Evidence(kind="slug", name="fired", likelihood_present=0.7, likelihood_absent=0.1),
            _Evidence(kind="slug", name="silent", likelihood_present=0.4, likelihood_absent=0.2),
        ),
    )
    like_present, like_absent = _fully_observed_node_likelihood(node, {"fired"})
    assert abs(like_present - 0.42) < 1e-12
    assert abs(like_absent - 0.08) < 1e-12


def test_enumeration_under_no_evidence_matches_engine() -> None:
    # Anchor the enumeration helper to the verified core at the empty
    # evidence configuration. For hideable nodes the no-evidence
    # observation likelihood is (1, 1) and the conditional reduces to the
    # prior marginal; the declarative node conditions on the all-absent
    # pattern even with nothing fired (CAL14), so its likelihood pair
    # comes from the model's own absence rule. Agreement within the
    # engine's four-decimal rounding ties the truth path to the engine
    # the differential harness verified.
    net = load_network()
    joint = prior_joint(net)
    no_evidence = {n.name: _reference_node_likelihood(n, []) for n in net.nodes}
    for node in net.nodes:
        if node.missingness != "declarative":
            assert no_evidence[node.name] == (1.0, 1.0)
    enumerated = _posteriors_from_likelihoods(joint, no_evidence)
    engine = {p.name: p.posterior for p in infer(net, [], [], priors_override={}).posteriors}
    for name, value in enumerated.items():
        assert abs(value - engine[name]) <= 6e-5, f"{name}: enumeration {value} vs engine {engine[name]}"


def test_perturb_world_stays_in_valid_interval_and_is_reproducible() -> None:
    net = load_network()
    world_a = perturb_world(net, 0.3, random.Random(7))  # noqa: S311 - deterministic test seed.
    world_b = perturb_world(net, 0.3, random.Random(7))  # noqa: S311 - deterministic test seed.
    assert world_a == world_b
    for node in world_a.nodes:
        for ev in node.evidence:
            assert 0.0 < ev.likelihood_present < 1.0
            assert 0.0 < ev.likelihood_absent < 1.0
        for _, lp, la in node.group_absence:
            assert 0.0 < lp < 1.0
            assert 0.0 < la < 1.0


def test_aggregate_output_carries_no_per_domain_data() -> None:
    # Same hygiene rule as the drift baseline: node names and numbers
    # only, never apexes / domains / org strings.
    results = run_coverage(deltas=(0.0,), worlds=1, samples=20, seed=_SEED)
    for level in results["deltas"].values():
        for name, row in level["nodes"].items():
            assert "." not in name
            assert set(row) == {
                "n",
                "fired_n",
                "coverage",
                "fired_coverage",
                "mar_coverage",
                "mar_fired_coverage",
                "mean_width",
            }
            assert all(isinstance(v, int | float) or v is None for v in row.values())
    assert results["legacy_metric_names"] == {
        "mar_coverage": "fully observed Bernoulli-pattern containment",
        "mar_fired_coverage": "the same metric on the fired-evidence subset",
        "note": "mar_* keys are historical compatibility names, not MAR assumptions",
    }
