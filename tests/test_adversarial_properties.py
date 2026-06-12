"""The suppression-monotonicity theorem, as a CI gate.

`validation/adversarial_properties.py` ships the theorem of
correlation.md section 4.3 (an operator who hides indicators can only
move a claim toward "we cannot tell," never toward a confident false
positive) as a machine-checked invariant. The first two tests ARE the
gate: the shipped network must satisfy the positive-indicator hypothesis
and the suppression monotonicity + bounds. The last two prove both
checks have teeth, by feeding a network with a negative-indicator
binding (a fired signal that favours absence) and asserting it is
flagged, so a future catalogue edit that broke the guarantee could not
pass silently.
"""

from __future__ import annotations

from recon_tool.bayesian import BayesianNetwork, _Evidence, _Node, load_network
from validation.adversarial_properties import (
    positive_indicator_violations,
    suppression_violations,
)


def _negative_indicator_network() -> BayesianNetwork:
    # A fired binding whose likelihood favours absence (0.2 < 0.8): adding it
    # lowers the posterior, so hiding it raises the posterior, violating the
    # theorem. This is exactly what the checks must catch.
    node = _Node(
        name="x",
        description="negative-indicator demo",
        parents=(),
        prior=0.5,
        cpt={},
        evidence=(_Evidence(kind="slug", name="neg", likelihood_present=0.2, likelihood_absent=0.8),),
    )
    return BayesianNetwork(version=1, nodes=(node,))


def test_shipped_network_satisfies_the_positive_indicator_hypothesis() -> None:
    violations = positive_indicator_violations(load_network())
    assert violations == [], f"the suppression theorem's hypothesis fails: {violations}"


def test_shipped_network_satisfies_suppression_monotonicity() -> None:
    violations = suppression_violations(load_network())
    assert violations == [], (
        "hiding a fired binding changed the posterior the wrong way or escaped the "
        f"[baseline, fully-observed] bound; the suppression guarantee does not hold: {violations}"
    )


def test_positive_indicator_check_catches_a_negative_binding() -> None:
    violations = positive_indicator_violations(_negative_indicator_network())
    assert len(violations) == 1
    assert "neg" in violations[0]


def test_suppression_check_catches_non_monotonicity() -> None:
    # With the negative indicator, firing "neg" drops the posterior from the
    # 0.5 baseline to 0.2, so hiding it raises the posterior: a suppression
    # violation the check must report.
    violations = suppression_violations(_negative_indicator_network())
    assert violations, "the check failed to catch a posterior that rose when a binding was hidden"
    assert any("raised the posterior" in v for v in violations)
