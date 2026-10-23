"""Evidence-group correction for conditionally-dependent bindings (CAL7).

Co-firing bindings that share a `group` are redundant readings of one fact, so
they must contribute a single effective likelihood ratio (the strongest), not
the over-counted independent product. See correlation.md section 3.2.
"""

from __future__ import annotations

from dataclasses import replace

from recon_tool.bayesian import (  # pyright: ignore[reportPrivateUsage]
    BayesianNetwork,
    _binding_llr,
    _contributing_evidence,
    _Evidence,
    _Node,
    infer,
)


def _ev(name: str, present: float, absent: float, group: str | None = None) -> _Evidence:
    return _Evidence(kind="slug", name=name, likelihood_present=present, likelihood_absent=absent, group=group)


def test_group_reduces_to_strongest_member() -> None:
    grouped = [
        _ev("microsoft365", 0.95, 0.03, "m365"),
        _ev("entra-id", 0.88, 0.02, "m365"),  # strongest |LLR|
        _ev("exchange-online", 0.85, 0.02, "m365"),
    ]
    contributing = _contributing_evidence(grouped)
    assert len(contributing) == 1
    assert contributing[0].name == "entra-id"
    assert abs(_binding_llr(contributing[0])) == max(abs(_binding_llr(e)) for e in grouped)


def test_ungrouped_bindings_all_contribute() -> None:
    independent = [_ev("a", 0.9, 0.1), _ev("b", 0.8, 0.2)]
    assert len(_contributing_evidence(independent)) == 2


def test_mixed_groups_and_independents() -> None:
    mixed = [
        _ev("g1a", 0.9, 0.1, "g1"),
        _ev("g1b", 0.95, 0.2, "g1"),
        _ev("solo", 0.7, 0.3),
    ]
    out = _contributing_evidence(mixed)
    names = {e.name for e in out}
    # one representative from g1 plus the independent binding
    assert len(out) == 2
    assert "solo" in names


def test_grouped_bindings_retain_one_effective_unit_in_a_synthetic_model() -> None:
    """A purpose-built model tests grouping without resurrecting retired roles."""
    bindings = (_ev("a", 0.9, 0.1, "shared"), _ev("b", 0.8, 0.1, "shared"), _ev("c", 0.7, 0.2, "shared"))
    node = _Node("synthetic", "Synthetic grouped observation", (), 0.3, {}, bindings)
    network = BayesianNetwork(1, (node,))
    three = infer(network, ["a", "b", "c"], [], priors_override={}).posteriors[0]
    one = infer(network, ["a"], [], priors_override={}).posteriors[0]
    duplicated = infer(network, ["a"] * 3, [], priors_override={}).posteriors[0]
    naive_node = replace(node, evidence=tuple(replace(binding, group=None) for binding in bindings))
    naive = infer(replace(network, nodes=(naive_node,)), ["a", "b", "c"], [], priors_override={}).posteriors[0]
    assert three.evidence_used == ("slug:a", "slug:b", "slug:c")
    assert one.evidence_used == ("slug:a",)
    assert duplicated == one
    assert three.n_eff == one.n_eff == 5.0
    assert naive.n_eff == 7.0
    assert not three.sparse
    assert three.posterior > 0.3
    assert three.posterior == one.posterior
    assert naive.posterior > three.posterior
    assert three.posterior < 0.99
