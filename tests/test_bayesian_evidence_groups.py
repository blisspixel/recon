"""Evidence-group correction for conditionally-dependent bindings (CAL7).

Co-firing bindings that share a `group` are redundant readings of one fact, so
they must contribute a single effective likelihood ratio (the strongest), not
the over-counted independent product. See correlation.md §4.8.3.
"""

from __future__ import annotations

from recon_tool.bayesian import (  # pyright: ignore[reportPrivateUsage]
    _binding_llr,
    _contributing_evidence,
    _Evidence,
    infer,
    load_network,
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


def test_grouped_m365_is_less_confident_than_naive_product() -> None:
    """On the real network, three co-firing M365 slugs land below the
    over-counted product and reduce to the single strongest binding."""
    network = load_network()
    three = infer(network, ["microsoft365", "entra-id", "exchange-online"], [], priors_override={})
    one = infer(network, ["entra-id"], [], priors_override={})
    m365_three = next(p for p in three.posteriors if p.name == "m365_tenant")
    m365_one = next(p for p in one.posteriors if p.name == "m365_tenant")
    # The group collapses the three readings to the strongest, so the posterior
    # matches the single-strongest-binding posterior rather than compounding.
    assert abs(m365_three.posterior - m365_one.posterior) < 1e-9
    # And it stays well below a degenerate near-1.0 over-count.
    assert m365_three.posterior < 0.99
