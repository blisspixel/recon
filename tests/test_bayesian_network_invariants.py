"""Invariants over the SHIPPED Bayesian network (``data/bayesian_network.yaml``).

The loader (``bayesian_loader.py``) raises on out-of-range priors, CPTs, and
likelihoods, so those cannot reach a loaded network. The gap these tests close is
the one the loader only ``logger.warning``s about, never rejects: a declarative
node whose grouped bindings lack a ``group_absence`` entry loads fine while
silently treating that absence as uninformative (LR=1), which quietly weakens the
"absence is evidence" contract the email-policy node depends on (CAL14). These
tests promote that warning to an assertion over the shipped network, and pin the
value invariants as a standing contract so a future loader regression (a dropped
range check) or a bad YAML edit is caught even when the network still loads.

This is the proportionate guard for the loader after the bayesian.py split: the
loaders sit outside the inference-core mutation surface by design, so their
semantic correctness is held here rather than by cosmic-ray. See
validation/mutation-gate.md.
"""

from __future__ import annotations

import logging

import pytest

from recon_tool.bayesian import BayesianNetwork, load_network

_LOADER_LOGGER = "recon_tool.bayesian_loader"


@pytest.fixture(scope="module")
def network() -> BayesianNetwork:
    """The shipped network (no path = ``data/bayesian_network.yaml``)."""
    return load_network()


def test_shipped_network_loads_without_warnings(caplog: pytest.LogCaptureFixture) -> None:
    """The shipped network must load clean. The only non-fatal load signal is the
    declarative/group_absence coverage warning, so zero warnings means every
    declarative node's grouped bindings are fully covered (no silent LR=1)."""
    with caplog.at_level(logging.WARNING, logger=_LOADER_LOGGER):
        load_network()
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING and r.name.startswith("recon_tool")]
    assert not warnings, "shipped network emitted load warnings:\n" + "\n".join(r.getMessage() for r in warnings)


def test_priors_and_cpts_in_unit_interval(network: BayesianNetwork) -> None:
    for node in network.nodes:
        if node.prior is not None:
            assert 0.0 < node.prior < 1.0, f"{node.name}: prior {node.prior} not in (0, 1)"
        for key, p in node.cpt.items():
            assert 0.0 < p < 1.0, f"{node.name}[{key}]: CPT value {p} not in (0, 1)"


def test_root_xor_cpt(network: BayesianNetwork) -> None:
    """A node is either a root (prior set, no parents, empty CPT) or has parents
    (no prior, CPT present). The inference engine relies on exactly one being true."""
    for node in network.nodes:
        if node.parents:
            assert node.prior is None, f"{node.name}: has parents but also a prior"
            assert node.cpt, f"{node.name}: has parents but no CPT"
        else:
            assert node.prior is not None, f"{node.name}: root node without a prior"
            assert not node.cpt, f"{node.name}: root node with a CPT"


def test_evidence_likelihoods_in_unit_interval(network: BayesianNetwork) -> None:
    for node in network.nodes:
        for ev in node.evidence:
            assert 0.0 < ev.likelihood_present < 1.0, f"{node.name}/{ev.name}: P(obs|present) not in (0, 1)"
            assert 0.0 < ev.likelihood_absent < 1.0, f"{node.name}/{ev.name}: P(obs|absent) not in (0, 1)"


def test_missingness_values_valid(network: BayesianNetwork) -> None:
    for node in network.nodes:
        assert node.missingness in ("hideable", "declarative"), f"{node.name}: bad missingness {node.missingness!r}"


def test_declarative_nodes_have_full_group_absence_coverage(network: BayesianNetwork) -> None:
    """Every evidence group on a declarative node must carry a group_absence pair.
    This is the assertion the loader only warns about: an uncovered group silently
    becomes LR=1, defeating the declarative-missingness model (CAL14)."""
    for node in network.nodes:
        if node.missingness != "declarative":
            continue
        grouped = {ev.group for ev in node.evidence if ev.group}
        covered = {g for g, _, _ in node.group_absence}
        uncovered = sorted(grouped - covered)
        assert not uncovered, f"{node.name}: declarative groups without group_absence: {uncovered}"


def test_group_absence_well_formed(network: BayesianNetwork) -> None:
    """group_absence entries reference real groups and carry in-range likelihoods,
    and only declarative nodes carry them."""
    for node in network.nodes:
        grouped = {ev.group for ev in node.evidence if ev.group}
        if node.group_absence:
            assert node.missingness == "declarative", f"{node.name}: group_absence on a non-declarative node"
        for group, lp, la in node.group_absence:
            assert group in grouped, f"{node.name}: group_absence group {group!r} has no bindings"
            assert 0.0 < lp < 1.0, f"{node.name}/{group}: P(no member|present) not in (0, 1)"
            assert 0.0 < la < 1.0, f"{node.name}/{group}: P(no member|absent) not in (0, 1)"
