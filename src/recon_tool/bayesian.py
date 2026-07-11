"""Bayesian-network inference layer (v1.9; stable v2.0+).

Discrete Bayesian network loaded from
``recon_tool/data/bayesian_network.yaml``. Computes a marginal
posterior :math:`P(\\text{node} = \\text{present} \\mid E)` for every
node in the network, given the observed-evidence set ``E`` derived from
a domain's slugs and signals.

This module is **separate from** ``recon_tool/fusion.py``:

  * ``fusion.py`` produces per-slug additive evidence-strength scores from raw
    evidence weights. It does not produce calibrated posterior probabilities.
  * ``bayesian.py`` (this module) operates one level up: nodes are
    high-level claims ("the tenant is M365-federated", "email security
    is strong"), and the network encodes how those claims relate.
    It answers "given everything we observed, how strongly do we
    believe this claim?".

Both layers ship side by side. The evidence-strength layer is single-slug and
deterministic. The Bayesian layer is multi-node, propagates through the DAG,
and runs by default on single-domain CLI lookups unless explicitly disabled.

## Inference

Exact inference via variable elimination over discrete factors. With
the current network at 9 nodes the product space is tiny (512 entries
worst case), so variable elimination is overkill but keeps the door
open for larger networks. Pure Python, with no numpy or scipy.

## Evidence-responsive uncertainty bands

The exact posterior is a single number :math:`\\mu \\in [0, 1]`. The
honest "how much do we trust it" report should also reflect:

1. how much evidence the queried domain produced for this node, and
2. whether evidence sources disagreed (cross-source conflict).

We return an 80% uncertainty band by treating the model posterior as the mean
of a separate Beta distribution with hand-set effective display mass
``n_eff``. Counted evidence units increase the mass and conflicts reduce it,
subject to a floor. Conflicts change the band but not the mean.

This is a post-inference display heuristic, not calibration. It is not a
Bayesian credible interval over parameter uncertainty, a frequentist confidence
interval, or a partial-identification region. Exact network arithmetic does not
validate the committed model against reality.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable
from itertools import product

import deal

from recon_tool.bayesian_interval import credible_interval
from recon_tool.bayesian_loader import apply_priors_override as _apply_priors_override
from recon_tool.bayesian_loader import load_network, load_priors_override
from recon_tool.bayesian_models import (  # re-exported: stable import path after the split
    BayesianNetwork,
    CalibrationSettings,
    ConflictProvenance,
    EvidenceContribution,
    InferenceResult,
    NodePosterior,
    UnitCounterfactual,
)
from recon_tool.bayesian_models import Evidence as _Evidence
from recon_tool.bayesian_models import Node as _Node
from recon_tool.bayesian_observations import signals_from_tenant_info
from recon_tool.source_status import ObservationChannel, SourceStatus

logger = logging.getLogger(__name__)

__all__ = [
    "BayesianNetwork",
    "CalibrationSettings",
    "ConflictProvenance",
    "EvidenceContribution",
    "InferenceResult",
    "NodePosterior",
    "UnitCounterfactual",
    "collection_masked_units",
    "infer",
    "infer_from_tenant_info",
    "load_network",
    "load_priors_override",
    "signals_from_tenant_info",
]

# Default effective-sample-size settings. load_network() reads the same values
# from bayesian_network.yaml's top-level calibration block; these constants
# remain for historical internal imports and default BayesianNetwork(...)
# construction.
#
# Minimum effective display mass. This floors the display heuristic; it is not a
# sample size or passive-observation ceiling.
_MIN_N_EFF = 4.0

# Per-evidence-record contribution to n_eff. With 1 record n_eff ≈ 5,
# with 4 records n_eff ≈ 8, with 10+ records n_eff ≈ 14. Tunable from
# validation runs without rewriting the math.
_EVIDENCE_N_EFF_CONTRIB = 1.0

# Per-conflict penalty subtracted from n_eff. A single cross-source
# conflict on this node's bound evidence widens the interval; many
# conflicts collapse n_eff toward _MIN_N_EFF.
_CONFLICT_N_EFF_PENALTY = 1.5


# ── Data structures ────────────────────────────────────────────────────


# ── Loaders ────────────────────────────────────────────────────────────


# ── Inference engine: variable elimination ────────────────────────────


# A factor is a mapping from tuple-of-(node, state) assignments to a probability.
# We represent assignments as frozensets of (var, state) pairs; products and
# marginalizations operate on those.
Assignment = frozenset[tuple[str, str]]
Factor = dict[Assignment, float]


# Design-by-Contract validators for the inference math below. Named and
# typed (rather than inline lambdas) so they carry no unknown-type noise
# and can be read and tested on their own. Each encodes an invariant the
# module already relies on; under `python -O` deal disables them (see
# recon_tool/__init__.py), so they are a test-time and dev-time guard.
def _factor_is_probabilities(factor: Factor) -> bool:
    """Every factor entry is a probability in ``[0, 1]``."""
    return all(0.0 <= v <= 1.0 for v in factor.values())


def _factor_is_strictly_positive(factor: Factor | None) -> bool:
    """A returned evidence factor has only strictly-positive entries.

    Encodes the no-degenerate-factor invariant: the schema rejects
    ``{0, 1}`` likelihoods because a single zero would pin a node's
    posterior permanently.
    """
    return factor is None or all(v > 0.0 for v in factor.values())


def _marginal_in_unit_range(dist: dict[str, float]) -> bool:
    """Each marginal probability is in ``[0, 1]``."""
    return all(0.0 <= v <= 1.0 for v in dist.values())


@deal.post(_factor_is_probabilities)  # pyright: ignore[reportUntypedFunctionDecorator]
def _factor_for_node(node: _Node) -> Factor:
    """Build the conditional factor :math:`P(\\text{node} \\mid \\text{parents})`.

    Contract: every factor entry is a probability in ``[0, 1]``. A value
    outside that range means a malformed prior or CPT slipped past
    ``load_network``'s validation.
    """
    factor: Factor = {}
    if not node.parents:
        prior = node.prior if node.prior is not None else 0.5
        factor[frozenset({(node.name, "present")})] = prior
        factor[frozenset({(node.name, "absent")})] = 1.0 - prior
        return factor
    for combo in product(["present", "absent"], repeat=len(node.parents)):
        key = ",".join(f"{p}={s}" for p, s in zip(node.parents, combo, strict=True))
        p_present = node.cpt[key]
        parent_assign = set(zip(node.parents, combo, strict=True))
        factor[frozenset(parent_assign | {(node.name, "present")})] = p_present
        factor[frozenset(parent_assign | {(node.name, "absent")})] = 1.0 - p_present
    return factor


def _binding_llr(ev: _Evidence) -> float:
    """Natural-log likelihood ratio for one binding. Finite (likelihoods in (0,1))."""
    return math.log(ev.likelihood_present / ev.likelihood_absent)


def _unit_name(ev: _Evidence) -> str:
    """The evidence-unit identifier for a binding.

    An evidence *unit* is the granularity at which evidence is independent
    in the model: a correlation group counts as one unit (its members are
    redundant readings of one fact, reduced by :func:`_contributing_evidence`),
    and an ungrouped binding is its own unit. Masking (``masked_units`` on
    :func:`infer`) and the leave-one-unit-out counterfactuals operate at this
    granularity — individual members of a group cannot be masked separately,
    because the model treats them as one observation.
    """
    return ev.group if ev.group is not None else ev.name


_CHANNEL_OBSERVATION_UNITS: dict[ObservationChannel, frozenset[str]] = {
    "apex_txt": frozenset({"spf_strict"}),
    "bimi": frozenset(),
    "caa": frozenset(),
    "dmarc": frozenset({"dmarc_policy"}),
    "dkim": frozenset(),
    "mta_sts": frozenset({"mta_sts_enforce"}),
    "mx": frozenset(),
    "tls_rpt": frozenset(),
}


def collection_masked_units(
    degraded_sources: Iterable[str],
    network: BayesianNetwork | None = None,
) -> frozenset[str]:
    """Map failed observation channels to structurally unobserved units.

    ``degraded_sources`` is collection provenance, not domain evidence. A
    failed channel must therefore suppress both a fired binding and the
    informative-absence factor for the units it owns. A whole ``dns`` or
    ``dns_records`` failure masks every declarative unit in the current network
    because all declarative bindings in the shipped model are public DNS
    declarations. Granular failures mask only their affected unit.
    """
    active_network = network if network is not None else load_network()
    status = SourceStatus.from_degraded_sources(degraded_sources)
    masked = {unit for channel in status.unavailable_channels for unit in _CHANNEL_OBSERVATION_UNITS.get(channel, ())}
    if status.whole_dns_unavailable:
        masked.update(
            _unit_name(evidence)
            for node in active_network.nodes
            if node.missingness == "declarative"
            for evidence in node.evidence
        )
    return frozenset(masked)


def _contributing_evidence(fired_evidence: list[_Evidence]) -> list[_Evidence]:
    """Reduce co-firing correlated bindings to one effective binding per group.

    Bindings that share a non-None ``group`` are redundant readings of one
    underlying fact (conditionally dependent given the node, e.g. the three
    M365 indicators), so multiplying their likelihoods over-counts the evidence
    and produces an over-confident posterior with too tight an interval. We keep
    only the strongest fired binding in each group (max ``|LLR|``), which under
    the reviewed dependency-group heuristic contributes
    :math:`\\lambda_g = \\max_{b \\in g} \\lambda_b` rather than the sum.
    This prevents known double counting but is not a bound on an unspecified
    joint likelihood. Ungrouped bindings are modeled as conditionally
    independent; that is an assumption, not an observed property. See
    correlation.md section 3.2.
    """
    independent: list[_Evidence] = []
    strongest: dict[str, _Evidence] = {}
    for ev in fired_evidence:
        if ev.group is None:
            independent.append(ev)
            continue
        current = strongest.get(ev.group)
        if current is None or abs(_binding_llr(ev)) > abs(_binding_llr(current)):
            strongest[ev.group] = ev
    return independent + list(strongest.values())


@deal.post(_factor_is_strictly_positive)  # pyright: ignore[reportUntypedFunctionDecorator]
def _factor_for_evidence(
    node: _Node,
    fired_evidence: list[_Evidence],
    masked_units: frozenset[str] = frozenset(),
) -> Factor | None:
    """Build the observation factor for a node given which of its bindings fired.

    Contract: when a factor is returned, every likelihood entry is
    strictly positive. This encodes the no-degenerate-factor invariant
    (the schema rejects ``{0, 1}`` likelihoods): a single zero would pin
    the node's posterior permanently, so a zero here is a bug, not a
    valid factor.

    Returns None when no evidence fired for this node; the node has no
    observation factor in that case (its prior/CPT factor still
    participates in inference).

    The factor is :math:`P(\\text{observation pattern} \\mid \\text{node})`,
    a function of the node's state. Bindings in different correlation groups
    (and ungrouped bindings) are combined as conditionally independent given
    the node, the standard naive-Bayes treatment; co-firing bindings within one
    group are first reduced to their strongest member by
    :func:`_contributing_evidence`, so redundant readings of one fact are not
    multiplied as if independent (correlation.md section 3.2).

    Missingness (roadmap CAL14):

    - **Hideable nodes** (default) do NOT condition on absence: a non-firing
      binding contributes nothing (LR=1). Passive collection cannot distinguish
      "this node truly lacks the binding" from "the binding is there but the
      operator hid it". Ignoring non-fire is an explicit conservative policy,
      not a value derived from MNAR (correlation.md section 3.3).
    - **Declarative nodes** DO condition on absence: a binding that could fire
      but did not is genuine disconfirming evidence, because the signal is a
      public declaration whose absence cannot be hidden from passive DNS
      (DMARC / SPF / MTA-STS policy). A non-firing independent binding
      contributes the complement of its likelihood; an entirely non-firing
      mutually-exclusive group (e.g. the DMARC policy level) contributes its
      explicit ``group_absence`` pair, because its members are alternatives,
      not independent features, so the complement-product would double-count.

    ``masked_units`` names evidence units (a correlation-group name, or an
    ungrouped binding's name — see :func:`_unit_name`) to treat as
    *structurally unobserved*: the unit contributes no factor in either
    direction. The caller must have already removed the masked units' fired
    bindings from ``fired_evidence`` (``infer`` does); this function's job is
    to also suppress the masked units' informative-absence contribution on
    declarative nodes, which is what distinguishes "unobserved" from "absent"
    there. On hideable nodes absence already contributes nothing, so the
    filtering of fired bindings is the whole story.
    """
    if node.missingness != "declarative":
        # Hideable (MNAR): only fired bindings contribute.
        if not fired_evidence:
            return None
        like_present = 1.0
        like_absent = 1.0
        for ev in _contributing_evidence(fired_evidence):
            like_present *= ev.likelihood_present
            like_absent *= ev.likelihood_absent
        return {
            frozenset({(node.name, "present")}): like_present,
            frozenset({(node.name, "absent")}): like_absent,
        }
    # Declarative, with a specified nonfire-informative observation model:
    # fired bindings contribute their likelihood and non-firing units contribute
    # their absence likelihood. This is not a missing-at-random conclusion. A
    # factor is always returned because all-absent is itself informative.
    like_present = 1.0
    like_absent = 1.0
    for ev in _contributing_evidence(fired_evidence):
        like_present *= ev.likelihood_present
        like_absent *= ev.likelihood_absent
    for _, _, absence_present, absence_absent in _declarative_absent_units(node, fired_evidence, masked_units):
        like_present *= absence_present
        like_absent *= absence_absent
    return {
        frozenset({(node.name, "present")}): like_present,
        frozenset({(node.name, "absent")}): like_absent,
    }


def _declarative_absent_units(
    node: _Node,
    fired_evidence: list[_Evidence],
    masked_units: frozenset[str] = frozenset(),
) -> list[tuple[str, str, float, float]]:
    """Enumerate every declarative absence factor applied by inference.

    Each tuple is ``(unit, kind, P(absence | present), P(absence | absent))``.
    Keeping factor construction and provenance on this one enumeration prevents
    a non-fire from affecting the posterior without appearing in diagnostics.
    Neutral factors remain in the list because inference applies them; the
    provenance projection below omits them because they cannot change a result.
    """
    out: list[tuple[str, str, float, float]] = []
    fired_groups = {ev.group for ev in fired_evidence if ev.group}
    fired_names = {ev.name for ev in fired_evidence}
    group_absence = {group: (present, absent) for group, present, absent in node.group_absence}
    seen_groups: set[str] = set()
    for evidence in node.evidence:
        if _unit_name(evidence) in masked_units or evidence.name in fired_names:
            continue
        if evidence.group:
            if evidence.group in fired_groups or evidence.group in seen_groups:
                continue
            seen_groups.add(evidence.group)
            pair = group_absence.get(evidence.group)
            if pair is not None:
                out.append((evidence.group, "group", pair[0], pair[1]))
        else:
            out.append(
                (
                    evidence.name,
                    evidence.kind,
                    1.0 - evidence.likelihood_present,
                    1.0 - evidence.likelihood_absent,
                )
            )
    return out


def _informative_absent_units(
    node: _Node,
    fired_evidence: list[_Evidence],
    masked_units: frozenset[str] = frozenset(),
) -> list[tuple[str, str]]:
    """The (unit, kind) pairs whose absence is informative on a declarative node.

    A unit is a correlation group (kind ``"group"``) or an ungrouped binding
    (kind = the binding's slug/signal kind). Every non-neutral absence factor
    that inference applies is included, even when its likelihood ratio is weak.
    This keeps the reported provenance and ``absence_informative`` flag exactly
    aligned with the factors that changed the posterior. Masked units are
    skipped: structurally unobserved is not absent. Single source of truth for
    ``n_eff`` counting and the leave-one-unit-out counterfactual enumeration.
    """
    return [
        (unit, kind)
        for unit, kind, absence_present, absence_absent in _declarative_absent_units(node, fired_evidence, masked_units)
        if absence_present != absence_absent
    ]


def _declarative_evidence_count(
    node: _Node,
    fired_evidence: list[_Evidence],
    masked_units: frozenset[str] = frozenset(),
) -> int:
    """Effective evidence-unit count for a declarative node's ``n_eff``.

    Counts each evidence unit (a correlation group, or an independent binding)
    that is informative: fired, or absent with a non-neutral absence
    likelihood ratio (per :func:`_informative_absent_units`). A
    confidently-disconfirmed declarative node (its strong signals genuinely
    absent) therefore earns evidence toward ``n_eff`` and is not flagged
    sparse, symmetric with a confidently-confirmed one.
    """
    return len(_contributing_evidence(fired_evidence)) + len(
        _informative_absent_units(node, fired_evidence, masked_units)
    )


def _multiply(a: Factor, b: Factor) -> Factor:
    """Pointwise factor product."""
    out: Factor = {}
    for ka, va in a.items():
        for kb, vb in b.items():
            # Compatible only if shared vars agree.
            shared_vars = {v for v, _ in ka} & {v for v, _ in kb}
            if shared_vars:
                ka_dict = dict(ka)
                kb_dict = dict(kb)
                if any(ka_dict[v] != kb_dict[v] for v in shared_vars):
                    continue
            merged = ka | kb
            out[merged] = out.get(merged, 0.0) + va * vb
    return out


def _sum_out(factor: Factor, var: str) -> Factor:
    """Marginalize ``var`` out of ``factor`` (sum over its states)."""
    out: Factor = {}
    for assign, val in factor.items():
        rest = frozenset((v, s) for v, s in assign if v != var)
        out[rest] = out.get(rest, 0.0) + val
    return out


@deal.post(_marginal_in_unit_range)  # pyright: ignore[reportUntypedFunctionDecorator]
def _query_marginal(factors: list[Factor], query: str, all_vars: list[str]) -> dict[str, float]:
    """Compute :math:`P(\\text{query})` by eliminating every other variable.

    Contract: each returned marginal probability is in ``[0, 1]`` (the
    normalization divides each entry by the non-negative total).
    """
    work = list(factors)
    for v in all_vars:
        if v == query:
            continue
        # Multiply all factors mentioning v into one, then sum out v.
        with_v = [f for f in work if any(var == v for k in f for var, _ in k)]
        without_v = [f for f in work if f not in with_v]
        if not with_v:
            work = without_v
            continue
        product_factor = with_v[0]
        for f in with_v[1:]:
            product_factor = _multiply(product_factor, f)
        marginalized = _sum_out(product_factor, v)
        work = [*without_v, marginalized]

    # Multiply remaining factors (all over the query var only).
    if not work:
        return {"present": 0.5, "absent": 0.5}
    final = work[0]
    for f in work[1:]:
        final = _multiply(final, f)
    # Normalize.
    total = sum(final.values())
    if total <= 0:
        # Degenerate all-zero factor (only reachable with a pinned 0/1 in a
        # custom model, which load_network now rejects). Fall back to the
        # uniform prior rather than return a non-normalized {0, 0}.
        return {"present": 0.5, "absent": 0.5}
    out: dict[str, float] = {"present": 0.0, "absent": 0.0}
    for assign, val in final.items():
        for var, state in assign:
            if var == query:
                out[state] = val / total
    return out


def _evidence_for_domain(
    node: _Node,
    observed_slugs: set[str],
    observed_signals: set[str],
) -> list[_Evidence]:
    """Return the subset of ``node.evidence`` that fired for this domain."""
    fired: list[_Evidence] = []
    for ev in node.evidence:
        if (ev.kind == "slug" and ev.name in observed_slugs) or (ev.kind == "signal" and ev.name in observed_signals):
            fired.append(ev)
    return fired


def _network_calibration(network: BayesianNetwork) -> CalibrationSettings:
    return network.calibration


# ── Public API ─────────────────────────────────────────────────────────


def _build_factors(
    network: BayesianNetwork,
    slug_set: set[str],
    signal_set: set[str],
    masked: frozenset[str],
) -> tuple[list[Factor], dict[str, list[_Evidence]]]:
    """Build the factor set for one evidence configuration.

    One CPT/prior factor per node, plus one observation factor per node with
    fired (or, on declarative nodes, informatively-absent) evidence, with
    ``masked`` units treated as structurally unobserved throughout. Extracted
    from :func:`infer` so the leave-one-unit-out counterfactuals re-run the
    exact same construction with one more unit masked.
    """
    factors: list[Factor] = []
    fired_per_node: dict[str, list[_Evidence]] = {}
    for node in network.nodes:
        factors.append(_factor_for_node(node))
        fired = _evidence_for_domain(node, slug_set, signal_set)
        if masked:
            fired = [ev for ev in fired if _unit_name(ev) not in masked]
        fired_per_node[node.name] = fired
        ev_factor = _factor_for_evidence(node, fired, masked)
        if ev_factor is not None:
            factors.append(ev_factor)
    return factors, fired_per_node


def _unit_counterfactuals(
    network: BayesianNetwork,
    node: _Node,
    posterior: float,
    contributing: list[_Evidence],
    fired: list[_Evidence],
    slug_set: set[str],
    signal_set: set[str],
    masked: frozenset[str],
    all_vars: list[str],
) -> tuple[UnitCounterfactual, ...]:
    """Exact leave-one-unit-out counterfactuals for one node.

    Enumerates the units informative for this node in this run — the fired
    contributing units, plus (declarative nodes) the informative absences —
    and for each re-runs exact inference with that unit additionally masked,
    globally: if a unit also feeds another node, the counterfactual world
    lacks the observation everywhere, which is the honest reading of "had
    this unit not been observed". Sorted by absolute delta descending, ties
    broken by unit name, so the output is diff-stable.
    """
    units: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for ev in contributing:
        unit = _unit_name(ev)
        if unit not in seen:
            seen.add(unit)
            units.append((unit, "group" if ev.group is not None else ev.kind, "fired"))
    if node.missingness == "declarative":
        for unit, kind in _informative_absent_units(node, fired, masked):
            if unit not in seen:
                seen.add(unit)
                units.append((unit, kind, "absent"))
    if not units:
        return ()
    out: list[UnitCounterfactual] = []
    for unit, kind, observed in units:
        cf_factors, _ = _build_factors(network, slug_set, signal_set, masked | {unit})
        cf_marginal = _query_marginal(cf_factors, node.name, all_vars)
        cf_post = max(0.0, min(1.0, cf_marginal.get("present", 0.5)))
        out.append(
            UnitCounterfactual(
                unit=unit,
                kind=kind,
                observed=observed,
                posterior_without=round(cf_post, 4),
                delta=round(posterior - cf_post, 4),
            )
        )
    out.sort(key=lambda c: (-abs(c.delta), c.unit))
    return tuple(out)


def infer(
    network: BayesianNetwork,
    observed_slugs: Iterable[str],
    observed_signals: Iterable[str],
    conflict_field_count: int = 0,
    priors_override: dict[str, float] | None = None,
    conflicts: tuple[ConflictProvenance, ...] = (),
    masked_units: Iterable[str] = (),
) -> InferenceResult:
    """Run inference for one domain.

    Args:
        network: the loaded Bayesian network.
        observed_slugs: slug names emitted by the deterministic
            pipeline for this domain.
        observed_signals: signal names emitted by the signal layer
            for this domain.
        conflict_field_count: number of fields with cross-source
            conflict for this domain (from
            ``info.merge_conflicts``). Each conflict subtracts
            ``_CONFLICT_N_EFF_PENALTY`` from n_eff for nodes whose
            evidence overlaps the conflict surface; we apply it
            globally as a conservative dampener. Ignored when
            ``conflicts`` is non-empty (the count is derived from
            ``len(conflicts)`` in that case).
        priors_override: optional mapping of node-name → new prior.
            When provided, supersedes the default ``load_priors_override``
            file lookup. Pass an empty dict to skip override entirely.
        conflicts: structured per-conflict details (field, sources,
            magnitude). When supplied, these surface on every
            ``NodePosterior.conflict_provenance`` and replace the count
            argument. Empty tuple preserves the legacy count-only path.
        masked_units: evidence units to treat as *structurally
            unobserved* — the exact leave-one-unit-out counterfactual
            primitive. A unit is a correlation-group name (e.g.
            ``m365_indicators``, ``dmarc_policy``) or an ungrouped
            binding's slug/signal name (e.g. ``okta``, ``spf_strict``);
            individual members of a group cannot be masked separately
            because the model treats a group as one observation. A
            masked unit contributes nothing in either direction: its
            fired bindings are dropped from the evidence (and from
            ``evidence_used`` / ``evidence_ranked`` / ``n_eff``), and on
            declarative nodes its informative-absence factor is
            suppressed too — which is what distinguishes "unobserved"
            from "observed to be absent" there. On hideable nodes,
            masking a unit is exactly equivalent to its bindings never
            firing (the MNAR absence rule already contributes LR=1).
            Default empty: behaviour is unchanged. Used by the held-out
            reference calibration (mask the unit that defines the label,
            so predictor and label are disjoint) and the
            evidence-semantics counterfactual diagnostics.

    Returns:
        ``InferenceResult`` with one ``NodePosterior`` per node.
    """
    if priors_override is None:
        priors_override = load_priors_override()
    network = _apply_priors_override(network, priors_override)

    if conflicts:
        conflict_field_count = len(conflicts)
    calibration = _network_calibration(network)

    slug_set = set(observed_slugs)
    signal_set = set(observed_signals)
    masked = frozenset(masked_units)

    factors, fired_per_node = _build_factors(network, slug_set, signal_set, masked)

    all_vars = list(network.node_names)

    posteriors: list[NodePosterior] = []
    total_entropy_reduction = 0.0
    total_evidence = 0
    for node in network.nodes:
        marginal = _query_marginal(factors, node.name, all_vars)
        post = marginal.get("present", 0.5)
        # Posterior should be a real probability in [0, 1].
        post = max(0.0, min(1.0, post))
        fired = fired_per_node[node.name]
        # CAL7: correlated co-firing bindings that share a group are redundant
        # readings of one underlying fact, so the posterior uses one effective
        # binding per group (_contributing_evidence). Reporting, n_eff, and
        # influence ranking use that same contributing set, not the raw fired
        # list, otherwise they over-count grouped evidence and report it as
        # separate influence with too tight a band. See correlation.md section 3.2.
        contributing = _contributing_evidence(fired)
        informative_absences = (
            _informative_absent_units(node, fired, masked) if node.missingness == "declarative" else []
        )
        total_evidence += len(contributing)
        # Hideable nodes count contributing bindings; declarative nodes also
        # count informative absences (CAL14), so a confidently-absent policy
        # node gets a narrower band around a low posterior rather than a
        # wide "sparse" one.
        n_eff_count = (
            _declarative_evidence_count(node, fired, masked) if node.missingness == "declarative" else len(contributing)
        )
        n_eff = max(
            calibration.min_n_eff,
            calibration.min_n_eff
            + n_eff_count * calibration.evidence_n_eff_contrib
            - conflict_field_count * calibration.conflict_n_eff_penalty,
        )
        low, high = credible_interval(post, n_eff)

        # Entropy reduction relative to prior. Prior comes from the
        # marginal under no evidence — recompute against an
        # evidence-free factor set.
        prior_marginal = _prior_marginal(network, node.name)
        prior_p = prior_marginal.get("present", 0.5)
        # Signed: negative when evidence widens this node (rare). Kept as a net
        # marginal entropy-change diagnostic, not clamped. It is not pointwise
        # information gain, and summing dependent nodes can double count.
        entropy_reduction = _binary_entropy(prior_p) - _binary_entropy(post)
        total_entropy_reduction += entropy_reduction

        evidence_ranked = _rank_evidence(contributing)
        counterfactuals = _unit_counterfactuals(
            network, node, post, contributing, fired, slug_set, signal_set, masked, all_vars
        )

        posteriors.append(
            NodePosterior(
                name=node.name,
                description=node.description,
                posterior=round(post, 4),
                interval_low=round(low, 4),
                interval_high=round(high, 4),
                # evidence_used lists every fired binding (what was observed);
                # the influence ranking above reflects the contributing set.
                evidence_used=tuple(f"{ev.kind}:{ev.name}" for ev in fired),
                n_eff=round(n_eff, 2),
                sparse=n_eff <= calibration.min_n_eff,
                conflict_provenance=conflicts,
                evidence_ranked=evidence_ranked,
                # True only when at least one unmasked, successfully observed
                # non-fire contributes a non-neutral absence likelihood. The
                # node's declarative policy alone is insufficient: structurally
                # unobserved units must not license an "absent" rendering.
                absence_informative=bool(informative_absences),
                entropy_reduction_nats=round(entropy_reduction, 4),
                unit_counterfactuals=counterfactuals,
            )
        )

    return InferenceResult(
        posteriors=tuple(posteriors),
        entropy_reduction=round(total_entropy_reduction, 4),
        evidence_count=total_evidence,
        conflict_count=conflict_field_count,
    )


def _prior_marginal(network: BayesianNetwork, query: str) -> dict[str, float]:
    """Marginal :math:`P(\\text{query})` with no evidence."""
    factors = [_factor_for_node(n) for n in network.nodes]
    return _query_marginal(factors, query, list(network.node_names))


def _binary_entropy(p: float) -> float:
    """Shannon entropy in nats for a binary outcome with probability p."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log(p) + (1.0 - p) * math.log(1.0 - p))


def _rank_evidence(fired: Iterable[_Evidence]) -> tuple[EvidenceContribution, ...]:
    """Rank fired bindings by absolute LLR contribution.

    For each binding that fired, compute
    :math:`\\text{LLR} = \\log\\!\\bigl(\\ell_{\\text{present}} /
    \\ell_{\\text{absent}}\\bigr)` where the likelihoods come from the
    binding's YAML entry. ``influence_pct`` normalizes ``|LLR|`` across
    all fired bindings for the same node so the operator sees a share,
    not a raw nats value, in the rendered output.

    Sorted by absolute LLR descending. Ties on absolute LLR are broken
    by ``(kind, name)`` ascending so the order is deterministic — this
    matters for the snapshot test pinning ``--explain-dag`` output.

    Returns an empty tuple when no bindings fired.
    """
    fired_list = list(fired)
    if not fired_list:
        return ()
    raw: list[tuple[_Evidence, float]] = []
    for ev in fired_list:
        # Schema guarantees both likelihoods in the open interval (0, 1),
        # so the ratio is positive and the log is finite — no clamp
        # needed. We still defend against a future schema relaxation by
        # clamping if either side rounds to exactly 0; behaviour stays
        # honest (LLR magnitude grows large but doesn't overflow).
        present = max(ev.likelihood_present, 1e-12)
        absent = max(ev.likelihood_absent, 1e-12)
        raw.append((ev, math.log(present / absent)))
    abs_sum = sum(abs(llr) for _, llr in raw) or 1.0
    ranked = sorted(
        raw,
        key=lambda pair: (-abs(pair[1]), pair[0].kind, pair[0].name),
    )
    return tuple(
        EvidenceContribution(
            kind=ev.kind,
            name=ev.name,
            llr=round(llr, 4),
            influence_pct=round(100.0 * abs(llr) / abs_sum, 2),
        )
        for ev, llr in ranked
    )


# ── TenantInfo adapter ────────────────────────────────────────────────


_CONFLICT_FIELDS: tuple[str, ...] = (
    "display_name",
    "auth_type",
    "region",
    "tenant_id",
    "dmarc_policy",
    "google_auth_type",
)


def _conflict_provenance(
    info: object,
    conflict_n_eff_penalty: float = _CONFLICT_N_EFF_PENALTY,
) -> tuple[ConflictProvenance, ...]:
    """Extract per-field conflict records from a TenantInfo's merge_conflicts.

    Returns empty tuple when there are no conflicts. Each record names
    the field, every source that contributed a candidate value, and the
    n_eff penalty this conflict applied (uniform at v1.9.1).
    """
    merge_conflicts = getattr(info, "merge_conflicts", None)
    if merge_conflicts is None:
        return ()
    out: list[ConflictProvenance] = []
    for field in _CONFLICT_FIELDS:
        candidates = getattr(merge_conflicts, field, ())
        if not candidates:
            continue
        sources: list[str] = []
        seen: set[str] = set()
        for c in candidates:
            src = getattr(c, "source", "")
            if src and src not in seen:
                sources.append(src)
                seen.add(src)
        out.append(
            ConflictProvenance(
                field=field,
                sources=tuple(sources),
                magnitude=conflict_n_eff_penalty,
            )
        )
    return tuple(out)


def infer_from_tenant_info(
    info: object,
    network: BayesianNetwork | None = None,
    priors_override: dict[str, float] | None = None,
    masked_units: Iterable[str] = (),
) -> InferenceResult:
    """Convenience wrapper that runs inference from a ``TenantInfo``.

    Args:
        info: a ``TenantInfo`` instance (typed as ``object`` to avoid
            importing the heavy models module at load time).
        network: optionally supply a pre-loaded network. When omitted,
            the bundled YAML is loaded on each call (cheap — small file).
        priors_override: as for ``infer``.
        masked_units: as for ``infer`` — evidence units to treat as
            structurally unobserved. Collection failures recorded in
            ``info.degraded_sources`` are unioned with this caller-supplied
            mask so an unavailable channel cannot become declarative absence.

    Returns:
        ``InferenceResult`` ready for serialization or downstream use.
    """
    from recon_tool.collection_view import collection_claim_info
    from recon_tool.models import TenantInfo

    if network is None:
        network = load_network()
    observable_info = collection_claim_info(info) if isinstance(info, TenantInfo) else info
    slugs = set(getattr(observable_info, "slugs", ()) or ())
    signals = signals_from_tenant_info(observable_info)
    conflict_records = _conflict_provenance(info, _network_calibration(network).conflict_n_eff_penalty)
    collection_mask = collection_masked_units(getattr(info, "degraded_sources", ()) or (), network)
    effective_mask = collection_mask | frozenset(masked_units)
    return infer(
        network,
        observed_slugs=slugs,
        observed_signals=signals,
        conflict_field_count=len(conflict_records),
        priors_override=priors_override,
        conflicts=conflict_records,
        masked_units=effective_mask,
    )
