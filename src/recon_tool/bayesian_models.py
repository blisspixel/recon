"""Frozen result/model dataclasses for the Bayesian inference layer.

Extracted from ``bayesian.py`` (docs/roadmap.md god-file track). Pure data: no
I/O, no inference, no loaders. ``bayesian.py`` re-exports every name (and aliases
``Evidence`` / ``Node`` back to their historical ``_Evidence`` / ``_Node``
spellings), so the ``recon_tool.bayesian`` import path is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Evidence:
    """One observable binding for a node."""

    kind: str  # "slug" or "signal"
    name: str
    likelihood_present: float  # P(observed | node=present)
    likelihood_absent: float  # P(observed | node=absent)
    # Optional correlation group. Bindings that share a group are treated as
    # redundant readings of one underlying fact (conditionally dependent given
    # the node), so a group contributes only its strongest fired binding rather
    # than the naive independent product. None = independent (legacy behaviour).
    # See correlation.md §4.3 "Conditionally-dependent bindings".
    group: str | None = None


@dataclass(frozen=True)
class Node:
    """One node in the Bayesian network."""

    name: str
    description: str
    parents: tuple[str, ...]
    # Either prior (no parents) is set, or cpt (with parents) is set.
    prior: float | None
    # CPT keyed on parent assignment string ("p1=present,p2=absent")
    # mapping to P(this_node=present | parents=that assignment).
    cpt: dict[str, float]
    evidence: tuple[Evidence, ...]
    # Missingness model for non-firing bindings (roadmap CAL14).
    #   "hideable" (default): a non-firing binding contributes nothing
    #     (LR=1). Correct for infrastructure an operator can hide.
    #   "declarative": a binding that could fire but did not is genuine
    #     disconfirming evidence (public declarations like DMARC/SPF whose
    #     absence cannot be hidden from passive DNS).
    missingness: str = "hideable"
    # For declarative nodes only: the absence likelihood of a mutually-
    # exclusive evidence group, as (group_name, P(no member | present),
    # P(no member | absent)). Independent declarative bindings use the
    # complement of their own likelihood; a group needs an explicit pair
    # because its members are alternatives, not independent features.
    group_absence: tuple[tuple[str, float, float], ...] = ()


@dataclass(frozen=True)
class CalibrationSettings:
    """Effective-sample-size settings for Bayesian interval reporting."""

    min_n_eff: float = 4.0
    evidence_n_eff_contrib: float = 1.0
    conflict_n_eff_penalty: float = 1.5


@dataclass(frozen=True)
class BayesianNetwork:
    """Loaded network ready for inference."""

    version: int
    nodes: tuple[Node, ...]
    calibration: CalibrationSettings = field(default_factory=CalibrationSettings)

    @property
    def node_names(self) -> tuple[str, ...]:
        return tuple(n.name for n in self.nodes)

    def get(self, name: str) -> Node:
        for n in self.nodes:
            if n.name == name:
                return n
        raise KeyError(f"node not in network: {name!r}")


@dataclass(frozen=True)
class ConflictProvenance:
    """One cross-source disagreement that dampened a node's interval.

    ``field`` is the merged ``TenantInfo`` field whose sources disagreed
    (e.g. ``auth_type``, ``dmarc_policy``). ``sources`` lists every
    distinct source that contributed a candidate value for that field.
    ``magnitude`` is the n_eff penalty (in n_eff units) this single
    conflict subtracted from the node's effective sample size — uniform
    at v1.9.1 ship time, but exposed as a number so future per-node
    relevance weighting can refine without breaking the JSON shape.
    """

    field: str
    sources: tuple[str, ...]
    magnitude: float


@dataclass(frozen=True)
class EvidenceContribution:
    """One bound observation's quantified influence on a node's posterior.

    The log-likelihood-ratio (LLR) for a binding that fired is
    :math:`\\log\\!\\bigl(P(\\text{obs}\\mid\\text{present})\\;/\\;P(\\text{obs}\\mid\\text{absent})\\bigr)`,
    positive when the observation favours ``present`` and negative when
    it favours ``absent``. ``influence_pct`` is this binding's
    ``|llr|`` normalized to a percentage across all fired bindings for
    the same node — the renderer uses it to surface "this evidence
    drove 42% of the posterior shift" without forcing the reader to
    convert nats to a share.

    Added v1.9.3.2 to support top-3 influential-edge rendering in
    ``--explain-dag``. Schema-additive: the default empty tuple on
    ``NodePosterior.evidence_ranked`` preserves the v1.9.0 shape for
    consumers that don't read this field.
    """

    kind: str  # "slug" or "signal"
    name: str
    llr: float  # natural-log likelihood ratio for the fired observation
    influence_pct: float  # |llr| / sum(|llr|) * 100 across this node's fired bindings


@dataclass(frozen=True)
class UnitCounterfactual:
    """One evidence unit's exact leave-one-out influence on a node's posterior.

    For each evidence unit that is informative for a node in this run (a
    fired unit, or — on a declarative node — an informatively-absent unit),
    the engine re-runs exact inference with that unit masked as structurally
    unobserved (``masked_units``) and reports the counterfactual posterior
    and the delta the unit contributes. This is an *evidence counterfactual
    over the model* — "what would this claim's posterior be had this unit
    not been observed" — never a causal claim about the world.

    ``observed`` is ``"fired"`` when the unit's evidence fired, or
    ``"absent"`` when the unit is an informative absence on a declarative
    node (there, ``delta`` is typically negative: the absence drags the
    posterior down, so removing it raises the counterfactual). ``delta`` is
    ``posterior - posterior_without``: positive when the unit pushes the
    node up, negative when it pushes it down.

    Two reading rules. The mask is global and the inference exact, so
    ``posterior_without`` reflects everything else still observed — including
    support flowing through the DAG from other nodes' evidence (a masked
    ``m365_indicators`` does not drop ``m365_tenant`` to its prior while a
    federation signal still supports it through the child CPT). And the
    deltas are individually exact but **not additive**: units interact
    through the DAG, so the sum of deltas need not equal the distance to the
    all-masked posterior.

    Added in 2.2.0 as part of the evidence-semantics diagnostics;
    schema-additive (the default empty tuple on
    ``NodePosterior.unit_counterfactuals`` preserves prior shapes).
    """

    unit: str  # group name, or the ungrouped binding's slug/signal name
    kind: str  # "group", "slug", or "signal"
    observed: str  # "fired" or "absent"
    posterior_without: float  # P(node=present | E with this unit masked)
    delta: float  # posterior - posterior_without


@dataclass(frozen=True)
class NodePosterior:
    """Per-node inference output."""

    name: str
    description: str
    posterior: float  # P(node=present | E) in [0, 1]
    interval_low: float  # 80% credible interval lower bound
    interval_high: float  # 80% credible interval upper bound
    evidence_used: tuple[str, ...]  # observed bindings that fired for this node
    n_eff: float  # effective sample size used to derive interval
    sparse: bool  # True when n_eff <= _MIN_N_EFF (wide interval)
    conflict_provenance: tuple[ConflictProvenance, ...] = ()
    """Cross-source conflicts that contributed to this node's n_eff
    penalty. Empty tuple when no conflicts dampened the interval. v1.9.1
    surfaces the same provenance on every node (penalty is global);
    schema is stable for future per-node relevance refinement."""
    evidence_ranked: tuple[EvidenceContribution, ...] = ()
    """Bindings ranked by absolute LLR contribution (descending), ties
    broken by binding name for diff-stability. The contributing set (one
    per correlation group, CAL7), not every fired binding, so the influence
    shares reflect what actually moved the posterior. Empty tuple when no
    bindings fired. Added v1.9.3.2 for top-3 influential-edge rendering in
    ``--explain-dag``; schema-additive."""

    absence_informative: bool = False
    """True for a declarative node (CAL14), where the absence of an expected
    public declaration (DMARC / SPF / MTA-STS) is itself evidence that moves
    the posterior. Lets the explanation renderer avoid the "no evidence,
    follows priors" phrasing when an empty ``evidence_used`` reflects
    informative absence rather than missing data. Default False keeps
    hideable nodes unchanged."""

    entropy_reduction_nats: float = 0.0
    """This node's share of the information recovered: H(prior marginal) -
    H(posterior), in nats, signed (negative when evidence widens the node).
    The per-node breakdown of the existing ``InferenceResult``-level total
    (CAL10). Added in 2.2.0; schema-additive."""

    unit_counterfactuals: tuple[UnitCounterfactual, ...] = ()
    """Exact leave-one-unit-out counterfactuals for every evidence unit that
    is informative for this node in this run, sorted by absolute delta
    descending (ties broken by unit name for diff-stability). Empty when no
    unit is informative. Added in 2.2.0; schema-additive."""


@dataclass(frozen=True)
class InferenceResult:
    """Full inference output for a domain."""

    posteriors: tuple[NodePosterior, ...]
    entropy_reduction: float  # nats, signed: sum of H(prior) - H(posterior); negative when evidence widens a node
    evidence_count: int  # total observed bindings across all nodes
    conflict_count: int  # cross-source conflicts that dampened intervals
