"""Machine-checked adversarial properties of the inference layer.

This harness checks the local suppression property described in
correlation.md section 3.4. The narrow statement is that, under the listed
hypotheses and sampled external contexts, deleting positive fired bindings does
not raise the presence posterior. It does not guarantee movement toward 0.5, a
wider uncertainty band, or protection from a confident absence error. Formally,
fixing all evidence outside a node X, the presence posterior is monotone
non-decreasing in X's fired set and bounded in [B_X, fully-observed], under
the hypotheses (every fired binding a positive indicator, alpha_b >= beta_b;
and on a declarative node every not-fired factor disconfirming, ratio <= 1).
The suppression floor B_X is the all-absent observation posterior: for a
hideable node it equals the prior baseline, but for the declarative node it
sits below the prior, because the absence of a public declaration is itself
disconfirming. The clean factorisation "prior baseline odds times a product
of per-unit likelihood ratios" is exact only for an evidence-isolated root;
for a node with parents or children the external evidence rescales the
baseline (and B_X) and couples slightly through the polytree, so the
no-external-evidence instance does not by itself settle the conclusion. The
proposition predicts monotonicity under any fixed external context because the
local observation factor enters multiplicatively. The harness checks every
local subset under a representative, not exhaustive, set of external contexts.

Three checks, all over the shipped network:

  * ``positive_indicator_violations`` verifies the first hypothesis as a
    catalogue invariant: every fired binding has
    ``likelihood_present >= likelihood_absent``. A negative-indicator
    binding would break the guarantee, so this is a standing gate on the
    network YAML.
  * ``disconfirming_absence_violations`` verifies the second hypothesis on
    the declarative node: every ``group_absence`` pair is disconfirming
    (``present <= absent``), so a missing public declaration favours absent
    and hiding a fired group member can only lower the posterior. Without
    this, an all-absent group could favour presence and break monotonicity.
  * ``suppression_violations`` verifies the conclusion on the engine
    itself: for every node, over every subset of its bindings, swept under a
    set of representative external-evidence contexts, the presence posterior
    never rises when a fired binding is hidden and stays within
    [B_X, all-fired], with B_X recomputed per context (it depends on the
    external evidence). The contexts are the extremes (no external evidence;
    every other node firing its strongest binding) and each other node firing
    its strongest binding alone, which exercises X's Markov blanket without a
    2^k blow-up; bindings whose name collides with X's own are excluded so
    external evidence never fires a binding of X. This replaces an earlier,
    incorrect justification that the no-external-evidence instance alone
    sufficed.

Synthetic and offline: no corpus, no network calls, no target data. The
nine-node network has at most four bindings on any node, so the per-node
subset sweep under the sampled contexts is small and enumerable.

Run:

    python -m validation.adversarial_properties
"""

# Reaches into the parsed network dataclasses (_Node / _Evidence), the same
# white-box allowance the differential-verification oracle takes.
# pyright: reportPrivateUsage=false
from __future__ import annotations

import sys
from dataclasses import dataclass
from itertools import chain, combinations
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.bayesian import BayesianNetwork, _Evidence, _Node, infer, load_network  # noqa: E402

# Reported posteriors are rounded to four decimals, so a correct engine can
# differ from an exact comparison by at most half a unit in the fourth place.
_TOL = 6e-5


@dataclass(frozen=True)
class PerturbationSummary:
    """Aggregate add/remove evidence movement for one node."""

    node: str
    contexts: int
    paired_cases: int
    max_stripping_drop: float
    max_planting_lift: float
    threshold_crossings: int
    max_planted_posterior: float


def _subsets(items: list[_Evidence]) -> list[tuple[_Evidence, ...]]:
    return list(chain.from_iterable(combinations(items, r) for r in range(len(items) + 1)))


def node_presence_posterior(
    network: BayesianNetwork,
    node: _Node,
    fired: tuple[_Evidence, ...],
    ext_slugs: tuple[str, ...] = (),
    ext_signals: tuple[str, ...] = (),
) -> float:
    """``P(node = present | fired, external)`` via the engine.

    ``ext_slugs`` / ``ext_signals`` are evidence on *other* nodes, the external
    context the proposition holds fixed. With both empty this is the
    no-external-evidence instance.
    """
    slugs = [e.name for e in fired if e.kind == "slug"] + list(ext_slugs)
    signals = [e.name for e in fired if e.kind == "signal"] + list(ext_signals)
    result = infer(network, slugs, signals, priors_override={})
    for p in result.posteriors:
        if p.name == node.name:
            return p.posterior
    raise KeyError(node.name)


def _binding_strength(e: _Evidence) -> float:
    return e.likelihood_present / e.likelihood_absent


def _external_contexts(network: BayesianNetwork, node: _Node) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    """Representative external-evidence contexts for testing ``node`` under coupling.

    The proposition fixes all evidence outside X; the floor B_X and the realized
    odds depend on that external evidence, so the no-external instance alone does
    not establish the conclusion for a node with parents or children. We sweep
    the extremes (no external evidence; every other node firing its strongest
    binding) and each other node firing its strongest binding alone, which
    exercises X's Markov blanket without a 2^k blow-up. Bindings whose name
    collides with one of X's own are excluded, so external evidence never
    accidentally fires a binding of X.
    """
    own = {e.name for e in node.evidence}
    others: list[_Evidence] = []
    for n in network.nodes:
        if n.name == node.name:
            continue
        fireable = [e for e in n.evidence if e.name not in own]
        if fireable:
            others.append(max(fireable, key=_binding_strength))

    def split(evs: list[_Evidence]) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return (
            tuple(e.name for e in evs if e.kind == "slug"),
            tuple(e.name for e in evs if e.kind == "signal"),
        )

    contexts: list[tuple[tuple[str, ...], tuple[str, ...]]] = [((), ())]
    for e in others:
        contexts.append(split([e]))
    contexts.append(split(others))
    return contexts


def positive_indicator_violations(network: BayesianNetwork) -> list[str]:
    """Bindings that violate the positive-indicator hypothesis (alpha >= beta)."""
    out: list[str] = []
    for n in network.nodes:
        for e in n.evidence:
            if e.likelihood_present < e.likelihood_absent:
                out.append(
                    f"{n.name}/{e.name}: likelihood_present {e.likelihood_present} "
                    f"< likelihood_absent {e.likelihood_absent} (not a positive indicator)"
                )
    return out


def disconfirming_absence_violations(network: BayesianNetwork) -> list[str]:
    """Declarative ``group_absence`` pairs that are not disconfirming.

    The declarative branch of the proposition needs every not-fired factor to
    have ratio <= 1, so hiding a fired binding can only lower the posterior. For
    a mutually-exclusive group that means the ``group_absence`` likelihood of
    presence must not exceed its likelihood of absence; otherwise an all-absent
    group would favour presence and break monotonicity. (Independent non-fired
    bindings use the complement ``(1 - present) / (1 - absent)``, which is
    already <= 1 whenever the positive-indicator check passes.)
    """
    out: list[str] = []
    for n in network.nodes:
        if n.missingness != "declarative":
            continue
        for group, lp, la in n.group_absence:
            if lp > la:
                out.append(
                    f"{n.name}/{group}: group_absence present {lp} > absent {la} "
                    f"(a missing public declaration must favour absent)"
                )
    return out


def suppression_violations(network: BayesianNetwork, tol: float = _TOL) -> list[str]:
    """Subsets where hiding a fired binding raises the posterior, or where the
    posterior escapes [B_X, fully-observed], swept over representative external-
    evidence contexts. B_X (the all-absent posterior) is recomputed per context,
    since it depends on the external evidence. Empty list means the proposition
    holds on the engine for this network."""
    out: list[str] = []
    for node in network.nodes:
        evidence = list(node.evidence)
        if not evidence:
            continue
        for ext_slugs, ext_signals in _external_contexts(network, node):
            ctx = sorted(ext_slugs) + sorted(ext_signals)
            post: dict[frozenset[str], float] = {}
            for subset in _subsets(evidence):
                post[frozenset(e.name for e in subset)] = node_presence_posterior(
                    network, node, subset, ext_slugs, ext_signals
                )
            baseline = post[frozenset()]
            full = post[frozenset(e.name for e in evidence)]
            for subset in _subsets(evidence):
                key = frozenset(e.name for e in subset)
                p = post[key]
                if not (baseline - tol <= p <= full + tol):
                    out.append(
                        f"{node.name} [ext {ctx}]: subset {sorted(key)} posterior {p} "
                        f"outside [{baseline}, {full}]"
                    )
                for e in subset:
                    p_hidden = post[key - {e.name}]
                    if p_hidden > p + tol:
                        out.append(
                            f"{node.name} [ext {ctx}]: hiding {e.name!r} from {sorted(key)} "
                            f"raised the posterior {p} -> {p_hidden}"
                        )
    return out


def perturbation_summaries(network: BayesianNetwork) -> list[PerturbationSummary]:
    """Measure posterior movement under paired stripping and planting.

    Each pair compares the same external context and the same fired set, once
    without a binding and once with that binding. Reading the pair as removal
    gives stripping movement. Reading it as addition gives planting movement.
    This is synthetic and model-internal: it measures the threat-model boundary,
    not attacker prevalence or real-domain exploitability.
    """
    rows: list[PerturbationSummary] = []
    for node in network.nodes:
        evidence = list(node.evidence)
        if not evidence:
            continue
        contexts = _external_contexts(network, node)
        paired_cases = 0
        max_stripping_drop = 0.0
        max_planting_lift = 0.0
        max_planted_posterior = 0.0
        threshold_crossings = 0
        for ext_slugs, ext_signals in contexts:
            post: dict[frozenset[str], float] = {}
            for subset in _subsets(evidence):
                post[frozenset(e.name for e in subset)] = node_presence_posterior(
                    network, node, subset, ext_slugs, ext_signals
                )
            for subset in _subsets(evidence):
                without = frozenset(e.name for e in subset)
                for evidence_unit in evidence:
                    if evidence_unit.name in without:
                        continue
                    with_unit = without | {evidence_unit.name}
                    before = post[without]
                    after = post[with_unit]
                    lift = after - before
                    paired_cases += 1
                    if lift > max_planting_lift:
                        max_planting_lift = lift
                    if lift > max_stripping_drop:
                        max_stripping_drop = lift
                    if after > max_planted_posterior:
                        max_planted_posterior = after
                    if before < 0.5 <= after:
                        threshold_crossings += 1
        rows.append(
            PerturbationSummary(
                node=node.name,
                contexts=len(contexts),
                paired_cases=paired_cases,
                max_stripping_drop=round(max_stripping_drop, 4),
                max_planting_lift=round(max_planting_lift, 4),
                threshold_crossings=threshold_crossings,
                max_planted_posterior=round(max_planted_posterior, 4),
            )
        )
    return rows


def main() -> int:
    network = load_network()
    pos = positive_indicator_violations(network)
    absent = disconfirming_absence_violations(network)
    sup = suppression_violations(network)
    perturbations = perturbation_summaries(network)

    print("Adversarial-property check over the shipped network")
    print(f"  positive-indicator hypothesis (alpha >= beta):  {len(pos)} violation(s)")
    print(f"  disconfirming-absence hypothesis (declarative): {len(absent)} violation(s)")
    print(f"  suppression monotonicity + bounds:              {len(sup)} violation(s)")
    print(f"  add/remove perturbation summaries:              {len(perturbations)} node(s)")
    if pos:
        print("\nPositive-indicator violations:")
        for v in pos:
            print(f"  {v}")
    if absent:
        print("\nDisconfirming-absence violations:")
        for v in absent:
            print(f"  {v}")
    if sup:
        print("\nSuppression violations:")
        for v in sup:
            print(f"  {v}")
    if pos or absent or sup:
        print("\nFAIL: the local suppression property (correlation.md section 3.4) failed.")
        return 1
    print("\nAdd/remove perturbation measurement:")
    for row in perturbations:
        print(
            f"  {row.node}: contexts={row.contexts}, paired_cases={row.paired_cases}, "
            f"max_stripping_drop={row.max_stripping_drop:.4f}, "
            f"max_planting_lift={row.max_planting_lift:.4f}, "
            f"threshold_crossings={row.threshold_crossings}, "
            f"max_planted_posterior={row.max_planted_posterior:.4f}"
        )
    print("\nOK: in the tested contexts, deleting fired bindings does not raise the")
    print("presence posterior and moves it toward the context-specific all-absent floor.")
    print("This does not imply movement toward 0.5 or robustness to planted evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
