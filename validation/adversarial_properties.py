"""Machine-checked adversarial properties of the inference layer.

This harness ships the suppression-monotonicity theorem
(correlation.md section 4.3) as an exhaustive, checkable invariant. The
theorem's plain statement: an operator who hides indicators can only move
a claim toward "we cannot tell," never toward a confident wrong answer.
Formally, for a node X with all other evidence fixed, the presence
posterior factors as a baseline odds times a product of per-binding
likelihood ratios, and under the positive-indicator hypothesis
(alpha_b >= beta_b for every binding, a fired slug favours presence) the
posterior is monotone non-decreasing in the fired set and bounded in
[baseline, fully-observed].

Two checks, both over the shipped network:

  * ``positive_indicator_violations`` verifies the theorem's one
    hypothesis as a catalogue invariant: every binding has
    ``likelihood_present >= likelihood_absent``. A negative-indicator
    binding would break the guarantee, so this is a standing gate on the
    network YAML.
  * ``suppression_violations`` verifies the conclusion on the engine
    itself: for every node, over every subset of its bindings, the
    presence posterior never rises when a fired binding is hidden, and
    stays within [no-evidence baseline, all-fired]. Because the node
    observation factor enters the marginal multiplicatively (the exact
    factorisation differential_verification.py confirms), checking the
    no-external-evidence instance is sufficient: external evidence only
    rescales the baseline odds by a positive constant and cannot change
    the sign of a per-binding likelihood ratio.

Synthetic and offline: no corpus, no network calls, no target data. The
nine-node network has at most four bindings on any node, so the full
per-node subset sweep is trivially enumerable.

Run:

    python -m validation.adversarial_properties
"""

# Reaches into the parsed network dataclasses (_Node / _Evidence), the same
# white-box allowance the differential-verification oracle takes.
# pyright: reportPrivateUsage=false
from __future__ import annotations

import sys
from itertools import chain, combinations
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.bayesian import BayesianNetwork, _Evidence, _Node, infer, load_network  # noqa: E402

# Reported posteriors are rounded to four decimals, so a correct engine can
# differ from an exact comparison by at most half a unit in the fourth place.
_TOL = 6e-5


def _subsets(items: list[_Evidence]) -> list[tuple[_Evidence, ...]]:
    return list(chain.from_iterable(combinations(items, r) for r in range(len(items) + 1)))


def node_presence_posterior(network: BayesianNetwork, node: _Node, fired: tuple[_Evidence, ...]) -> float:
    """``P(node = present | fired)`` with no other evidence, via the engine."""
    slugs = [e.name for e in fired if e.kind == "slug"]
    signals = [e.name for e in fired if e.kind == "signal"]
    result = infer(network, slugs, signals, priors_override={})
    for p in result.posteriors:
        if p.name == node.name:
            return p.posterior
    raise KeyError(node.name)


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


def suppression_violations(network: BayesianNetwork, tol: float = _TOL) -> list[str]:
    """Subsets where hiding a fired binding raises the posterior, or where the
    posterior escapes [baseline, fully-observed]. Empty list means the theorem
    holds on the engine for this network."""
    out: list[str] = []
    for node in network.nodes:
        evidence = list(node.evidence)
        if not evidence:
            continue
        post: dict[frozenset[str], float] = {}
        for subset in _subsets(evidence):
            post[frozenset(e.name for e in subset)] = node_presence_posterior(network, node, subset)
        baseline = post[frozenset()]
        full = post[frozenset(e.name for e in evidence)]
        for subset in _subsets(evidence):
            key = frozenset(e.name for e in subset)
            p = post[key]
            if not (baseline - tol <= p <= full + tol):
                out.append(f"{node.name}: subset {sorted(key)} posterior {p} outside [{baseline}, {full}]")
            for e in subset:
                p_hidden = post[key - {e.name}]
                if p_hidden > p + tol:
                    out.append(
                        f"{node.name}: hiding {e.name!r} from {sorted(key)} raised the posterior "
                        f"{p} -> {p_hidden} (suppression must not increase presence)"
                    )
    return out


def main() -> int:
    network = load_network()
    pos = positive_indicator_violations(network)
    sup = suppression_violations(network)

    print("Adversarial-property check over the shipped network")
    print(f"  positive-indicator hypothesis (alpha >= beta): {len(pos)} violation(s)")
    print(f"  suppression monotonicity + bounds:             {len(sup)} violation(s)")
    if pos:
        print("\nPositive-indicator violations:")
        for v in pos:
            print(f"  {v}")
    if sup:
        print("\nSuppression violations:")
        for v in sup:
            print(f"  {v}")
    if pos or sup:
        print("\nFAIL: the suppression guarantee (correlation.md 4.3) does not hold as stated.")
        return 1
    print("\nOK: hiding any fired binding only moves a claim toward the baseline; no false")
    print("positive can be manufactured by suppression. The theorem holds on the engine.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
