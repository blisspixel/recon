"""Differential verification of the Bayesian inference core.

The shipped engine (``recon_tool/bayesian.py``) answers each
``P(node = present | E)`` query by variable elimination: it builds a
prior/CPT factor per node and an observation-likelihood factor per node
with fired evidence, then multiplies and marginalizes those factors
(``_multiply`` / ``_sum_out`` / ``_query_marginal``). That machinery is
fast and exact, but "exact" is a claim, not a proof, and the factor
construction has real subtlety: correlation-group reduction (CAL7),
declarative absence conditioning (CAL14), and soft/virtual evidence
(likelihoods strictly in ``(0, 1)``, never hard 0/1).

This harness verifies that claim by brute force. It carries a *second,
independent* implementation that does no factor algebra at all: it
enumerates the full joint over the nine binary nodes (``2**9 = 512``
states), weights each state by the prior/CPT product and by the
per-node observation likelihood, and reads the marginal straight off
the normalized sum. Nothing here calls ``_factor_for_node``,
``_factor_for_evidence``, ``_multiply``, ``_sum_out``, or
``_query_marginal``; the only shared input is the loaded network data
(priors, CPTs, evidence bindings), which both implementations are
entitled to read. If variable elimination and naive enumeration agree
on every node for every evidence configuration, the elimination plumbing
and the factor construction are verified, not merely tested.

The evidence space swept is the ternary "local scenario" cross product
the roadmap describes (each node contributes none / one / all of its
bindings firing), deduplicated where a node has fewer than two bindings.
That cross product is enumerable in full, and on top of it the tricky
factor-construction nodes (the two correlation groups and the
declarative policy node) get an exhaustive per-node subset sweep so
every group-reduction and absence-conditioning branch is exercised
under several backgrounds.

The independent reference is anchored to hand computation in
``tests/test_bayesian_differential.py`` (the no-evidence root and
descendant marginals are checked against closed-form values), so the
cross-check is not circular: the reference is known-correct on the
cases a human can verify, and variable elimination is then held to the
reference everywhere.

Run:

    python validation/differential_verification.py
    python validation/differential_verification.py --tricky-only
    python validation/differential_verification.py --tol 1e-6
"""

# This harness verifies the inference core by reaching into its parsed network
# dataclasses (_Node / _Evidence), legitimate white-box access for a
# verification oracle, the same allowance the pyright config grants tests/.
# pyright: reportPrivateUsage=false
from __future__ import annotations

import argparse
import math
import sys
from collections.abc import Iterator
from itertools import combinations, product
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.bayesian import (  # noqa: E402
    BayesianNetwork,
    _Evidence,
    _Node,
    infer,
    load_network,
)

# The reported posteriors are rounded to four decimals by ``infer``, so a
# correct engine can differ from the exact reference by at most half a unit
# in the fourth place (5e-5). Anything materially larger is a real defect:
# a wrong CPT key, a missed absence factor, or a group counted twice all
# move a posterior by 0.01 to 0.5, orders of magnitude past this bound.
_DEFAULT_TOL = 6e-5

# Names of the factor-construction-heavy nodes that earn an exhaustive
# per-node subset sweep (every local fired-subset, not just none/one/all):
# the two correlation groups and the declarative absence-conditioning node.
_TRICKY_NODES = ("m365_tenant", "google_workspace_tenant", "email_security_policy_enforcing")


# ── Independent reference: naive full-joint enumeration ────────────────


def _binding_abs_llr(ev: _Evidence) -> float:
    """|log LR| for one binding. Used to pick a correlation group's lead."""
    return abs(math.log(ev.likelihood_present / ev.likelihood_absent))


def _reference_contributing(fired: list[_Evidence]) -> list[_Evidence]:
    """One effective binding per correlation group, plus every ungrouped one.

    Re-derived from the documented spec (correlation.md 4.3): bindings that
    share a ``group`` are redundant readings of one fact, so the group
    contributes only its strongest member (largest ``|log LR|``) rather than
    the product of all members. Written from the definition, independently of
    ``recon_tool.bayesian._contributing_evidence``.
    """
    ungrouped = [ev for ev in fired if ev.group is None]
    lead: dict[str, _Evidence] = {}
    for ev in fired:
        if ev.group is None:
            continue
        best = lead.get(ev.group)
        if best is None or _binding_abs_llr(ev) > _binding_abs_llr(best):
            lead[ev.group] = ev
    return ungrouped + list(lead.values())


def _reference_node_likelihood(node: _Node, fired: list[_Evidence]) -> tuple[float, float]:
    """``P(observation pattern for this node | node state)`` as ``(present, absent)``.

    Independent re-derivation of the observation factor:

    - Fired bindings (after group reduction) multiply in their likelihoods.
    - Hideable node: nothing else. A binding that did not fire says nothing,
      because passive collection cannot distinguish a truly-absent feature from
      a hidden one (the MNAR rule).
    - Declarative node: a binding that could fire but did not is genuine
      disconfirmation. An ungrouped non-firing binding multiplies in the
      complement of its likelihood; an entirely non-firing mutually-exclusive
      group multiplies in its explicit ``group_absence`` pair (once), because
      its members are alternatives, not independent features.
    """
    like_present = 1.0
    like_absent = 1.0
    for ev in _reference_contributing(fired):
        like_present *= ev.likelihood_present
        like_absent *= ev.likelihood_absent

    if node.missingness != "declarative":
        return like_present, like_absent

    fired_names = {ev.name for ev in fired}
    fired_groups = {ev.group for ev in fired if ev.group}
    group_absence = {g: (lp, la) for g, lp, la in node.group_absence}
    handled_groups: set[str] = set()
    for ev in node.evidence:
        if ev.name in fired_names:
            continue
        if ev.group:
            if ev.group in fired_groups or ev.group in handled_groups:
                continue
            handled_groups.add(ev.group)
            pair = group_absence.get(ev.group)
            if pair is not None:
                like_present *= pair[0]
                like_absent *= pair[1]
        else:
            like_present *= 1.0 - ev.likelihood_present
            like_absent *= 1.0 - ev.likelihood_absent
    return like_present, like_absent


def prior_joint(network: BayesianNetwork) -> tuple[list[str], list[tuple[tuple[str, ...], float]]]:
    """Precompute the prior/CPT weight of every full assignment (512 states).

    Evidence-independent, so the sweep computes it once and reuses it. Returns
    the node-name order and a list of ``(states_tuple, weight)`` where
    ``weight = prod_n P(n = state_n | parents = their states)``.
    """
    names = [n.name for n in network.nodes]
    index = {name: i for i, name in enumerate(names)}
    out: list[tuple[tuple[str, ...], float]] = []
    for combo in product(("present", "absent"), repeat=len(names)):
        weight = 1.0
        for node in network.nodes:
            if not node.parents:
                p_present = node.prior if node.prior is not None else 0.5
            else:
                key = ",".join(f"{p}={combo[index[p]]}" for p in node.parents)
                p_present = node.cpt[key]
            state = combo[index[node.name]]
            weight *= p_present if state == "present" else 1.0 - p_present
        out.append((combo, weight))
    return names, out


def reference_posteriors(
    network: BayesianNetwork,
    observed_slugs: set[str],
    observed_signals: set[str],
    joint: tuple[list[str], list[tuple[tuple[str, ...], float]]] | None = None,
) -> dict[str, float]:
    """``P(node = present | E)`` for every node, by naive joint enumeration.

    The independent oracle: no variable elimination, no factor objects. Weight
    each of the 512 full assignments by its prior/CPT product and by every
    node's observation likelihood for its state in that assignment, then sum
    and normalize.
    """
    names, states = joint if joint is not None else prior_joint(network)
    index = {name: i for i, name in enumerate(names)}

    node_likelihood: dict[str, tuple[float, float]] = {}
    for node in network.nodes:
        fired = [
            ev
            for ev in node.evidence
            if (ev.kind == "slug" and ev.name in observed_slugs)
            or (ev.kind == "signal" and ev.name in observed_signals)
        ]
        node_likelihood[node.name] = _reference_node_likelihood(node, fired)

    present_mass = dict.fromkeys(names, 0.0)
    total = 0.0
    for combo, prior_weight in states:
        weight = prior_weight
        for node in network.nodes:
            like_present, like_absent = node_likelihood[node.name]
            state = combo[index[node.name]]
            weight *= like_present if state == "present" else like_absent
        total += weight
        for name in names:
            if combo[index[name]] == "present":
                present_mass[name] += weight
    if total <= 0.0:
        return dict.fromkeys(names, 0.5)
    return {name: present_mass[name] / total for name in names}


# ── Evidence-configuration sweeps ──────────────────────────────────────


def _node_local_scenarios(node: _Node) -> list[tuple[_Evidence, ...]]:
    """The none / one / all fired-subsets for one node, deduplicated.

    A node with no bindings yields the single empty scenario; a single-binding
    node yields none/one (all == one); a multi-binding node yields all three.
    """
    ev = list(node.evidence)
    if not ev:
        return [()]
    candidates = [(), (ev[0],), tuple(ev)]
    seen: set[frozenset[str]] = set()
    scenarios: list[tuple[_Evidence, ...]] = []
    for subset in candidates:
        key = frozenset(e.name for e in subset)
        if key not in seen:
            seen.add(key)
            scenarios.append(subset)
    return scenarios


def _scenario_to_observed(subsets: tuple[tuple[_Evidence, ...], ...]) -> tuple[set[str], set[str]]:
    """Fold a per-node fired-subset selection into observed slug / signal sets."""
    slugs: set[str] = set()
    signals: set[str] = set()
    for subset in subsets:
        for ev in subset:
            (slugs if ev.kind == "slug" else signals).add(ev.name)
    return slugs, signals


def iter_structured_configs(network: BayesianNetwork) -> Iterator[tuple[set[str], set[str]]]:
    """The full ternary cross product: every node at none / one / all.

    This is the enumerable "3 states per node" sweep. The empty configuration
    (no evidence anywhere) and the all-firing configuration both fall out of it.
    """
    per_node = [_node_local_scenarios(node) for node in network.nodes]
    for selection in product(*per_node):
        yield _scenario_to_observed(tuple(selection))


def structured_config_count(network: BayesianNetwork) -> int:
    count = 1
    for node in network.nodes:
        count *= len(_node_local_scenarios(node))
    return count


def _all_local_subsets(node: _Node) -> list[tuple[_Evidence, ...]]:
    """Every fired-subset of a node's bindings (the full power set)."""
    ev = list(node.evidence)
    subsets: list[tuple[_Evidence, ...]] = []
    for r in range(len(ev) + 1):
        subsets.extend(combinations(ev, r))
    return subsets


def iter_tricky_configs(network: BayesianNetwork) -> Iterator[tuple[set[str], set[str]]]:
    """Exhaustive per-node subset sweep for the factor-heavy nodes.

    For each tricky node, walk its entire local power set while the rest of the
    network is held at two backgrounds (everything else absent, everything else
    fully firing), so group reduction and declarative absence conditioning are
    exercised against both a sparse and a dense surround.
    """
    tricky = [n for n in network.nodes if n.name in _TRICKY_NODES]
    others_absent = {n.name: () for n in network.nodes}
    others_all = {n.name: tuple(n.evidence) for n in network.nodes}
    for target in tricky:
        for background in (others_absent, others_all):
            for subset in _all_local_subsets(target):
                selection = dict(background)
                selection[target.name] = subset
                yield _scenario_to_observed(tuple(selection[n.name] for n in network.nodes))


# ── Comparison ─────────────────────────────────────────────────────────


def max_abs_error(
    network: BayesianNetwork,
    observed_slugs: set[str],
    observed_signals: set[str],
    joint: tuple[list[str], list[tuple[tuple[str, ...], float]]] | None = None,
) -> tuple[float, str]:
    """Worst per-node gap between variable elimination and the reference.

    Returns ``(max_gap, worst_node_name)``. ``priors_override={}`` pins the
    engine to the shipped priors so a stray ``~/.recon/priors.yaml`` on the
    runner cannot perturb the comparison.
    """
    result = infer(network, observed_slugs, observed_signals, priors_override={})
    reference = reference_posteriors(network, observed_slugs, observed_signals, joint=joint)
    worst = 0.0
    worst_node = ""
    for post in result.posteriors:
        gap = abs(post.posterior - reference[post.name])
        if gap > worst:
            worst = gap
            worst_node = post.name
    return worst, worst_node


def run_sweep(
    network: BayesianNetwork,
    configs: Iterator[tuple[set[str], set[str]]],
    tol: float,
) -> tuple[int, int, float, list[str]]:
    """Compare VE and the reference over ``configs``.

    Returns ``(checked, failures, worst_gap, failure_lines)``.
    """
    joint = prior_joint(network)
    checked = 0
    failures = 0
    worst_gap = 0.0
    failure_lines: list[str] = []
    for slugs, signals in configs:
        gap, node = max_abs_error(network, slugs, signals, joint=joint)
        checked += 1
        worst_gap = max(worst_gap, gap)
        if gap > tol:
            failures += 1
            if len(failure_lines) < 20:
                failure_lines.append(
                    f"  gap={gap:.2e} at node {node!r}; slugs={sorted(slugs)} signals={sorted(signals)}"
                )
    return checked, failures, worst_gap, failure_lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tol", type=float, default=_DEFAULT_TOL, help="max allowed per-node gap")
    parser.add_argument(
        "--tricky-only",
        action="store_true",
        help="run only the exhaustive per-node subset sweep (fast)",
    )
    args = parser.parse_args()

    network = load_network()
    n_nodes = len(network.nodes)
    full_states = 2**n_nodes
    print(f"Differential verification of the {n_nodes}-node inference core")
    print(f"Reference: naive enumeration over the full joint ({full_states} states), no factor algebra.")
    print(f"Tolerance: per-node gap <= {args.tol:.1e} (engine rounds posteriors to 4 dp).")
    print()

    total_checked = 0
    total_failures = 0
    overall_worst = 0.0
    all_failures: list[str] = []

    sweeps: list[tuple[str, Iterator[tuple[set[str], set[str]]], int]] = []
    if not args.tricky_only:
        sweeps.append(
            (
                "structured none/one/all cross product",
                iter_structured_configs(network),
                structured_config_count(network),
            )
        )
    sweeps.append(("exhaustive tricky-node subsets", iter_tricky_configs(network), -1))

    for label, configs, expected in sweeps:
        suffix = f" ({expected} configs)" if expected >= 0 else ""
        print(f"Sweep: {label}{suffix} ...")
        checked, failures, worst_gap, lines = run_sweep(network, configs, args.tol)
        print(f"  checked {checked}, failures {failures}, worst gap {worst_gap:.2e}")
        total_checked += checked
        total_failures += failures
        overall_worst = max(overall_worst, worst_gap)
        all_failures.extend(lines)

    print()
    print(f"Total configurations checked: {total_checked}")
    print(f"Worst per-node gap observed:  {overall_worst:.2e}")
    if total_failures:
        print(f"FAIL: {total_failures} configuration(s) exceeded tolerance:")
        for line in all_failures:
            print(line)
        return 1
    print("PASS: variable elimination matches naive enumeration on every configuration.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
