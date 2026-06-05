"""CAL8: likelihood-perturbation sensitivity for the v1.9 Bayesian layer.

The CPT likelihoods in ``bayesian_network.yaml`` are hand-elicited
(concept-first, not corpus-fitted; see ``CONTRIBUTING.md`` CPT-change
discipline). A fair question is whether the calibration story depends
sensitively on those exact numbers. This script answers it.

Method (generative truth held fixed, only inference perturbed):

1. Generate one fixed synthetic dataset from the baseline network: for
   each sample, draw a ground-truth assignment and the evidence pattern
   recon would observe.
2. Build perturbed networks by scaling every evidence likelihood by a
   factor: two systematic corners (all x1.2 and all x0.8) plus a random
   jitter ensemble (each likelihood scaled independently by a factor in
   [0.8, 1.2]), clipped to the valid open interval.
3. Re-run ``infer()`` on the SAME observations under the baseline and
   under every perturbed network. Score each node's posteriors against
   the fixed ground truth (Brier, ECE) and against the baseline run
   (decision flips: does ``posterior >= 0.5`` still match).
4. Report, per node, the baseline metric and the maximum deviation any
   perturbation produced. Small deviation means the calibration is
   robust to the hand-elicited values, not knife-edge dependent.

Synthetic-only and publishable: there are no real targets. Prints an
aggregate table to stdout; the per-trial detail is summarized, not
dumped. Reproducible under a fixed seed.

Run:

    python validation/likelihood_sensitivity.py
    python validation/likelihood_sensitivity.py --samples 5000 --trials 12
"""

from __future__ import annotations

import argparse
import dataclasses
import random
import sys
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.bayesian import BayesianNetwork, infer, load_network  # noqa: E402

# Stay inside the valid open interval the schema enforces (no {0, 1}
# degenerate likelihoods, which would pin a posterior permanently).
_LIK_LO = 0.02
_LIK_HI = 0.98


def _clip(x: float) -> float:
    return max(_LIK_LO, min(_LIK_HI, x))


def _sample_topological(net: BayesianNetwork, rng: random.Random) -> dict[str, str]:
    """Sample one full assignment from the joint distribution."""
    by_name = {n.name: n for n in net.nodes}
    incoming: dict[str, set[str]] = {n.name: set(n.parents) for n in net.nodes}
    queue: list[str] = sorted(n for n, p in incoming.items() if not p)
    out: dict[str, str] = {}
    while queue:
        cur = queue.pop(0)
        node = by_name[cur]
        if not node.parents:
            if node.prior is None:
                raise ValueError(f"root node {node.name!r} is missing a prior")
            p_present = node.prior
        else:
            key = ",".join(f"{p}={out[p]}" for p in node.parents)
            p_present = node.cpt[key]
        out[cur] = "present" if rng.random() < p_present else "absent"
        for n in net.nodes:
            if cur in incoming[n.name]:
                incoming[n.name].discard(cur)
                if not incoming[n.name]:
                    queue.append(n.name)
        queue.sort()
    return out


def _sample_observations(
    net: BayesianNetwork, true_state: dict[str, str], rng: random.Random
) -> tuple[list[str], list[str]]:
    """Given the ground-truth assignment, simulate which bindings fire."""
    obs_slugs: list[str] = []
    obs_signals: list[str] = []
    for node in net.nodes:
        state = true_state[node.name]
        for ev in node.evidence:
            p_obs = ev.likelihood_present if state == "present" else ev.likelihood_absent
            if rng.random() < p_obs:
                (obs_slugs if ev.kind == "slug" else obs_signals).append(ev.name)
    return obs_slugs, obs_signals


def _brier(predicted: list[float], outcome: list[int]) -> float:
    if not predicted:
        return 0.0
    return sum((p - o) ** 2 for p, o in zip(predicted, outcome, strict=True)) / len(predicted)


def _ece(predicted: list[float], outcome: list[int], bins: int) -> float:
    """Expected calibration error: weighted mean |bin-midpoint - empirical freq|."""
    total = len(predicted)
    if total == 0:
        return 0.0
    width = 1.0 / bins
    buckets: dict[int, list[int]] = defaultdict(list)
    for p, o in zip(predicted, outcome, strict=True):
        buckets[min(bins - 1, int(p / width))].append(o)
    err = 0.0
    for idx, outs in buckets.items():
        midpoint = (idx + 0.5) * width
        freq = sum(outs) / len(outs)
        err += (len(outs) / total) * abs(midpoint - freq)
    return err


def _perturb(net: BayesianNetwork, draw: Callable[[], tuple[float, float]]) -> BayesianNetwork:
    """Return a copy of ``net`` with every evidence likelihood scaled.

    ``draw`` yields a ``(present_factor, absent_factor)`` pair per binding;
    a constant pair is a systematic corner, a random pair is jitter.
    """
    nodes = []
    for node in net.nodes:
        ev_out = []
        for ev in node.evidence:
            fp, fa = draw()
            ev_out.append(
                dataclasses.replace(
                    ev,
                    likelihood_present=_clip(ev.likelihood_present * fp),
                    likelihood_absent=_clip(ev.likelihood_absent * fa),
                )
            )
        nodes.append(dataclasses.replace(node, evidence=tuple(ev_out)))
    return dataclasses.replace(net, nodes=tuple(nodes))


def _score(
    net: BayesianNetwork,
    dataset: list[tuple[dict[str, str], list[str], list[str]]],
    bins: int,
) -> dict[str, tuple[float, float, list[float]]]:
    """Run inference under ``net`` over the fixed dataset.

    Returns per node: (Brier, ECE, posterior list) against ground truth.
    """
    preds: dict[str, list[float]] = {n.name: [] for n in net.nodes}
    outs: dict[str, list[int]] = {n.name: [] for n in net.nodes}
    for true_state, obs_slugs, obs_signals in dataset:
        for p in infer(net, obs_slugs, obs_signals, priors_override={}).posteriors:
            preds[p.name].append(p.posterior)
            outs[p.name].append(1 if true_state[p.name] == "present" else 0)
    return {name: (_brier(preds[name], outs[name]), _ece(preds[name], outs[name], bins), preds[name]) for name in preds}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=4000, help="Synthetic domains in the fixed dataset.")
    parser.add_argument("--trials", type=int, default=10, help="Random jitter trials (plus 2 systematic corners).")
    parser.add_argument("--seed", type=int, default=1729, help="RNG seed for reproducibility.")
    parser.add_argument("--bins", type=int, default=10, help="Reliability bins (positive integer).")
    args = parser.parse_args()
    if args.bins < 1:
        parser.error("--bins must be a positive integer")  # _ece divides by bins
    if args.samples < 1:
        parser.error("--samples must be a positive integer")

    net = load_network()
    rng = random.Random(args.seed)  # noqa: S311 - reproducible synthetic experiment.

    # 1. Fixed generative dataset from the baseline network.
    print(f"Generating {args.samples} synthetic domains from the baseline network...", flush=True)
    dataset: list[tuple[dict[str, str], list[str], list[str]]] = []
    for _ in range(args.samples):
        true_state = _sample_topological(net, rng)
        obs_slugs, obs_signals = _sample_observations(net, true_state, rng)
        dataset.append((true_state, obs_slugs, obs_signals))

    # 2. Baseline scores.
    base = _score(net, dataset, args.bins)

    # 3. Perturbation trials: two systematic corners + random jitter ensemble.
    def _jitter() -> tuple[float, float]:
        return (0.8 + 0.4 * rng.random(), 0.8 + 0.4 * rng.random())

    trial_nets = [
        _perturb(net, lambda: (1.2, 1.2)),
        _perturb(net, lambda: (0.8, 0.8)),
    ]
    trial_nets += [_perturb(net, _jitter) for _ in range(args.trials)]
    print(
        f"Re-inferring under {len(trial_nets)} perturbed networks "
        f"(2 systematic +/-20% corners, {args.trials} random jitter)...",
        flush=True,
    )

    worst_brier_dev: dict[str, float] = {n.name: 0.0 for n in net.nodes}
    worst_ece_dev: dict[str, float] = {n.name: 0.0 for n in net.nodes}
    worst_flip_rate: dict[str, float] = {n.name: 0.0 for n in net.nodes}
    for tnet in trial_nets:
        for name, (brier, ece, preds) in _score(tnet, dataset, args.bins).items():
            worst_brier_dev[name] = max(worst_brier_dev[name], abs(brier - base[name][0]))
            worst_ece_dev[name] = max(worst_ece_dev[name], abs(ece - base[name][1]))
            base_preds = base[name][2]
            flips = sum(1 for a, b in zip(base_preds, preds, strict=True) if (a >= 0.5) != (b >= 0.5))
            worst_flip_rate[name] = max(worst_flip_rate[name], flips / max(len(preds), 1))

    # 4. Report.
    print()
    print(
        f"Likelihood-perturbation sensitivity (n={args.samples}, "
        f"{len(trial_nets)} perturbed networks, seed={args.seed})"
    )
    print("Each row: baseline metric, then the worst deviation any +/-20% perturbation produced.")
    print()
    header = f"{'node':<34}{'Brier':>8}{'dBrier':>9}{'ECE':>8}{'dECE':>9}{'flip%':>8}"
    print(header)
    print("-" * len(header))
    max_ece_dev = 0.0
    max_flip = 0.0
    for n in net.nodes:
        b, e, _ = base[n.name]
        de = worst_ece_dev[n.name]
        fl = worst_flip_rate[n.name] * 100
        max_ece_dev = max(max_ece_dev, de)
        max_flip = max(max_flip, fl)
        print(f"{n.name:<34}{b:>8.3f}{worst_brier_dev[n.name]:>9.3f}{e:>8.3f}{de:>9.3f}{fl:>8.1f}")
    print("-" * len(header))
    print(f"Worst-case across all nodes: dECE <= {max_ece_dev:.3f}, decision flips <= {max_flip:.1f}%.")
    print("Small deviations indicate the calibration is robust to the hand-elicited likelihoods,")
    print("not knife-edge dependent on the exact CPT values.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
