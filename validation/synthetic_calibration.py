"""Synthetic reliability diagnostic for the v1.9 layer.

This harness compares model-relative posteriors with latent states sampled from
the committed prior/CPT graph, then samples each evidence binding independently
as a Bernoulli variable using the committed marginal likelihood parameters. It
is an independent-Bernoulli misspecification stress test, not the committed
model's generative process and not evidence of calibration on real domains.

This script generates synthetic ground truth instead. We:

1. Sample a latent state ``X*`` for each node from the network's
   prior / CPT distribution.
2. Independently sample every evidence-binding outcome from the corresponding
   likelihood given ``X*``.
3. Run inference with ``infer()`` to get the posterior ``p_hat``.
4. Bin posteriors by predicted probability and compare to the
   empirical frequency of ``X* = present`` in each bin.

This generator neither implements correlation-group observation structure nor
the shipped missingness semantics. It treats every binding as conditionally
independent and every non-fire as generated, while shipped inference reduces
correlated groups and ignores hideable non-fire. The mismatch is intentional:
the experiment asks how inference behaves under this particular misspecification
while sharing marginal parameters. We report two reliability diagnostics:

  - **Marginal reliability.** Standard reliability diagram over all
    samples. Includes the "no binding fired" bucket where the
    posterior equals the network prior.
  - **Conditional-on-fired-evidence diagnostic.** Restricted to samples
    where at least one binding fired for the node. Selection on firing is
    itself informative, and the generator conditions on non-fire differently
    from shipped hideable-node inference. This remains a model-internal
    diagnostic, not a calibration claim (see correlation.md section 3.3).

Output includes Brier score and binned expected calibration error (Murphy 1973;
Gneiting et al. 2007). Neither metric becomes external calibration evidence in
this misspecification stress experiment.

Run:

    python validation/synthetic_calibration.py
    python validation/synthetic_calibration.py --samples 50000 --seed 42
    python validation/synthetic_calibration.py --node m365_tenant

The script does not write any files; it prints to stdout. Output is publishable
because the synthetic data has no real-world targets in it.
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.bayesian import BayesianNetwork, infer, load_network  # noqa: E402


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
                msg = f"root node {node.name!r} is missing a prior"
                raise ValueError(msg)
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
    """Independently Bernoulli-sample each binding given the latent state.

    This deliberately ignores evidence groups and shipped missingness semantics;
    callers must treat it as a misspecification stress generator.
    """
    obs_slugs: list[str] = []
    obs_signals: list[str] = []
    for node in net.nodes:
        state = true_state[node.name]
        for ev in node.evidence:
            p_obs = ev.likelihood_present if state == "present" else ev.likelihood_absent
            if rng.random() < p_obs:
                if ev.kind == "slug":
                    obs_slugs.append(ev.name)
                else:
                    obs_signals.append(ev.name)
    return obs_slugs, obs_signals


def _brier(predicted: list[float], outcome: list[int]) -> float:
    """Mean squared error between predicted posterior and binary outcome."""
    if not predicted:
        return 0.0
    return sum((p - o) ** 2 for p, o in zip(predicted, outcome, strict=True)) / len(predicted)


def _reliability_table(
    predicted: list[float], outcome: list[int], bins: int = 10
) -> list[tuple[float, float, float, int]]:
    """Bin predictions; return (bin_low, bin_high, empirical_freq, count)."""
    width = 1.0 / bins
    buckets: dict[int, list[int]] = defaultdict(list)
    for p, o in zip(predicted, outcome, strict=True):
        idx = min(bins - 1, int(p / width))
        buckets[idx].append(o)
    out: list[tuple[float, float, float, int]] = []
    for idx in range(bins):
        if not buckets[idx]:
            continue
        out.append(
            (
                idx * width,
                (idx + 1) * width,
                sum(buckets[idx]) / len(buckets[idx]),
                len(buckets[idx]),
            )
        )
    return out


def _expected_calibration_error(table: list[tuple[float, float, float, int]], total: int) -> float:
    """Weighted mean of |bin_midpoint - empirical_freq| over bins."""
    if total == 0:
        return 0.0
    total_err = 0.0
    for low, high, freq, count in table:
        midpoint = (low + high) / 2
        total_err += (count / total) * abs(midpoint - freq)
    return total_err


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--samples", type=int, default=20000, help="Number of synthetic domains to simulate (default 20000)."
    )
    parser.add_argument("--seed", type=int, default=1729, help="RNG seed for reproducibility (default 1729).")
    parser.add_argument(
        "--node", type=str, default=None, help="Restrict reliability table to one node. Default: all nodes."
    )
    parser.add_argument("--bins", type=int, default=10, help="Number of probability bins (default 10).")
    args = parser.parse_args()

    net = load_network()
    rng = random.Random(args.seed)  # noqa: S311 - reproducible synthetic experiment, not security-sensitive.

    # Per-node prediction, outcome, and fired-flag lists.
    # ``fired`` records whether at least one binding fired for this
    # node on this sample. The selected subset remains model-internal and does
    # not acquire a calibration guarantee through selection.
    by_node: dict[str, tuple[list[float], list[int], list[bool]]] = {
        n.name: ([], [], []) for n in net.nodes
    }
    fired_names_per_node: dict[str, set[str]] = {n.name: {ev.name for ev in n.evidence} for n in net.nodes}

    print(f"Simulating {args.samples} independent-Bernoulli misspecification worlds...")
    for i in range(args.samples):
        if (i + 1) % 5000 == 0:
            print(f"  {i + 1}/{args.samples} ...", flush=True)
        true_state = _sample_topological(net, rng)
        obs_slugs, obs_signals = _sample_observations(net, true_state, rng)
        result = infer(net, obs_slugs, obs_signals, priors_override={})
        observed_set = set(obs_slugs) | set(obs_signals)
        for p in result.posteriors:
            preds, outs, fireds = by_node[p.name]
            preds.append(p.posterior)
            outs.append(1 if true_state[p.name] == "present" else 0)
            fireds.append(bool(fired_names_per_node[p.name] & observed_set))
    print()

    target_nodes = [args.node] if args.node else [n.name for n in net.nodes]
    overall_brier: list[float] = []
    overall_ece: list[tuple[float, int]] = []
    overall_brier_cond: list[float] = []
    overall_ece_cond: list[tuple[float, int]] = []

    for node in target_nodes:
        if node not in by_node:
            print(f"  unknown node: {node!r}", file=sys.stderr)
            continue
        predicted, outcome, fired = by_node[node]
        if not predicted:
            continue

        # Marginal reliability over all samples (includes the
        # no-binding-fired regime where the asymmetric-likelihood
        # model deliberately reports the prior).
        brier = _brier(predicted, outcome)
        table = _reliability_table(predicted, outcome, bins=args.bins)
        ece = _expected_calibration_error(table, len(predicted))
        overall_brier.append(brier)
        overall_ece.append((ece, len(predicted)))

        # Conditional diagnostic over samples where at least one binding fired
        # for this node. Selection does not make the result an external
        # calibration claim (see correlation.md section 3.3).
        cond_pred = [p for p, f in zip(predicted, fired, strict=True) if f]
        cond_out = [o for o, f in zip(outcome, fired, strict=True) if f]

        print(f"\n=== {node} ({len(predicted)} samples; {len(cond_pred)} with fired evidence) ===")
        print(f"  Marginal Brier: {brier:.4f}  ECE: {ece:.4f}")
        if cond_pred:
            cond_brier = _brier(cond_pred, cond_out)
            cond_table = _reliability_table(cond_pred, cond_out, bins=args.bins)
            cond_ece = _expected_calibration_error(cond_table, len(cond_pred))
            overall_brier_cond.append(cond_brier)
            overall_ece_cond.append((cond_ece, len(cond_pred)))
            print(f"  Conditional-on-evidence Brier: {cond_brier:.4f}  ECE: {cond_ece:.4f}")
        print("  Reliability (marginal):")
        print(f"    {'bin':<14} {'predicted':>11} {'observed':>11} {'count':>8}")
        for low, high, freq, count in table:
            mid = (low + high) / 2
            print(f"    [{low:.2f}, {high:.2f})  {mid:>11.3f} {freq:>11.3f} {count:>8d}")

    if len(overall_brier) > 1:
        avg_brier = sum(overall_brier) / len(overall_brier)
        weight_total = sum(c for _, c in overall_ece)
        avg_ece = sum(e * c for e, c in overall_ece) / weight_total
        print("\n=== Network-wide ===")
        print(f"  Mean Brier (marginal):           {avg_brier:.4f}")
        print(f"  Sample-weighted ECE (marginal):  {avg_ece:.4f}")
        if overall_brier_cond:
            avg_brier_cond = sum(overall_brier_cond) / len(overall_brier_cond)
            cond_weight_total = sum(c for _, c in overall_ece_cond)
            avg_ece_cond = sum(e * c for e, c in overall_ece_cond) / cond_weight_total
            print(f"  Mean Brier (conditional):        {avg_brier_cond:.4f}")
            print(f"  Sample-weighted ECE (conditional): {avg_ece_cond:.4f}")
        print()
        print("  Marginal ECE can be high in this independent-Bernoulli stress test.")
        print("  Under shipped hideable-node semantics, posteriors in the")
        print("  no-evidence-fired regime equal the network prior, not the")
        print("  posterior conditional on absence. This records a generator/inference")
        print("  mismatch; it is not an estimate of an MNAR price.")
        print()
        print("  Conditional ECE, over samples where >= 1 binding fired, is a")
        print("  model-internal diagnostic. Selection on firing remains informative,")
        print("  so this is not an external calibration claim.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
