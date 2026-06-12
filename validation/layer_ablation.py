"""Layer ablations: what does each inference layer add, measured.

The paper's evaluation inventory asks the question the architecture begs:
recon pairs deterministic slug matching with a Bayesian network and a CT
co-occurrence graph layer — what does each layer *add* over the simpler
thing? This harness answers it twice, both times on fully synthetic data
(publishable, no corpus, no network, fixed seeds).

Experiment A — the Bayesian layer over single-source slug matching.
Sample worlds from the network's own generative process (the
synthetic-calibration sampler: true states from the prior/CPTs, evidence
from the likelihoods), then score three predictors per node against the
sampled truth:

  - ``full``: the shipped posterior (multi-signal fusion, DAG
    propagation, declarative-absence semantics).
  - ``any_fired``: the deterministic single-source baseline — claim
    present iff any of the node's bindings fired. This is what
    slug-matching alone supports. Scored by Brier (which for a hard 0/1
    predictor equals its error rate) and accuracy; no log-score, which a
    hard predictor degenerates.
  - ``strongest_only``: prior odds updated by the single strongest fired
    binding only (max |LLR|), ignoring co-evidence, absence semantics,
    and the DAG. Isolates what *combining* evidence adds over one good
    signal.

Honesty note, per the CAL1 discipline: the worlds are sampled FROM the
model, so this measures the value of the inference machinery under the
model's own assumptions — the gap each simplification opens when the
model is right. It is not a real-world validity claim; those live in the
reference-calibration harnesses against public records.

Experiment B — the graph layer over naive grouping. Plant K org clusters
in synthetic CT entries (each cluster's hosts co-occur on intra-org
certs), then add shared-CDN-style noise certs that bridge clusters at
rate ``noise``. Recover the partition two ways — Louvain (the shipped
graph layer) and connected components (what you would get with no
community detection) — and score each against the planted truth with the
adjusted Rand index. Bridging noise collapses connected components into
one blob; the measured ARI gap is precisely what the graph layer buys.

Run (synthetic, deterministic, publishable):

    python -m validation.layer_ablation
    python -m validation.layer_ablation --samples 20000 --seed 7
    python -m validation.layer_ablation --skip-graph   # Bayesian half only
"""

# Reuses the synthetic-calibration sampler and scoring internals — the single
# source for that logic, the same allowance the other harnesses take.
# pyright: reportPrivateUsage=false
from __future__ import annotations

import argparse
import math
import random
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.bayesian import BayesianNetwork, _prior_marginal, infer, load_network  # noqa: E402
from recon_tool.infra_graph import adjusted_rand_index, build_infrastructure_clusters  # noqa: E402
from validation.synthetic_calibration import (  # noqa: E402
    _brier,
    _sample_observations,
    _sample_topological,
)

# ── Experiment A: Bayesian layer vs slug-matching baselines ─────────────


def any_fired_prediction(node_evidence_names: set[str], fired: set[str]) -> float:
    """The deterministic single-source baseline: 1.0 iff any binding fired."""
    return 1.0 if node_evidence_names & fired else 0.0


def strongest_only_prediction(
    prior: float,
    fired_llrs: list[float],
) -> float:
    """Prior odds updated by the single strongest fired binding only.

    ``fired_llrs`` are the natural-log likelihood ratios of the node's fired
    bindings; the strongest by |LLR| is applied alone. With nothing fired the
    prediction is the prior (no absence semantics — that is the point of the
    ablation).
    """
    if not fired_llrs:
        return prior
    strongest = max(fired_llrs, key=abs)
    odds = (prior / (1.0 - prior)) * math.exp(strongest)
    return odds / (1.0 + odds)


@dataclass(frozen=True)
class NodeAblation:
    """Aggregate scores for one node across the sampled worlds.

    The ``*_fired`` fields restrict to worlds where at least one of the
    node's own bindings fired — the regime where the predictors actually
    compete. The pooled Brier difference is dominated by the no-fire regime,
    where the engine deliberately sits at the prior (the MNAR stance: absence
    of hideable evidence is not evidence of absence) while the baselines
    exploit the synthetic world's benign missingness. Splitting the regimes
    keeps that deliberate price visible instead of letting it read as the
    fusion machinery losing.
    """

    node: str
    n: int
    brier_full: float
    brier_any_fired: float
    brier_strongest: float
    acc_full: float
    acc_any_fired: float
    acc_strongest: float
    n_fired: int
    brier_full_fired: float
    brier_any_fired_fired: float
    brier_strongest_fired: float


def run_bayesian_ablation(
    network: BayesianNetwork, samples: int, seed: int
) -> list[NodeAblation]:
    """Score full posterior vs the two slug-matching baselines per node."""
    rng = random.Random(seed)
    by_node_pred: dict[str, dict[str, list[float]]] = {
        n.name: {"full": [], "any": [], "strongest": []} for n in network.nodes
    }
    by_node_truth: dict[str, list[int]] = {n.name: [] for n in network.nodes}
    by_node_fired: dict[str, list[bool]] = {n.name: [] for n in network.nodes}

    node_meta: dict[str, tuple[set[str], dict[str, float], float]] = {}
    for n in network.nodes:
        names = {ev.name for ev in n.evidence}
        llrs = {ev.name: math.log(ev.likelihood_present / ev.likelihood_absent) for ev in n.evidence}
        # The baselines get the node's *marginal* prior (for CPT nodes, the
        # prior implied by the DAG with no evidence): the comparison isolates
        # what evidence *propagation* adds, not what knowing the base rate
        # adds. A 0.5 strawman on derived nodes would flatter the full model.
        prior = _prior_marginal(network, n.name).get("present", 0.5)
        node_meta[n.name] = (names, llrs, prior)

    for _ in range(samples):
        truth = _sample_topological(network, rng)
        slugs, signals = _sample_observations(network, truth, rng)
        fired = set(slugs) | set(signals)
        result = infer(network, slugs, signals, priors_override={})
        posterior = {p.name: p.posterior for p in result.posteriors}
        for name, (ev_names, llrs, prior) in node_meta.items():
            outcome = 1 if truth[name] == "present" else 0
            fired_here = ev_names & fired
            by_node_truth[name].append(outcome)
            by_node_fired[name].append(bool(fired_here))
            by_node_pred[name]["full"].append(posterior[name])
            by_node_pred[name]["any"].append(any_fired_prediction(ev_names, fired))
            by_node_pred[name]["strongest"].append(
                strongest_only_prediction(prior, [llrs[f] for f in fired_here])
            )

    def _acc(preds: list[float], outcomes: list[int]) -> float:
        if not preds:
            return 0.0
        return sum(1 for p, o in zip(preds, outcomes, strict=True) if (p >= 0.5) == bool(o)) / len(preds)

    out: list[NodeAblation] = []
    for n in network.nodes:
        truths = by_node_truth[n.name]
        preds = by_node_pred[n.name]
        fired_mask = by_node_fired[n.name]
        f_truths = [t for t, m in zip(truths, fired_mask, strict=True) if m]

        def _fired_subset(values: list[float], mask: list[bool] = fired_mask) -> list[float]:
            return [v for v, m in zip(values, mask, strict=True) if m]

        out.append(
            NodeAblation(
                node=n.name,
                n=len(truths),
                brier_full=round(_brier(preds["full"], truths), 4),
                brier_any_fired=round(_brier(preds["any"], truths), 4),
                brier_strongest=round(_brier(preds["strongest"], truths), 4),
                acc_full=round(_acc(preds["full"], truths), 4),
                acc_any_fired=round(_acc(preds["any"], truths), 4),
                acc_strongest=round(_acc(preds["strongest"], truths), 4),
                n_fired=len(f_truths),
                brier_full_fired=round(_brier(_fired_subset(preds["full"]), f_truths), 4),
                brier_any_fired_fired=round(_brier(_fired_subset(preds["any"]), f_truths), 4),
                brier_strongest_fired=round(_brier(_fired_subset(preds["strongest"]), f_truths), 4),
            )
        )
    return out


# ── Experiment B: graph layer vs connected components ───────────────────


def planted_corpus(
    clusters: int,
    hosts_per_cluster: int,
    intra_certs: int,
    noise_certs: int,
    rng: random.Random,
) -> tuple[list[dict[str, object]], list[set[str]]]:
    """Synthetic CT entries with a planted org partition plus bridging noise.

    Each planted cluster contributes ``intra_certs`` certificates over random
    subsets of its hosts (every cert carries at least two SANs, so it forms
    edges). ``noise_certs`` shared-CDN-style certificates each span two hosts
    drawn from two *different* clusters — the bridging pattern that defeats
    naive grouping. Hostnames are fictional (``example.com`` subdomains).
    Returns (entries, planted_partition).
    """
    planted: list[set[str]] = []
    entries: list[dict[str, object]] = []
    for c in range(clusters):
        members = {f"host{h}.org{c}.example.com" for h in range(hosts_per_cluster)}
        planted.append(members)
        ordered = sorted(members)
        for _ in range(intra_certs):
            k = rng.randint(2, len(ordered))
            sans = rng.sample(ordered, k)
            entries.append(
                {
                    "dns_names": sans,
                    "issuer_name": "Synthetic Org CA",
                    "not_before": "2025-01-01T00:00:00",
                    "not_after": "2026-01-01T00:00:00",
                }
            )
    for _ in range(noise_certs):
        a, b = rng.sample(range(clusters), 2)
        entries.append(
            {
                "dns_names": [
                    rng.choice(sorted(planted[a])),
                    rng.choice(sorted(planted[b])),
                ],
                "issuer_name": "Synthetic CDN CA",
                "not_before": "2025-01-01T00:00:00",
                "not_after": "2026-01-01T00:00:00",
            }
        )
    rng.shuffle(entries)
    return entries, planted


def connected_components_partition(entries: list[dict[str, object]]) -> list[set[str]]:
    """The no-graph-layer baseline: union-find over shared-cert edges."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for entry in entries:
        raw = entry.get("dns_names", [])
        if not isinstance(raw, list):
            continue
        names = [str(n) for n in raw if isinstance(n, str) and not n.startswith("*.")]
        for n in names:
            parent.setdefault(n, n)
        for i in range(1, len(names)):
            union(names[0], names[i])
    groups: dict[str, set[str]] = {}
    for n in parent:
        groups.setdefault(find(n), set()).add(n)
    return list(groups.values())


def louvain_partition_of(entries: list[dict[str, object]]) -> list[set[str]]:
    """The shipped graph layer's partition (every member, uncapped sizes)."""
    report = build_infrastructure_clusters(list(entries))
    return [set(c.members) for c in report.clusters]


def _restrict(partition: list[set[str]], universe: set[str]) -> list[set[str]]:
    """Restrict a partition to ``universe`` so ARIs compare like with like.

    The shipped report caps members per cluster and drops sub-minimum
    clusters; scoring is computed over the hosts present in both the planted
    truth and the recovered partition (singletons added for missing hosts).
    """
    covered: set[str] = set()
    out: list[set[str]] = []
    for block in partition:
        keep = block & universe
        if keep:
            out.append(keep)
            covered |= keep
    out.extend({h} for h in universe - covered)
    return out


@dataclass(frozen=True)
class GraphAblation:
    """ARI against the planted truth at one noise level."""

    noise_certs: int
    ari_louvain: float
    ari_components: float


def run_graph_ablation(
    clusters: int,
    hosts_per_cluster: int,
    intra_certs: int,
    noise_grid: list[int],
    seed: int,
) -> list[GraphAblation]:
    out: list[GraphAblation] = []
    for noise in noise_grid:
        rng = random.Random(seed + noise)
        entries, planted = planted_corpus(clusters, hosts_per_cluster, intra_certs, noise, rng)
        universe = set().union(*planted)
        louvain = _restrict(louvain_partition_of(entries), universe)
        components = _restrict(connected_components_partition(entries), universe)
        out.append(
            GraphAblation(
                noise_certs=noise,
                ari_louvain=round(adjusted_rand_index(planted, louvain), 4),
                ari_components=round(adjusted_rand_index(planted, components), 4),
            )
        )
    return out


# ── CLI ──────────────────────────────────────────────────────────────────


def _print_bayesian(rows: list[NodeAblation], samples: int) -> None:
    print(f"\nExperiment A — Bayesian layer vs slug-matching baselines ({samples} synthetic worlds)")
    print("(model-grounded truth: measures the machinery under the model's own assumptions, per CAL1)")
    print("\nPooled over all worlds (the no-fire regime carries the deliberate MNAR price):")
    print(f"  {'node':<36}{'Brier full':>11}{'any-fired':>11}{'strongest':>11}{'acc full':>10}{'any':>7}{'str':>7}")
    print("  " + "-" * 93)
    for r in rows:
        print(
            f"  {r.node:<36}{r.brier_full:>11.4f}{r.brier_any_fired:>11.4f}{r.brier_strongest:>11.4f}"
            f"{r.acc_full:>10.4f}{r.acc_any_fired:>7.4f}{r.acc_strongest:>7.4f}"
        )
    print("\nFired regime only (at least one of the node's bindings fired — where the predictors compete):")
    print(f"  {'node':<36}{'n fired':>8}{'Brier full':>11}{'any-fired':>11}{'strongest':>11}")
    print("  " + "-" * 77)
    for r in rows:
        print(
            f"  {r.node:<36}{r.n_fired:>8}{r.brier_full_fired:>11.4f}"
            f"{r.brier_any_fired_fired:>11.4f}{r.brier_strongest_fired:>11.4f}"
        )


def _print_graph(rows: list[GraphAblation], clusters: int, hosts: int, intra: int) -> None:
    print(
        f"\nExperiment B — graph layer vs connected components "
        f"({clusters} planted clusters x {hosts} hosts, {intra} intra-org certs each)"
    )
    print(f"  {'bridging noise certs':>21}{'ARI louvain':>13}{'ARI components':>16}")
    print("  " + "-" * 50)
    for r in rows:
        print(f"  {r.noise_certs:>21}{r.ari_louvain:>13.4f}{r.ari_components:>16.4f}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Layer ablations on synthetic data (publishable; no corpus).")
    parser.add_argument("--samples", type=int, default=20000, help="Synthetic worlds for experiment A.")
    parser.add_argument("--seed", type=int, default=7, help="RNG seed for both experiments.")
    parser.add_argument("--clusters", type=int, default=6, help="Planted org clusters for experiment B.")
    parser.add_argument("--hosts", type=int, default=8, help="Hosts per planted cluster.")
    parser.add_argument("--intra-certs", type=int, default=12, help="Intra-org certs per cluster.")
    parser.add_argument(
        "--noise-grid",
        type=int,
        nargs="*",
        default=[0, 2, 5, 10, 20, 40],
        help="Bridging noise-cert counts to sweep.",
    )
    parser.add_argument("--skip-graph", action="store_true", help="Run experiment A only.")
    parser.add_argument("--skip-bayesian", action="store_true", help="Run experiment B only.")
    args = parser.parse_args(argv)

    network = load_network()
    if not args.skip_bayesian:
        _print_bayesian(run_bayesian_ablation(network, args.samples, args.seed), args.samples)
    if not args.skip_graph:
        _print_graph(
            run_graph_ablation(args.clusters, args.hosts, args.intra_certs, list(args.noise_grid), args.seed),
            args.clusters,
            args.hosts,
            args.intra_certs,
        )
    print(
        "\nReading: experiment A's gap is what fusion + absence semantics + the DAG add"
        "\nwhen the model is right (synthetic worlds; not a real-world validity claim);"
        "\nexperiment B's gap is what community detection adds over naive grouping when"
        "\nshared-CDN noise bridges org clusters."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
