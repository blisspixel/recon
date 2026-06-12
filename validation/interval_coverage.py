"""Credible-interval perturbation coverage for the Bayesian layer.

The 80% credible interval is the output recon asks operators to trust
(README "the interval is the load-bearing field"), and the roadmap
assurance track calls for a coverage check on it, framed as honestly as
CAL1 requires. This harness provides that check without claiming
ground-truth calibration, which no passive tool can observe (CAL13).

What the interval claims. ``_credible_interval`` widens with low
``n_eff``: the width exists to absorb the acknowledged imprecision of
the hand-elicited CPT likelihoods (directionally-accurate,
corpus-grounded estimates, not values precise to many decimals; see
``docs/maintainer-validation.md``). That claim is testable without any
real-world label: if the likelihoods recon believes are off by up to a
multiplicative band, the interval should still contain the conditional
probability a correctly-parameterized model would report.

Method, per perturbation level ``delta``:

1. Build "worlds": copies of the shipped network with every evidence
   likelihood (and declarative ``group_absence`` pair) scaled by an
   independent factor drawn from ``[1 - delta, 1 + delta]``, clipped to
   the valid open interval. ``delta = 0.2`` is the CAL8 sensitivity
   band.
2. Sample synthetic domains from each world (ground-truth assignment,
   then observed bindings), the same generative procedure as
   ``synthetic_calibration.py`` and ``likelihood_sensitivity.py``.
3. For each sample, run the SHIPPED model's ``infer()`` to get each
   node's posterior and 80% interval, and compute the world's own
   conditional probability ``P(node = present | observations)`` with
   the independent full-joint reference from
   ``differential_verification.py`` (no engine code in the truth path).
4. Report, per node, how often the shipped interval contains the
   world's conditional probability: marginally and conditional on at
   least one binding having fired (the regime where the model makes a
   claim; see correlation.md 4.3).

At ``delta = 0`` the world equals the model, the reference equals the
engine (verified differentially in v2.1.7), and coverage is total by
construction. That row is a consistency sanity check in the CAL1 sense,
not evidence; the informative rows are ``delta > 0``.

A second, diagnostic truth is also reported: the raw generative (MAR)
conditional, where every non-fired binding contributes its complement
for every node. The shipped model deliberately refuses that conditioning
for hideable nodes (the MNAR absence rule), so MAR coverage quantifies
the documented cost of that refusal in a world where absence is genuine
evidence. It is reported for honesty, not gated: recon's position is
that the real world is MNAR for hideable infrastructure.

Synthetic-only and publishable: no real targets anywhere. Reproducible
under a fixed seed. Aggregate output only.

Run:

    python -m validation.interval_coverage
    python -m validation.interval_coverage --deltas 0,0.2 --worlds 8 --samples 250
    python -m validation.interval_coverage --json
"""

# Reads the parsed network dataclasses (_Node / _Evidence): legitimate
# white-box access for a verification harness, the same allowance the
# differential-verification oracle uses.
# pyright: reportPrivateUsage=false
from __future__ import annotations

import argparse
import dataclasses
import json
import random
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.bayesian import BayesianNetwork, _Node, infer, load_network  # noqa: E402
from validation.differential_verification import (  # noqa: E402
    _reference_node_likelihood,
    prior_joint,
)
from validation.likelihood_sensitivity import (  # noqa: E402
    _clip,
    _sample_observations,
    _sample_topological,
)

# Containment tolerance: ``infer`` rounds interval bounds to four
# decimals, so a probability can sit within half a unit in the fourth
# place of a bound and still be "inside" the unrounded interval.
_EDGE_TOL = 6e-5

# Default perturbation sweep. 0.0 is the consistency sanity row;
# 0.2 is the CAL8 band and the gated level; 0.1 / 0.3 show the response.
_DEFAULT_DELTAS = (0.0, 0.1, 0.2, 0.3)


def perturb_world(net: BayesianNetwork, delta: float, rng: random.Random) -> BayesianNetwork:
    """A copy of ``net`` with every evidence-model parameter jittered.

    Each binding's ``likelihood_present`` / ``likelihood_absent`` and each
    declarative ``group_absence`` pair is scaled by its own factor drawn
    uniformly from ``[1 - delta, 1 + delta]``, clipped to the valid open
    interval. Priors and CPT entries are left alone: the interval's
    ``n_eff`` machinery keys off evidence volume, so the evidence model
    is the surface whose imprecision it claims to absorb (prior
    grounding is tracked separately as CAL12).
    """

    def factor() -> float:
        return 1.0 - delta + 2.0 * delta * rng.random()

    nodes = []
    for node in net.nodes:
        evidence = tuple(
            dataclasses.replace(
                ev,
                likelihood_present=_clip(ev.likelihood_present * factor()),
                likelihood_absent=_clip(ev.likelihood_absent * factor()),
            )
            for ev in node.evidence
        )
        group_absence = tuple((g, _clip(lp * factor()), _clip(la * factor())) for g, lp, la in node.group_absence)
        nodes.append(dataclasses.replace(node, evidence=evidence, group_absence=group_absence))
    return dataclasses.replace(net, nodes=tuple(nodes))


def _generative_node_likelihood(node: _Node, fired_names: set[str]) -> tuple[float, float]:
    """``P(this node's full firing pattern | node state)`` under the raw
    generative (MAR) semantics: every binding is an independent coin given
    the node state, so a non-fired binding contributes its complement for
    every node, hideable or not."""
    like_present = 1.0
    like_absent = 1.0
    for ev in node.evidence:
        if ev.name in fired_names:
            like_present *= ev.likelihood_present
            like_absent *= ev.likelihood_absent
        else:
            like_present *= 1.0 - ev.likelihood_present
            like_absent *= 1.0 - ev.likelihood_absent
    return like_present, like_absent


def _posteriors_from_likelihoods(
    joint: tuple[list[str], list[tuple[tuple[str, ...], float]]],
    node_likelihood: dict[str, tuple[float, float]],
) -> dict[str, float]:
    """Exact ``P(node = present | observations)`` by full-joint enumeration,
    given a per-node ``(P(obs | present), P(obs | absent))`` map."""
    names, states = joint
    likes = [node_likelihood[name] for name in names]
    present_mass = dict.fromkeys(names, 0.0)
    total = 0.0
    for combo, prior_weight in states:
        weight = prior_weight
        for i, state in enumerate(combo):
            like_present, like_absent = likes[i]
            weight *= like_present if state == "present" else like_absent
        total += weight
        for i, state in enumerate(combo):
            if state == "present":
                present_mass[names[i]] += weight
    if total <= 0.0:
        return dict.fromkeys(names, 0.5)
    return {name: present_mass[name] / total for name in names}


@dataclasses.dataclass
class _NodeTally:
    """Coverage counters for one node at one delta."""

    n: int = 0
    fired_n: int = 0
    covered: int = 0
    fired_covered: int = 0
    mar_covered: int = 0
    mar_fired_covered: int = 0
    width_sum: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "fired_n": self.fired_n,
            "coverage": round(self.covered / self.n, 4) if self.n else None,
            "fired_coverage": round(self.fired_covered / self.fired_n, 4) if self.fired_n else None,
            "mar_coverage": round(self.mar_covered / self.n, 4) if self.n else None,
            "mar_fired_coverage": round(self.mar_fired_covered / self.fired_n, 4) if self.fired_n else None,
            "mean_width": round(self.width_sum / self.n, 4) if self.n else None,
        }


def run_coverage(
    deltas: tuple[float, ...] = _DEFAULT_DELTAS,
    worlds: int = 10,
    samples: int = 200,
    seed: int = 1729,
) -> dict[str, Any]:
    """Run the sweep; return aggregate-only results keyed by delta.

    For each delta, ``worlds`` perturbed networks are built and
    ``samples`` synthetic domains are drawn from each, so a delta level
    aggregates ``worlds * samples`` observations per node.
    """
    shipped = load_network()
    rng = random.Random(seed)  # noqa: S311 - reproducible synthetic experiment, not security-sensitive.
    node_names = [n.name for n in shipped.nodes]
    by_name = {n.name: n for n in shipped.nodes}
    binding_names = {n.name: {ev.name for ev in n.evidence} for n in shipped.nodes}

    out: dict[str, Any] = {
        "seed": seed,
        "worlds": worlds,
        "samples_per_world": samples,
        "edge_tolerance": _EDGE_TOL,
        "deltas": {},
    }
    for delta in deltas:
        tallies = {name: _NodeTally() for name in node_names}
        for _ in range(worlds):
            world = perturb_world(shipped, delta, rng)
            joint = prior_joint(world)
            for _ in range(samples):
                true_state = _sample_topological(world, rng)
                obs_slugs, obs_signals = _sample_observations(world, true_state, rng)
                observed = set(obs_slugs) | set(obs_signals)

                model_like: dict[str, tuple[float, float]] = {}
                mar_like: dict[str, tuple[float, float]] = {}
                for name in node_names:
                    node = world.get(name)
                    fired = [ev for ev in node.evidence if ev.name in observed]
                    model_like[name] = _reference_node_likelihood(node, fired)
                    mar_like[name] = _generative_node_likelihood(node, observed)
                truth = _posteriors_from_likelihoods(joint, model_like)
                mar_truth = _posteriors_from_likelihoods(joint, mar_like)

                result = infer(shipped, obs_slugs, obs_signals, priors_override={})
                for p in result.posteriors:
                    tally = tallies[p.name]
                    lo = p.interval_low - _EDGE_TOL
                    hi = p.interval_high + _EDGE_TOL
                    fired_any = bool(binding_names[p.name] & observed)
                    tally.n += 1
                    tally.width_sum += p.interval_high - p.interval_low
                    in_model = lo <= truth[p.name] <= hi
                    in_mar = lo <= mar_truth[p.name] <= hi
                    if in_model:
                        tally.covered += 1
                    if in_mar:
                        tally.mar_covered += 1
                    if fired_any:
                        tally.fired_n += 1
                        if in_model:
                            tally.fired_covered += 1
                        if in_mar:
                            tally.mar_fired_covered += 1
        out["deltas"][f"{delta:.2f}"] = {
            "nodes": {name: tallies[name].as_dict() for name in node_names},
            "missingness": {name: by_name[name].missingness for name in node_names},
        }
    return out


def _print_report(results: dict[str, Any]) -> None:
    print(
        f"Credible-interval perturbation coverage "
        f"(seed={results['seed']}, {results['worlds']} worlds x "
        f"{results['samples_per_world']} samples per delta)"
    )
    print()
    print("coverage: share of samples where the shipped 80% interval contains the")
    print("perturbed world's conditional probability under the model's own")
    print("conditioning semantics (the gated number, conditional on fired evidence).")
    print("mar: the same against the raw generative conditional where absence is")
    print("informative for every node; diagnostic only (correlation.md 4.3).")
    for delta_key, level in results["deltas"].items():
        print()
        tautological = " (consistency sanity row; total by construction)" if float(delta_key) == 0.0 else ""
        print(f"=== delta = {delta_key}{tautological} ===")
        header = f"{'node':<34}{'n':>7}{'fired':>7}{'cov':>8}{'cov|f':>8}{'mar':>8}{'mar|f':>8}{'width':>8}"
        print(header)
        print("-" * len(header))
        for name, row in level["nodes"].items():

            def fmt(v: float | None) -> str:
                return f"{v:.3f}" if v is not None else "-"

            print(
                f"{name:<34}{row['n']:>7}{row['fired_n']:>7}"
                f"{fmt(row['coverage']):>8}{fmt(row['fired_coverage']):>8}"
                f"{fmt(row['mar_coverage']):>8}{fmt(row['mar_fired_coverage']):>8}"
                f"{fmt(row['mean_width']):>8}"
            )
    print()
    print("The delta=0.20 fired-evidence coverage is the assurance claim: under the")
    print("CAL8 likelihood-imprecision band, the 80% interval should contain the")
    print("correct-world conditional at least 80% of the time. This is model-internal")
    print("coverage against parameter misspecification, not ground-truth calibration")
    print("(CAL13); no real-world labels are involved.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Credible-interval perturbation coverage (synthetic, aggregate-only).")
    parser.add_argument(
        "--deltas",
        type=str,
        default=",".join(str(d) for d in _DEFAULT_DELTAS),
        help="Comma-separated perturbation levels (default '0.0,0.1,0.2,0.3').",
    )
    parser.add_argument("--worlds", type=int, default=10, help="Perturbed networks per delta (default 10).")
    parser.add_argument("--samples", type=int, default=200, help="Synthetic domains per world (default 200).")
    parser.add_argument("--seed", type=int, default=1729, help="RNG seed for reproducibility (default 1729).")
    parser.add_argument("--json", action="store_true", help="Emit the aggregate results as JSON instead of a table.")
    args = parser.parse_args()
    if args.worlds < 1 or args.samples < 1:
        parser.error("--worlds and --samples must be positive integers")
    try:
        deltas = tuple(float(d) for d in args.deltas.split(",") if d.strip())
    except ValueError:
        parser.error("--deltas must be a comma-separated list of numbers")
    if any(d < 0.0 or d >= 1.0 for d in deltas):
        parser.error("each delta must be in [0, 1)")

    results = run_coverage(deltas=deltas, worlds=args.worlds, samples=args.samples, seed=args.seed)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        _print_report(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
