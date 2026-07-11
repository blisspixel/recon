"""Model-relative uncertainty-band perturbation experiment.

The shipped 80% uncertainty band is a post-inference display heuristic. This
harness checks one finite sensitivity scenario without treating the result as a
credible interval, confidence interval, identification region, or ground-truth
calibration claim.

What the experiment checks. For selected multiplicative likelihood
perturbations, measure whether the shipped band contains the conditional
probability under each perturbed model. This is scenario containment over a
finite sampled set, not a bound over all parameter, dependence, or missingness
uncertainty.

Method, per perturbation level ``delta``:

1. Build "worlds": copies of the shipped network with every evidence
   likelihood (and declarative ``group_absence`` pair) scaled by an
   independent factor drawn from ``[1 - delta, 1 + delta]``, clipped to
   the valid open interval. ``delta = 0.2`` is the CAL8 sensitivity
   band.
2. Sample latent assignments from each prior/CPT graph, then sample bindings
   independently as Bernoulli variables, the same misspecification stress
   procedure as ``synthetic_calibration.py``. This is not the committed grouped
   observation or missingness model.
3. For each sample, run the SHIPPED model's ``infer()`` to get each
   node's posterior and 80% interval, and compute the world's own
   conditional probability ``P(node = present | observations)`` with
   the independent full-joint reference from
   ``differential_verification.py`` (no engine code in the truth path).
4. Report, per node, how often the shipped band contains the world's
   conditional probability: over all samples and over the selected subset in
   which at least one binding fired. The selected subset is reported as a
   diagnostic, not as a population or assurance claim.

At ``delta = 0`` the world equals the model, the reference equals the
engine (verified differentially in v2.1.7), and coverage is total by
construction. That row is a consistency sanity check in the CAL1 sense,
not evidence; the informative rows are ``delta > 0``.

A second diagnostic reference is also reported: the fully observed Bernoulli
conditional, where each binding's fired or non-fired outcome is observed and a
non-fire contributes its Bernoulli complement for every node. This is a
nonfire-informative synthetic observation model, not a MAR missing-data model.
The shipped model deliberately declines to condition on non-fire for hideable
nodes. Their comparison describes two synthetic conditioning rules; it does not
identify public-channel missingness.

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
# 0.2 is the recorded CAL8 scenario; 0.1 / 0.3 show the response.
_DEFAULT_DELTAS = (0.0, 0.1, 0.2, 0.3)


def perturb_world(net: BayesianNetwork, delta: float, rng: random.Random) -> BayesianNetwork:
    """A copy of ``net`` with every evidence-model parameter jittered.

    Each binding's ``likelihood_present`` / ``likelihood_absent`` and each
    declarative ``group_absence`` pair is scaled by its own factor drawn
    uniformly from ``[1 - delta, 1 + delta]``, clipped to the valid open
    interval. Priors and CPT entries are left alone because this finite
    experiment varies only the evidence-likelihood surface. It does not claim
    to bound prior, CPT, dependence, or missingness uncertainty.
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


def _fully_observed_node_likelihood(node: _Node, fired_names: set[str]) -> tuple[float, float]:
    """``P(full fired/non-fired pattern | node state)`` for Bernoulli bindings.

    Every binding outcome is observed, so a non-fire contributes its complement
    for every node. This is a fully observed synthetic likelihood, not a MAR
    missing-data construction.
    """
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
    fully_observed_covered: int = 0
    fully_observed_fired_covered: int = 0
    width_sum: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "fired_n": self.fired_n,
            "coverage": round(self.covered / self.n, 4) if self.n else None,
            "fired_coverage": round(self.fired_covered / self.fired_n, 4) if self.fired_n else None,
            # Historical JSON keys are retained for compatibility with recorded
            # validation artifacts. They mean fully observed Bernoulli-pattern
            # containment, not missing-at-random coverage.
            "mar_coverage": round(self.fully_observed_covered / self.n, 4) if self.n else None,
            "mar_fired_coverage": (
                round(self.fully_observed_fired_covered / self.fired_n, 4) if self.fired_n else None
            ),
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
        "legacy_metric_names": {
            "mar_coverage": "fully observed Bernoulli-pattern containment",
            "mar_fired_coverage": "the same metric on the fired-evidence subset",
            "note": "mar_* keys are historical compatibility names, not MAR assumptions",
        },
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
                fully_observed_like: dict[str, tuple[float, float]] = {}
                for name in node_names:
                    node = world.get(name)
                    fired = [ev for ev in node.evidence if ev.name in observed]
                    model_like[name] = _reference_node_likelihood(node, fired)
                    fully_observed_like[name] = _fully_observed_node_likelihood(node, observed)
                truth = _posteriors_from_likelihoods(joint, model_like)
                fully_observed_truth = _posteriors_from_likelihoods(joint, fully_observed_like)

                result = infer(shipped, obs_slugs, obs_signals, priors_override={})
                for p in result.posteriors:
                    tally = tallies[p.name]
                    lo = p.interval_low - _EDGE_TOL
                    hi = p.interval_high + _EDGE_TOL
                    fired_any = bool(binding_names[p.name] & observed)
                    tally.n += 1
                    tally.width_sum += p.interval_high - p.interval_low
                    in_model = lo <= truth[p.name] <= hi
                    in_fully_observed = lo <= fully_observed_truth[p.name] <= hi
                    if in_model:
                        tally.covered += 1
                    if in_fully_observed:
                        tally.fully_observed_covered += 1
                    if fired_any:
                        tally.fired_n += 1
                        if in_model:
                            tally.fired_covered += 1
                        if in_fully_observed:
                            tally.fully_observed_fired_covered += 1
        out["deltas"][f"{delta:.2f}"] = {
            "nodes": {name: tallies[name].as_dict() for name in node_names},
            "missingness": {name: by_name[name].missingness for name in node_names},
        }
    return out


def _print_report(results: dict[str, Any]) -> None:
    print(
        f"Uncertainty-band perturbation containment "
        f"(seed={results['seed']}, {results['worlds']} worlds x "
        f"{results['samples_per_world']} samples per delta)"
    )
    print()
    print("coverage: historical metric key for the sampled share where the shipped")
    print("80% uncertainty band contains the")
    print("perturbed world's conditional probability under the model's own")
    print("conditioning semantics; fired evidence is a separately selected subset.")
    print("fullobs: the same against a fully observed Bernoulli conditional where")
    print("non-fire is informative for every node; diagnostic only. JSON retains")
    print("historical mar_* keys for artifact compatibility, not as a MAR claim.")
    for delta_key, level in results["deltas"].items():
        print()
        tautological = " (consistency sanity row; total by construction)" if float(delta_key) == 0.0 else ""
        print(f"=== delta = {delta_key}{tautological} ===")
        header = f"{'node':<34}{'n':>7}{'fired':>7}{'cov':>8}{'cov|f':>8}{'fullobs':>8}{'full|f':>8}{'width':>8}"
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
    print("The delta=0.20 row is a finite, seeded scenario-containment regression.")
    print("Its 0.80 test threshold preserves recorded behavior for these sampled")
    print("worlds. It is not a nominal coverage guarantee or a bound on parameter,")
    print("dependence, missingness, or real-world uncertainty.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Uncertainty-band scenario containment (synthetic, aggregate-only).")
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
