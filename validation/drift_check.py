"""PV2 drift detection: a corpus-free fingerprint of the inference layer.

Part of the maintainer-validation loop (see ``docs/maintainer-validation.md``).
The Bayesian network's CPT-implied marginals are deterministic from
``bayesian_network.yaml`` with no corpus, so a committed baseline plus this check
mechanically enforce the CPT-change discipline: any edit that shifts a node's
implied distribution beyond ``_MARGINAL_BAND`` fails the gate until the baseline
is regenerated with ``--update``, a deliberate acknowledgment that shows up in
the diff next to the network change that caused it.

Two fixed evidence configurations fingerprint every node's CPT sensitively:

  * the no-evidence **prior marginal** (catches a changed prior or a CPT change
    that propagates through to a downstream node with no evidence), and
  * the **all-bindings-present posterior** and its interval width (catches a
    changed likelihood / CPT entry that only moves a node once its evidence
    fires, which the prior marginal would miss).

The corpus-dependent half of PV2 (catalog firing-rate drift, base-rate
re-grounding) stays maintainer-local against the gitignored corpus and is run
via ``scan.py`` + ``compute_node_stability.py``; only this deterministic
inference fingerprint is committed and CI-gated.

Usage::

    python -m validation.drift_check            # check; nonzero exit on un-ack'd drift
    python -m validation.drift_check --json      # agent-readable drift report
    python -m validation.drift_check --update     # regenerate the committed baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from recon_tool.bayesian import infer, load_network

_BASELINE_PATH = Path(__file__).parent / "inference_baseline.json"

# Absolute move in a node's prior, all-present posterior, or interval width that
# counts as material drift. The priors/likelihoods are directionally-accurate
# corpus-grounded estimates, not values precise to many decimals, so a sub-0.01
# wobble is below the meaningful resolution; anything larger is a real shift in
# the implied distribution that a reviewer should see and acknowledge.
_MARGINAL_BAND = 0.01

_SCHEMA = 1

_FIELDS = ("prior", "all_present", "all_present_interval_width")


def _r(x: float) -> float:
    return round(float(x), 4)


def compute_fingerprint() -> dict[str, Any]:
    """Return the deterministic per-node CPT fingerprint of the shipped network."""
    net = load_network()
    all_slugs = sorted({e.name for n in net.nodes for e in n.evidence if e.kind == "slug"})
    all_signals = sorted({e.name for n in net.nodes for e in n.evidence if e.kind == "signal"})

    prior = {p.name: p for p in infer(net, [], [], priors_override={}).posteriors}
    full = {p.name: p for p in infer(net, all_slugs, all_signals, priors_override={}).posteriors}

    nodes: dict[str, Any] = {}
    for node in net.nodes:
        name = node.name
        pr = prior[name]
        fu = full[name]
        nodes[name] = {
            "prior": _r(pr.posterior),
            "all_present": _r(fu.posterior),
            "all_present_interval_width": _r(fu.interval_high - fu.interval_low),
        }
    return {"schema": _SCHEMA, "inference": {"network_nodes": len(net.nodes), "nodes": nodes}}


def compare(baseline: dict[str, Any], current: dict[str, Any], band: float = _MARGINAL_BAND) -> dict[str, Any]:
    """Return the drift report: every node field that moved beyond ``band``."""
    base_nodes = baseline.get("inference", {}).get("nodes", {})
    cur_nodes = current["inference"]["nodes"]

    drift: list[dict[str, Any]] = []
    for name in sorted(set(base_nodes) | set(cur_nodes)):
        b = base_nodes.get(name)
        c = cur_nodes.get(name)
        if b is None:
            drift.append({"node": name, "field": "(node added)", "baseline": None, "current": c, "delta": None})
            continue
        if c is None:
            drift.append({"node": name, "field": "(node removed)", "baseline": b, "current": None, "delta": None})
            continue
        for field in _FIELDS:
            delta = round(float(c[field]) - float(b[field]), 4)
            if abs(delta) > band:
                drift.append({"node": name, "field": field, "baseline": b[field], "current": c[field], "delta": delta})
    return {"band": band, "drift": drift, "drifted": bool(drift)}


def _print_human(report: dict[str, Any]) -> None:
    if not report["drift"]:
        print(f"No inference drift: every node is within +/-{report['band']} of the committed baseline.")
        return
    print(f"INFERENCE DRIFT (band +/-{report['band']}): {len(report['drift'])} field(s) moved.\n")
    print(f"{'node':<35} {'field':<28} {'baseline':>10} {'current':>10} {'delta':>9}")
    print("-" * 95)
    for d in report["drift"]:
        base = "-" if d["baseline"] is None else f"{d['baseline']}"
        cur = "-" if d["current"] is None else f"{d['current']}"
        delta = "-" if d["delta"] is None else f"{d['delta']:+.4f}"
        print(f"{d['node']:<35} {d['field']:<28} {base:>10} {cur:>10} {delta:>9}")
    print(
        "\nIf this change is intended, regenerate the baseline with "
        "`python -m validation.drift_check --update` and commit it alongside the "
        "network edit so the implied-distribution shift is reviewed in the diff."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true", help="regenerate the committed baseline")
    parser.add_argument("--json", action="store_true", help="emit the drift report as JSON (agent-readable)")
    args = parser.parse_args(argv)

    current = compute_fingerprint()

    if args.update:
        _BASELINE_PATH.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print(f"Baseline written: {_BASELINE_PATH}")
        return 0

    if not _BASELINE_PATH.exists():
        print(f"No baseline at {_BASELINE_PATH}; run --update to create it.", file=sys.stderr)
        return 2

    baseline = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    report = compare(baseline, current)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)

    # Gate: un-acknowledged inference drift fails so the CPT-change discipline is
    # enforced; an intended change is acknowledged by committing a fresh baseline.
    return 1 if report["drifted"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
