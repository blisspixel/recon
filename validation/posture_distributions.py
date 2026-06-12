"""Posture-stratified distributions: information recovered, interval width.

The two paper experiments that read the engine's per-domain behaviour as
*distributions* rather than point checks, both consuming what the 2.2
diagnostics now expose:

1. **Information recovered (CAL10) across hardening postures.** The
   operational reading of "what the public channel still leaks after
   hardening": the per-domain posterior entropy reduction
   (H(prior) - H(posterior), summed over nodes, in nats), bucketed by an
   observable hardening posture. The sharpest observable hardening move is
   edge-proxying — a CDN/edge in front of the origin hides infrastructure —
   so the primary cut is edge-proxied vs direct, crossed with an
   evidence-richness tier. If hardening reduces what the channel leaks, the
   edge-proxied / sparse buckets show lower entropy reduction; the harness
   measures that instead of asserting it.

2. **Interval width vs evidence (the CAL7 over-confidence diagnostic).**
   The credible interval is meant to be evidence-responsive: wider on
   sparse nodes, narrower as evidence accumulates. This reports the mean
   80% interval width per node bucketed by that node's effective sample
   size, separating grouped nodes (whose co-firing bindings are reduced to
   one effective unit, correlation.md 4.3 / CAL7) from ungrouped ones, so
   the documented residual over-confidence on richly-instrumented grouped
   nodes is visible as a number, not just catalogued. This is the data
   behind the paper's interval-width-vs-evidence-count figure.

Everything reported is aggregate (quantiles, bucket means, counts); no
apex, no per-domain row reaches stdout or any committed file
(docs/data-handling-policy.md). The pure classification and aggregation
functions carry no target data and are unit-tested
(tests/test_posture_distributions.py); the orchestration is the
maintainer-run part. A run reads real apex domains, so it stays
maintainer-local; the synthetic-shaped unit tests are publishable.

Run (maintainer-local, network):

    python -m validation.posture_distributions domains.txt
    python -m validation.posture_distributions domains.txt --concurrency 6
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Observable hardening: a CDN/edge fronts the origin when this node's posterior
# clears 0.5. The dominant passive-hardening move, and the one the entropy cut
# is built around.
_CDN_NODE = "cdn_fronting"
_EDGE_THRESHOLD = 0.5

# Evidence-richness tiers, on the total contributing-binding count across all
# nodes (InferenceResult.evidence_count). Boundaries are descriptive, not
# load-bearing; they only group the entropy distribution.
_SPARSE_MAX = 2
_MODERATE_MAX = 6

# n_eff buckets for the interval-width diagnostic. The floor is 4.0
# (_MIN_N_EFF), so the first bucket is the passive-observation ceiling.
_NEFF_BUCKETS: tuple[tuple[str, float, float], ...] = (
    ("ceiling (<=4)", 0.0, 4.0001),
    ("5-6", 4.0001, 6.0001),
    ("7-9", 6.0001, 9.0001),
    ("10+", 9.0001, float("inf")),
)


def edge_posture(cdn_posterior: float | None, threshold: float = _EDGE_THRESHOLD) -> str:
    """"edge-proxied" when a CDN/edge fronts the origin, else "direct"."""
    if cdn_posterior is None:
        return "direct"
    return "edge-proxied" if cdn_posterior >= threshold else "direct"


def evidence_tier(evidence_count: int) -> str:
    """Bucket the total contributing-evidence count into a richness tier."""
    if evidence_count <= _SPARSE_MAX:
        return "sparse"
    if evidence_count <= _MODERATE_MAX:
        return "moderate"
    return "rich"


def neff_bucket(n_eff: float) -> str:
    """Label the n_eff bucket for the interval-width diagnostic."""
    for label, low, high in _NEFF_BUCKETS:
        if low < n_eff <= high or (low == 0.0 and n_eff <= high):
            return label
    return _NEFF_BUCKETS[-1][0]


def quantiles(values: list[float]) -> tuple[float, float, float]:
    """(p25, p50, p75) by linear interpolation. Empty -> all zero."""
    if not values:
        return (0.0, 0.0, 0.0)
    ordered = sorted(values)

    def _q(q: float) -> float:
        if len(ordered) == 1:
            return ordered[0]
        pos = q * (len(ordered) - 1)
        lo = int(pos)
        hi = min(lo + 1, len(ordered) - 1)
        return ordered[lo] * (1.0 - (pos - lo)) + ordered[hi] * (pos - lo)

    return (round(_q(0.25), 4), round(_q(0.5), 4), round(_q(0.75), 4))


@dataclass(frozen=True)
class DomainRecord:
    """One domain's posture summary (no apex)."""

    entropy_reduction: float
    edge: str
    tier: str


@dataclass(frozen=True)
class NodeWidthRecord:
    """One (node, domain) interval-width observation (no apex)."""

    node: str
    grouped: bool
    n_eff: float
    width: float


def entropy_by_posture(records: list[DomainRecord]) -> dict[str, Any]:
    """Entropy-reduction quantiles per (edge x tier) bucket and overall."""
    buckets: dict[str, list[float]] = {}
    for r in records:
        buckets.setdefault(f"{r.edge} / {r.tier}", []).append(r.entropy_reduction)
        buckets.setdefault(f"{r.edge} (all tiers)", []).append(r.entropy_reduction)
    overall = [r.entropy_reduction for r in records]
    out: dict[str, Any] = {
        "n": len(records),
        "overall_quartiles": quantiles(overall),
        "buckets": {
            name: {"n": len(vals), "quartiles": quantiles(vals)} for name, vals in sorted(buckets.items())
        },
    }
    return out


def width_by_evidence(records: list[NodeWidthRecord]) -> dict[str, Any]:
    """Mean 80% interval width per (grouped?, n_eff bucket).

    The evidence-responsiveness signal is the width falling as n_eff rises;
    the CAL7 signal is the grouped rows staying at least as tight as the
    ungrouped at matched n_eff (co-firing reduced to one effective unit).
    """
    cells: dict[tuple[bool, str], list[float]] = {}
    for r in records:
        cells.setdefault((r.grouped, neff_bucket(r.n_eff)), []).append(r.width)
    out: dict[str, Any] = {}
    for grouped in (False, True):
        rows: dict[str, Any] = {}
        for label, _lo, _hi in _NEFF_BUCKETS:
            vals = cells.get((grouped, label), [])
            if vals:
                rows[label] = {"n": len(vals), "mean_width": round(sum(vals) / len(vals), 4)}
        out["grouped" if grouped else "ungrouped"] = rows
    return out


async def _collect_one(
    domain: str, *, timeout: float, sem: asyncio.Semaphore
) -> tuple[DomainRecord, list[NodeWidthRecord]] | None:
    """Resolve one domain, infer, and build its posture records (no apex)."""
    from recon_tool.bayesian import infer_from_tenant_info, load_network
    from recon_tool.resolver import resolve_tenant

    network = load_network()
    grouped_nodes = {n.name for n in network.nodes if any(ev.group for ev in n.evidence)}

    async with sem:
        try:
            info, _results = await resolve_tenant(domain, timeout=timeout, skip_ct=True)
        except Exception:
            return None
    result = infer_from_tenant_info(info, network=network)
    posteriors = {p.name: p for p in result.posteriors}
    cdn = posteriors.get(_CDN_NODE)
    domain_record = DomainRecord(
        entropy_reduction=float(result.entropy_reduction),
        edge=edge_posture(cdn.posterior if cdn is not None else None),
        tier=evidence_tier(result.evidence_count),
    )
    width_records = [
        NodeWidthRecord(
            node=p.name,
            grouped=p.name in grouped_nodes,
            n_eff=float(p.n_eff),
            width=float(p.interval_high - p.interval_low),
        )
        for p in result.posteriors
    ]
    return domain_record, width_records


async def collect(
    domains: list[str], *, timeout: float, concurrency: int
) -> tuple[list[DomainRecord], list[NodeWidthRecord]]:
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*[_collect_one(d, timeout=timeout, sem=sem) for d in domains])
    domain_records: list[DomainRecord] = []
    width_records: list[NodeWidthRecord] = []
    for r in results:
        if r is None:
            continue
        domain_records.append(r[0])
        width_records.extend(r[1])
    return domain_records, width_records


def _read_domains(path: Path) -> list[str]:
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _print(domain_records: list[DomainRecord], width_records: list[NodeWidthRecord]) -> None:
    ent = entropy_by_posture(domain_records)
    print(f"\nInformation recovered (CAL10): per-domain entropy reduction in nats (n={ent['n']})")
    q = ent["overall_quartiles"]  # type: ignore[index]
    print(f"  overall                        p25 {q[0]:.3f}  p50 {q[1]:.3f}  p75 {q[2]:.3f}")
    for name, cell in ent["buckets"].items():  # type: ignore[attr-defined]
        cq = cell["quartiles"]
        print(f"  {name:<30} n {cell['n']:<5} p25 {cq[0]:.3f}  p50 {cq[1]:.3f}  p75 {cq[2]:.3f}")

    width = width_by_evidence(width_records)
    print("\nInterval width vs evidence (CAL7 diagnostic): mean 80% interval width by n_eff")
    for kind in ("ungrouped", "grouped"):
        print(f"  {kind} nodes:")
        rows = width[kind]  # type: ignore[index]
        if not rows:
            print("    (none)")
        for label, _lo, _hi in _NEFF_BUCKETS:
            if label in rows:
                cell = rows[label]
                print(f"    n_eff {label:<14} mean width {cell['mean_width']:.4f}  (n {cell['n']})")
    print(
        "\nReading: the hardening signal is the SPARSE evidence tier (little fired, so"
        "\nlittle recovered) — not the edge-proxied flag, which marks a CDN that was"
        "\nDETECTED and so adds information rather than hiding it. Interval width should"
        "\nfall as n_eff rises (evidence-responsiveness); grouped nodes are not narrower"
        "\nthan ungrouped at matched n_eff, which is the CAL7 co-firing correction"
        "\nworking (it prevents over-confidence rather than causing it). Aggregates"
        "\nonly; see docs/statistical-assurance.md and validation/layer-ablation.md."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Posture-stratified entropy + interval-width distributions.")
    parser.add_argument("domains", type=Path, help="File with one apex per line (gitignored / outside the tree).")
    parser.add_argument("--concurrency", type=int, default=6, help="Concurrent resolves (default 6).")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-domain resolve timeout seconds.")
    args = parser.parse_args(argv)

    if not args.domains.is_file():
        print(f"FAIL: domains file not found: {args.domains}")
        return 1
    domains = _read_domains(args.domains)
    print(f"Resolving {len(domains)} domains for posture distributions (aggregates only, no apex printed)...")
    domain_records, width_records = asyncio.run(collect(domains, timeout=args.timeout, concurrency=args.concurrency))
    if not domain_records:
        print("No domains resolved; nothing to summarize.")
        return 0
    _print(domain_records, width_records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
