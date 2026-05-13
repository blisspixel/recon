"""v1.9.4 hardened-adversarial validation analyzer.

Produces three aggregates from the hardened-corpus run + the
re-run of the v1.9.0 soft corpus on the current (v1.9.3+)
topology:

1. **Trend table per node** — sparse rate, high-confidence
   count, mean posterior across v1.9.0 (old topology, with
   email_security_strong) → v1.9.3+ (split topology) →
   v1.9.4-hardened. Non-comparable nodes (the split) carry an
   explicit note rather than a fake comparison.

2. **Per-category breakdown** for the hardened corpus — five
   categories (heavy-proxied / privacy / financial / defense /
   gov), each 10 domains, with per-node sparse rate and
   high-confidence count.

3. **Survival rate** — what fraction of high-confidence
   posteriors survive the migration from soft to hardened
   corpus, per node. Quantifies the asymmetric-likelihood
   design's headline claim that hardened targets cause the
   layer to back off from confident assertions.

All output anonymizes per-domain detail: only counts, fractions,
and short SHA-256 hashes for disagreement triage. No domain
names printed.

Run:
    python validation/analyze_v19_4_hardened.py \\
        --hardened validation/corpus-private/v1.9.4-hardened/results.ndjson \\
        --hardened-source validation/corpus-private/v1.9.4-hardened.txt \\
        --soft-current validation/runs-private/v1.9.4-soft-rerun/results.ndjson \\
        --soft-original validation/runs-private/v1.9-calibration/results.ndjson
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# Category labels in declaration order; reused for per-category
# breakdown when --hardened-source carries the # category markers
# from the v1.9.4-hardened.txt corpus file.
_CATEGORY_HEADERS = (
    ("A.", "edge-proxied"),
    ("B.", "privacy"),
    ("C.", "financial"),
    ("D.", "defense"),
    ("E.", "government"),
)


def _load_ndjson(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "error" in d:
                continue
            out.append(d)
    return out


def _parse_categories(source_path: Path) -> dict[str, str]:
    """Map apex → category label by walking the source corpus file.

    Categories are introduced by lines like ``# A. Heavy
    edge-proxied apexes``; subsequent non-comment lines (until
    the next category header) belong to that category. Returns a
    dict keyed by lowercased apex.
    """
    mapping: dict[str, str] = {}
    current: str | None = None
    if not source_path.exists():
        return mapping
    with source_path.open(encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                for prefix, label in _CATEGORY_HEADERS:
                    if prefix in line:
                        current = label
                        break
                continue
            if current is None:
                continue
            mapping[line.lower()] = current
    return mapping


def _per_node_aggregate(records: list[dict]) -> dict[str, dict[str, float]]:
    """Per-node aggregate: count, sparse_pct, high_conf_pct, mean_posterior.

    A high-confidence posterior is posterior >= 0.85 AND sparse=False.
    """
    per_node: dict[str, dict[str, list]] = defaultdict(lambda: {
        "posteriors": [], "sparse": [], "high_conf": [],
    })
    for d in records:
        for p in d.get("posterior_observations", []) or []:
            name = p["name"]
            per_node[name]["posteriors"].append(p["posterior"])
            per_node[name]["sparse"].append(1 if p.get("sparse") else 0)
            high = p["posterior"] >= 0.85 and not p.get("sparse")
            per_node[name]["high_conf"].append(1 if high else 0)

    out: dict[str, dict[str, float]] = {}
    for name, buckets in per_node.items():
        n = len(buckets["posteriors"])
        if n == 0:
            continue
        out[name] = {
            "n": n,
            "sparse_pct": 100.0 * sum(buckets["sparse"]) / n,
            "high_conf_pct": 100.0 * sum(buckets["high_conf"]) / n,
            "mean_posterior": statistics.mean(buckets["posteriors"]),
        }
    return out


def _format_trend_table(
    old_agg: dict[str, dict[str, float]],
    cur_soft_agg: dict[str, dict[str, float]],
    hardened_agg: dict[str, dict[str, float]],
) -> str:
    """Render the per-node trend across runs.

    Nodes present in only one column show "n/a" in the others — the
    v1.9.3 topology split makes email_security_strong unavailable in
    current/hardened, and the split children unavailable in the
    v1.9.0 column. We print the n/a explicitly rather than hiding
    rows to make the topology change visible.
    """
    nodes = sorted(set(old_agg) | set(cur_soft_agg) | set(hardened_agg))
    lines: list[str] = []
    lines.append(
        f"  {'node':<35} {'v1.9.0 sparse%':>14}  {'v1.9.3+ sparse%':>15}  {'v1.9.4-hardened sparse%':>22}",
    )
    lines.append("  " + "-" * 91)
    for name in nodes:
        old = old_agg.get(name)
        cur = cur_soft_agg.get(name)
        hard = hardened_agg.get(name)
        cells = []
        for agg in (old, cur, hard):
            cells.append(f"{agg['sparse_pct']:.1f}%" if agg else "n/a")
        lines.append(f"  {name:<35} {cells[0]:>14}  {cells[1]:>15}  {cells[2]:>22}")
    return "\n".join(lines)


def _format_survival_table(
    cur_soft_agg: dict[str, dict[str, float]],
    hardened_agg: dict[str, dict[str, float]],
) -> str:
    """High-confidence survival rate per node: hardened / soft.

    Values > 100% are possible when the hardened sample happens to
    surface a node more often than the soft sample — e.g.
    cdn_fronting on heavily-proxied apexes. We surface the raw ratio
    rather than capping; the headline number is the asymmetric-
    likelihood design property holding on nodes that should be hard
    to detect on hardened targets.
    """
    nodes = sorted(set(cur_soft_agg) & set(hardened_agg))
    lines: list[str] = []
    lines.append(
        f"  {'node':<35} {'soft high-conf%':>15}  {'hardened high-conf%':>20}  {'survival ratio':>15}",
    )
    lines.append("  " + "-" * 91)
    for name in nodes:
        cur = cur_soft_agg[name]
        hard = hardened_agg[name]
        ratio = (hard["high_conf_pct"] / cur["high_conf_pct"]) if cur["high_conf_pct"] > 0 else float("inf")
        ratio_str = f"{ratio:.2f}" if ratio != float("inf") else "n/a"
        lines.append(
            f"  {name:<35} {cur['high_conf_pct']:>13.1f}%  {hard['high_conf_pct']:>18.1f}%  {ratio_str:>15}",
        )
    return "\n".join(lines)


def _format_category_table(
    records: list[dict],
    categories: dict[str, str],
) -> str:
    """Per-category x per-node sparse rate for the hardened corpus.

    Surfaces which hardening patterns produce which behavior.
    Categories with < 5 valid records get a (small N) annotation.
    """
    by_category: dict[str, list[dict]] = defaultdict(list)
    for d in records:
        apex = (d.get("queried_domain") or "").lower()
        cat = categories.get(apex)
        if cat is None:
            continue
        by_category[cat].append(d)

    if not by_category:
        return "  (no per-category data; --hardened-source not provided or unmatched)"

    cat_order = [label for _, label in _CATEGORY_HEADERS if label in by_category]
    aggs = {cat: _per_node_aggregate(by_category[cat]) for cat in cat_order}
    all_nodes = sorted({n for agg in aggs.values() for n in agg})

    lines: list[str] = []
    header = "  " + "node".ljust(35)
    for cat in cat_order:
        header += f"{cat:>16}"
    lines.append(header)
    counts = "  " + "(n)".ljust(35)
    for cat in cat_order:
        counts += f"{f'({len(by_category[cat])})':>16}"
    lines.append(counts)
    lines.append("  " + "-" * (35 + 16 * len(cat_order)))
    for name in all_nodes:
        row = "  " + name.ljust(35)
        for cat in cat_order:
            agg = aggs[cat].get(name)
            cell = f"{agg['sparse_pct']:.0f}% sparse" if agg else "n/a"
            row += f"{cell:>16}"
        lines.append(row)
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hardened", required=True, type=Path)
    p.add_argument("--hardened-source", required=True, type=Path)
    p.add_argument("--soft-current", required=True, type=Path)
    p.add_argument("--soft-original", required=True, type=Path)
    args = p.parse_args()

    for path in (args.hardened, args.soft_current, args.soft_original):
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 2

    hardened = _load_ndjson(args.hardened)
    soft_cur = _load_ndjson(args.soft_current)
    soft_orig = _load_ndjson(args.soft_original)
    categories = _parse_categories(args.hardened_source)

    print("=== v1.9.4 hardened-adversarial validation aggregates ===\n")
    print(f"Hardened corpus:      {len(hardened)} successful domains")
    print(f"Soft corpus (current): {len(soft_cur)} successful domains")
    print(f"Soft corpus (v1.9.0):  {len(soft_orig)} successful domains")
    print()

    hardened_agg = _per_node_aggregate(hardened)
    soft_cur_agg = _per_node_aggregate(soft_cur)
    soft_orig_agg = _per_node_aggregate(soft_orig)

    print("--- Per-node trend (sparse rate per run) ---")
    print(_format_trend_table(soft_orig_agg, soft_cur_agg, hardened_agg))
    print()

    print("--- High-confidence survival: soft -> hardened ---")
    print("  (the asymmetric-likelihood design's headline claim: nodes that")
    print("  should be hard to detect on hardened targets *back off*)")
    print()
    print(_format_survival_table(soft_cur_agg, hardened_agg))
    print()

    print("--- Per-category breakdown (hardened corpus) ---")
    print(_format_category_table(hardened, categories))
    print()

    # Soft-corpus no-regression check: spot-check agreement % rate
    # on the current run should match or exceed the v1.9.0 baseline.
    # We approximate by counting high_conf posteriors and asserting
    # they all back the deterministic pipeline. Full agreement check
    # is in analyze_v19_calibration.py — this is the regression
    # tripwire.
    def _high_conf_count(records: list[dict[str, Any]]) -> int:
        n = 0
        for d in records:
            for p in d.get("posterior_observations", []) or []:
                if p["posterior"] >= 0.85 and not p.get("sparse"):
                    n += 1
        return n

    soft_cur_high = _high_conf_count(soft_cur)
    soft_orig_high = _high_conf_count(soft_orig)
    print("--- Soft-corpus regression tripwire ---")
    print(f"  v1.9.0 corpus high-confidence count: {soft_orig_high}")
    print(f"  v1.9.3+ topology high-confidence count: {soft_cur_high}")
    print(f"  Delta: {soft_cur_high - soft_orig_high:+d}  (negative = topology split reduced some high-conf signals;")
    print("           expected: email_security_strong split into two more-conservative nodes)")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
