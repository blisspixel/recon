"""Stateless cohort reducer with caller grouping over recon output (v2.1).

Downstream sidecar, not recon core. The per-cohort statistics (observability,
public-claim rates, hideable model support, model-score mass, and mix
concentration) and the math live in
``recon_tool.cohort_summary`` and are shared with the in-core ``recon batch
--summary`` so the two never drift. This reducer adds only the downstream parts:
caller-supplied grouping, distinctive-slug ranking (weighted log-odds with a
Dirichlet prior), and the multi-cohort document.

It never stores anything, ships no baselines, makes no baseline-relative anomaly
score, infers no unobserved services, and names no domain in its output. See
``docs/aggregate-state.md``.

Usage:
    python aggregate_state.py results.ndjson [--group-by groups.csv] [--label NAME]
    recon batch domains.txt --ndjson | python aggregate_state.py - --group-by g.csv

The optional grouping file is a two-column ``domain,label`` CSV owned by the
caller; it stays local. Output is JSON on stdout.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from recon_tool.cohort_summary import COHORT_DISCLAIMER, summarize_cohort

# Dirichlet smoothing for the weighted log-odds; a small symmetric prior shrinks
# rare slug counts toward no-difference.
_LOGODDS_ALPHA = 0.5

# A slug must appear in at least this many domains in a group to be ranked, so a
# single domain cannot manufacture a distinctive finding.
_MIN_DISTINCTIVE_SUPPORT = 3

_SUPPRESS_MAX = 10
_SMALL_N = 30


def weighted_log_odds(
    group_counts: Mapping[str, int],
    background_counts: Mapping[str, int],
    alpha: float = _LOGODDS_ALPHA,
) -> dict[str, tuple[float, float]]:
    """Monroe et al. weighted log-odds-ratio with a symmetric Dirichlet prior.

    Returns {term: (delta, z)} where delta is the smoothed log-odds-ratio of the
    term in the group versus the background and z is delta over its standard
    deviation. Larger |z| means more distinctive; the prior shrinks rare counts.
    """
    vocab = set(group_counts) | set(background_counts)
    v = len(vocab)
    a0 = alpha * v
    n_i = sum(group_counts.values())
    n_j = sum(background_counts.values())
    out: dict[str, tuple[float, float]] = {}
    for term in vocab:
        y_i = group_counts.get(term, 0)
        y_j = background_counts.get(term, 0)
        num_i = y_i + alpha
        den_i = n_i + a0 - y_i - alpha
        num_j = y_j + alpha
        den_j = n_j + a0 - y_j - alpha
        if den_i <= 0 or den_j <= 0:
            continue
        delta = math.log(num_i / den_i) - math.log(num_j / den_j)
        var = 1.0 / num_i + 1.0 / num_j
        z = delta / math.sqrt(var) if var > 0 else 0.0
        out[term] = (delta, z)
    return out


def _suppressed(count: int) -> int | str:
    return "<=10 (suppressed)" if 1 <= count <= _SUPPRESS_MAX else count


def distinctiveness(groups: Mapping[str, Sequence[Mapping[str, Any]]], top_k: int = 5) -> dict[str, Any]:
    """Per-group distinctive slugs by weighted log-odds versus the rest of the
    caller's cohort. Needs at least two groups; slugs below the support floor are
    not ranked."""
    if len(groups) < 2:
        return {"note": "distinctiveness needs at least two caller groups"}
    slug_counts: dict[str, Counter[str]] = {}
    for label, recs in groups.items():
        c: Counter[str] = Counter()
        for r in recs:
            slugs = r.get("slugs")
            for slug in (slugs if isinstance(slugs, (list, tuple)) else []):
                c[str(slug)] += 1
        slug_counts[label] = c
    out: dict[str, Any] = {}
    for label, group_c in slug_counts.items():
        background: Counter[str] = Counter()
        for other, c in slug_counts.items():
            if other != label:
                background.update(c)
        scored = weighted_log_odds(group_c, background)
        ranked = sorted(
            (
                {"slug": s, "log_odds": round(d, 3), "z": round(z, 3), "support": _suppressed(group_c[s])}
                for s, (d, z) in scored.items()
                if group_c[s] >= _MIN_DISTINCTIVE_SUPPORT
            ),
            # Total, deterministic order: z descending, then log-odds, then slug.
            # weighted_log_odds iterates a set, so sorting on z alone left tied
            # z-scores in hash-seed-dependent order (and top_k could then drop
            # different slugs across runs).
            key=lambda row: (-float(row["z"]), -float(row["log_odds"]), str(row["slug"])),
        )
        out[label] = ranked[:top_k]
    return out


def reduce_records(
    records: Sequence[Mapping[str, Any]],
    grouping: Mapping[str, str] | None = None,
    label: str = "cohort",
) -> dict[str, Any]:
    """Top-level reduction: global summary, per-group summaries, distinctiveness."""
    result: dict[str, Any] = {
        "record_type": "cohort_summary",
        "schema_version": "2.1",
        "disclaimer": COHORT_DISCLAIMER,
        "suppression_policy": f"counts 1..{_SUPPRESS_MAX} withheld; small-n warning below {_SMALL_N}",
        "global": summarize_cohort(records, label),
    }
    if grouping:
        groups: dict[str, list[Mapping[str, Any]]] = {}
        for r in records:
            dom = str(r.get("queried_domain") or r.get("default_domain") or "")
            grp = grouping.get(dom)
            if grp:
                groups.setdefault(grp, []).append(r)
        if groups:
            result["by_group"] = {g: summarize_cohort(recs, g) for g, recs in sorted(groups.items())}
            result["distinctiveness"] = distinctiveness(groups)
    return result


def load_records(source: str) -> list[dict[str, Any]]:
    """Read recon JSON: a JSON array, an NDJSON stream, or a {"results": [...]}
    wrapper. ``source`` of '-' reads stdin."""
    text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    text = text.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict) and isinstance(parsed.get("results"), list):
            records = parsed["results"]
        else:
            records = [parsed]
    except json.JSONDecodeError:
        records = []
        for raw in text.splitlines():
            row = raw.strip()
            if not row:
                continue
            try:
                records.append(json.loads(row))
            except json.JSONDecodeError:
                continue  # skip a malformed NDJSON line rather than abort the run
    # Keep only object records; a non-dict element (scalar, list, null) from a
    # hand-edited or third-party file must not crash the reducer.
    return [r for r in records if isinstance(r, dict)]


def load_grouping(path: str) -> dict[str, str]:
    """Read a caller-owned ``domain,label`` CSV. Stays local."""
    grouping: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            row = raw.strip()
            if not row or row.startswith("#"):
                continue
            parts = [p.strip() for p in row.split(",")]
            if len(parts) >= 2 and parts[0].lower() != "domain":
                grouping[parts[0]] = parts[1]
    return grouping


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stateless cohort reducer over recon JSON output.")
    parser.add_argument("source", help="recon JSON/NDJSON file, or - for stdin")
    parser.add_argument("--group-by", dest="group_by", help="caller-owned domain,label CSV", default=None)
    parser.add_argument("--label", default="cohort", help="label for the global cohort")
    args = parser.parse_args(argv)

    records = load_records(args.source)
    grouping = load_grouping(args.group_by) if args.group_by else None
    summary = reduce_records(records, grouping, label=args.label)
    json.dump(summary, sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
