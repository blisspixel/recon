#!/usr/bin/env python3
"""Measure slug co-occurrence over a private corpus run.

Motivation
----------
recon reports vendors one at a time. Which vendors appear *together*, and how
far past chance, is a separate observation that nothing currently measures.
Three different things produce a high co-occurrence lift, and telling them
apart is the point of this reducer:

1. **Shared evidence.** Two unrelated vendors that co-occur on essentially
   every namespace where the rarer one fires are usually one underlying record
   being attributed twice. This reducer found the wildcard-TXT defect
   independently: `github-advanced-security`, `gitlab` and `slack` co-occurred
   at a conditional probability of 1.00, and so did `afternic`, a domain
   parking service whose namespaces answer any probed label.

2. **A vendor relationship.** `dmarc-analyzer` and `mimecast` co-occur at
   roughly eleven times chance because Mimecast acquired DMARC Analyzer. These
   are not two independent observations of an organization's stack, and the
   catalog records that relationship in the display name rather than in the
   ``parent_vendor`` field that `ecosystem.py` consumes.

3. **A genuine stack archetype.** `klaviyo` with `shopify`, or `mta-sts-enforce`
   with `tls-rpt`, are distinct vendors that travel together because one
   decision tends to accompany the other.

Only the third is a finding about the queried namespace. The first is a bug and
the second is catalog metadata, so both must be separated out before any
co-occurrence result is read as an observation about an organization.

Disclosure safety
-----------------
The reducer reads only the ``slugs`` list from each record and reduces to
counts keyed by slug, which is catalog vocabulary rather than target data. It
never reads ``queried_domain`` or any other identifying field, and a runtime
guard enforces that.

Usage::

    python validation/slug_cooccurrence.py RUN_DIR --out OUT.json
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from recon_tool.fingerprints import load_fingerprints  # noqa: E402

_FORBIDDEN_FIELDS = ("queried_domain", "display_name", "tenant_id", "related_domains", "tenant_domains")

# A pair is only reported when the rarer slug clears this count, so a handful of
# namespaces cannot produce a headline lift.
MIN_PAIR_COUNT = 25

# At or above this conditional probability the rarer slug essentially never
# appears without the other, which is the shared-evidence signature.
SHARED_EVIDENCE_CONDITIONAL = 0.93


class SafeRecord:
    """A results record that refuses reads of target-identifying fields.

    The projection this reducer needs is two keys wide. Wrapping the payload
    means a later edit that reaches for a domain or tenant field raises here
    rather than silently widening what the reducer reads.
    """

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def get(self, key: str, default: Any = None) -> Any:
        if key in _FORBIDDEN_FIELDS:
            raise AssertionError(f"reducer must not read target-identifying field {key!r}")
        return self._data.get(key, default)


def _slugs(record: SafeRecord) -> set[str]:
    return {s for s in (record.get("slugs") or []) if isinstance(s, str)}


def measure(run_dir: Path) -> dict[str, Any]:
    results = run_dir / "results.ndjson"
    if not results.is_file():
        raise SystemExit(f"no results.ndjson under {run_dir}")

    vendor_of = {fp.slug: fp.parent_vendor for fp in load_fingerprints() if fp.parent_vendor}
    family_of = {fp.slug: fp.product_family for fp in load_fingerprints() if fp.product_family}

    observations: list[set[str]] = []
    with results.open(encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            record = SafeRecord(json.loads(line))
            if record.get("record_type") != "lookup":
                continue
            found = _slugs(record)
            if found:
                observations.append(found)

    total = len(observations)
    single: Counter[str] = Counter()
    for found in observations:
        single.update(found)
    pairs: Counter[tuple[str, str]] = Counter()
    for found in observations:
        for combo in itertools.combinations(sorted(found), 2):
            pairs[combo] += 1

    rows: list[dict[str, Any]] = []
    for (left, right), both in pairs.items():
        if both < MIN_PAIR_COUNT:
            continue
        p_left, p_right = single[left] / total, single[right] / total
        lift = (both / total) / (p_left * p_right)
        rarer = left if single[left] <= single[right] else right
        conditional = both / single[rarer]
        linked = bool(
            (vendor_of.get(left) and vendor_of.get(left) == vendor_of.get(right))
            or (family_of.get(left) and family_of.get(left) == family_of.get(right))
        )
        rows.append(
            {
                "a": left,
                "b": right,
                "both": both,
                "count_a": single[left],
                "count_b": single[right],
                "lift": round(lift, 3),
                "rarer": rarer,
                "conditional_on_rarer": round(conditional, 4),
                "vendor_linked": linked,
                "shared_evidence_suspect": conditional >= SHARED_EVIDENCE_CONDITIONAL and not linked,
            }
        )

    rows.sort(key=lambda row: -row["lift"])
    suspects = [r for r in rows if r["shared_evidence_suspect"]]
    all_slugs = {fp.slug for fp in load_fingerprints()}
    coverage = round(len(vendor_of) / max(1, len(all_slugs)), 4)
    return {
        "schema": "slug-cooccurrence/1.0",
        "namespaces_with_slugs": total,
        "distinct_slugs": len(single),
        "pairs_reported": len(rows),
        "shared_evidence_suspects": len(suspects),
        "catalog_parent_vendor_coverage": coverage,
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir", type=Path, help="ignored private run directory containing results.ndjson")
    parser.add_argument("--out", type=Path, required=True, help="output JSON path (must be an ignored workspace)")
    args = parser.parse_args(argv)

    payload = measure(args.run_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"{payload['namespaces_with_slugs']} namespaces, {payload['pairs_reported']} pairs reported, "
        f"{payload['shared_evidence_suspects']} shared-evidence suspects"
    )
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
