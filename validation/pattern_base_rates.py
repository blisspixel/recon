#!/usr/bin/env python3
"""Measure per-pattern base rates and corroboration over a private corpus run.

Motivation
----------
Evidence weight in recon is currently a function of source type alone.
``fusion.SOURCE_WEIGHTS`` keys on ``EvidenceRecord.source_type`` and
``merger._build_detection_weight_map`` keys on ``(slug, detection type)``,
taking the maximum across every detection sharing that pair. Neither consults
how *discriminative* an individual pattern is, and ``specificity.py`` models
specificity only as a binary admission gate against a synthetic corpus.

This reducer supplies the missing empirical input: for every catalog detection
pattern, how often it fires across a frozen private corpus run, and how often
the slug it attributes is independently corroborated by a different source
type on the same namespace.

Disclosure safety
-----------------
The reducer never reads ``queried_domain`` or any other target-identifying
field. It consumes only ``evidence[].source_type`` and ``evidence[].raw_value``
and reduces to counts keyed by catalog pattern, which is provider-owned text.
Domain identity is represented solely by the record's ordinal position in the
input stream, which is discarded after aggregation. ``_FORBIDDEN_FIELDS``
asserts this at runtime so a future edit cannot quietly widen the read set.

Raw values are matched with the same helpers the production detectors use, so
a fire counted here is a fire recorded by recon: regex search for TXT-shaped
paths, and DNS-label suffix or dotless substring semantics elsewhere.

Usage::

    python validation/pattern_base_rates.py RUN_DIR --out OUT.json

``RUN_DIR`` is an ignored private run directory containing ``results.ndjson``.
The output belongs in an ignored workspace; render a disclosure-safe memo from
it rather than committing it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from recon_tool.fingerprints import load_fingerprints  # noqa: E402
from recon_tool.regex_safety import compile_regex  # noqa: E402
from recon_tool.validator import host_has_suffix, is_domain_shaped  # noqa: E402

# Evidence source_type -> catalog detection type. Source types with no catalog
# detection type (HTTP, DKIM, A, DMARC, BIMI, MTA_STS, MTA_STS_POLICY) carry
# attribution but are not pattern-matched here; they still count toward
# corroboration.
SOURCE_TO_DETECTION_TYPE: dict[str, str] = {
    "TXT": "txt",
    "CNAME": "cname",
    "SPF": "spf",
    "NS": "ns",
    "MX": "mx",
    "CAA": "caa",
    "SRV": "srv",
    "DMARC_RUA": "dmarc_rua",
    "SUBDOMAIN_TXT": "subdomain_txt",
}

# Detection types whose patterns are regexes rather than DNS names.
REGEX_TYPES = frozenset({"txt", "subdomain_txt"})

# Fields the reducer must never read. Enforced at runtime.
_FORBIDDEN_FIELDS = ("queried_domain", "display_name", "tenant_id", "related_domains", "tenant_domains")

# Counts below this are reported as a band rather than an exact number, matching
# the small-stratum suppression rule in the data-handling policy.
SUPPRESS_BELOW = 10

_MAX_TXT_MATCH_LENGTH = 4096
_MAX_CNAME_MATCH_LEN = 2048


class SafeRecord:
    """A results record that refuses reads of target-identifying fields."""

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def get(self, key: str, default: Any = None) -> Any:
        if key in _FORBIDDEN_FIELDS:
            raise AssertionError(f"reducer must not read target-identifying field {key!r}")
        return self._data.get(key, default)


def _pattern_matches(detection_type: str, pattern: str, raw_value: str) -> bool:
    """Apply production matching semantics for one pattern against one value."""
    if detection_type in REGEX_TYPES:
        if len(raw_value) > _MAX_TXT_MATCH_LENGTH:
            return False
        compiled = compile_regex(pattern, re.IGNORECASE)
        return compiled is not None and compiled.search(raw_value) is not None

    candidate = raw_value.lower()[:_MAX_CNAME_MATCH_LEN]
    fields = candidate.split()
    target = fields[-1].rstrip(".") if fields else ""
    needle = pattern.lower().rstrip(".")
    if is_domain_shaped(needle):
        return host_has_suffix(target, needle)
    return needle in candidate


def _load_catalog_patterns() -> dict[str, list[tuple[str, str, str]]]:
    """Return detection type -> list of (slug, name, pattern)."""
    by_type: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for fingerprint in load_fingerprints():
        for rule in fingerprint.detections:
            by_type[rule.type].append((fingerprint.slug, fingerprint.name, rule.pattern))
    return by_type


def _band(count: int) -> str:
    return f"<{SUPPRESS_BELOW}" if count < SUPPRESS_BELOW else str(count)


def _observed_namespaces(run_dir: Path) -> dict[str, int]:
    """Return detection type -> namespaces where that path was actually observed.

    ``evidence`` records are attributions, so counting domains that produced one
    would condition the denominator on a match having already happened and
    inflate every base rate. The run's own gap aggregate records the real
    observation opportunity per path, so the denominator is
    ``available + partial`` from that file instead.
    """
    gaps = run_dir / "catalog-gaps.json"
    if not gaps.is_file():
        return {}
    payload = json.loads(gaps.read_text(encoding="utf-8"))
    record_types = payload.get("aggregate", {}).get("record_types", {})
    denominators: dict[str, int] = {}
    for path, entry in record_types.items():
        availability = entry.get("availability", {})
        denominators[path] = int(availability.get("available", 0)) + int(availability.get("partial", 0))
    return denominators


class Tally:
    """Mutable accumulators for one measurement pass."""

    __slots__ = ("catalog", "competitors", "corroborated", "errors", "fires", "measured", "total")

    def __init__(self, catalog: dict[str, list[tuple[str, str, str]]]) -> None:
        self.catalog = catalog
        # (slug, type, pattern) -> set of record ordinals
        self.fires: dict[tuple[str, str, str], set[int]] = defaultdict(set)
        # (slug, type, pattern) -> ordinals where the slug had >= 2 distinct source types
        self.corroborated: dict[tuple[str, str, str], set[int]] = defaultdict(set)
        # (slug, type, pattern) -> distinct competing slugs matched on the same value
        self.competitors: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        self.total = 0
        self.measured = 0
        self.errors = 0


def _slug_source_types(evidence: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Map each attributed slug to the distinct source types supporting it."""
    slug_sources: dict[str, set[str]] = defaultdict(set)
    for item in evidence:
        slug = item.get("slug")
        if slug:
            slug_sources[slug].add(item.get("source_type") or "")
    return slug_sources


def _score_value(
    tally: Tally,
    detection_type: str,
    raw_value: str,
    ordinal: int,
    slug_sources: dict[str, set[str]],
) -> None:
    """Record every catalog pattern of one type that matches one observed value."""
    hits = [
        (entry[0], detection_type, entry[2])
        for entry in tally.catalog.get(detection_type, ())
        if _pattern_matches(detection_type, entry[2], raw_value)
    ]
    matched_slugs = {key[0] for key in hits}
    for key in hits:
        tally.fires[key].add(ordinal)
        if len(slug_sources.get(key[0], ())) >= 2:
            tally.corroborated[key].add(ordinal)
        tally.competitors[key].update(matched_slugs - {key[0]})


def _accumulate(results: Path, catalog: dict[str, list[tuple[str, str, str]]]) -> Tally:
    """Stream the run output and tally pattern fires without reading identity."""
    tally = Tally(catalog)
    with results.open(encoding="utf-8") as handle:
        for ordinal, raw_line in enumerate(handle):
            line = raw_line.strip()
            if not line:
                continue
            tally.total += 1
            record = SafeRecord(json.loads(line))
            if record.get("record_type") != "lookup":
                tally.errors += 1
                continue
            tally.measured += 1

            evidence = record.get("evidence") or []
            slug_sources = _slug_source_types(evidence)
            for item in evidence:
                detection_type = SOURCE_TO_DETECTION_TYPE.get(item.get("source_type") or "")
                raw_value = item.get("raw_value") or ""
                if detection_type is not None and raw_value:
                    _score_value(tally, detection_type, raw_value, ordinal, slug_sources)
    return tally


def measure(run_dir: Path) -> dict[str, Any]:
    results = run_dir / "results.ndjson"
    if not results.is_file():
        raise SystemExit(f"no results.ndjson under {run_dir}")

    catalog = _load_catalog_patterns()
    measurable_types = {t for t in catalog if t in SOURCE_TO_DETECTION_TYPE.values()}
    observed = _observed_namespaces(run_dir)
    if not observed:
        raise SystemExit(f"no catalog-gaps.json under {run_dir}; cannot establish honest denominators")

    tally = _accumulate(results, catalog)
    fires, corroborated, competitors = tally.fires, tally.corroborated, tally.competitors
    total, measured, errors = tally.total, tally.measured, tally.errors

    rows: list[dict[str, Any]] = []
    for detection_type, entries in sorted(catalog.items()):
        eligible_n = observed.get(detection_type, 0)
        for slug, name, pattern in entries:
            key = (slug, detection_type, pattern)
            fire_n = len(fires.get(key, ()))
            corr_n = len(corroborated.get(key, ()))
            rows.append(
                {
                    "slug": slug,
                    "name": name,
                    "type": detection_type,
                    "pattern": pattern,
                    "measurable": detection_type in measurable_types,
                    "eligible_domains": eligible_n,
                    "fire_domains": fire_n,
                    "fire_domains_band": _band(fire_n),
                    "base_rate": round(fire_n / eligible_n, 6) if eligible_n else None,
                    "corroborated_domains": corr_n,
                    "corroboration_rate": round(corr_n / fire_n, 4) if fire_n else None,
                    "competing_slugs": len(competitors.get(key, ())),
                }
            )

    return {
        "schema": "pattern-base-rates/1.0",
        "run_label": _read_label(run_dir),
        "records_total": total,
        "records_measured": measured,
        "records_error": errors,
        "catalog_detections": sum(len(v) for v in catalog.values()),
        "measurable_detections": sum(1 for row in rows if row["measurable"]),
        "observed_namespaces_by_type": dict(sorted(observed.items())),
        "rows": rows,
    }


def _read_label(run_dir: Path) -> str:
    meta = run_dir / "meta.json"
    if not meta.is_file():
        return ""
    try:
        return str(json.loads(meta.read_text(encoding="utf-8")).get("label", ""))
    except (ValueError, OSError):
        return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir", type=Path, help="ignored private run directory containing results.ndjson")
    parser.add_argument("--out", type=Path, required=True, help="output JSON path (must be an ignored workspace)")
    args = parser.parse_args(argv)

    payload = measure(args.run_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"measured {payload['records_measured']} records against {payload['catalog_detections']} detections")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
