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
SOURCE_TO_DETECTION_TYPES: dict[str, tuple[str, ...]] = {
    "TXT": ("txt",),
    # The surface-attribution pipeline emits its chain matches as CNAME
    # evidence, so one CNAME record carries both apex `cname` rules and the
    # `cname_target` rules that match any hop of the resolved chain.
    "CNAME": ("cname", "cname_target"),
    "SPF": ("spf",),
    "NS": ("ns",),
    "MX": ("mx",),
    "CAA": ("caa",),
    "SRV": ("srv",),
    "DMARC_RUA": ("dmarc_rua",),
    "SUBDOMAIN_TXT": ("subdomain_txt",),
}

# Detection types whose patterns are regexes rather than DNS names. `cname`
# rules are regex-validated at load time and the live path matches them with
# `regex=True`, so `^cdn\.webflow\.com\.?$` is an anchored expression and not a
# hostname. `cname_target` keeps hostname-suffix and dotless-substring
# semantics, so the two CNAME-derived types are matched differently.
REGEX_TYPES = frozenset({"txt", "subdomain_txt"})
REGEX_OVER_TARGETS = frozenset({"cname"})

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


def _match_targets(detection_type: str, raw_value: str) -> list[str]:
    """Extract the host targets a pattern should be tested against.

    ``EvidenceRecord.raw_value`` is a rendering of the observed record, not the
    parsed target the live detector matched. Taking the last whitespace field
    works for MX, SRV, and NS but silently corrupts the others: a CAA value
    carries a tag and an opening quote (``0 issue "amazon.com``) and may carry
    trailing parameters, an SPF record holds many mechanisms of which the last
    is not privileged, a DMARC ``rua`` target sits after ``mailto:`` and ``@``,
    and a CNAME rendering prefixes the owner and may chain through ``->``.
    Each type is normalized to the hosts the live path would have matched.
    """
    value = raw_value.lower()[:_MAX_CNAME_MATCH_LEN]
    if detection_type == "caa":
        # 0 issue "ca.example; params  ->  ca.example
        body = value.split('"', 1)[1] if '"' in value else value.split(None, 2)[-1]
        return [body.split(";", 1)[0].strip().strip('"').rstrip(".")]
    if detection_type == "spf":
        targets = re.findall(r"(?:include:|redirect=)([^\s]+)", value)
        return [t.rstrip(".") for t in targets]
    if detection_type == "dmarc_rua":
        return [t.rstrip(".") for t in re.findall(r"mailto:[^@\s]*@([^\s,;]+)", value)]
    if detection_type in ("cname", "cname_target"):
        # "owner: target -> target2"  ->  every chain hop. A cname_target rule
        # fires on any hop of the resolved chain, not only its terminal.
        chain = value.split(":", 1)[1] if ":" in value.split()[0] else value
        return [hop.strip().rstrip(".") for hop in chain.split("->") if hop.strip()]
    fields = value.split()
    return [fields[-1].rstrip(".")] if fields else []


def _pattern_matches(detection_type: str, pattern: str, raw_value: str) -> bool:
    """Apply production matching semantics for one pattern against one value."""
    if detection_type in REGEX_TYPES:
        if len(raw_value) > _MAX_TXT_MATCH_LENGTH:
            return False
        # A subdomain_txt pattern is `owner:regex`; only the regex half is
        # matched against the value, exactly as detect_subdomain_txt splits it.
        expression = pattern.split(":", 1)[1] if detection_type == "subdomain_txt" and ":" in pattern else pattern
        compiled = compile_regex(expression, re.IGNORECASE)
        return compiled is not None and compiled.search(raw_value) is not None

    targets = _match_targets(detection_type, raw_value)
    if detection_type in REGEX_OVER_TARGETS:
        compiled = compile_regex(pattern, re.IGNORECASE)
        return compiled is not None and any(compiled.search(target) is not None for target in targets)

    needle = pattern.lower().rstrip(".")
    if is_domain_shaped(needle):
        return any(host_has_suffix(target, needle) for target in targets)
    return any(needle in target for target in targets)


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
                detection_types = SOURCE_TO_DETECTION_TYPES.get(item.get("source_type") or "", ())
                raw_value = item.get("raw_value") or ""
                for detection_type in detection_types if raw_value else ():
                    _score_value(tally, detection_type, raw_value, ordinal, slug_sources)
    return tally


def check_candidates(run_dir: Path) -> dict[str, Any]:
    """Report which unclassified candidates the CURRENT catalog already covers.

    A run's gap queue is generated against the catalog as it stood during
    collection, so every rule promoted afterwards keeps appearing there as an
    open gap. Re-mining that queue therefore rediscovers work already done: the
    four CAA issuer rules, `_d.easydmarc.pro` and `valimail-legacy-spf` were all
    promoted two hours after the 2026-07-17 round and still read as gaps.

    `triage_candidates.py` performs this check, but only for `cname_target` and
    only over the chain-only `gaps.json`. The all-path candidate queue in
    `catalog-gaps.json` has no coverage check, which is where the rediscovery
    happens. Deduplicating candidates against current coverage before they enter
    a proposal queue is what keeps the discovery loop from cycling.

    One limitation is inherited rather than introduced: a pattern permissive
    enough to match anything reports coverage it does not have. The
    `_slack-challenge`, `_gitlab-pages-verification-code` and `_github-challenge`
    rules accept any non-empty value, so this check reports the `_mcp` and
    `_agent` candidates as covered when what actually matched was a wildcard
    answer. The detector-side guard suppresses that at lookup time; here it
    still reads as a match, so treat a `subdomain_txt` coverage claim as
    provisional.
    """
    gaps = run_dir / "catalog-gaps.json"
    if not gaps.is_file():
        raise SystemExit(f"no catalog-gaps.json under {run_dir}")
    payload = json.loads(gaps.read_text(encoding="utf-8"))
    catalog = _load_catalog_patterns()

    covered: list[dict[str, Any]] = []
    open_rows: list[dict[str, Any]] = []
    for detection_type, entries in sorted(payload.get("candidates", {}).items()):
        for entry in entries:
            samples = [str(s.get("value", "")) for s in entry.get("samples", []) if s.get("value")]
            if not samples:
                continue
            hit = None
            for entry_slug, _, entry_pattern in catalog.get(detection_type, ()):
                # A candidate sample may be a whole record or an already
                # extracted target, so test both readings before calling it open.
                if any(
                    _pattern_matches(detection_type, entry_pattern, value)
                    or any(
                        _pattern_matches(detection_type, entry_pattern, target)
                        for target in _match_targets(detection_type, value)
                    )
                    for value in samples
                ):
                    hit = entry_slug
                    break
            row = {
                "type": detection_type,
                "key": entry.get("key"),
                "namespaces": entry.get("distinct_namespace_count"),
                "occurrences": entry.get("count"),
            }
            if hit:
                covered.append({**row, "covered_by": hit})
            else:
                open_rows.append(row)

    covered.sort(key=lambda r: -(r["namespaces"] or 0))
    open_rows.sort(key=lambda r: -(r["namespaces"] or 0))
    return {
        "schema": "gap-candidate-coverage/1.0",
        "run_catalog": payload.get("aggregate", {}).get("catalog", {}),
        "candidates_total": len(covered) + len(open_rows),
        "already_covered_by_current_catalog": len(covered),
        "still_open": len(open_rows),
        "covered": covered,
        "open": open_rows,
    }


def measure(run_dir: Path) -> dict[str, Any]:
    results = run_dir / "results.ndjson"
    if not results.is_file():
        raise SystemExit(f"no results.ndjson under {run_dir}")

    catalog = _load_catalog_patterns()
    mapped = {t for types in SOURCE_TO_DETECTION_TYPES.values() for t in types}
    measurable_types = {t for t in catalog if t in mapped}
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
    parser.add_argument(
        "--candidates",
        action="store_true",
        help="report which unclassified gap candidates the current catalog already covers, instead of measuring rules",
    )
    args = parser.parse_args(argv)

    if args.candidates:
        payload = check_candidates(args.run_dir)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"{payload['candidates_total']} candidates: "
            f"{payload['already_covered_by_current_catalog']} already covered by the current catalog, "
            f"{payload['still_open']} still open"
        )
        print(f"wrote {args.out}")
        return 0

    payload = measure(args.run_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"measured {payload['records_measured']} records against {payload['catalog_detections']} detections")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
