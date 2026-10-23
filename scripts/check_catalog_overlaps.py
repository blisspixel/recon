#!/usr/bin/env python3
"""Find cross-slug matcher overlaps on bounded, disclosure-safe witnesses.

This checks candidate matches, before first-match selection or AND gating. It
is not a regex-equivalence solver or evidence of real-world collision rates.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path

from recon_tool.regex_safety import compile_regex
from recon_tool.sources.dns_infra import _cname_pattern_matches, _ns_pattern_matches
from recon_tool.sources.dns_tables import classify_chain, cname_target_pattern_matches
from recon_tool.validator import host_has_suffix, is_domain_shaped
from scripts.check_fingerprint_freshness import CATALOG_ROOT, DetectionKey, parse_catalog_text

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/catalog-match-witnesses.json"
REVIEWS = ROOT / "docs/catalog-overlap-reviews.json"
_HOST_MATCHERS: dict[str, Callable[[str, str], bool]] = {
    "cname": _cname_pattern_matches,
    "cname_target": cname_target_pattern_matches,
    "ns": _ns_pattern_matches,
}


@dataclass(frozen=True)
class Rule:
    key: DetectionKey
    tier: str = "application"

    @property
    def identifier(self) -> str:
        return f"{self.key.source}/{self.key.slug}/{self.key.detection_type}/{self.key.pattern}"

    @property
    def pattern(self) -> str:
        return self.key.pattern


@dataclass(frozen=True, order=True)
class Witness:
    detection_type: str
    value: str
    owner: str = "synthetic.example.com"


@dataclass(frozen=True)
class Overlap:
    left: Rule
    right: Rule
    witness: Witness | None

    @property
    def pair(self) -> tuple[str, str]:
        left, right = sorted((self.left.identifier, self.right.identifier))
        return left, right

    def render(self) -> str:
        sample = repr(self.witness.value) if self.witness else "no witness yet; add one to review equal rules"
        return f"{self.left.identifier} <> {self.right.identifier}: witness={sample}"


def canonical_rules() -> tuple[Rule, ...]:
    import yaml

    rules = []
    for path in sorted(CATALOG_ROOT.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        metadata = parse_catalog_text(text, source=path.name)
        raw = yaml.safe_load(text)
        entries = raw["fingerprints"] if isinstance(raw, dict) else raw
        tiers = {
            (entry["slug"], rule["type"], rule["pattern"]): rule.get("tier", "application")
            for entry in entries
            for rule in entry.get("detections", [])
        }
        rules.extend(Rule(key, tiers[key.slug, key.detection_type, key.pattern]) for key in metadata)
    return tuple(rules)


def matches(rule: Rule, witness: Witness) -> bool:
    """Apply the canonical candidate grammar to normalized record values."""
    kind, pattern, value = rule.key.detection_type, rule.pattern, witness.value
    if kind != witness.detection_type:
        return False
    matcher = _HOST_MATCHERS.get(kind)
    if matcher is not None:
        return matcher(value, pattern)
    if kind in {"mx", "spf", "caa", "dmarc_rua"}:
        return host_has_suffix(value, pattern)
    if kind == "srv":
        normalized = pattern.lower().strip().lstrip(".").rstrip(".")
        return host_has_suffix(value, normalized) if "." in normalized else normalized in value.lower()
    if kind == "subdomain_txt":
        owner, _, pattern = pattern.partition(":")
        if witness.owner != f"{owner}.example.com":
            return False
    compiled = compile_regex(pattern, re.IGNORECASE)
    return compiled is not None and compiled.search(value[:4096]) is not None


def witnesses(rules: tuple[Rule, ...], corpus: Path = CORPUS) -> tuple[Witness, ...]:
    """Share explicit regex examples and deterministic literal lookalikes."""
    raw = json.loads(corpus.read_text(encoding="utf-8"))
    result = {Witness(**row) for row in raw}
    for rule in rules:
        pattern = rule.pattern.lstrip(".").rstrip(".")
        if is_domain_shaped(pattern):
            for value in (pattern, f"synthetic.{pattern}", f"not{pattern}", f"{pattern}.attacker.invalid"):
                result.add(Witness(rule.key.detection_type, value))
        elif rule.key.detection_type == "txt":
            prefix = pattern.removeprefix("^")
            if re.fullmatch(r"[a-zA-Z0-9=-]+", prefix):
                for value in (f"{prefix}synthetic-token", f"note={prefix}synthetic-token"):
                    result.add(Witness("txt", value))
    return tuple(sorted(result))


def find_overlaps(rules: tuple[Rule, ...], samples: tuple[Witness, ...]) -> tuple[Overlap, ...]:
    """Keep one actionable witness per cross-slug pair, plus all equal rules."""
    found: dict[tuple[str, str], Overlap] = {}
    for left, right in combinations(rules, 2):
        if (
            left.key.slug != right.key.slug
            and left.key.detection_type == right.key.detection_type
            and left.pattern == right.pattern
        ):
            overlap = Overlap(left, right, None)
            found[overlap.pair] = overlap
    by_type: dict[str, list[Rule]] = {}
    for rule in rules:
        by_type.setdefault(rule.key.detection_type, []).append(rule)
    for sample in samples:
        hits = [rule for rule in by_type.get(sample.detection_type, []) if matches(rule, sample)]
        for left, right in combinations(hits, 2):
            if left.key.slug != right.key.slug:
                overlap = Overlap(left, right, sample)
                previous = found.get(overlap.pair)
                if previous is None or previous.witness is None:
                    found[overlap.pair] = overlap
    return tuple(found[key] for key in sorted(found))


def review_overlaps(overlaps: tuple[Overlap, ...], rules: tuple[Rule, ...], ledger: Path = REVIEWS) -> list[str]:
    """An exception must bind a pair, a reason and actual retained provenance."""
    raw = json.loads(ledger.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"version", "reviews"} or raw["version"] != 1:
        raise ValueError("overlap review ledger must have version 1 and reviews")
    indexed = {}
    for row in raw["reviews"]:
        if set(row) != {"rules", "disposition", "reason", "retained", "source_type", "scope"}:
            raise ValueError("overlap review has missing or unknown fields")
        pair = tuple(sorted(row["rules"]))
        if len(pair) != 2 or pair[0] == pair[1] or pair in indexed:
            raise ValueError("overlap reviews need unique pairs of distinct rule IDs")
        if row["disposition"] not in {"specificity", "distinct_roles"} or not row["reason"].strip():
            raise ValueError("overlap reviews need a supported disposition and reason")
        indexed[pair] = row
    errors = []
    observed = set()
    for overlap in overlaps:
        observed.add(overlap.pair)
        row = indexed.get(overlap.pair)
        if row is None or overlap.witness is None:
            errors.append(f"Unreviewed overlap: {overlap.render()}")
            continue
        sample = overlap.witness
        if sample.detection_type == "cname_target":
            candidates = tuple(
                sorted(
                    (rule for rule in rules if rule.key.detection_type == "cname_target"), key=lambda r: -len(r.pattern)
                )
            )
            selected = classify_chain([sample.value], candidates)
            retained = sorted(rule.identifier for rule in selected if rule is not None)
            valid_scope = row["source_type"] == "CNAME" and row["scope"] == "related_host"
        else:
            # Other intentional multi-attribution needs an explicit TXT role
            # case; first-match DNS suppression cannot be guessed here.
            retained = sorted(rule.identifier for rule in rules if matches(rule, sample))
            valid_scope = sample.detection_type == "txt" and row["source_type"] == "TXT" and row["scope"] == "apex"
        expected_count = 1 if row["disposition"] == "specificity" else 2
        if not valid_scope or retained != sorted(row["retained"]) or len(retained) != expected_count:
            errors.append(f"Overlap provenance differs from review: {overlap.render()}; retained={retained}")
    errors.extend(f"Stale overlap review: {pair}" for pair in indexed.keys() - observed)
    return errors


def main() -> int:
    try:
        rules = canonical_rules()
        samples = witnesses(rules)
        errors = review_overlaps(find_overlaps(rules, samples), rules)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Catalog overlap check failed: {exc}")
        return 1
    if errors:
        print("\n".join(errors))
        return 1
    print(f"OK: {len(rules)} rules, {len(samples)} synthetic witnesses; all witnessed overlaps reviewed.")
    print("Finite witness coverage only; no general regex-equivalence or precision claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
