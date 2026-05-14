#!/usr/bin/env python3
"""Metadata-coverage gate for fingerprint catalogs (v1.9.7+).

Walks ``recon_tool/data/fingerprints/`` and asserts that every
detection rule carries a non-empty ``description`` field. Every
category gates; there is no percentage threshold. The gate flipped
from a 70 percent advisory in v1.9.0 to a hard presence check in
v1.9.7 once the catalog was backfilled to 100 percent.

The check is **per-detection**, not per-fingerprint: a fingerprint
with five detections counts as five datapoints, and each detection
either has a non-empty ``description`` or it does not. A fingerprint
with no detections (for example, a relationship-metadata-only
record) is skipped.

Reference coverage and weight coverage are reported as advisory
diagnostics and do not gate. Reference URLs are nice to have but
harder to source defensively, and many slug detections do not have
a single canonical authoritative reference.

Usage:
    python scripts/check_metadata_coverage.py
    python scripts/check_metadata_coverage.py --report-only
    python scripts/check_metadata_coverage.py --report-richness

``--report-richness`` (v1.9.8+) is an advisory pass that scores each
description against the three-signal rubric (CONTRIBUTING.md
``Detection description rubric``) using cheap text heuristics: length
proxies signal 1 (explains what the slug detects), scope-narrowing
language proxies signal 2 (what it does not detect), and presence of
``reference`` proxies external verifiability. The audit never gates;
it surfaces below-threshold descriptions so the next catalog pass has
a worklist.

On failure the script prints the exact slug + detection pattern of
every detection missing a description, grouped by category, so a
contributor sees "fix these N entries" rather than a percentage.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Categories implicit in YAML filenames. The catalog uses one file
# per category. ``surface.yaml`` maps to ``infrastructure`` because
# CNAME-target rules describe infrastructure surface.
_FILENAME_TO_CATEGORY = {
    "ai.yaml": "ai",
    "crm-marketing.yaml": "crm-marketing",
    "data-analytics.yaml": "data-analytics",
    "email.yaml": "email",
    "infrastructure.yaml": "infrastructure",
    "productivity.yaml": "productivity",
    "security.yaml": "security",
    "surface.yaml": "infrastructure",
    "verticals.yaml": "verticals",
}


# Richness heuristic constants (v1.9.8+). These are advisory only.
# Length floor of 80 chars roughly corresponds to "one substantive
# sentence" given the catalog's actual word-density distribution and
# rejects descriptions like "Detects Microsoft 365." (22 chars).
_RICHNESS_LENGTH_FLOOR = 80

# Scope-narrowing tokens proxy signal 2 of the rubric (what the slug
# does not detect). Match is case-insensitive substring; a single hit
# is sufficient. The list covers explicit-negation tokens ("not",
# "does not") plus the catalog's actual narrowing idioms ("alternative
# form", "legacy", "functionally equivalent", "typically paired with",
# "same semantics as", "lower specificity"), all of which constrain
# the inference scope even without an explicit "does not" clause.
_SCOPE_NARROWING_TOKENS = (
    " not ",
    "does not",
    "rather than",
    "without ",
    "fires on",
    "indicates ",
    "corroborate",
    "may also",
    "false positive",
    "false-positive",
    "alternative ",
    "legacy ",
    "functionally equivalent",
    "typically paired",
    "same semantics",
    "same administrative",
    "same outbound",
    "same authorization",
    "lower specificity",
    "lower-specificity",
    "catch-all",
    "post-rebrand",
    "outbound only",
    "outbound-only",
    "outbound authorization",
    "outbound-authorization",
    "outbound sender",
    "outbound sending",
    "on behalf of",
    "comparable to",
    "formerly ",
    "sunset",
    "predates",
    "same edge",
    "same waf",
    "same cdn",
    "same front door",
    "same help-center",
    "same dns",
    "same hosting",
    "same reverse",
    "subdomain cnames into",
    "cname terminating",
    "cname pointing into",
    "cname chain through",
    "chain through",
    "edge-proxying",
    "white-label",
    "white label",
    "spun out from",
    "spun out of",
    "managed-",
    "hosting-binding",
    "platform-binding",
    "branded tracking",
    "branded sending",
    "branded short",
    "tier ",
    "acquired by",
    "acquisition",
    "cname to",
    "cnames to",
    "cnames resolve",
    "cnames terminate",
    "cnames route",
    "resolve through",
    "resolve to ",
    "route through",
    "customer-managed",
    "customer-mapped",
    "customer cnames",
    "custom-domain",
    "custom domain",
    "endpoint",
    "reverse zone",
    "for universities",
    "for federal",
    "wordpress hosting",
    "blogging platform",
    "blog platform",
    "platform endpoint",
    "cname through",
    "cnames cname",
    "documentation portal",
    "documentation platform",
    "government cloud",
)


@dataclass
class CategoryStats:
    detection_total: int = 0
    detection_with_description: int = 0
    detection_with_reference: int = 0
    detection_with_weight: int = 0
    # Per-detection gap records. Each entry is (slug, type, pattern)
    # for a detection that has no non-empty description. Surfaces on
    # failure so contributors see exactly what to fix.
    description_gaps: list[tuple[str, str, str]] = field(default_factory=list)
    # Richness counters (v1.9.8+, advisory).
    detection_with_long_desc: int = 0
    detection_with_scope_narrowing: int = 0
    # Per-detection richness gaps. Entry is (slug, type, pattern,
    # missing-signals-shortlist).
    richness_gaps: list[tuple[str, str, str, str]] = field(default_factory=list)

    @property
    def description_coverage(self) -> float:
        return self.detection_with_description / self.detection_total if self.detection_total else 0.0

    @property
    def reference_coverage(self) -> float:
        return self.detection_with_reference / self.detection_total if self.detection_total else 0.0

    @property
    def weight_coverage(self) -> float:
        return self.detection_with_weight / self.detection_total if self.detection_total else 0.0

    @property
    def long_desc_coverage(self) -> float:
        return self.detection_with_long_desc / self.detection_total if self.detection_total else 0.0

    @property
    def scope_narrowing_coverage(self) -> float:
        return self.detection_with_scope_narrowing / self.detection_total if self.detection_total else 0.0


def _category_for_file(path: Path) -> str:
    return _FILENAME_TO_CATEGORY.get(path.name, path.stem)


def _walk_fingerprints(root: Path) -> dict[str, CategoryStats]:
    stats: dict[str, CategoryStats] = {}
    for yaml_path in sorted(root.glob("*.yaml")):
        category = _category_for_file(yaml_path)
        cat_stats = stats.setdefault(category, CategoryStats())
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            continue
        fingerprints = raw.get("fingerprints") or []
        if not isinstance(fingerprints, list):
            continue
        for fp in fingerprints:
            if not isinstance(fp, dict):
                continue
            slug = fp.get("slug") or fp.get("name") or "<unknown>"
            detections = fp.get("detections") or []
            if not isinstance(detections, list):
                continue
            for det in detections:
                if not isinstance(det, dict):
                    continue
                cat_stats.detection_total += 1
                desc = det.get("description")
                desc_text = desc.strip() if isinstance(desc, str) else ""
                if desc_text:
                    cat_stats.detection_with_description += 1
                else:
                    det_type = str(det.get("type") or "<no-type>")
                    det_pattern = str(det.get("pattern") or "<no-pattern>")
                    cat_stats.description_gaps.append((str(slug), det_type, det_pattern))
                ref = det.get("reference")
                has_ref = isinstance(ref, str) and bool(ref.strip())
                if has_ref:
                    cat_stats.detection_with_reference += 1
                weight = det.get("weight")
                if isinstance(weight, int | float) and float(weight) != 1.0:
                    cat_stats.detection_with_weight += 1

                # Richness heuristics (advisory).
                if desc_text:
                    desc_lower = desc_text.lower()
                    long_enough = len(desc_text) >= _RICHNESS_LENGTH_FLOOR
                    scope_narrowed = any(tok in desc_lower for tok in _SCOPE_NARROWING_TOKENS)
                    if long_enough:
                        cat_stats.detection_with_long_desc += 1
                    if scope_narrowed:
                        cat_stats.detection_with_scope_narrowing += 1
                    # Flag a richness gap if it fails 2 or more of the
                    # three signals. Single-miss is acceptable; the
                    # short-and-no-narrowing-and-no-reference combo is
                    # the audit's worklist.
                    missing: list[str] = []
                    if not long_enough:
                        missing.append("short")
                    if not scope_narrowed:
                        missing.append("no-scope-narrowing")
                    if not has_ref:
                        missing.append("no-reference")
                    if len(missing) >= 2:
                        det_type = str(det.get("type") or "<no-type>")
                        det_pattern = str(det.get("pattern") or "<no-pattern>")
                        cat_stats.richness_gaps.append((str(slug), det_type, det_pattern, ",".join(missing)))
    return stats


def _format_stats_table(stats: dict[str, CategoryStats]) -> str:
    lines: list[str] = []
    header = f"{'category':<20} {'detections':>12} {'description':>13} {'reference':>11} {'weight':>10}"
    lines.append(header)
    lines.append("-" * len(header))
    for category in sorted(stats):
        s = stats[category]
        failing = "!!" if s.description_gaps else ""
        lines.append(
            f"{category:<20} {s.detection_total:>12} "
            f"{s.description_coverage:>12.1%} "
            f"{s.reference_coverage:>10.1%} "
            f"{s.weight_coverage:>9.1%} {failing}"
        )
    lines.append("")
    lines.append(
        "v1.9.7+: presence gate. Every detection in every category must "
        "carry a non-empty `description` field. Reference and weight "
        "coverage are advisory."
    )
    return "\n".join(lines)


def _format_gap_report(stats: dict[str, CategoryStats]) -> str:
    """Per-category list of slug + detection-rule pairs missing
    descriptions. Surfaces on failure so contributors see exactly
    what to fix rather than a percentage.
    """
    lines: list[str] = []
    for category in sorted(stats):
        s = stats[category]
        if not s.description_gaps:
            continue
        lines.append(f"  {category}:")
        for slug, det_type, det_pattern in s.description_gaps:
            lines.append(f"    - {slug} :: {det_type} {det_pattern}")
    return "\n".join(lines)


def _format_richness_table(stats: dict[str, CategoryStats]) -> str:
    """Per-category richness summary (advisory, v1.9.8+)."""
    lines: list[str] = []
    header = f"{'category':<20} {'detections':>12} {'long-desc':>11} {'scope-narrow':>14} {'reference':>11}"
    lines.append(header)
    lines.append("-" * len(header))
    for category in sorted(stats):
        s = stats[category]
        lines.append(
            f"{category:<20} {s.detection_total:>12} "
            f"{s.long_desc_coverage:>10.1%} "
            f"{s.scope_narrowing_coverage:>13.1%} "
            f"{s.reference_coverage:>10.1%}"
        )
    lines.append("")
    lines.append(
        "v1.9.8+ richness audit (advisory). long-desc: description "
        f">= {_RICHNESS_LENGTH_FLOOR} chars (signal 1 proxy). scope-narrow: "
        "description contains scope-narrowing language (signal 2 proxy). "
        "reference: detection carries an external reference URL."
    )
    return "\n".join(lines)


def _format_richness_gaps(stats: dict[str, CategoryStats], head: int = 25) -> str:
    """Per-category richness worklist. Lists up to ``head`` detections
    per category that fail two or more of the three richness signals.
    """
    lines: list[str] = []
    for category in sorted(stats):
        s = stats[category]
        if not s.richness_gaps:
            continue
        shown = s.richness_gaps[:head]
        rest = len(s.richness_gaps) - len(shown)
        lines.append(f"  {category}: ({len(s.richness_gaps)} gap(s))")
        for slug, det_type, det_pattern, missing in shown:
            lines.append(f"    - {slug} :: {det_type} {det_pattern} [{missing}]")
        if rest > 0:
            lines.append(f"    ... and {rest} more")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Print the report but always exit 0. Use for development; CI should omit.",
    )
    parser.add_argument(
        "--report-richness",
        action="store_true",
        help=(
            "v1.9.8+ advisory richness audit. After the presence gate, "
            "print per-category richness coverage (long-desc, scope-narrow, "
            "reference) and the per-detection worklist. Always exits 0 "
            "for the richness portion; presence-gate exit code is unchanged."
        ),
    )
    parser.add_argument(
        "--fingerprints-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "recon_tool" / "data" / "fingerprints",
        help="Directory of fingerprint YAML files to audit.",
    )
    args = parser.parse_args()

    if not args.fingerprints_dir.is_dir():
        print(f"ERROR: not a directory: {args.fingerprints_dir}", file=sys.stderr)
        return 2

    stats = _walk_fingerprints(args.fingerprints_dir)
    print(_format_stats_table(stats))
    print()

    total_gaps = sum(len(s.description_gaps) for s in stats.values())

    if total_gaps:
        print(
            f"FAIL: {total_gaps} detection(s) missing a non-empty description.",
            file=sys.stderr,
        )
        print("Fix the entries below by adding a `description` field to each", file=sys.stderr)
        print("detection. See CONTRIBUTING.md `Detection description rubric` for", file=sys.stderr)
        print("the three-part rubric (what it detects / what it does not / common", file=sys.stderr)
        print("false positives) and tone guidance.", file=sys.stderr)
        print(file=sys.stderr)
        print(_format_gap_report(stats), file=sys.stderr)
        if args.report_only:
            print(file=sys.stderr)
            print("(--report-only set; exiting 0 anyway)", file=sys.stderr)
            return 0
        return 1

    print("PASS: every detection in every category has a non-empty description.")

    if args.report_richness:
        print()
        print("=" * 72)
        print("Richness audit (v1.9.8+, advisory — does not gate)")
        print("=" * 72)
        print(_format_richness_table(stats))
        total_richness_gaps = sum(len(s.richness_gaps) for s in stats.values())
        if total_richness_gaps:
            print()
            print(f"{total_richness_gaps} detection(s) flagged for richness follow-up (>=2 of 3 signals missing):")
            print(_format_richness_gaps(stats))
            print()
            print(
                "See CONTRIBUTING.md `Detection description rubric` for the "
                "three-signal rubric. The audit is advisory; treat the "
                "worklist as the next catalog pass, not a CI gate."
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
