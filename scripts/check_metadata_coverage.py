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

    @property
    def description_coverage(self) -> float:
        return self.detection_with_description / self.detection_total if self.detection_total else 0.0

    @property
    def reference_coverage(self) -> float:
        return self.detection_with_reference / self.detection_total if self.detection_total else 0.0

    @property
    def weight_coverage(self) -> float:
        return self.detection_with_weight / self.detection_total if self.detection_total else 0.0


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
                if isinstance(desc, str) and desc.strip():
                    cat_stats.detection_with_description += 1
                else:
                    det_type = str(det.get("type") or "<no-type>")
                    det_pattern = str(det.get("pattern") or "<no-pattern>")
                    cat_stats.description_gaps.append((str(slug), det_type, det_pattern))
                ref = det.get("reference")
                if isinstance(ref, str) and ref.strip():
                    cat_stats.detection_with_reference += 1
                weight = det.get("weight")
                if isinstance(weight, int | float) and float(weight) != 1.0:
                    cat_stats.detection_with_weight += 1
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Print the report but always exit 0. Use for development; CI should omit.",
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
