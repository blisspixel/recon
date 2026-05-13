#!/usr/bin/env python3
"""Metadata coverage gate for fingerprint catalogs.

Walks ``recon_tool/data/fingerprints/`` and reports the per-category
description coverage rate. Fails (non-zero exit) when any high-stakes
category drops below the configured threshold. Used as a CI gate
starting in v1.9 to keep the catalog from growing without metadata.

Categories we care about (false-positive cost is highest):
  * identity
  * security
  * infrastructure

Usage:
    python scripts/check_metadata_coverage.py
    python scripts/check_metadata_coverage.py --threshold 0.7
    python scripts/check_metadata_coverage.py --report-only

The check is **per-detection**, not per-fingerprint: a fingerprint
with five detections counts as five datapoints, and each detection
either has a non-empty ``description`` or it doesn't. A fingerprint
with no detections (e.g. one that is purely a relationship-metadata
record) is skipped.

Reference coverage and weight coverage are reported but do not gate
CI — the threshold is currently descriptions only, since reference
URLs are nice-to-have but harder to source defensively.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

# Categories whose description coverage gates CI. Other categories
# (productivity, data-analytics, etc.) still get reported but don't
# fail the build.
_GATED_CATEGORIES = ("identity", "security", "infrastructure")
_DEFAULT_THRESHOLD = 0.70

# Categories implicit in YAML filenames. The catalog uses one file
# per category — surface.yaml maps to "infrastructure" because
# CNAME-target rules describe infrastructure surface.
_FILENAME_TO_CATEGORY = {
    "ai.yaml": "ai",
    "crm-marketing.yaml": "crm-marketing",
    "data-analytics.yaml": "data-analytics",
    "email.yaml": "email",
    "infrastructure.yaml": "infrastructure",
    "productivity.yaml": "productivity",
    "security.yaml": "security",
    "surface.yaml": "infrastructure",  # cname-target rules: infra surface
    "verticals.yaml": "verticals",
}


@dataclass
class CategoryStats:
    detection_total: int = 0
    detection_with_description: int = 0
    detection_with_reference: int = 0
    detection_with_weight: int = 0  # non-default weight set explicitly

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
                ref = det.get("reference")
                if isinstance(ref, str) and ref.strip():
                    cat_stats.detection_with_reference += 1
                weight = det.get("weight")
                if isinstance(weight, int | float) and float(weight) != 1.0:
                    cat_stats.detection_with_weight += 1
    return stats


def _format_stats_table(stats: dict[str, CategoryStats], threshold: float) -> str:
    lines: list[str] = []
    header = f"{'category':<20} {'detections':>12} {'description':>13} {'reference':>11} {'weight':>10}"
    lines.append(header)
    lines.append("-" * len(header))
    for category in sorted(stats):
        s = stats[category]
        gated = "*" if category in _GATED_CATEGORIES else " "
        below = "!!" if category in _GATED_CATEGORIES and s.description_coverage < threshold else ""
        lines.append(
            f"{gated} {category:<18} {s.detection_total:>12} "
            f"{s.description_coverage:>12.1%} "
            f"{s.reference_coverage:>10.1%} "
            f"{s.weight_coverage:>9.1%} {below}"
        )
    lines.append("")
    lines.append(f"* gated category — must hit description coverage >= {threshold:.0%}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--threshold",
        type=float,
        default=_DEFAULT_THRESHOLD,
        help=f"Description-coverage threshold for gated categories (default {_DEFAULT_THRESHOLD}).",
    )
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
    print(_format_stats_table(stats, args.threshold))
    print()

    failures: list[str] = []
    for category in _GATED_CATEGORIES:
        s = stats.get(category)
        if s is None or s.detection_total == 0:
            continue
        if s.description_coverage < args.threshold:
            failures.append(
                f"{category}: description coverage {s.description_coverage:.1%} "
                f"below threshold {args.threshold:.0%} "
                f"({s.detection_with_description}/{s.detection_total} detections)"
            )

    if failures:
        print("FAIL — gated categories below threshold:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        if args.report_only:
            print("(--report-only set; exiting 0 anyway)", file=sys.stderr)
            return 0
        return 1

    print("PASS — all gated categories meet description-coverage threshold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
