#!/usr/bin/env python
"""One-shot migration script: split ``fingerprints.yaml`` into per-category files.

Runs once as part of the v1.1 migration. Reads the monolithic
``recon_tool/data/fingerprints.yaml``, merges duplicate-slug entries
by concatenating their detection rules under the first entry's
``name`` + ``category``, and writes the result out across eight
per-category files under ``recon_tool/data/fingerprints/``.

This script is not imported or called at runtime — the split output is
the source of truth from v1.1 onward. Kept in the repo for auditability:
a reviewer can re-run it against the pre-split monolith to verify the
split is reproducible.

Usage::

    python scripts/split_fingerprints.py \\
        --input recon_tool/data/fingerprints.yaml \\
        --output-dir recon_tool/data/fingerprints/
"""

from __future__ import annotations

import argparse
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any

import yaml

# Map a raw fingerprint ``category:`` field to the target output file.
# Keep categories semantically meaningful and file sizes reasonable
# (10–70 entries each). The original ``category:`` value stays on each
# entry — only the physical file placement changes.
_CATEGORY_TO_FILE: dict[str, str] = {
    "AI & Generative": "ai.yaml",
    "Email & Communication": "email.yaml",
    "Email Governance": "email.yaml",
    "Security & Compliance": "security.yaml",
    "Identity": "security.yaml",
    "Infrastructure": "infrastructure.yaml",
    "DevTools & Infrastructure": "infrastructure.yaml",
    "Productivity & Collaboration": "productivity.yaml",
    "Support & Helpdesk": "productivity.yaml",
    "HR & Operations": "productivity.yaml",
    "CRM & Marketing": "crm-marketing.yaml",
    "Sales Intelligence": "crm-marketing.yaml",
    "Sales & Marketing": "crm-marketing.yaml",
    "Social & Advertising": "crm-marketing.yaml",
    "Data & Analytics": "data-analytics.yaml",
    "Education": "verticals.yaml",
    "Nonprofit": "verticals.yaml",
    "Payments & Finance": "verticals.yaml",
    "Misc": "verticals.yaml",
}

_FILE_HEADERS: dict[str, str] = {
    "ai.yaml": (
        "AI & generative tooling fingerprints. LLM providers, enterprise AI platforms, agent-framework discovery."
    ),
    "email.yaml": (
        "Email platform and deliverability fingerprints. Cloud email providers, "
        "gateways, DMARC / DKIM / SPF ecosystem tooling."
    ),
    "security.yaml": (
        "Security and identity fingerprints. EDR, SIEM, IdP, zero-trust access, credential-hygiene tooling."
    ),
    "infrastructure.yaml": (
        "Infrastructure fingerprints. Cloud providers, CDNs, DNS, CAs, container and CI/CD platforms."
    ),
    "productivity.yaml": (
        "Productivity and collaboration fingerprints. Suite tooling, helpdesk, HR platforms, knowledge management."
    ),
    "crm-marketing.yaml": (
        "CRM, sales, marketing, and advertising fingerprints. Marketing automation, sales intelligence, ad platforms."
    ),
    "data-analytics.yaml": ("Data and analytics fingerprints. Warehouses, BI tools, product analytics, observability."),
    "verticals.yaml": (
        "Vertical-specific fingerprints. Education, nonprofit, payments, and "
        "other verticals too small for their own file."
    ),
}


def _merge_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge multiple entries with the same slug.

    Keeps the first entry's name + category + top-level metadata;
    concatenates detection rules, deduped by (type, pattern).
    """
    first = entries[0]
    merged = {k: v for k, v in first.items() if k != "detections"}
    seen: set[tuple[str, str]] = set()
    merged_detections: list[dict[str, Any]] = []
    for entry in entries:
        for det in entry.get("detections", []):
            if not isinstance(det, dict):
                continue
            key = (str(det.get("type", "")), str(det.get("pattern", "")))
            if key in seen:
                continue
            seen.add(key)
            merged_detections.append(det)
    merged["detections"] = merged_detections
    return merged


def _emit_file(path: Path, header: str, entries: list[dict[str, Any]]) -> None:
    """Write a per-category file with a header comment and a YAML body."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [f"# {header}", "#", "# Loaded by recon_tool.fingerprints.load_fingerprints."]
    lines.append("# Custom overrides: ~/.recon/fingerprints.yaml (additive only).")
    lines.append("")
    # Dump with sort_keys=False to preserve field order; each entry's keys
    # are emitted in the order they appear in the source dict.
    body = yaml.safe_dump(
        {"fingerprints": entries},
        sort_keys=False,
        allow_unicode=True,
        width=120,
        default_flow_style=False,
    )
    lines.append(body.rstrip())
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Split monolithic fingerprints.yaml into per-category files.")
    parser.add_argument("--input", type=Path, required=True, help="Path to monolithic fingerprints.yaml")
    parser.add_argument("--output-dir", type=Path, required=True, help="Output directory for per-category files")
    args = parser.parse_args(argv)

    if not args.input.exists():
        print(f"error: {args.input} does not exist", file=sys.stderr)
        return 2

    raw = yaml.safe_load(args.input.read_text(encoding="utf-8"))
    entries = raw.get("fingerprints", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        print("error: expected a 'fingerprints:' list", file=sys.stderr)
        return 2

    # Group by slug to merge duplicates.
    by_slug: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
    skipped = 0
    for e in entries:
        if not isinstance(e, dict):
            skipped += 1
            continue
        slug = e.get("slug")
        if not isinstance(slug, str) or not slug:
            skipped += 1
            continue
        by_slug.setdefault(slug, []).append(e)

    merged_entries: list[dict[str, Any]] = []
    merges: list[str] = []
    for slug, group in by_slug.items():
        if len(group) == 1:
            merged_entries.append(group[0])
        else:
            merged_entries.append(_merge_entries(group))
            merges.append(f"{slug} ({len(group)} entries merged)")

    # Bucket into per-category files.
    buckets: dict[str, list[dict[str, Any]]] = {fname: [] for fname in set(_CATEGORY_TO_FILE.values())}
    unmapped: list[tuple[str, str]] = []
    for fp in merged_entries:
        cat = fp.get("category", "")
        target = _CATEGORY_TO_FILE.get(cat)
        if target is None:
            unmapped.append((str(fp.get("slug", "?")), str(cat)))
            continue
        buckets[target].append(fp)

    if unmapped:
        print("error: unmapped categories — extend _CATEGORY_TO_FILE:", file=sys.stderr)
        for slug, cat in unmapped:
            print(f"  {slug}: {cat!r}", file=sys.stderr)
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for fname, fps in sorted(buckets.items()):
        header = _FILE_HEADERS.get(fname, f"Fingerprints: {fname}")
        _emit_file(args.output_dir / fname, header, fps)

    print(f"Wrote {len(buckets)} files to {args.output_dir}:")
    for fname in sorted(buckets.keys()):
        print(f"  {fname}: {len(buckets[fname])} entries")
    print()
    print(f"Input entries: {len(entries)}  (skipped {skipped} shape-invalid)")
    print(f"Unique slugs:  {len(merged_entries)}")
    if merges:
        print(f"Merged duplicates: {len(merges)}")
        for m in merges:
            print(f"  {m}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
