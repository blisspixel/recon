"""Compare two recon validation runs and surface what changed.

Either input may be a single JSON file (one domain or a list) or a directory
of per-domain JSON files. The output is a diff report showing:

  * domains added/removed between the two runs
  * per-domain slug deltas (newly detected, lost)
  * per-domain surface-attribution deltas (newly attributed subdomains, lost)
  * aggregate slug-frequency change

Use this after adding new fingerprints to verify uplift, or week-over-week
to track how the catalogue grows against your private corpus.

Usage:
    python validation/diff_runs.py --before runs-private/baseline/ \\
        --after runs-private/20260502/ --output diff.json
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _iter_json_payloads(path: Path) -> list[dict[str, Any]]:
    """Read a file as JSON array, NDJSON, or single JSON object.

    Mirrors ``find_gaps._iter_json_payloads`` so both validation tools
    accept the same input shapes.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
        return []
    stripped = text.lstrip()
    if not stripped:
        return []
    if stripped[0] == "[":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            print(f"warning: invalid JSON array in {path}: {exc}", file=sys.stderr)
            return []
        return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []
    if stripped[0] == "{":
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass
    out: list[dict[str, Any]] = []
    for line_num, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"warning: skipping malformed line {line_num} in {path}: {exc}", file=sys.stderr)
            continue
        if isinstance(entry, dict):
            out.append(entry)
    return out


def _load_runs(path: Path) -> dict[str, dict[str, Any]]:
    """Return ``{queried_domain: result_dict}`` from a file or directory.

    Accepts JSON arrays, NDJSON streams, single-object JSON files, or
    directories containing any of the above.
    """
    files: list[Path] = (
        [Path(p) for p in sorted(glob.glob(str(path / "*.json")))]
        + [Path(p) for p in sorted(glob.glob(str(path / "*.ndjson")))]
        if path.is_dir()
        else [path]
    )
    out: dict[str, dict[str, Any]] = {}
    for fp in files:
        for entry in _iter_json_payloads(fp):
            domain = str(entry.get("queried_domain", "")) or fp.stem
            if domain:
                out[domain] = entry
    return out


def _slugs_in(d: dict[str, Any]) -> set[str]:
    raw = d.get("slugs") or []
    return {str(s) for s in raw if isinstance(s, str)}


def _surface_pairs(d: dict[str, Any]) -> set[tuple[str, str]]:
    """Return ``{(subdomain, primary_slug)}`` pairs from surface_attributions."""
    out: set[tuple[str, str]] = set()
    for entry in d.get("surface_attributions") or []:
        if not isinstance(entry, dict):
            continue
        sub = str(entry.get("subdomain", ""))
        slug = str(entry.get("primary_slug", ""))
        if sub and slug:
            out.add((sub, slug))
    return out


def diff(before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Build the diff report. Domains present in both are compared field-by-field."""
    before_keys = set(before.keys())
    after_keys = set(after.keys())

    per_domain: list[dict[str, Any]] = []
    for domain in sorted(before_keys & after_keys):
        b = before[domain]
        a = after[domain]

        b_slugs = _slugs_in(b)
        a_slugs = _slugs_in(a)
        added_slugs = sorted(a_slugs - b_slugs)
        removed_slugs = sorted(b_slugs - a_slugs)

        b_surface = _surface_pairs(b)
        a_surface = _surface_pairs(a)
        added_surface = sorted(a_surface - b_surface)
        removed_surface = sorted(b_surface - a_surface)

        if not (added_slugs or removed_slugs or added_surface or removed_surface):
            continue

        per_domain.append(
            {
                "domain": domain,
                "added_slugs": added_slugs,
                "removed_slugs": removed_slugs,
                "added_surface_attributions": [{"subdomain": s, "primary_slug": slug} for s, slug in added_surface],
                "removed_surface_attributions": [{"subdomain": s, "primary_slug": slug} for s, slug in removed_surface],
            }
        )

    # Aggregate slug frequency change across both corpora.
    before_freq: Counter[str] = Counter()
    after_freq: Counter[str] = Counter()
    for d in before.values():
        for slug in _slugs_in(d):
            before_freq[slug] += 1
    for d in after.values():
        for slug in _slugs_in(d):
            after_freq[slug] += 1

    slug_freq_pairs: list[tuple[str, int, int, int]] = []
    for slug in sorted(set(before_freq) | set(after_freq)):
        delta = after_freq[slug] - before_freq[slug]
        if delta != 0:
            slug_freq_pairs.append((slug, before_freq[slug], after_freq[slug], delta))
    slug_freq_pairs.sort(key=lambda t: (-abs(t[3]), t[0]))
    slug_freq_changes = [{"slug": s, "before": b, "after": a, "delta": d} for s, b, a, d in slug_freq_pairs]

    return {
        "added_domains": sorted(after_keys - before_keys),
        "removed_domains": sorted(before_keys - after_keys),
        "domains_compared": len(before_keys & after_keys),
        "domains_changed": len(per_domain),
        "per_domain": per_domain,
        "slug_freq_changes": slug_freq_changes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True, help="Earlier run (file or directory).")
    parser.add_argument("--after", type=Path, required=True, help="Later run (file or directory).")
    parser.add_argument("--output", type=Path, default=None, help="Write diff.json here. Default: stdout.")
    args = parser.parse_args()

    before = _load_runs(args.before)
    after = _load_runs(args.after)
    report = diff(before, after)
    payload = json.dumps(report, indent=2)

    if args.output is None:
        print(payload)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"wrote {args.output} ({report['domains_changed']} of {report['domains_compared']} compared changed)")


if __name__ == "__main__":
    main()
