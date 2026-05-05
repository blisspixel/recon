"""Pre-filter ``gaps.json`` to a triage-ready candidate list.

The fingerprint-discovery loop is split:

  1. Programmatic — this script. Drops noise that doesn't need human or LLM
     judgment: chains already covered by an existing pattern, intra-org
     hostnames the apex obviously owns, low-count one-offs that aren't
     worth a fingerprint, and a tunable ``--min-count`` floor.

  2. Human or LLM — the survivors. Each is a real candidate for a new
     ``cname_target`` fingerprint or an extension of an existing one. The
     ``/recon-fingerprint-triage`` Claude skill consumes the output of this
     script directly.

Inputs:
  * ``gaps.json`` produced by ``find_gaps.py``
  * The fingerprint catalogue directory (default ``recon_tool/data/fingerprints/``)

Output: ``candidates.json`` — same shape as ``gaps.json`` but only the entries
worth surfacing for triage.

Usage:
    python validation/triage_candidates.py \\
        --gaps runs-private/<latest>/gaps.json \\
        --fingerprints recon_tool/data/fingerprints/ \\
        --output runs-private/<latest>/candidates.json \\
        --min-count 2
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml


def load_existing_patterns(fingerprints_dir: Path) -> set[str]:
    """Return the set of every ``cname_target`` pattern across all YAMLs.

    Used to drop gap suffixes that already match an existing pattern. We
    consume only the ``cname_target`` rules because that's the type the
    surface classifier consults; ``cname`` rules fire on a different
    code path and don't disqualify a gap candidate.
    """
    patterns: set[str] = set()
    for fp in sorted(fingerprints_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(fp.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            print(f"warning: skipping {fp}: {exc}", file=sys.stderr)
            continue
        entries = data.get("fingerprints") if isinstance(data, dict) else data
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for det in entry.get("detections", []) or []:
                if not isinstance(det, dict):
                    continue
                if det.get("type") == "cname_target":
                    pat = det.get("pattern")
                    if isinstance(pat, str) and pat:
                        patterns.add(pat.lower())
    return patterns


def is_already_covered(suffix: str, patterns: set[str]) -> bool:
    """True when an existing fingerprint pattern matches the suffix.

    Substring-match the suffix against every pattern; if any pattern is a
    substring of the suffix, the suffix is already classified.
    """
    s = suffix.lower()
    return any(p in s for p in patterns)


def looks_intra_org(suffix: str, samples: list[dict[str, Any]]) -> bool:
    """True when the chains all stay inside the queried domain's brand zone.

    Delegates to ``recon_tool.discovery`` so both this script and the
    ``recon discover`` subcommand share the same heuristic. The brand-label
    check correctly handles multi-part TLDs (``contoso.co.uk`` → ``contoso``)
    by skipping the second-level public suffix.
    """
    if not samples:
        return False
    # Reconstruct the apex from a sample subdomain — same approximation as
    # before, but with TLD-aware brand-label extraction.
    sample = samples[0]
    sub = str(sample.get("subdomain", "")).lower()
    parts = sub.split(".")
    # For multi-part TLDs (foo.contoso.co.uk), the apex is the rightmost three
    # labels; for foo.example.com it's the rightmost two. Use the brand-label
    # extractor to drive the decision: pick whichever right-anchored slice
    # produces a non-empty brand label.
    from recon_tool.discovery import looks_intra_org_brand

    for n in (3, 2):
        if len(parts) >= n:
            apex_candidate = ".".join(parts[-n:])
            if looks_intra_org_brand(apex_candidate, suffix, samples):
                return True
    return False


def triage(
    gaps: list[dict[str, Any]],
    *,
    existing_patterns: set[str],
    min_count: int,
    drop_intra_org: bool,
) -> list[dict[str, Any]]:
    """Return only the gap entries worth human or LLM triage."""
    survivors: list[dict[str, Any]] = []
    for entry in gaps:
        suffix = str(entry.get("suffix", ""))
        count_raw = entry.get("count", 0)
        count = int(count_raw) if isinstance(count_raw, int) else 0
        samples_raw = entry.get("samples") or []
        samples = samples_raw if isinstance(samples_raw, list) else []
        if count < min_count:
            continue
        if is_already_covered(suffix, existing_patterns):
            continue
        if drop_intra_org and looks_intra_org(suffix, samples):
            continue
        survivors.append(entry)
    return survivors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gaps", type=Path, required=True, help="Path to gaps.json")
    parser.add_argument(
        "--fingerprints",
        type=Path,
        default=Path("recon_tool/data/fingerprints"),
        help="Directory of fingerprint YAML files (default: recon_tool/data/fingerprints).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Where to write candidates.json. Default: stdout.",
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=2,
        help="Drop suffixes seen fewer than N times across the corpus (default: 2).",
    )
    parser.add_argument(
        "--keep-intra-org",
        action="store_true",
        help="Don't drop chains that look intra-organizational (false-positive prone but more inclusive).",
    )
    args = parser.parse_args()

    gaps_data = json.loads(args.gaps.read_text(encoding="utf-8"))
    if not isinstance(gaps_data, list):
        print(f"error: expected gaps.json to contain a JSON array, got {type(gaps_data).__name__}", file=sys.stderr)
        raise SystemExit(2)

    existing = load_existing_patterns(args.fingerprints)
    survivors = triage(
        gaps_data,
        existing_patterns=existing,
        min_count=args.min_count,
        drop_intra_org=not args.keep_intra_org,
    )
    payload = json.dumps(survivors, indent=2)

    covered_drops = sum(
        1 for g in gaps_data if is_already_covered(str(g.get("suffix", "")), existing)
    )
    summary = (
        f"input: {len(gaps_data)} gaps, "
        f"existing-patterns dropped: {covered_drops}, "
        f"survivors: {len(survivors)}"
    )

    if args.output is None:
        print(payload)
        print(summary, file=sys.stderr)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"wrote {args.output} ({len(survivors)} candidates)")
        print(summary, file=sys.stderr)


if __name__ == "__main__":
    main()
