"""Pre-filter ``gaps.json`` to a triage-ready candidate list.

The fingerprint-discovery loop is split:

  1. Programmatic: this script. Drops noise that doesn't need human or LLM
     judgment: chains already covered by an existing pattern, intra-org
     hostnames the apex obviously owns, low-count one-offs that aren't
     worth a fingerprint, and tunable occurrence and distinct-namespace
     floors.

  2. Human or LLM: the survivors. Each is a real candidate for a new
     ``cname_target`` fingerprint or an extension of an existing one. The
     ``/recon-fingerprint-triage`` skill consumes the output of this script
     directly.

Inputs:
  * ``gaps.json`` produced by ``find_gaps.py``
  * The fingerprint catalogue directory (default
    ``src/recon_tool/data/fingerprints/``)

Output: ``candidates.json`` has the same shape as ``gaps.json`` but only the entries
worth surfacing for triage.

Usage:
    python validation/triage_candidates.py \\
        --gaps runs-private/<latest>/gaps.json \\
        --fingerprints src/recon_tool/data/fingerprints/ \\
        --output runs-private/<latest>/candidates.json \\
        --min-count 2 \\
        --min-distinct-namespaces 2
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from recon_tool.discovery import looks_intra_org_brand, pattern_matches_hostname


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


def _has_matching_pattern(value: str, patterns: set[str]) -> bool:
    """True when an existing fingerprint pattern matches ``value``."""
    return any(pattern_matches_hostname(value, pattern) for pattern in patterns)


def is_already_covered(suffix: str, patterns: set[str]) -> bool:
    """True when an existing fingerprint pattern matches the bucket suffix."""
    return _has_matching_pattern(suffix, patterns)


def _candidate_values(suffix: str, samples: list[dict[str, Any]]) -> list[str]:
    """Return suffix, terminals, and chain hops that may carry a known pattern."""
    values = [suffix]
    for sample in samples:
        terminal = sample.get("terminal")
        if isinstance(terminal, str) and terminal:
            values.append(terminal)
        chain = sample.get("chain")
        if isinstance(chain, list):
            values.extend(str(hop) for hop in chain if hop)
    return values


def entry_is_already_covered(suffix: str, samples: list[dict[str, Any]], patterns: set[str]) -> bool:
    """True when the suffix or any sample hostname already matches a pattern.

    ``find_gaps`` buckets terminals by their rightmost three labels. That can
    hide the specific label an existing fingerprint needs, for example an AWS
    ELB terminal bucketed as ``us-gov-east-1.amazonaws.com`` while the actual
    covered terminal contains ``elb.us-gov-east-1.amazonaws.com``.
    """
    return any(_has_matching_pattern(value, patterns) for value in _candidate_values(suffix, samples))


def looks_intra_org(suffix: str, samples: list[dict[str, Any]]) -> bool:
    """True when the chains all stay inside the queried domain's brand zone.

    Delegates to ``recon_tool.discovery`` so both this script and the
    ``recon discover`` subcommand share the same heuristic. The brand-label
    check correctly handles multi-part TLDs (``sample.example.co.uk`` to ``example``)
    by skipping the second-level public suffix.
    """
    if not samples:
        return False
    # Reconstruct the apex from a sample subdomain with the same approximation as
    # before, but with TLD-aware brand-label extraction.
    sample = samples[0]
    sub = str(sample.get("subdomain", "")).lower()
    parts = sub.split(".")
    # For multi-part TLDs (foo.sample.example.co.uk), the apex is the rightmost three
    # labels; for foo.example.com it's the rightmost two. Use the brand-label
    # extractor to drive the decision: pick whichever right-anchored slice
    # produces a non-empty brand label.
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
    min_distinct_namespaces: int,
    drop_intra_org: bool,
) -> list[dict[str, Any]]:
    """Return only the gap entries worth human or LLM triage."""
    survivors: list[dict[str, Any]] = []
    for entry in gaps:
        suffix = str(entry.get("suffix", ""))
        count_raw = entry.get("count", 0)
        count = int(count_raw) if isinstance(count_raw, int) else 0
        namespace_count_raw = entry.get("distinct_namespace_count", 0)
        namespace_count = int(namespace_count_raw) if isinstance(namespace_count_raw, int) else 0
        samples_raw = entry.get("samples") or []
        samples = samples_raw if isinstance(samples_raw, list) else []
        if count < min_count:
            continue
        if namespace_count < min_distinct_namespaces:
            continue
        if entry_is_already_covered(suffix, samples, existing_patterns):
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
        default=Path("src/recon_tool/data/fingerprints"),
        help="Directory of fingerprint YAML files (default: src/recon_tool/data/fingerprints).",
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
        "--min-distinct-namespaces",
        type=int,
        default=2,
        help=(
            "Drop suffixes observed in fewer than N distinct queried namespaces "
            "(default: 2). Legacy gaps without this field require an explicit value of 0."
        ),
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
        min_distinct_namespaces=args.min_distinct_namespaces,
        drop_intra_org=not args.keep_intra_org,
    )
    payload = json.dumps(survivors, indent=2)

    covered_drops = 0
    for entry in gaps_data:
        samples_raw = entry.get("samples") if isinstance(entry, dict) else None
        samples = samples_raw if isinstance(samples_raw, list) else []
        if isinstance(entry, dict) and entry_is_already_covered(str(entry.get("suffix", "")), samples, existing):
            covered_drops += 1
    summary = f"input: {len(gaps_data)} gaps, existing-patterns dropped: {covered_drops}, survivors: {len(survivors)}"

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
