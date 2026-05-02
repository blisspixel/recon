"""Fingerprint-discovery library: turn unclassified CNAME chains into candidates.

The single-domain ``recon discover <domain>`` command and the corpus-scale
``validation/`` scripts share the logic in this module. Keep it programmatic
and pure: input is the JSON shape recon emits with ``--include-unclassified``;
output is a ranked list of candidate dicts ready for human or LLM triage.

Three steps:

1. Bucket unclassified terminals by zone-suffix (rightmost ~3 labels).
2. Drop chains that look intra-organizational (terminal in the apex's brand
   zone). Best-effort; the LLM step handles brand siblings.
3. Drop terminals already covered by an existing fingerprint pattern
   (substring match against the bundled catalog).

The result is a list of ``{suffix, count, samples}`` records, each one a
real candidate worth proposing as a new ``cname_target`` fingerprint or an
extension to an existing one.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml


def suffix_for(terminal: str) -> str:
    """Bucket a terminal hostname by its rightmost three labels.

    ``edge.fastly.net`` → ``fastly.net``. ``deep.cdn.fastly.net`` →
    ``cdn.fastly.net``. The 3-label window keeps the bucket specific enough
    to reveal real services while wide enough to merge per-customer
    subdomains under a single fingerprint candidate.
    """
    parts = terminal.split(".")
    return ".".join(parts[-3:]) if len(parts) >= 3 else terminal


def is_intra_org(apex: str, terminal: str) -> bool:
    """Return True when terminal is inside the queried apex's own DNS zone."""
    apex = apex.lower().lstrip(".")
    terminal = terminal.lower().lstrip(".")
    return terminal == apex or terminal.endswith("." + apex)


# Second-level public suffixes that aren't a brand label. Skipped when
# extracting the apex's brand stem so ``bbc.co.uk`` → "bbc" and
# ``yahoo.co.jp`` → "yahoo" instead of "co".
_SECOND_LEVEL_PUBLIC: frozenset[str] = frozenset(
    {"co", "com", "ac", "org", "net", "gov", "edu", "ne", "or", "go", "mil", "biz"}
)


def extract_brand_label(apex: str) -> str:
    """Return the most distinctive label of the apex — the "brand stem".

    Treats the rightmost label as the TLD (com/org/uk/jp/ru/...) and skips
    common second-level public suffixes (co, ac, org, net, gov, edu, ...)
    so that:

    * ``bbc.co.uk`` → ``"bbc"``
    * ``nytimes.com`` → ``"nytimes"``
    * ``yahoo.co.jp`` → ``"yahoo"``
    * ``deutsche-bank.de`` → ``"deutsche-bank"``
    * ``softchoice.com`` → ``"softchoice"``

    Returns an empty string when the apex has fewer than two labels or no
    plausible brand label survives the skip rules.
    """
    parts = apex.lower().split(".")
    if len(parts) < 2:
        return ""
    # Walk right-to-left, skipping the TLD (always rightmost) and any
    # second-level public suffix. Return the first label that isn't a
    # public suffix and is at least 3 characters long.
    for i in range(len(parts) - 2, -1, -1):
        label = parts[i]
        if label and label not in _SECOND_LEVEL_PUBLIC and len(label) >= 3:
            return label
    return ""


def looks_intra_org_brand(apex: str, suffix: str, samples: list[dict[str, Any]]) -> bool:
    """Heuristic check for cross-zone same-brand chains.

    The strict ``is_intra_org`` check only catches chains that stay within
    the apex's own zone. Many enterprises route through a sibling brand
    domain (gslbjpmchase.com from chase.com, bbcnewslabs.co.uk from bbc.com).
    Two patterns are caught here:

    1. **Full brand label substring** — ``softchoice`` appears anywhere in
       the suffix.
    2. **Brand-stem abbreviation** — the brand's first 3+ characters appear
       as a standalone label in the suffix. Catches the nytimes.com → nyt.net
       case (brand="nytimes", abbreviation="nyt") without over-matching on
       arbitrary 3-char substrings.

    Best-effort. Genuine acronym abbreviations (generalmotors → gm,
    internationalbusinessmachines → ibm) won't match — those need the LLM
    step to recognize the relationship.
    """
    if not samples:
        return False
    brand_label = extract_brand_label(apex)
    if not brand_label:
        return False
    suffix_lower = suffix.lower()
    # Pattern 1: full brand label appears as substring.
    if brand_label in suffix_lower:
        return True
    # Pattern 2: brand-stem prefix appears as a standalone suffix label.
    # The 3-char floor avoids matching incidental letter sequences ("am" in
    # ".amazonaws.com" because of "amazon"); the standalone-label check
    # requires the prefix to be a whole DNS label, not a substring of one.
    if len(brand_label) >= 5:
        prefix = brand_label[:3]
        suffix_labels = suffix_lower.split(".")
        if prefix in suffix_labels:
            return True
    return False


def load_existing_patterns(fingerprints_dir: Path) -> set[str]:
    """Return the set of every ``cname_target`` pattern across all YAMLs.

    Used to drop gap suffixes that already match an existing pattern. We
    consume only ``cname_target`` rules because that's the type the surface
    classifier consults; ``cname`` rules fire on a different code path and
    don't disqualify a candidate.
    """
    patterns: set[str] = set()
    if not fingerprints_dir.is_dir():
        return patterns
    for fp in sorted(fingerprints_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(fp.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
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


def already_covered(suffix: str, patterns: set[str]) -> bool:
    """True when an existing ``cname_target`` pattern matches the suffix."""
    s = suffix.lower()
    return any(p in s for p in patterns)


def find_candidates(
    runs: list[tuple[str, list[dict[str, Any]]]],
    *,
    existing_patterns: set[str] | None = None,
    fingerprints_dir: Path | None = None,
    min_count: int = 1,
    drop_intra_org: bool = True,
    max_samples_per_suffix: int = 5,
) -> list[dict[str, Any]]:
    """Build the ranked candidate list from per-domain unclassified chains.

    Parameters:
      runs: ``[(apex, [{subdomain, chain}]), ...]``. Each entry is one
        domain's ``unclassified_cname_chains`` array as emitted by recon's
        JSON output.
      existing_patterns: set of ``cname_target`` patterns to consider
        already-covered. Pass ``None`` and ``fingerprints_dir`` to load from
        disk; pass an explicit set to reuse across calls.
      fingerprints_dir: directory of fingerprint YAMLs. Loaded when
        ``existing_patterns`` is None. ``None`` and no preloaded set means
        no already-covered filter.
      min_count: drop suffixes seen fewer than this many times across the
        runs. Default 1 (keep everything).
      drop_intra_org: filter chains where the terminal is in the apex's
        zone or shares the apex's brand label.
      max_samples_per_suffix: cap the ``samples`` list per suffix.

    Returns: ``[{suffix, count, samples: [{subdomain, terminal, chain}]}, ...]``
    sorted by count descending, then suffix.
    """
    if existing_patterns is None and fingerprints_dir is not None:
        existing_patterns = load_existing_patterns(fingerprints_dir)
    elif existing_patterns is None:
        existing_patterns = set()

    suffix_count: dict[str, int] = defaultdict(int)
    suffix_samples: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for apex, unclassified in runs:
        for entry in unclassified:
            subdomain = str(entry.get("subdomain", ""))
            chain = entry.get("chain") or []
            if not isinstance(chain, list) or not chain:
                continue
            terminal = str(chain[-1])
            if not terminal:
                continue
            if drop_intra_org and is_intra_org(apex, terminal):
                continue
            suffix = suffix_for(terminal)
            if drop_intra_org and looks_intra_org_brand(
                apex, suffix, [{"subdomain": subdomain, "terminal": terminal}]
            ):
                continue
            if already_covered(suffix, existing_patterns):
                continue
            suffix_count[suffix] += 1
            if len(suffix_samples[suffix]) < max_samples_per_suffix:
                suffix_samples[suffix].append(
                    {
                        "subdomain": subdomain,
                        "terminal": terminal,
                        "chain": [str(h) for h in chain],
                    }
                )

    # Build the final list, ranked by (count desc, suffix asc).
    ranked = sorted(suffix_count.items(), key=lambda pair: (-pair[1], pair[0]))
    rows: list[dict[str, Any]] = [
        {"suffix": suffix, "count": count, "samples": suffix_samples[suffix]}
        for suffix, count in ranked
        if count >= min_count
    ]
    return rows
