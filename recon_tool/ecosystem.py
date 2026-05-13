"""Batch-scope hypergraph ecosystem view (v1.8+).

Builds hyperedges over the domains in a single ``recon batch`` run when
two or more domains share an observable signature. Each hyperedge is
descriptive structure — co-membership in a public broadcast pattern —
not an ownership claim.

Hyperedge types
---------------
* ``top_issuer``     — domains whose CT top-issuer (most-frequent
                       issuer name) is the same.
* ``bimi_org``       — domains whose BIMI VMC organization name is
                       identical (after light normalisation).
* ``parent_vendor``  — domains that detected at least one fingerprint
                       sharing a v1.8 ``parent_vendor`` metadata
                       value.
* ``shared_slugs``   — pairs of domains sharing two or more
                       fingerprint slugs (Jaccard-style overlap, no
                       transitive grouping).

Each hyperedge surfaces only when at least two domains agree, so
single-domain runs are silent. The matcher is purely a re-projection
of already-collected ``TenantInfo`` data — zero new network calls,
deterministic, and capped at ``MAX_HYPEREDGES`` to bound JSON payload
sizes on heavy corpus runs.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import combinations

from recon_tool.fingerprints import load_fingerprints
from recon_tool.models import TenantInfo

__all__ = [
    "MAX_HYPEREDGES",
    "MAX_MEMBERS_PER_HYPEREDGE",
    "Hyperedge",
    "build_ecosystem_hyperedges",
]

# Caps applied across all hyperedge types combined.
MAX_HYPEREDGES = 200
MAX_MEMBERS_PER_HYPEREDGE = 100

# Minimum overlap to fire a ``shared_slugs`` hyperedge between a pair
# of domains. Bumped from 2 → 3 in v1.8 after the validation corpus
# showed pair-of-2 overlap firing on trivial coincidences (every
# enterprise has Microsoft365 + DocuSign + Adobe).
_MIN_SLUG_OVERLAP = 3

# Slugs that appear on more than this fraction of the batch are
# treated as a baseline and removed from shared_slugs intersection
# computation. Empirically ~50 % is the right floor for the corpus
# diversity we see — any tighter and meaningful pairs get masked,
# any looser and ubiquitous SaaS (google-site, mailchimp, sendgrid)
# pollute every pair. Adaptive rather than a hardcoded list so the
# filter scales with whatever corpus the operator runs.
_BASELINE_FREQ_THRESHOLD = 0.5

# Don't apply the baseline filter on tiny batches — every slug in a
# 2-domain batch has frequency 1.0 by definition, so the filter would
# strip everything and the rule could never fire. Real-world corpus
# runs comfortably exceed this; CI fixtures with synthetic 2-3
# domains exercise the unfiltered path.
_MIN_BATCH_FOR_BASELINE = 5


@dataclass(frozen=True)
class Hyperedge:
    """One observed multi-domain signature.

    ``edge_type`` selects the rule that produced the edge; ``key`` is
    the value the rule fired on (issuer name, BIMI org, parent vendor,
    or, for ``shared_slugs``, the comma-joined intersection of slug
    names). ``members`` is the sorted list of domains that share the
    signature.
    """

    edge_type: str
    key: str
    members: tuple[str, ...]


def _slug_to_parent_vendor() -> dict[str, str]:
    """Return ``{slug: parent_vendor}`` for fingerprints with the
    metadata populated."""
    return {fp.slug: fp.parent_vendor for fp in load_fingerprints() if fp.parent_vendor is not None}


def _normalize_org(name: str) -> str:
    """Light case/whitespace normalisation for BIMI org-name matching."""
    return " ".join(name.lower().split())


def _top_issuer_hyperedges(
    infos: Mapping[str, TenantInfo],
) -> list[Hyperedge]:
    buckets: dict[str, list[str]] = defaultdict(list)
    for domain, info in infos.items():
        if info.cert_summary is None or not info.cert_summary.top_issuers:
            continue
        # Top issuer is the first entry — Counter.most_common(3)[0] in
        # build_cert_summary.
        top = info.cert_summary.top_issuers[0]
        buckets[top].append(domain)
    out: list[Hyperedge] = []
    for issuer, members in buckets.items():
        if len(members) < 2:
            continue
        members_sorted = tuple(sorted(set(members)))[:MAX_MEMBERS_PER_HYPEREDGE]
        out.append(Hyperedge(edge_type="top_issuer", key=issuer, members=members_sorted))
    return out


def _bimi_org_hyperedges(
    infos: Mapping[str, TenantInfo],
) -> list[Hyperedge]:
    buckets: dict[str, tuple[str, list[str]]] = {}
    for domain, info in infos.items():
        if info.bimi_identity is None or not info.bimi_identity.organization:
            continue
        normalized = _normalize_org(info.bimi_identity.organization)
        if not normalized:
            continue
        if normalized in buckets:
            buckets[normalized][1].append(domain)
        else:
            buckets[normalized] = (info.bimi_identity.organization, [domain])
    out: list[Hyperedge] = []
    for _, (canonical_name, members) in buckets.items():
        if len(members) < 2:
            continue
        members_sorted = tuple(sorted(set(members)))[:MAX_MEMBERS_PER_HYPEREDGE]
        out.append(Hyperedge(edge_type="bimi_org", key=canonical_name, members=members_sorted))
    return out


def _parent_vendor_hyperedges(
    infos: Mapping[str, TenantInfo],
) -> list[Hyperedge]:
    slug_to_vendor = _slug_to_parent_vendor()
    if not slug_to_vendor:
        return []
    buckets: dict[str, set[str]] = defaultdict(set)
    for domain, info in infos.items():
        for slug in info.slugs:
            vendor = slug_to_vendor.get(slug)
            if vendor:
                buckets[vendor].add(domain)
    out: list[Hyperedge] = []
    for vendor, members in buckets.items():
        if len(members) < 2:
            continue
        members_sorted = tuple(sorted(members))[:MAX_MEMBERS_PER_HYPEREDGE]
        out.append(Hyperedge(edge_type="parent_vendor", key=vendor, members=members_sorted))
    return out


def _baseline_slugs(
    domain_slugs: Mapping[str, frozenset[str]],
) -> frozenset[str]:
    """Identify ubiquitous slugs to exclude from shared_slugs overlap.

    A slug present on more than ``_BASELINE_FREQ_THRESHOLD`` of the
    batch is treated as part of the baseline (think SPF/DMARC/DKIM,
    google-site verification, Microsoft 365, common SaaS that every
    enterprise has) and removed from the intersection used to fire
    shared_slugs edges. The filter is adaptive — it scales with
    whatever corpus the operator submits.
    """
    if not domain_slugs or len(domain_slugs) < _MIN_BATCH_FOR_BASELINE:
        return frozenset()
    n = len(domain_slugs)
    counts: dict[str, int] = {}
    for slug_set in domain_slugs.values():
        for slug in slug_set:
            counts[slug] = counts.get(slug, 0) + 1
    return frozenset(slug for slug, c in counts.items() if c / n > _BASELINE_FREQ_THRESHOLD)


def _shared_slugs_hyperedges(
    infos: Mapping[str, TenantInfo],
) -> list[Hyperedge]:
    """Pairs of domains sharing ``_MIN_SLUG_OVERLAP`` or more slugs.

    Pairwise rather than transitive: A↔B and B↔C are independent
    edges. Transitive grouping would falsely suggest A↔C overlap when
    they may share zero slugs directly.

    Ubiquitous slugs (above ``_BASELINE_FREQ_THRESHOLD`` corpus-wide
    prevalence) are stripped from the intersection before the
    threshold check — this is the v1.8 fix for the noise floor that
    let "everyone has Microsoft365 + DocuSign + Adobe" fire as a
    pair on every domain combination.
    """
    out: list[Hyperedge] = []
    domain_slugs = {d: frozenset(info.slugs) for d, info in infos.items() if info.slugs}
    baseline = _baseline_slugs(domain_slugs)
    # Strip baseline once per domain rather than per pair — saves
    # work when the corpus is large.
    discriminating = {d: slugs - baseline for d, slugs in domain_slugs.items()}
    domains_sorted = sorted(discriminating)
    seen_keys: set[tuple[str, ...]] = set()
    for a, b in combinations(domains_sorted, 2):
        overlap = discriminating[a] & discriminating[b]
        if len(overlap) < _MIN_SLUG_OVERLAP:
            continue
        members: tuple[str, ...] = tuple(sorted({a, b}))
        if members in seen_keys:
            continue
        seen_keys.add(members)
        # The "key" for shared-slug edges is the canonical slug
        # intersection so consumers can group similar pairs.
        key = ",".join(sorted(overlap))
        out.append(Hyperedge(edge_type="shared_slugs", key=key, members=members))
    return out


def build_ecosystem_hyperedges(
    infos: Mapping[str, TenantInfo],
) -> tuple[Hyperedge, ...]:
    """Build the ecosystem hypergraph for a batch of resolved domains.

    Returns an empty tuple when fewer than two domains are supplied or
    no rule fires. Output is deterministic — sorted by
    ``(edge_type, key, members)`` — and capped at ``MAX_HYPEREDGES``.
    Cap order: ``top_issuer`` first (most informative for shared
    infrastructure), then ``bimi_org``, then ``parent_vendor``, then
    ``shared_slugs`` (most numerous, pruned last).
    """
    if len(infos) < 2:
        return ()

    by_type: list[tuple[str, list[Hyperedge]]] = [
        ("top_issuer", _top_issuer_hyperedges(infos)),
        ("bimi_org", _bimi_org_hyperedges(infos)),
        ("parent_vendor", _parent_vendor_hyperedges(infos)),
        ("shared_slugs", _shared_slugs_hyperedges(infos)),
    ]

    flat: list[Hyperedge] = []
    for _, edges in by_type:
        edges.sort(key=lambda e: (e.edge_type, e.key, e.members))
        flat.extend(edges)
        if len(flat) >= MAX_HYPEREDGES:
            flat = flat[:MAX_HYPEREDGES]
            break

    return tuple(flat)
