"""Batch-scope hypergraph ecosystem view.

Builds hyperedges over the domains in a single ``recon batch`` run when
two or more domains share an observable signature. Each hyperedge is
descriptive structure — co-membership in a public broadcast pattern —
not an ownership claim.

Hyperedge types
---------------
* ``top_issuer``     — domains whose CT top-issuer (most-frequent
                       issuer name) is the same.
* ``parent_vendor``  — domains that detected at least one fingerprint
                       sharing a ``parent_vendor`` metadata value.
* ``shared_slugs``: pairs of domains sharing three or more
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
from dataclasses import asdict, dataclass
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
MAX_PAIR_VISITS = 100_000

# Per-builder candidate cap, independent of the indexed pair-visit budget.
# Bound intermediate edge materialization before final output selection.
_MAX_CANDIDATE_HYPEREDGES = MAX_HYPEREDGES * 10

# Minimum overlap to fire a ``shared_slugs`` hyperedge between a pair
# of domains. Bumped from 2 → 3 after the validation corpus showed
# pair-of-2 overlap firing on trivial coincidences (every enterprise
# has Microsoft365 + DocuSign + Adobe).
_MIN_SLUG_OVERLAP = 3

# Slugs that appear on more than this fraction of the submitted batch are
# treated as a cohort-local baseline and removed from shared-slug intersections.
# The threshold is a heuristic, not a population rarity estimate. Empty slug
# rows remain in the denominator so the outcome cannot select its own baseline.
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
    the value the rule fired on (issuer name, parent vendor, or, for
    ``shared_slugs``, the comma-joined intersection of slug
    names). ``members`` is the sorted list of domains that share the
    signature.
    """

    edge_type: str
    key: str
    members: tuple[str, ...]


@dataclass
class _EcosystemWork:
    """Actual enumeration counters, separate from the bounded emitted edges."""

    baseline_slugs_filtered: int = 0
    pair_visits: int = 0
    pair_visits_possible: int = 0
    unique_pairs_examined: int = 0
    pair_search_complete: bool = True
    candidate_limit_reached: bool = False
    known_omitted_candidates: int = 0
    omitted_member_occurrences: int = 0


@dataclass(frozen=True)
class EcosystemReport:
    """Retained edges plus bounded-search and omission diagnostics."""

    hyperedges: tuple[Hyperedge, ...]
    completeness: dict[str, object]


def _bucket_hyperedges(
    buckets: Mapping[str, list[str] | set[str]], edge_type: str, work: _EcosystemWork | None
) -> list[Hyperedge]:
    """Project indexed groups and count omissions without expanding pairs."""
    out: list[Hyperedge] = []
    for key, members in sorted(buckets.items()):
        if len(members) < 2:
            continue
        if len(out) >= _MAX_CANDIDATE_HYPEREDGES:
            if work is not None:
                work.candidate_limit_reached = True
                work.known_omitted_candidates += 1
            continue
        ordered = tuple(sorted(set(members)))
        if work is not None:
            work.omitted_member_occurrences += max(0, len(ordered) - MAX_MEMBERS_PER_HYPEREDGE)
        out.append(Hyperedge(edge_type=edge_type, key=key, members=ordered[:MAX_MEMBERS_PER_HYPEREDGE]))
    return out


def _slug_to_parent_vendor() -> dict[str, str]:
    """Return ``{slug: parent_vendor}`` for fingerprints with the
    metadata populated."""
    return {fp.slug: fp.parent_vendor for fp in load_fingerprints() if fp.parent_vendor is not None}


def _top_issuer_hyperedges(
    infos: Mapping[str, TenantInfo],
    work: _EcosystemWork | None = None,
) -> list[Hyperedge]:
    buckets: dict[str, list[str]] = defaultdict(list)
    for domain, info in infos.items():
        if info.cert_summary is None or not info.cert_summary.top_issuers:
            continue
        # Top issuer is the first entry — Counter.most_common(3)[0] in
        # build_cert_summary.
        top = info.cert_summary.top_issuers[0]
        buckets[top].append(domain)
    return _bucket_hyperedges(buckets, "top_issuer", work)


def _parent_vendor_hyperedges(
    infos: Mapping[str, TenantInfo],
    work: _EcosystemWork | None = None,
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
    return _bucket_hyperedges(buckets, "parent_vendor", work)


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
    work: _EcosystemWork | None = None,
) -> list[Hyperedge]:
    """Pairs of domains sharing ``_MIN_SLUG_OVERLAP`` or more slugs.

    Pairwise rather than transitive: A↔B and B↔C are independent
    edges. Transitive grouping would falsely suggest A↔C overlap when
    they may share zero slugs directly.

    Ubiquitous slugs (above ``_BASELINE_FREQ_THRESHOLD`` corpus-wide
    prevalence) are stripped from the intersection before the
    threshold check — this is the fix for the noise floor that
    let "everyone has Microsoft365 + DocuSign + Adobe" fire as a
    pair on every domain combination.
    """
    out: list[Hyperedge] = []
    domain_slugs = {d: frozenset(info.slugs) for d, info in infos.items()}
    baseline = _baseline_slugs(domain_slugs)
    # Strip baseline once per domain rather than per pair — saves
    # work when the corpus is large.
    discriminating = {d: slugs - baseline for d, slugs in domain_slugs.items()}
    postings: dict[str, list[str]] = defaultdict(list)
    for domain in sorted(discriminating):
        slugs = discriminating[domain]
        if len(slugs) >= _MIN_SLUG_OVERLAP:
            for slug in sorted(slugs):
                postings[slug].append(domain)
    progress = work if work is not None else _EcosystemWork()
    progress.baseline_slugs_filtered = len(baseline)
    progress.pair_visits_possible = sum(len(members) * (len(members) - 1) // 2 for members in postings.values())
    seen_pairs: set[tuple[str, str]] = set()
    for slug in sorted(postings):
        for a, b in combinations(postings[slug], 2):
            progress.pair_visits += 1
            if (a, b) not in seen_pairs:
                seen_pairs.add((a, b))
                progress.unique_pairs_examined += 1
                overlap = discriminating[a] & discriminating[b]
                if len(overlap) >= _MIN_SLUG_OVERLAP:
                    out.append(Hyperedge(edge_type="shared_slugs", key=",".join(sorted(overlap)), members=(a, b)))
            if progress.pair_visits >= MAX_PAIR_VISITS or len(out) >= _MAX_CANDIDATE_HYPEREDGES:
                progress.pair_search_complete = progress.pair_visits == progress.pair_visits_possible
                progress.candidate_limit_reached = (
                    len(out) >= _MAX_CANDIDATE_HYPEREDGES and not progress.pair_search_complete
                )
                return out
    return out


def build_ecosystem_hyperedges(
    infos: Mapping[str, TenantInfo],
) -> tuple[Hyperedge, ...]:
    """Build the ecosystem hypergraph for a batch of resolved domains.

    Returns an empty tuple when fewer than two domains are supplied or
    no rule fires. Output is deterministic — sorted by
    ``(edge_type, key, members)`` — and capped at ``MAX_HYPEREDGES``.
    Cap order favors non-ubiquitous ``shared_slugs``, then broad
    ``parent_vendor`` and ``top_issuer`` categories. No type establishes shared
    infrastructure or ownership, and no transitive relationship is inferred.
    """
    return build_ecosystem_report(infos).hyperedges


def build_ecosystem_report(infos: Mapping[str, TenantInfo], *, input_count: int | None = None) -> EcosystemReport:
    """Build the same edge projection with explicit completeness and work bounds.

    Indexed shared-slug candidates avoid comparing disjoint namespaces. Pair
    visits (including duplicate posting encounters) are capped independently
    of qualifying results; the candidate pool and final output retain their
    existing caps. Unvisited pairs have unknown qualifying edge counts.
    """

    # Enforce observability at the public builder boundary. The CLI batch path
    # already supplies these views, but keeping the invariant here prevents a
    # direct or future caller from correlating raw values retained for an
    # unavailable collection channel.
    from recon_tool.collection_view import collection_observable_info

    observable_infos = {domain: collection_observable_info(info) for domain, info in infos.items()}

    work = _EcosystemWork()
    by_type: list[list[Hyperedge]] = [
        _shared_slugs_hyperedges(observable_infos, work),
        _parent_vendor_hyperedges(observable_infos, work),
        _top_issuer_hyperedges(observable_infos, work),
    ]

    flat: list[Hyperedge] = []
    for edges in by_type:
        edges.sort(key=lambda e: (e.edge_type, e.key, e.members))
        flat.extend(edges)
    completeness: dict[str, object] = {
        **asdict(work),
        "input_namespaces": input_count if input_count is not None else len(infos),
        "resolved_namespaces": len(infos),
        "failed_namespaces": max(0, input_count - len(infos)) if input_count is not None else 0,
        "source_unavailable_namespaces": sum(bool(info.degraded_sources) for info in infos.values()),
        "pair_visit_limit": MAX_PAIR_VISITS,
        "candidate_limit_per_type": _MAX_CANDIDATE_HYPEREDGES,
        "edge_limit": MAX_HYPEREDGES,
        "member_limit_per_edge": MAX_MEMBERS_PER_HYPEREDGE,
        "known_omitted_edges_lower_bound": work.known_omitted_candidates + max(0, len(flat) - MAX_HYPEREDGES),
        "unvisited_qualifying_edges_unknown": not work.pair_search_complete,
    }
    return EcosystemReport(tuple(flat[:MAX_HYPEREDGES]), completeness)
