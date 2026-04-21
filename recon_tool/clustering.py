"""Shared verification token clustering (v0.9.3).

Batch-scope correlation: when the same ``google-site-verification``,
``MS=``, or similar TXT verification token appears on multiple domains
in a single batch run, those domains are *possibly related* (shared
operator, subsidiary, acquisition, or cross-company infrastructure).
The clustering is hedged — the output never commits to a verdict,
only surfaces the observation.

This module is a pure function layer. It takes a list of
``TenantInfo`` (or a list of ``(domain, tokens)`` pairs) and returns a
mapping from each domain to its observed peers. No I/O, no network,
no persistence. The lifetime of the resulting map is the lifetime of
the caller — batch runs throw it away when they finish; the MCP tool
re-computes on demand from cached ``TenantInfo``.

Design rationale
    Site-verification tokens are issued per-account by the SaaS
    provider (Google, Microsoft, Atlassian, Zoom, etc.). A reused
    token across two apex domains means the same account provisioned
    the verification, which in turn implies a shared operator — but
    does NOT prove corporate identity. Common false-positive cases:
    a managed-services provider handling DNS for multiple customers,
    a historical migration where the same admin owned both before the
    split, a subsidiary that kept the parent's account. The observation
    is genuinely two-sided and stays hedged.

    This is intentionally weaker than brand-matching or legal-name
    correlation. It's the passive observation floor: *these domains
    are linked by at least one operator-scoped credential*.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass

__all__ = [
    "ClusterEntry",
    "DisplayNameCluster",
    "TenantCluster",
    "cluster_tokens",
    "compute_display_name_clusters",
    "compute_shared_tokens",
    "compute_tenant_clusters",
]


@dataclass(frozen=True)
class TenantCluster:
    """Domains that share the same Microsoft 365 tenant ID.

    This is a cryptographically strong signal — two domains under the
    same tenant ID are provably registered to the same M365 customer
    account. Unlike token-sharing or display-name matching, this is
    not hedged.
    """

    tenant_id: str
    domains: tuple[str, ...]  # sorted, 2+ entries


@dataclass(frozen=True)
class DisplayNameCluster:
    """Domains whose tenant display names normalize to the same key.

    Weaker than tenant-ID clustering because display names are
    customer-supplied and can be spoofed or coincidentally match.
    ``normalized_name`` is the comparison key; ``raw_names`` preserves
    each domain's verbatim display name for audit.
    """

    normalized_name: str
    domains: tuple[str, ...]  # sorted, 2+ entries
    raw_names: tuple[str, ...]  # one per domain, same order as ``domains``


# Corporate-entity suffixes stripped during display-name normalization.
# Kept deliberately short — we're removing unambiguous legal-form
# markers, not every possible suffix. Over-stripping risks collapsing
# unrelated orgs (e.g. "Acme Group" vs "Beta Group" would both become
# "acme"/"beta" and the "Group" signal is actually useful for context).
_CORPORATE_SUFFIXES: tuple[str, ...] = (
    "inc",
    "inc.",
    "incorporated",
    "corp",
    "corp.",
    "corporation",
    "llc",
    "ltd",
    "ltd.",
    "limited",
    "co",
    "co.",
    "company",
    "plc",
    "gmbh",
    "sa",
    "s.a.",
    "ag",
    "ab",
    "bv",
    "b.v.",
    "srl",
    "sas",
    "pty",
    "pte",
)

# Collapse runs of whitespace + punctuation during normalization.
_WS_RE = re.compile(r"[\s,\-_/]+")


@dataclass(frozen=True)
class ClusterEntry:
    """A shared-token peer relationship between two domains.

    ``token`` is the verification token that both domains carry.
    ``peer`` is the other domain (relative to the subject domain when
    this entry appears in a subject's peer list).
    """

    token: str
    peer: str


def _normalize(token: str) -> str:
    """Normalize a verification token for comparison.

    Strips whitespace, lowercases the prefix label (``google-site-
    verification=`` etc.) but preserves the token value. Empty tokens
    are returned as the empty string.
    """
    t = token.strip()
    if not t:
        return ""
    # If the token has a "key=value" shape, lowercase the key but
    # preserve the value (which is typically base64/hex and
    # case-significant).
    if "=" in t:
        k, _, v = t.partition("=")
        return f"{k.lower().strip()}={v.strip()}"
    return t


def cluster_tokens(
    domain_tokens: dict[str, tuple[str, ...]],
) -> dict[str, set[str]]:
    """Build a token → set-of-domains map from a domain → tokens map.

    Args:
        domain_tokens: Mapping from domain name to that domain's
            observed verification tokens.

    Returns:
        Mapping from each normalized token to the set of domain names
        that carry it. Tokens that appear on only one domain are
        included in the output but with a singleton set — callers
        filter for len >= 2 when surfacing peer relationships.
    """
    token_map: dict[str, set[str]] = defaultdict(set)
    for domain, tokens in domain_tokens.items():
        seen_in_this_domain: set[str] = set()
        for raw in tokens:
            norm = _normalize(raw)
            if not norm:
                continue
            if norm in seen_in_this_domain:
                continue
            seen_in_this_domain.add(norm)
            token_map[norm].add(domain)
    return dict(token_map)


def compute_shared_tokens(
    domain_tokens: dict[str, tuple[str, ...]],
) -> dict[str, tuple[ClusterEntry, ...]]:
    """Compute peer relationships for each domain.

    Args:
        domain_tokens: Mapping from domain to verification tokens.

    Returns:
        Mapping from each domain to a tuple of ClusterEntry values
        listing the tokens that link it to at least one other domain
        in the input, and the peer that shares each token. Domains
        with no shared tokens are omitted from the output entirely —
        callers can iterate freely without filtering.

    Invariants:
        * Symmetric — if A shares token X with B, both A's and B's
          entries include each other as peers.
        * No self-peers — a domain never appears as its own peer.
        * Multi-peer — if A, B, C all share token X, A's entry lists
          both B and C as peers (one ClusterEntry per peer).
        * Deterministic — peer lists are sorted by ``(token, peer)``
          so output is stable across runs with the same input.
    """
    token_map = cluster_tokens(domain_tokens)

    per_domain: dict[str, list[ClusterEntry]] = defaultdict(list)
    for token, domains in token_map.items():
        if len(domains) < 2:
            continue
        # For each domain in the cluster, every other domain is a peer
        # via this token.
        for d in domains:
            for peer in domains:
                if peer == d:
                    continue
                per_domain[d].append(ClusterEntry(token=token, peer=peer))

    # Sort each entry list for deterministic output and freeze to tuples
    return {d: tuple(sorted(entries, key=lambda e: (e.token, e.peer))) for d, entries in per_domain.items()}


def _normalize_display_name(name: str) -> str:
    """Normalize a tenant display name for equality comparison.

    Steps (conservative — prefer false negatives over false positives):
    1. Lowercase, strip.
    2. Collapse runs of whitespace / commas / hyphens / underscores
       to a single space.
    3. Drop trailing corporate-form suffixes (``inc``, ``llc``, ``gmbh``,
       etc.) — one pass only so ``Acme Holdings Inc.`` becomes
       ``acme holdings``, not ``acme``.
    4. Strip leading / trailing whitespace one more time.

    Returns the empty string if normalization leaves nothing
    (conservative: callers should treat empty as "not clusterable").
    """
    if not name:
        return ""
    n = _WS_RE.sub(" ", name.strip().lower()).strip()
    if not n:
        return ""
    # Drop a single trailing corporate suffix if present.
    parts = n.rsplit(" ", 1)
    if len(parts) == 2 and parts[1] in _CORPORATE_SUFFIXES:
        n = parts[0].strip()
    return n


def compute_tenant_clusters(
    domain_tenants: Mapping[str, str | None],
) -> tuple[TenantCluster, ...]:
    """Cluster domains by shared Microsoft 365 tenant ID.

    Args:
        domain_tenants: Mapping from domain to its tenant ID (or None
            if no tenant was resolved).

    Returns:
        Tuple of TenantCluster entries for every tenant that contains
        2+ domains in the input. Sorted by tenant_id for determinism.
        Domains without a tenant ID are skipped; tenants with only
        one domain in the batch are omitted.
    """
    buckets: dict[str, list[str]] = defaultdict(list)
    for domain, tenant_id in domain_tenants.items():
        if not tenant_id:
            continue
        buckets[tenant_id].append(domain)

    clusters: list[TenantCluster] = []
    for tenant_id, members in buckets.items():
        if len(members) < 2:
            continue
        clusters.append(TenantCluster(tenant_id=tenant_id, domains=tuple(sorted(set(members)))))
    return tuple(sorted(clusters, key=lambda c: c.tenant_id))


def compute_display_name_clusters(
    domain_names: Mapping[str, str | None],
) -> tuple[DisplayNameCluster, ...]:
    """Cluster domains by normalized tenant display name.

    Args:
        domain_names: Mapping from domain to its tenant display name
            (or None if no display name was resolved).

    Returns:
        Tuple of DisplayNameCluster entries for every normalized name
        that contains 2+ domains. Sorted by normalized_name. Domains
        without a display name are skipped; names that only appear
        on one domain are omitted.

    The clustering is intentionally exact on the normalized key: we
    collapse whitespace and strip one trailing corporate-form
    suffix, but we do NOT do fuzzy matching or substring containment.
    Conservatism is deliberate — display names are customer-supplied
    and substring matches easily conflate unrelated orgs (``Acme``
    matches ``Acme Holdings`` matches ``Acme Properties``).
    """
    buckets: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for domain, display_name in domain_names.items():
        if not display_name:
            continue
        normalized = _normalize_display_name(display_name)
        if not normalized:
            continue
        buckets[normalized].append((domain, display_name))

    clusters: list[DisplayNameCluster] = []
    for normalized, members in buckets.items():
        if len(members) < 2:
            continue
        members_sorted = sorted(set(members))
        domains = tuple(d for d, _ in members_sorted)
        raw_names = tuple(n for _, n in members_sorted)
        clusters.append(
            DisplayNameCluster(
                normalized_name=normalized,
                domains=domains,
                raw_names=raw_names,
            )
        )
    return tuple(sorted(clusters, key=lambda c: c.normalized_name))
