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

from collections import defaultdict
from dataclasses import dataclass

__all__ = [
    "ClusterEntry",
    "cluster_tokens",
    "compute_shared_tokens",
]


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
    return {
        d: tuple(sorted(entries, key=lambda e: (e.token, e.peer)))
        for d, entries in per_domain.items()
    }
