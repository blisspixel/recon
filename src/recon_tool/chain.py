"""Chain resolver: recursive related-namespace discovery via BFS.

Follows every ``related_domains`` observation returned by the ordinary resolver
up to a configurable depth. These currently include CT, CNAME,
Exchange/identity endpoint, autodiscover, and DKIM tenant-domain breadcrumbs.
Reuses the existing ``resolve_tenant()`` pipeline for each domain.

The chain is BFS (breadth-first): all domains at depth N are resolved
before moving to depth N+1. This ensures the most closely related
domains are always resolved first, even if the domain or depth cap
is reached before exploring deeper levels.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, replace

from recon_tool.models import ChainReport, ChainResult, ReconLookupError
from recon_tool.resolver import RESOLVE_TIMEOUT, SourcePool, resolve_tenant

logger = logging.getLogger("recon")

__all__ = [
    "chain_resolve",
]

# Hard limits to prevent runaway lookups
MAX_CHAIN_DEPTH = 3
MAX_CHAIN_DOMAINS = 50

# Cap the next-level discovery queue so a pathological per-domain fan-out
# cannot grow it without bound before the dedup + MAX_CHAIN_DOMAINS gate.
# Generous relative to the resolution cap; only guards memory.
_MAX_NEXT_LEVEL_QUEUE = MAX_CHAIN_DOMAINS * 20


@dataclass(frozen=True, slots=True)
class _ChainLookup:
    pool: SourcePool | None
    skip_ct: bool
    active_probes: bool


async def _resolve_one_chain_domain(
    domain: str,
    depth: int,
    lookup: _ChainLookup,
    *,
    seed: str,
    have_results: bool,
) -> ChainResult | None:
    """Resolve one queued name. Seed failure is raised; later names are skipped."""
    try:
        info, _ = await resolve_tenant(
            domain,
            pool=lookup.pool,
            timeout=RESOLVE_TIMEOUT,
            skip_ct=lookup.skip_ct,
            active_probes=lookup.active_probes,
        )
    except ReconLookupError as exc:
        if domain == seed and not have_results:
            raise
        logger.debug("Chain: skipping %s at depth %d: %s", domain, depth, exc)
        return None
    except Exception as exc:
        if domain == seed and not have_results:
            raise
        logger.debug("Chain: unexpected error for %s at depth %d: %s", domain, depth, exc)
        return None
    return ChainResult(domain=domain, info=info, chain_depth=depth)


async def chain_resolve(
    domain: str,
    depth: int = 1,
    pool: SourcePool | None = None,
    skip_ct: bool = False,
    active_probes: bool = False,
) -> ChainReport:
    """BFS resolution of related domains up to *depth* levels.

    At each level:
    1. Resolve all unvisited domains via resolve_tenant()
    2. Collect related_domains from each result
    3. Filter out visited domains, add new ones to next-level queue
    4. Stop when depth cap, domain cap (50), or aggregate timeout is reached

    Args:
        domain: Starting domain to resolve.
        depth: Maximum recursion depth (1-3, default 1).
        pool: Optional SourcePool (defaults to standard pool).
        skip_ct: When True, skip cert-transparency providers for every
            domain visited in the chain. Forwarded into each
            ``resolve_tenant`` call so ``--no-ct`` is honored across
            the BFS, not just the seed domain.
        active_probes: When True, forward the opt-in direct-probe choice
            (Google CSE, BIMI VMC) into each ``resolve_tenant`` call so
            ``--direct-probes`` is honored across the whole chain.

    Returns:
        ChainReport with all resolved domains and metadata.
    """
    # Clamp depth to valid range
    depth = max(1, min(depth, MAX_CHAIN_DEPTH))

    # Aggregate timeout: depth × 120 seconds
    aggregate_timeout = depth * 120.0
    start_time = time.monotonic()

    visited: set[str] = set()
    results: list[ChainResult] = []
    truncated = False
    max_depth_reached = 0

    # BFS queue: current level of domains to resolve
    seed = domain.lower()
    current_level: list[str] = [seed]

    for current_depth in range(depth + 1):
        if not current_level:
            break

        # Check aggregate timeout before starting a new level
        if time.monotonic() - start_time > aggregate_timeout:
            logger.debug(
                "Chain: aggregate timeout (%.0fs) reached after %d domains",
                aggregate_timeout,
                len(results),
            )
            truncated = True
            break

        next_level: list[str] = []

        for d in current_level:
            if d in visited:
                continue
            if len(visited) >= MAX_CHAIN_DOMAINS:
                truncated = True
                break

            # Check aggregate timeout before each domain resolution
            if time.monotonic() - start_time > aggregate_timeout:
                logger.debug(
                    "Chain: aggregate timeout (%.0fs) reached after %d domains",
                    aggregate_timeout,
                    len(results),
                )
                truncated = True
                break

            visited.add(d)

            resolved = await _resolve_one_chain_domain(
                d,
                current_depth,
                _ChainLookup(pool, skip_ct, active_probes),
                seed=seed,
                have_results=bool(results),
            )
            if resolved is None:
                continue
            results.append(resolved)
            max_depth_reached = max(max_depth_reached, current_depth)

            # Collect related domains for next level (queue bounded).
            for related in resolved.info.related_domains:
                if len(next_level) >= _MAX_NEXT_LEVEL_QUEUE:
                    break
                r_lower = related.lower()
                if r_lower not in visited:
                    next_level.append(r_lower)

        if truncated:
            break

        # Deduplicate next level, preserving discovery order
        current_level = list(dict.fromkeys(d for d in next_level if d not in visited))

    # Correlate site-verification tokens across resolved domains
    results = _correlate_site_verification(results)

    return ChainReport(
        results=tuple(results),
        max_depth_reached=max_depth_reached,
        truncated=truncated,
    )


def _correlate_site_verification(
    results: list[ChainResult],
) -> list[ChainResult]:
    """Identify domains sharing google-site-verification tokens.

    When two or more domains share the same token, an insight is added
    to each domain's TenantInfo noting the relationship.
    """
    # Build token → list of domains mapping. A retained raw token from a failed
    # apex-TXT query is diagnostic provenance, not an observed correlation.
    from recon_tool.collection_view import collection_observable_info

    token_to_domains: dict[str, list[str]] = defaultdict(list)
    for r in results:
        observable = collection_observable_info(r.info)
        for token in observable.site_verification_tokens:
            token_to_domains[token].append(r.domain)

    # Find tokens shared by 2+ domains
    shared: dict[str, list[str]] = {token: domains for token, domains in token_to_domains.items() if len(domains) >= 2}

    if not shared:
        return results

    # Build per-domain insight strings
    domain_insights: dict[str, set[str]] = defaultdict(set)
    for _token, domains in shared.items():
        for domain in domains:
            siblings = sorted(d for d in domains if d != domain)
            if siblings:
                domain_insights[domain].add(f"Shares google-site-verification token with {', '.join(siblings)}")

    # Create updated ChainResults with correlation insights
    updated: list[ChainResult] = []
    for r in results:
        new_insights = domain_insights.get(r.domain)
        if new_insights:
            # merger.py deliberately inserts conflict warnings at index 0, so
            # a whole-list sort here demoted them; keep the existing order and
            # append only novel correlation lines, sorted among themselves.
            additions = sorted(new_insights.difference(r.info.insights))
            merged = (*r.info.insights, *additions)
            updated_info = replace(r.info, insights=merged)
            updated.append(
                ChainResult(
                    domain=r.domain,
                    info=updated_info,
                    chain_depth=r.chain_depth,
                )
            )
        else:
            updated.append(r)

    return updated
