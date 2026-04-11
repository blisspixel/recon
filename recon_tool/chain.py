"""Chain resolver — recursive domain discovery via BFS.

Follows related domains discovered via CNAME breadcrumbs and certificate
transparency logs up to a configurable depth. Reuses the existing
resolve_tenant() pipeline for each domain.

The chain is BFS (breadth-first): all domains at depth N are resolved
before moving to depth N+1. This ensures the most closely related
domains are always resolved first, even if the domain or depth cap
is reached before exploring deeper levels.
"""

from __future__ import annotations

import logging
import time

from recon_tool.models import ChainReport, ChainResult, ReconLookupError
from recon_tool.resolver import RESOLVE_TIMEOUT, SourcePool, resolve_tenant

logger = logging.getLogger("recon")

__all__ = [
    "chain_resolve",
]

# Hard limits to prevent runaway lookups
MAX_CHAIN_DEPTH = 3
MAX_CHAIN_DOMAINS = 50


async def chain_resolve(
    domain: str,
    depth: int = 1,
    pool: SourcePool | None = None,
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
    current_level: list[str] = [domain.lower()]

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

            try:
                info, _ = await resolve_tenant(
                    d,
                    pool=pool,
                    timeout=RESOLVE_TIMEOUT,
                )
                results.append(
                    ChainResult(
                        domain=d,
                        info=info,
                        chain_depth=current_depth,
                    )
                )
                max_depth_reached = max(max_depth_reached, current_depth)

                # Collect related domains for next level
                for related in info.related_domains:
                    r_lower = related.lower()
                    if r_lower not in visited:
                        next_level.append(r_lower)

            except ReconLookupError as exc:
                logger.debug(
                    "Chain: skipping %s at depth %d: %s",
                    d,
                    current_depth,
                    exc,
                )
                continue
            except Exception as exc:
                logger.debug(
                    "Chain: unexpected error for %s at depth %d: %s",
                    d,
                    current_depth,
                    exc,
                )
                continue

        if truncated:
            break

        # Deduplicate next level, preserving discovery order
        current_level = list(dict.fromkeys(
            d for d in next_level if d not in visited
        ))

    return ChainReport(
        results=tuple(results),
        max_depth_reached=max_depth_reached,
        truncated=truncated,
    )
