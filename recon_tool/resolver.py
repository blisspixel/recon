"""Resolver orchestration — queries all sources in parallel, merges results.

When related domains are discovered (via CNAME breadcrumbs like autodiscover
redirects or DKIM delegation), the resolver automatically runs DNS-only lookups
on them and merges the additional services/slugs into the primary result.
This means `recon northwindtraders.com` automatically picks up services configured
on `northwind-internal.com` without the user needing to know about the internal domain.

NOTE: Related domain enrichment is intentionally non-recursive. If a related
domain's DNS records point to yet another domain, those second-level related
domains are not followed. This prevents unbounded lookup chains and keeps
resolution time predictable.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from typing import Any

import httpx

from recon_tool.merger import merge_results
from recon_tool.models import ReconLookupError, SourceResult, TenantInfo
from recon_tool.sources.base import LookupSource

__all__ = [
    "RESOLVE_TIMEOUT",
    "SourcePool",
    "default_pool",
    "resolve_tenant",
]

logger = logging.getLogger("recon")

# Maximum wall-clock time for the entire resolve_tenant pipeline, including
# all source queries and related domain enrichment. Prevents runaway lookups
# from blocking the CLI or MCP server indefinitely.
# Default aggregate wall-clock timeout for a full resolve (all sources +
# related-domain enrichment). Raised from 60s to 120s in v0.9.2 after
# observing that CT-heavy domains with degraded crt.sh fell back to
# CertSpotter pagination, then ran related-domain enrichment, and
# consistently blew past 60s — producing catastrophic 25–93% batch
# failure rates. 120s gives a realistic ceiling while still catching
# runaway lookups. Override per call via resolve_tenant(timeout=...)
# or CLI --timeout.
RESOLVE_TIMEOUT = 120.0


class SourcePool:
    """Ordered collection of LookupSources. Supports registration and iteration."""

    def __init__(self, sources: list[LookupSource] | None = None) -> None:
        """Initialize with optional list of sources in priority order."""
        self._sources: list[LookupSource] = list(sources) if sources else []

    def register(self, source: LookupSource) -> None:
        """Add a source to the end of the pool."""
        self._sources.append(source)

    def __iter__(self):
        """Iterate over sources in priority order."""
        return iter(self._sources)

    def __len__(self) -> int:
        """Return number of sources."""
        return len(self._sources)


def default_pool() -> SourcePool:
    """Return a SourcePool with the standard sources."""
    from recon_tool.sources.dns import DNSSource
    from recon_tool.sources.google import GoogleSource
    from recon_tool.sources.google_identity import GoogleIdentitySource
    from recon_tool.sources.oidc import OIDCSource
    from recon_tool.sources.userrealm import UserRealmSource

    return SourcePool(
        [
            OIDCSource(),
            UserRealmSource(),
            GoogleSource(),
            GoogleIdentitySource(),
            DNSSource(),
        ]
    )


async def _safe_lookup(
    source: LookupSource,
    domain: str,
    **kwargs: Any,
) -> SourceResult:
    """Run a single source lookup, capturing any unexpected exceptions."""
    try:
        return await source.lookup(domain, **kwargs)
    except Exception as exc:
        return SourceResult(
            source_name=source.name,
            error=f"Unexpected error: {exc}",
        )


async def _enrich_from_related(
    info: TenantInfo,
    all_results: list[SourceResult],
) -> tuple[TenantInfo, list[SourceResult]]:
    """If related domains were found, run lookups on them and merge.

    Two-tier enrichment:
    - Subdomains of the queried domain (from crt.sh): lightweight CNAME+TXT only.
      These are high-volume (dozens of subdomains) and most DNS record types
      (MX, NS, DKIM, SRV, M365 CNAMEs) are meaningless for subdomains.
    - Separate domains (from autodiscover/DKIM breadcrumbs): full DNS lookup.
      These are rare (1-2 typically) and may have their own TXT/MX/NS records.

    Caps at MAX_RELATED_ENRICHMENTS total to prevent runaway lookups.
    """
    from recon_tool.sources.dns import DNSSource, lightweight_subdomain_lookup

    MAX_RELATED_ENRICHMENTS = 25

    # Filter to actionable related domains (skip onmicrosoft — they're just
    # the tenant's internal M365 domain with no SaaS verification records)
    all_candidates = [d for d in info.related_domains if not d.endswith(".onmicrosoft.com")]

    if not all_candidates:
        return info, all_results

    # Split into subdomains vs separate domains
    base_domain = info.queried_domain.lower() if info.queried_domain else ""
    all_subdomains = [d for d in all_candidates if base_domain and d.endswith(f".{base_domain}")]
    separate_domains = [d for d in all_candidates if d not in all_subdomains]

    # Prioritize subdomains by signal value before capping.
    # High-signal prefixes (auth, login, shop, api, em) sort first so they
    # survive the enrichment cap. Low-signal or deep subdomains sort last.
    _HIGH_SIGNAL_PREFIXES = (
        "auth",
        "login",
        "sso",
        "secure",
        "id",
        "identity",
        "shop",
        "store",
        "checkout",
        "pay",
        "api",
        "app",
        "portal",
        "dashboard",
        "admin",
        "support",
        "help",
        "status",
        "click",
        "image",
        "view",
        "email",
        "em",
        "cdn",
        "assets",
        "static",
        "media",
        "blog",
        "docs",
        "stage",
        "staging",
        "dev",
    )

    def _enrich_priority(name: str) -> tuple[int, int, str]:
        prefix = name.split(f".{base_domain}")[0] if base_domain else name
        is_high = (
            0
            if any(
                prefix == p or prefix.startswith(p + ".") or prefix.startswith(p + "-") for p in _HIGH_SIGNAL_PREFIXES
            )
            else 1
        )
        depth = prefix.count(".")
        return (is_high, depth, name)

    prioritized_subs = sorted(all_subdomains, key=_enrich_priority)

    # Cap total enrichment lookups, but separate domains always get a slot
    sep_cap = min(len(separate_domains), MAX_RELATED_ENRICHMENTS)
    sub_cap = MAX_RELATED_ENRICHMENTS - sep_cap
    capped_subs = prioritized_subs[: max(sub_cap, 0)]
    capped_separate = separate_domains[:sep_cap]

    logger.debug(
        "Enriching from %d related (%d/%d subdomains, %d separate): %s",
        len(capped_subs) + len(capped_separate),
        len(capped_subs),
        len(all_subdomains),
        len(capped_separate),
        ", ".join((capped_subs + capped_separate)[:5]) + ("..." if len(capped_subs) + len(capped_separate) > 5 else ""),
    )

    # Run both tiers concurrently
    dns_source = DNSSource()
    all_tasks = [
        *(lightweight_subdomain_lookup(d) for d in capped_subs),
        *(_safe_lookup(dns_source, d) for d in capped_separate),
    ]
    related_results = await asyncio.gather(*all_tasks)

    # Collect additional services and slugs from related domains
    extra_services: set[str] = set(info.services)
    extra_slugs: set[str] = set(info.slugs)
    found_new = False

    for result in related_results:
        new_services = set(result.detected_services) - extra_services
        new_slugs = set(result.detected_slugs) - extra_slugs
        if new_services or new_slugs:
            found_new = True
            extra_services.update(result.detected_services)
            extra_slugs.update(result.detected_slugs)

    if not found_new:
        return info, all_results

    # Re-run insight generation with the enriched data to get updated signals
    from recon_tool.merger import build_insights_with_signals

    enriched_insights = build_insights_with_signals(
        extra_services,
        extra_slugs,
        info.auth_type,
        info.dmarc_policy,
        info.domain_count,
        google_auth_type=info.google_auth_type,
        google_idp_name=info.google_idp_name,
        primary_email_provider=info.primary_email_provider,
        likely_primary_email_provider=info.likely_primary_email_provider,
        cloud_instance=info.cloud_instance,
        tenant_region_sub_scope=info.tenant_region_sub_scope,
        msgraph_host=info.msgraph_host,
    )

    # Build enriched TenantInfo — keep identity fields, update services/slugs/insights
    enriched = replace(
        info,
        services=tuple(sorted(extra_services)),
        slugs=tuple(sorted(extra_slugs)),
        insights=tuple(enriched_insights),
    )

    return enriched, all_results + list(related_results)


async def _resolve_tenant_inner(
    domain: str,
    pool: SourcePool,
    client: httpx.AsyncClient | None = None,
) -> tuple[TenantInfo, list[SourceResult]]:
    """Inner resolution logic — no timeout wrapper."""
    sources = list(pool)

    if len(sources) == 0:
        raise ReconLookupError(
            domain=domain,
            message="No lookup sources configured",
            error_type="not_found",
        )

    kwargs: dict[str, httpx.AsyncClient] = {}
    if client is not None:
        kwargs["client"] = client

    # Run all sources concurrently
    results = await asyncio.gather(*(_safe_lookup(source, domain, **kwargs) for source in sources))

    info = merge_results(list(results), domain)

    # Auto-enrich from related domains (e.g. northwind-internal.com discovered via
    # autodiscover CNAME when looking up northwindtraders.com)
    info, all_results = await _enrich_from_related(info, list(results))

    return info, all_results


async def resolve_tenant(
    domain: str,
    pool: SourcePool | None = None,
    client: httpx.AsyncClient | None = None,
    timeout: float = RESOLVE_TIMEOUT,
) -> tuple[TenantInfo, list[SourceResult]]:
    """Orchestrates tenant lookup across the SourcePool.

    All sources are queried concurrently using asyncio.gather.
    Individual source failures do NOT abort — every source gets a chance.
    After all sources complete, results are merged via merge_results.

    If related domains are discovered (from CNAME breadcrumbs), the resolver
    automatically runs DNS-only lookups on them and merges the additional
    services into the result.

    The entire pipeline is wrapped in an aggregate timeout (default 60s)
    to prevent runaway lookups from blocking indefinitely.

    Args:
        domain: A validated domain string.
        pool: Optional SourcePool (defaults to standard pool with all sources).
        client: Optional httpx client (for testing/injection).
        timeout: Max wall-clock seconds for the entire resolution pipeline.

    Returns:
        Tuple of (TenantInfo, list[SourceResult]) so the CLI can show verbose info.

    Raises:
        ReconLookupError: If all sources fail, no sources are configured, or timeout.
    """
    if pool is None:
        pool = default_pool()

    try:
        return await asyncio.wait_for(
            _resolve_tenant_inner(domain, pool, client),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        raise ReconLookupError(
            domain=domain,
            message=f"Resolution timed out after {timeout:.0f}s for {domain}",
            error_type="timeout",
        ) from None
