"""MCP server for recon — domain intelligence.

Exposes lookup tool, reload tool, and prompt template over stdio transport.
Read-only (lookup) and idempotent, queries public endpoints and DNS.

Includes a bounded TTL cache for resolved results (default 120s, max 1000 entries)
to avoid hammering upstream endpoints when an AI agent calls lookup_tenant
repeatedly, and a bounded per-domain rate limiter to prevent abuse.
"""

from __future__ import annotations

import json as json_mod
import logging
import time
import uuid

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from recon_tool.formatter import detect_provider, format_tenant_json, format_tenant_markdown
from recon_tool.models import ReconLookupError, SourceResult, TenantInfo
from recon_tool.resolver import resolve_tenant
from recon_tool.validator import validate_domain

logger = logging.getLogger("recon")

# Configure the recon logger with a default handler so structured logs
# are actually visible. Without this, log messages are silently dropped
# unless the consumer configures the logger externally.
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

_VALID_FORMATS = frozenset({"text", "json", "markdown"})

mcp = FastMCP("recon-tool")


# ── Bounded TTL cache for resolved results ──────────────────────────────
# Prevents hammering upstream endpoints when an AI agent calls lookup_tenant
# repeatedly for the same domain. Cache entries expire after CACHE_TTL seconds.
# Max size prevents unbounded memory growth from unique domain lookups.
#
# Module-level mutable dicts are used intentionally here. The MCP server runs
# as a single-process stdio transport, so there are no concurrency issues.
# If this ever moves to a multi-worker model, these should be replaced with
# a shared cache (e.g., Redis) or wrapped in a class with proper locking.

CACHE_TTL = 120.0  # seconds
CACHE_MAX_SIZE = 1000

_cache: dict[str, tuple[float, TenantInfo, tuple[SourceResult, ...]]] = {}


def _cache_evict_expired() -> None:
    """Remove all expired entries from the cache."""
    now = time.monotonic()
    expired = [k for k, (ts, _, _) in _cache.items() if now - ts > CACHE_TTL]
    for k in expired:
        del _cache[k]


def _cache_get(domain: str) -> tuple[TenantInfo, tuple[SourceResult, ...]] | None:
    """Return cached result if present and not expired."""
    entry = _cache.get(domain)
    if entry is None:
        return None
    ts, info, results = entry
    if time.monotonic() - ts > CACHE_TTL:
        del _cache[domain]
        return None
    return info, results


def _cache_set(domain: str, info: TenantInfo, results: list[SourceResult]) -> None:
    """Store a result in the cache with current timestamp.

    Converts the results list to a tuple for immutability.
    Evicts expired entries first. If still at capacity, evicts the oldest entry.
    """
    # Periodic eviction of expired entries
    if len(_cache) >= CACHE_MAX_SIZE:
        _cache_evict_expired()
    # If still at capacity after eviction, drop the oldest entry
    if len(_cache) >= CACHE_MAX_SIZE:
        oldest_key = min(_cache, key=lambda k: _cache[k][0])
        del _cache[oldest_key]
    _cache[domain] = (time.monotonic(), info, tuple(results))


def _cache_clear() -> None:
    """Clear the entire cache — used by reload_data and tests."""
    _cache.clear()


# ── Bounded per-domain rate limiter ─────────────────────────────────────
# Prevents abuse by limiting how often the same domain can be looked up
# (cache misses only). Uses a simple timestamp-based approach with periodic
# eviction to prevent unbounded memory growth.

RATE_LIMIT_WINDOW = 5.0  # seconds between lookups for the same domain
_RATE_LIMIT_MAX_SIZE = 5000

_rate_limit: dict[str, float] = {}


def _rate_limit_evict_expired() -> None:
    """Remove all expired entries from the rate limiter."""
    now = time.monotonic()
    expired = [k for k, ts in _rate_limit.items() if now - ts >= RATE_LIMIT_WINDOW]
    for k in expired:
        del _rate_limit[k]


def _rate_limit_check(domain: str) -> bool:
    """Return True if the domain lookup should be allowed.

    Does NOT record the timestamp — call _rate_limit_record() after a
    successful lookup so transient failures don't block retries.
    """
    now = time.monotonic()
    last = _rate_limit.get(domain, 0.0)
    return now - last >= RATE_LIMIT_WINDOW


def _rate_limit_record(domain: str) -> None:
    """Record that a lookup was performed for rate limiting purposes.

    Called after a successful lookup (or cache-miss attempt) so that
    transient errors don't prevent immediate retries.
    """
    # Periodic eviction to prevent unbounded growth
    if len(_rate_limit) >= _RATE_LIMIT_MAX_SIZE:
        _rate_limit_evict_expired()
    _rate_limit[domain] = time.monotonic()


def _rate_limit_clear() -> None:  # pyright: ignore[reportUnusedFunction]
    """Clear the rate limiter — for testing."""
    _rate_limit.clear()


def _log_structured(level: int, msg: str, **fields: object) -> None:
    """Emit a structured log entry as JSON for machine-parseable logging.

    Falls back to standard logging format when JSON serialization fails.
    """
    entry = {"msg": msg, **fields}
    try:
        logger.log(level, json_mod.dumps(entry))
    except (TypeError, ValueError):
        logger.log(level, msg, extra=fields)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def lookup_tenant(
    domain: str,
    format: str = "text",  # noqa: A002 — shadows builtin, but is the public MCP parameter name
) -> str:
    """Look up domain intelligence — company name, email provider, tenant ID,
    tech stack, email security score, and signal intelligence.

    Works for any domain — Microsoft 365, Google Workspace, or any provider.
    Returns detected SaaS services (185+ fingerprints), email security posture,
    infrastructure, and derived signals (AI adoption, GTM maturity, security
    stack, collaboration tools, etc.).

    Queries only public, unauthenticated endpoints and DNS records.
    No credentials or API keys required.

    Args:
        domain: A domain name to look up (e.g., pepsi.com, microsoft.com).
        format: Output format — "text" (default), "json" (structured), or "markdown" (full report).

    Returns:
        Domain intelligence in the requested format, or an error message.
    """
    output_format = format
    if output_format not in _VALID_FORMATS:
        return f"Error: invalid format {output_format!r}. Must be one of: {', '.join(sorted(_VALID_FORMATS))}"

    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        _log_structured(
            logging.WARNING,
            "validation_failed",
            request_id=request_id,
            domain=domain,
            error=str(exc),
        )
        return f"Error: {exc}"

    # Check cache first — avoids hitting upstream endpoints for repeated lookups
    cached = _cache_get(validated)
    if cached is not None:
        info, results = cached
        _log_structured(
            logging.INFO,
            "cache_hit",
            request_id=request_id,
            domain=validated,
        )
    else:
        # Rate limit check — only for cache misses (actual network calls)
        if not _rate_limit_check(validated):
            return f"Rate limited: {domain} was looked up recently. Try again in a few seconds."

        try:
            info, results = await resolve_tenant(validated)
        except ReconLookupError as exc:
            elapsed = time.monotonic() - start_time
            _log_structured(
                logging.INFO,
                "no_data",
                request_id=request_id,
                domain=domain,
                elapsed_s=round(elapsed, 2),
                error=exc.message,
            )
            return f"No information found for {domain}"
        except Exception:
            elapsed = time.monotonic() - start_time
            logger.exception(
                "Unexpected error looking up %s (request_id=%s)",
                domain,
                request_id,
            )
            return f"Error looking up {domain}: an internal error occurred"

        # Cache the successful result and record rate limit
        _cache_set(validated, info, results)
        _rate_limit_record(validated)

    elapsed = time.monotonic() - start_time
    _log_structured(
        logging.INFO,
        "resolved",
        request_id=request_id,
        domain=domain,
        display_name=info.display_name,
        services=len(info.services),
        elapsed_s=round(elapsed, 2),
    )

    # JSON format
    if output_format == "json":
        return format_tenant_json(info)

    # Markdown format
    if output_format == "markdown":
        return format_tenant_markdown(info)

    # Default text format
    provider = detect_provider(info.services, info.slugs)
    lines = [
        f"Company: {info.display_name}",
        f"Domain: {info.default_domain}",
        f"Provider: {provider}",
    ]
    if info.tenant_id:
        lines.append(f"Tenant ID: {info.tenant_id}")
    if info.region:
        lines.append(f"Region: {info.region}")
    if info.auth_type:
        lines.append(f"Auth: {info.auth_type}")
    lines.append(f"Confidence: {info.confidence.value} ({len(info.sources)} sources)")
    if info.services:
        lines.append(f"Services: {', '.join(info.services)}")
    if info.insights:
        lines.append(f"Insights: {' | '.join(info.insights)}")
    if info.domain_count > 0:
        lines.append(f"Domains in tenant: {info.domain_count}")
    if info.related_domains:
        lines.append(f"Related domains: {', '.join(info.related_domains)}")

    # Google Workspace details
    gws_slugs = set(info.slugs)
    is_gws = any(s.lower().startswith("google workspace") for s in info.services) or "google-workspace" in gws_slugs
    if is_gws:
        if info.google_auth_type:
            auth_label = info.google_auth_type
            if info.google_idp_name:
                auth_label += f" ({info.google_idp_name})"
            lines.append(f"GWS Auth: {auth_label}")
        gws_modules = [s.replace("Google Workspace: ", "") for s in info.services if s.startswith("Google Workspace: ")]
        if gws_modules:
            lines.append(f"GWS Modules: {', '.join(gws_modules)}")

    return "\n".join(lines)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def analyze_posture(domain: str) -> str:
    """Analyze a domain's configuration posture and return neutral observations.

    Returns factual observations about the domain's email security, identity,
    infrastructure, SaaS footprint, certificate activity, and configuration
    consistency. Observations are neutral — they describe what is, not what
    should be.

    Args:
        domain: A domain name to analyze (e.g., "northwindtraders.com")

    Returns:
        JSON array of observations, each with category, salience, statement,
        and related_slugs.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        _log_structured(
            logging.WARNING,
            "validation_failed",
            request_id=request_id,
            domain=domain,
            error=str(exc),
        )
        return f"Error: {exc}"

    # Check cache first
    cached = _cache_get(validated)
    if cached is not None:
        info, _results = cached
        _log_structured(
            logging.INFO,
            "cache_hit",
            request_id=request_id,
            domain=validated,
        )
    else:
        if not _rate_limit_check(validated):
            return f"Rate limited: {domain} was looked up recently. Try again in a few seconds."

        try:
            info, results = await resolve_tenant(validated)
        except ReconLookupError as exc:
            elapsed = time.monotonic() - start_time
            _log_structured(
                logging.INFO,
                "no_data",
                request_id=request_id,
                domain=domain,
                elapsed_s=round(elapsed, 2),
                error=exc.message,
            )
            return f"No information found for {domain}"
        except Exception:
            logger.exception(
                "Unexpected error looking up %s (request_id=%s)",
                domain,
                request_id,
            )
            return f"Error looking up {domain}: an internal error occurred"

        _cache_set(validated, info, results)
        _rate_limit_record(validated)

    from recon_tool.formatter import format_posture_observations
    from recon_tool.posture import analyze_posture as _analyze_posture

    observations = _analyze_posture(info)

    elapsed = time.monotonic() - start_time
    _log_structured(
        logging.INFO,
        "posture_analyzed",
        request_id=request_id,
        domain=domain,
        observations=len(observations),
        elapsed_s=round(elapsed, 2),
    )

    return json_mod.dumps(format_posture_observations(observations), indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def chain_lookup(domain: str, depth: int = 1) -> str:
    """Recursively resolve a domain and its related domains.

    Follows CNAME breadcrumbs and certificate transparency discoveries
    up to the specified depth. Returns intelligence for all discovered domains.

    Args:
        domain: Starting domain (e.g., "northwindtraders.com")
        depth: Maximum recursion depth (1-3, default 1)

    Returns:
        JSON object with total_domains, max_depth_reached, truncated flag,
        and an array of domain intelligence objects with chain_depth.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    # Clamp depth
    depth = max(1, min(depth, 3))

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        _log_structured(
            logging.WARNING,
            "validation_failed",
            request_id=request_id,
            domain=domain,
            error=str(exc),
        )
        return f"Error: {exc}"

    try:
        from recon_tool.chain import chain_resolve
        from recon_tool.formatter import format_chain_json

        report = await chain_resolve(validated, depth=depth)
    except Exception:
        logger.exception(
            "Unexpected error in chain lookup for %s (request_id=%s)",
            domain,
            request_id,
        )
        return f"Error looking up {domain}: an internal error occurred"

    elapsed = time.monotonic() - start_time
    _log_structured(
        logging.INFO,
        "chain_resolved",
        request_id=request_id,
        domain=domain,
        total_domains=len(report.results),
        max_depth=report.max_depth_reached,
        truncated=report.truncated,
        elapsed_s=round(elapsed, 2),
    )

    return format_chain_json(report)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def reload_data() -> str:
    """Reload fingerprint and signal definitions from disk.

    Use this after updating ~/.recon/fingerprints.yaml or the built-in
    data files. Also clears the lookup cache so subsequent lookups use
    the new definitions.
    """
    from recon_tool.fingerprints import reload_fingerprints
    from recon_tool.posture import reload_posture
    from recon_tool.signals import reload_signals

    reload_fingerprints()
    reload_signals()
    reload_posture()
    _cache_clear()

    from recon_tool.fingerprints import load_fingerprints
    from recon_tool.posture import load_posture_rules
    from recon_tool.signals import load_signals

    fp_count = len(load_fingerprints())
    sig_count = len(load_signals())
    posture_count = len(load_posture_rules())

    _log_structured(
        logging.INFO,
        "data_reloaded",
        fingerprints=fp_count,
        signals=sig_count,
        posture_rules=posture_count,
    )
    return f"Reloaded: {fp_count} fingerprints, {sig_count} signals, {posture_count} posture rules. Cache cleared."


@mcp.prompt()
def domain_report(domain: str) -> str:
    """Generate a domain intelligence report.

    Use this to get a comprehensive analysis of a company's email provider,
    tech stack, email security posture, and infrastructure.
    """
    return f"Look up {domain} using the lookup_tenant tool with format='markdown', then summarize the key findings."


def main() -> None:
    """Run the MCP server with stdio transport."""
    mcp.run()


if __name__ == "__main__":
    main()
