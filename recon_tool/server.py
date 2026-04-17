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

# Server Instructions — injected into the model's context each session so the
# agent knows how to compose recon's tools without requiring the user to
# explain. Keep this focused: what the server is, the passive-only invariant,
# the tool composition patterns, and what the confidence levels mean. Avoid
# duplicating individual tool docstrings — those speak for themselves.
_SERVER_INSTRUCTIONS = """\
recon is a passive domain-intelligence MCP server. It queries public DNS
records, Microsoft/Google identity endpoints, and certificate-transparency
logs. It performs zero active scanning, requires zero credentials, and never
touches a target's own HTTP infrastructure.

## When to use which tool

- `lookup_tenant(domain)` — start here for any question about a domain. Returns
  the full TenantInfo: company name, provider, tenant ID, auth type, email
  security score, services, related domains, insights. Use `format="json"` for
  structured output, `explain=True` for the provenance DAG.
- `analyze_posture(domain)` — neutral configuration observations. Accepts a
  `profile` argument (fintech, healthcare, saas-b2b, high-value-target,
  public-sector, higher-ed) to apply a posture lens.
- `assess_exposure(domain)` / `find_hardening_gaps(domain)` — defensive-review
  framing with a posture score (0–100) and categorized gap list.
- `compare_postures(domain_a, domain_b)` — side-by-side comparison for peer /
  acquisition / vendor analysis.
- `simulate_hardening(domain, fixes=[...])` — what-if: re-computes the posture
  score with hypothetical fixes applied. Zero network calls (operates on cached
  pipeline data).
- `test_hypothesis(domain, hypothesis)` — test a theory ("this org is
  mid-migration to Entra ID") against evidence. Returns likelihood + evidence.
- `chain_lookup(domain, depth)` — recursively resolve related domains up to
  depth 1–3. Good for portfolio / subsidiary surfacing.
- `cluster_verification_tokens(domains=[...])` — batch-scope clustering that
  surfaces hedged "possible relationship" signals from shared TXT tokens.

## Composition patterns

Typical agentic flow for a defensive review:
1. `lookup_tenant(domain, explain=True)` — establish the baseline.
2. `analyze_posture(domain)` with the relevant `profile` — posture lens.
3. `find_hardening_gaps(domain)` — categorized gaps with severity.
4. `simulate_hardening(domain, fixes=[...])` — quantify the improvement.

For introspection / hypothesis work:
- `get_fingerprints()` / `get_signals()` — inspect what the tool knows how to
  detect.
- `explain_signal(signal_name, domain)` — understand why a signal did or did
  not fire for this domain.
- `inject_ephemeral_fingerprint(...)` + `reevaluate_domain(domain)` — test new
  detection patterns against cached DNS data without any network calls.

## Invariants (important for agent behavior)

- Passive only. No active scanning, no credentialed access. All tools are
  read-only and idempotent. The server has a 120 s TTL cache and per-domain
  rate limiting — repeated `lookup_tenant` calls for the same domain are cheap.
- Output is hedged. Confidence levels: High (3+ corroborating sources),
  Medium (2 sources, partial), Low (1 source or indirect). Insights marked
  "(likely)" are inferences, not DNS-confirmed detections — treat them as
  hypotheses the user can investigate, not verdicts.
- The fingerprint database is rule-based and solo-maintained. A match means
  "evidence fits this service's DNS signature", not "this service is in use".
  Always flag uncertainty when confidence is Low.

## Explaining results

Prefer `explain=True` on `lookup_tenant` and `analyze_posture` when the user
asks "why" or "how do you know". The returned `explanation_dag` carries
`evidence → slug → rule → signal → insight` provenance and is the authoritative
answer to traceability questions.
"""

mcp = FastMCP("recon-tool", instructions=_SERVER_INSTRUCTIONS)


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
    explain: bool = False,
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
        domain: A domain name to look up (e.g., contoso.com, northwindtraders.com).
        format: Output format — "text" (default), "json" (structured), or "markdown" (full report).
        explain: When true, include structured explanations for insights and signals in the response.

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
        if explain:
            return _lookup_tenant_json_with_explain(info, list(results))
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

    if info.degraded_sources:
        lines.append(f"Degraded sources: {', '.join(info.degraded_sources)}")

    return "\n".join(lines)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def analyze_posture(
    domain: str,
    explain: bool = False,
    profile: str | None = None,
) -> str:
    """Analyze a domain's configuration posture and return neutral observations.

    Returns factual observations about the domain's email security, identity,
    infrastructure, SaaS footprint, certificate activity, and configuration
    consistency. Observations are neutral — they describe what is, not what
    should be.

    Args:
        domain: A domain name to analyze (e.g., "northwindtraders.com")
        explain: When true, include explanation data for each posture observation.
        profile: Optional profile name (e.g. "fintech", "healthcare",
            "saas-b2b", "high-value-target", "public-sector"). Reweights
            and filters observations to the profile's lens without
            adding new intelligence. Added in v0.9.3.

    Returns:
        JSON array of observations, each with category, salience, statement,
        and related_slugs. When explain is true, includes explanation data.
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
    from recon_tool.profiles import apply_profile, list_profiles, load_profile

    observations = _analyze_posture(info)

    # v0.9.3: apply profile lens if requested
    profile_note: str | None = None
    if profile:
        prof = load_profile(profile)
        if prof is None:
            available = ", ".join(p.name for p in list_profiles()) or "(none)"
            return json_mod.dumps(
                {
                    "error": f"Unknown profile {profile!r}",
                    "available_profiles": available,
                }
            )
        observations = apply_profile(tuple(observations), prof)
        profile_note = prof.prepend_note or prof.description

    elapsed = time.monotonic() - start_time
    _log_structured(
        logging.INFO,
        "posture_analyzed",
        request_id=request_id,
        domain=domain,
        observations=len(observations),
        elapsed_s=round(elapsed, 2),
    )

    result_list = format_posture_observations(observations)

    if explain:
        from recon_tool.explanation import explain_observations, serialize_explanation
        from recon_tool.posture import load_posture_rules

        posture_rules = load_posture_rules()
        explanation_records = explain_observations(observations, posture_rules, info.evidence, info.detection_scores)
        explanations = [serialize_explanation(rec) for rec in explanation_records]
        payload: dict[str, object] = {"observations": result_list, "explanations": explanations}
        if profile_note:
            payload["profile_note"] = profile_note
        return json_mod.dumps(payload, indent=2)

    if profile_note:
        return json_mod.dumps({"observations": result_list, "profile_note": profile_note}, indent=2)
    return json_mod.dumps(result_list, indent=2)


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


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def assess_exposure(domain: str) -> str:
    """Assess a domain's publicly observable security posture for defensive review.

    For defensive security posture assessment only.

    Returns a structured JSON object containing email security posture, identity
    posture, infrastructure footprint, configuration consistency observations,
    hardening status, and an overall posture score (0–100) based on publicly
    observable controls.

    Args:
        domain: A domain name to assess (e.g., "northwindtraders.com")

    Returns:
        JSON object with the full exposure assessment, or an error message.
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
        except ReconLookupError:
            elapsed = time.monotonic() - start_time
            _log_structured(
                logging.INFO,
                "no_data",
                request_id=request_id,
                domain=domain,
                elapsed_s=round(elapsed, 2),
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

    from recon_tool.exposure import assess_exposure_from_info
    from recon_tool.formatter import format_exposure_json

    assessment = assess_exposure_from_info(info)

    elapsed = time.monotonic() - start_time
    _log_structured(
        logging.INFO,
        "exposure_assessed",
        request_id=request_id,
        domain=domain,
        posture_score=assessment.posture_score,
        elapsed_s=round(elapsed, 2),
    )

    return format_exposure_json(assessment)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def find_hardening_gaps(domain: str) -> str:
    """Identify hardening opportunities in a domain's public configuration.

    For defensive security posture assessment only.

    Returns a JSON array of hardening gaps, each with category, severity,
    observation, suggested action, and supporting evidence references.

    Args:
        domain: A domain name to analyze (e.g., "northwindtraders.com")

    Returns:
        JSON object with the gap report, or an error message.
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
        except ReconLookupError:
            elapsed = time.monotonic() - start_time
            _log_structured(
                logging.INFO,
                "no_data",
                request_id=request_id,
                domain=domain,
                elapsed_s=round(elapsed, 2),
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

    from recon_tool.exposure import find_gaps_from_info
    from recon_tool.formatter import format_gaps_json

    report = find_gaps_from_info(info)

    elapsed = time.monotonic() - start_time
    _log_structured(
        logging.INFO,
        "gaps_analyzed",
        request_id=request_id,
        domain=domain,
        gaps=len(report.gaps),
        elapsed_s=round(elapsed, 2),
    )

    return format_gaps_json(report)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def compare_postures(domain_a: str, domain_b: str) -> str:
    """Compare the security postures of two domains side by side.

    For defensive security posture assessment only.

    Returns a structured JSON comparison with side-by-side metrics,
    control differences, and relative posture assessment.

    Args:
        domain_a: First domain to compare (e.g., "northwindtraders.com")
        domain_b: Second domain to compare (e.g., "contoso.com")

    Returns:
        JSON object with the posture comparison, or an error message.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    # Validate both domains
    try:
        validated_a = validate_domain(domain_a)
    except ValueError as exc:
        _log_structured(
            logging.WARNING,
            "validation_failed",
            request_id=request_id,
            domain=domain_a,
            error=str(exc),
        )
        return f"Error: {exc}"

    try:
        validated_b = validate_domain(domain_b)
    except ValueError as exc:
        _log_structured(
            logging.WARNING,
            "validation_failed",
            request_id=request_id,
            domain=domain_b,
            error=str(exc),
        )
        return f"Error: {exc}"

    # Resolve domain_a
    cached_a = _cache_get(validated_a)
    if cached_a is not None:
        info_a, _ = cached_a
    else:
        if not _rate_limit_check(validated_a):
            return f"Rate limited: {domain_a} was looked up recently. Try again in a few seconds."
        try:
            info_a, results_a = await resolve_tenant(validated_a)
        except ReconLookupError:
            return f"Could not resolve domain_a: {domain_a}. The comparison requires both domains to be resolvable."
        except Exception:
            logger.exception(
                "Unexpected error looking up %s (request_id=%s)",
                domain_a,
                request_id,
            )
            return f"Error looking up {domain_a}: an internal error occurred"
        _cache_set(validated_a, info_a, results_a)
        _rate_limit_record(validated_a)

    # Resolve domain_b
    cached_b = _cache_get(validated_b)
    if cached_b is not None:
        info_b, _ = cached_b
    else:
        if not _rate_limit_check(validated_b):
            return f"Rate limited: {domain_b} was looked up recently. Try again in a few seconds."
        try:
            info_b, results_b = await resolve_tenant(validated_b)
        except ReconLookupError:
            return f"Could not resolve domain_b: {domain_b}. The comparison requires both domains to be resolvable."
        except Exception:
            logger.exception(
                "Unexpected error looking up %s (request_id=%s)",
                domain_b,
                request_id,
            )
            return f"Error looking up {domain_b}: an internal error occurred"
        _cache_set(validated_b, info_b, results_b)
        _rate_limit_record(validated_b)

    from recon_tool.exposure import compare_postures_from_infos
    from recon_tool.formatter import format_comparison_json

    comparison = compare_postures_from_infos(info_a, info_b)

    elapsed = time.monotonic() - start_time
    _log_structured(
        logging.INFO,
        "postures_compared",
        request_id=request_id,
        domain_a=domain_a,
        domain_b=domain_b,
        elapsed_s=round(elapsed, 2),
    )

    return format_comparison_json(comparison)


def _lookup_tenant_json_with_explain(info: TenantInfo, results: list[SourceResult]) -> str:
    """Build JSON response for lookup_tenant with explain=True.

    Includes explanations for insights, signals, confidence, and conflicts.
    """
    from recon_tool.absence import evaluate_absence_signals, evaluate_positive_absence
    from recon_tool.explanation import (
        explain_confidence,
        explain_insights,
        explain_signals,
        serialize_explanation,
    )
    from recon_tool.formatter import format_tenant_dict
    from recon_tool.models import SignalContext, serialize_conflicts
    from recon_tool.signals import evaluate_signals, load_signals

    base = format_tenant_dict(info)

    # Build signal context for explanation
    context = SignalContext(
        detected_slugs=frozenset(info.slugs),
        dmarc_policy=info.dmarc_policy,
        auth_type=info.auth_type,
        email_security_score=sum(
            1
            for svc in info.services
            if svc
            in {
                "DMARC",
                "DKIM (Exchange Online)",
                "DKIM",
                "SPF: strict (-all)",
                "MTA-STS",
                "BIMI",
            }
        ),
    )
    signal_matches = evaluate_signals(context)
    signals = load_signals()

    # Third pass: absence signals + positive hardening observations (v0.9.3)
    absence_matches = evaluate_absence_signals(signal_matches, signals, context.detected_slugs)
    positive_matches = evaluate_positive_absence(signal_matches, signals, context.detected_slugs)
    all_signal_matches = signal_matches + absence_matches + positive_matches

    context_metadata: dict[str, object] = {
        "dmarc_policy": info.dmarc_policy,
        "auth_type": info.auth_type,
        "email_security_score": context.email_security_score,
    }

    all_explanations: list[dict[str, object]] = []

    # Signal explanations
    signal_recs = explain_signals(
        all_signal_matches, signals, context.detected_slugs, context_metadata, info.evidence, info.detection_scores
    )
    all_explanations.extend(serialize_explanation(r) for r in signal_recs)

    # Insight explanations
    insight_recs = explain_insights(
        list(info.insights), frozenset(info.slugs), frozenset(info.services), info.evidence, info.detection_scores
    )
    all_explanations.extend(serialize_explanation(r) for r in insight_recs)

    # Confidence explanation
    conf_rec = explain_confidence(results, info.evidence_confidence, info.inference_confidence, info.confidence)
    all_explanations.append(serialize_explanation(conf_rec))

    base["explanations"] = all_explanations

    # v0.9.3: structured provenance DAG in parallel with the flat list.
    # Both views are emitted so existing tooling keeps working.
    from recon_tool.explanation import build_explanation_dag

    all_records = [*signal_recs, *insight_recs, conf_rec]
    base["explanation_dag"] = build_explanation_dag(all_records, info.evidence)

    # Include conflicts when present
    if info.merge_conflicts and info.merge_conflicts.has_conflicts:
        base["conflicts"] = serialize_conflicts(info.merge_conflicts)

    return json_mod.dumps(base, indent=2)


# ── Helper: resolve or use cache ────────────────────────────────────────


async def _resolve_or_cache(domain: str) -> tuple[TenantInfo, list[SourceResult]] | str:
    """Resolve a domain, using cache if available. Returns error string on failure."""
    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        return f"Error: {exc}"

    cached = _cache_get(validated)
    if cached is not None:
        info, results = cached
        return info, list(results)

    if not _rate_limit_check(validated):
        return f"Rate limited: {domain} was looked up recently. Try again in a few seconds."

    try:
        info, results = await resolve_tenant(validated)
    except ReconLookupError:
        return f"No information found for {domain}"
    except Exception:
        logger.exception("Unexpected error looking up %s", domain)
        return f"Error looking up {domain}: an internal error occurred"

    _cache_set(validated, info, results)
    _rate_limit_record(validated)
    return info, list(results)


# ── MCP Introspection Tools ─────────────────────────────────────────────


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def get_fingerprints(category: str | None = None) -> str:
    """List all loaded fingerprints with slugs, categories, and detection types.

    Returns a JSON array of fingerprint summaries from both built-in and custom
    sources. Each entry includes name, slug, category, confidence, match_mode,
    provider_group, display_group, and the set of detection types used.

    Args:
        category: Optional category filter (case-insensitive partial match).

    Returns:
        JSON array of fingerprint summaries.
    """
    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    if category:
        cat_lower = category.lower()
        fps = tuple(fp for fp in fps if cat_lower in fp.category.lower())
    result = [
        {
            "name": fp.name,
            "slug": fp.slug,
            "category": fp.category,
            "confidence": fp.confidence,
            "match_mode": fp.match_mode,
            "provider_group": fp.provider_group,
            "display_group": fp.display_group,
            "detection_types": sorted({d.type for d in fp.detections}),
        }
        for fp in fps
    ]
    return json_mod.dumps(result, indent=2)


def _classify_signal_layer(sig: object) -> int:
    """Classify a signal into a layer number.

    Layer 1: basic (no metadata, no requires_signals, single category focus)
    Layer 2: composite (cross-category or has metadata conditions)
    Layer 3: consistency (category is Consistency)
    Layer 4: meta (has requires_signals)
    """
    from recon_tool.signals import Signal

    if not isinstance(sig, Signal):
        return 1
    if sig.requires_signals:
        return 4
    if sig.category.lower() == "consistency":
        return 3
    if sig.metadata:
        return 2
    return 1


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def get_signals(category: str | None = None, layer: int | None = None) -> str:
    """List all loaded signals with rules, layers, and conditions.

    Returns a JSON array of signal definitions from both built-in and custom
    sources. Each entry includes name, category, confidence, description,
    candidates, min_matches, metadata conditions, contradicts, requires_signals,
    explain, and computed layer.

    Layers: 1=basic, 2=composite (has metadata), 3=consistency, 4=meta (requires_signals).

    Args:
        category: Optional category filter (case-insensitive partial match).
        layer: Optional layer filter (1, 2, 3, or 4).

    Returns:
        JSON array of signal definitions.
    """
    from recon_tool.signals import load_signals

    sigs = load_signals()
    result: list[dict[str, object]] = []
    for sig in sigs:
        sig_layer = _classify_signal_layer(sig)
        if category and category.lower() not in sig.category.lower():
            continue
        if layer is not None and sig_layer != layer:
            continue
        result.append(
            {
                "name": sig.name,
                "category": sig.category,
                "confidence": sig.confidence,
                "description": sig.description,
                "candidates": list(sig.candidates),
                "min_matches": sig.min_matches,
                "metadata": [{"field": m.field, "operator": m.operator, "value": m.value} for m in sig.metadata],
                "contradicts": list(sig.contradicts),
                "requires_signals": list(sig.requires_signals),
                "explain": sig.explain,
                "layer": sig_layer,
            }
        )
    return json_mod.dumps(result, indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def explain_signal(signal_name: str, domain: str | None = None) -> str:
    """Query a specific signal's trigger conditions and current state for a domain.

    Without a domain: returns the signal's definition, trigger conditions,
    and a list of conditions that would weaken or suppress the signal.

    With a domain: resolves the domain (using cache if available), evaluates
    the signal, and returns its current state with matched evidence and
    specific weakening conditions.

    Args:
        signal_name: Name of the signal to explain (required).
        domain: Optional domain to evaluate the signal against.

    Returns:
        JSON object with signal definition and evaluation state, or an error.
    """
    from recon_tool.signals import Signal, load_signals

    all_signals = load_signals()
    sig: Signal | None = None
    for s in all_signals:
        if s.name == signal_name:
            sig = s
            break

    if sig is None:
        available = sorted(s.name for s in all_signals)
        return json_mod.dumps(
            {"error": f"Signal '{signal_name}' not found", "available_signals": available},
            indent=2,
        )

    # Build base definition
    definition: dict[str, object] = {
        "name": sig.name,
        "category": sig.category,
        "confidence": sig.confidence,
        "description": sig.description,
        "explain": sig.explain,
        "layer": _classify_signal_layer(sig),
        "trigger_conditions": {
            "candidates": list(sig.candidates),
            "min_matches": sig.min_matches,
            "metadata": [{"field": m.field, "operator": m.operator, "value": m.value} for m in sig.metadata],
            "contradicts": list(sig.contradicts),
            "requires_signals": list(sig.requires_signals),
        },
        "weakening_conditions": _static_weakening_conditions(sig),
    }

    if domain is None:
        return json_mod.dumps(definition, indent=2)

    # Resolve domain and evaluate signal
    resolved = await _resolve_or_cache(domain)
    if isinstance(resolved, str):
        return resolved

    info, _results = resolved

    from recon_tool.models import SignalContext
    from recon_tool.signals import evaluate_signals

    context = SignalContext(
        detected_slugs=frozenset(info.slugs),
        dmarc_policy=info.dmarc_policy,
        auth_type=info.auth_type,
        email_security_score=sum(
            1
            for svc in info.services
            if svc
            in {
                "DMARC",
                "DKIM (Exchange Online)",
                "DKIM",
                "SPF: strict (-all)",
                "MTA-STS",
                "BIMI",
            }
        ),
    )
    signal_matches = evaluate_signals(context)
    fired = any(m.name == signal_name for m in signal_matches)
    matched_slugs = [slug for slug in sig.candidates if slug in context.detected_slugs]

    # Build domain-specific weakening conditions
    from recon_tool.explanation import _weakening_conditions_for_signal  # pyright: ignore[reportPrivateUsage]

    context_metadata: dict[str, object] = {
        "dmarc_policy": info.dmarc_policy,
        "auth_type": info.auth_type,
        "email_security_score": context.email_security_score,
    }
    weakening = _weakening_conditions_for_signal(sig, matched_slugs, context_metadata)

    # Collect evidence for matched slugs
    evidence_list: list[dict[str, str]] = []
    for slug in matched_slugs:
        for ev in info.evidence:
            if ev.slug == slug:
                evidence_list.append(
                    {
                        "source_type": ev.source_type,
                        "raw_value": ev.raw_value,
                        "rule_name": ev.rule_name,
                        "slug": ev.slug,
                    }
                )

    evaluation: dict[str, object] = {
        **definition,
        "domain": domain,
        "fired": fired,
        "matched_slugs": matched_slugs,
        "matched_evidence": evidence_list,
        "domain_weakening_conditions": list(weakening),
    }
    return json_mod.dumps(evaluation, indent=2)


def _static_weakening_conditions(sig: object) -> list[str]:
    """Generate static weakening conditions for a signal definition (no domain context)."""
    from recon_tool.signals import Signal

    if not isinstance(sig, Signal):
        return []
    conditions: list[str] = []
    if sig.candidates and sig.min_matches > 0:
        conditions.append(
            f"Signal requires at least {sig.min_matches} of {len(sig.candidates)} candidate slug(s) to be detected"
        )
    for cond in sig.metadata:
        conditions.append(f"Metadata condition: {cond.field} {cond.operator} {cond.value}")
    for slug in sig.contradicts:
        conditions.append(f"Detecting slug '{slug}' would suppress this signal")
    if sig.requires_signals:
        conditions.append(f"Requires all of these signals to fire first: {', '.join(sig.requires_signals)}")
    return conditions


# ── MCP Agentic Tools ───────────────────────────────────────────────────

# Keyword groups for hypothesis matching — maps keywords to signal/slug categories
_HYPOTHESIS_KEYWORDS: dict[str, list[str]] = {
    "migration": ["migration", "migrate", "transition", "moving", "switching"],
    "security": ["security", "secure", "protection", "defense", "defensive"],
    "email": ["email", "mail", "dmarc", "dkim", "spf", "mta-sts", "bimi"],
    "identity": ["identity", "sso", "federated", "okta", "entra", "auth", "authentication"],
    "cloud": ["cloud", "aws", "azure", "gcp", "saas"],
    "ai": ["ai", "artificial intelligence", "llm", "openai", "generative", "machine learning"],
    "compliance": ["compliance", "governance", "audit", "regulation"],
    "collaboration": ["collaboration", "teams", "slack", "zoom", "communication"],
    "monitoring": ["monitoring", "observability", "logging", "telemetry"],
    "cdn": ["cdn", "edge", "waf", "firewall", "cloudflare", "akamai"],
}


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def test_hypothesis(domain: str, hypothesis: str) -> str:
    """Test a theory about a domain against signals and evidence.

    Proposes a theory (e.g., "this organization appears to be mid-migration
    to Entra ID") and receives a structured assessment of likelihood,
    supporting evidence, contradicting evidence, and what is missing.

    Operates purely on cached pipeline data — zero additional network calls
    beyond the initial domain resolution.

    Args:
        domain: A domain name to test against (e.g., "northwindtraders.com").
        hypothesis: A theory to evaluate (e.g., "mid-migration to cloud identity").

    Returns:
        JSON object with likelihood, supporting_signals, contradicting_signals,
        missing_evidence, and confidence.
    """
    resolved = await _resolve_or_cache(domain)
    if isinstance(resolved, str):
        return resolved

    info, _results = resolved

    from recon_tool.models import SignalContext
    from recon_tool.signals import evaluate_signals, load_signals

    context = SignalContext(
        detected_slugs=frozenset(info.slugs),
        dmarc_policy=info.dmarc_policy,
        auth_type=info.auth_type,
        email_security_score=sum(
            1
            for svc in info.services
            if svc
            in {
                "DMARC",
                "DKIM (Exchange Online)",
                "DKIM",
                "SPF: strict (-all)",
                "MTA-STS",
                "BIMI",
            }
        ),
    )
    signal_matches = evaluate_signals(context)
    all_signals = load_signals()
    fired_names = {m.name for m in signal_matches}

    # Map hypothesis to relevant categories via keyword matching
    hyp_lower = hypothesis.lower()
    relevant_categories: set[str] = set()
    for cat, keywords in _HYPOTHESIS_KEYWORDS.items():
        if any(kw in hyp_lower for kw in keywords):
            relevant_categories.add(cat)

    # Find supporting and contradicting signals
    supporting: list[str] = []
    contradicting: list[str] = []
    missing: list[str] = []

    for sig in all_signals:
        # Check if signal is relevant to hypothesis via keyword matching
        sig_text = f"{sig.name} {sig.description} {sig.category} {sig.explain}".lower()
        is_relevant = any(kw in sig_text for kw in hyp_lower.split()) or any(
            any(kw in sig_text for kw in keywords)
            for cat, keywords in _HYPOTHESIS_KEYWORDS.items()
            if cat in relevant_categories
        )
        if not is_relevant:
            continue

        if sig.name in fired_names:
            supporting.append(sig.name)
        else:
            # Check if it contradicts or is just missing
            has_contradiction_slugs = sig.contradicts and any(
                slug in context.detected_slugs for slug in sig.contradicts
            )
            if has_contradiction_slugs:
                contradicting.append(sig.name)
            else:
                missing.append(
                    f"Signal '{sig.name}' did not fire — "
                    f"detecting additional slugs ({', '.join(sig.candidates[:3])}) "
                    f"could strengthen or weaken this hypothesis"
                    if sig.candidates
                    else f"Signal '{sig.name}' did not fire — metadata conditions not met"
                )

    # Determine likelihood
    if supporting and not contradicting:
        if len(supporting) >= 3:
            likelihood = "strong"
        elif len(supporting) >= 1:
            likelihood = "moderate"
        else:
            likelihood = "weak"
    elif contradicting and not supporting:
        likelihood = "unsupported"
    elif supporting and contradicting:
        likelihood = "moderate" if len(supporting) > len(contradicting) else "weak"
    else:
        likelihood = "unsupported"

    # Determine confidence based on data completeness
    if info.degraded_sources:
        confidence = "low"
    elif len(info.sources) >= 3:
        confidence = "high"
    else:
        confidence = "medium"

    result: dict[str, object] = {
        "domain": domain,
        "hypothesis": hypothesis,
        "likelihood": likelihood,
        "supporting_signals": supporting,
        "contradicting_signals": contradicting,
        "missing_evidence": missing,
        "confidence": confidence,
        "disclaimer": (
            "This assessment is based on publicly observable indicators and "
            "cached pipeline data. Indicators suggest possible patterns but "
            "do not confirm organizational intent or internal decisions."
        ),
    }
    return json_mod.dumps(result, indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def simulate_hardening(domain: str, fixes: list[str]) -> str:
    """What-if simulation: re-compute exposure score with hypothetical fixes.

    Accepts a list of fix descriptions (e.g., "DMARC reject", "MTA-STS enforce")
    and simulates what the posture score would be if those fixes were applied.

    Operates purely on cached pipeline data — zero additional network calls
    beyond the initial domain resolution.

    Args:
        domain: A domain name to simulate against (e.g., "northwindtraders.com").
        fixes: Array of fix descriptions or gap slugs to hypothetically apply.

    Returns:
        JSON object with current_score, simulated_score, score_delta,
        applied_fixes, and remaining_gaps.
    """
    resolved = await _resolve_or_cache(domain)
    if isinstance(resolved, str):
        return resolved

    info, _results = resolved

    from recon_tool.exposure import assess_exposure_from_info, find_gaps_from_info

    current_assessment = assess_exposure_from_info(info)
    current_score = current_assessment.posture_score

    # Parse fixes and simulate by mutating a copy of TenantInfo fields
    applied: list[str] = []
    sim_services = set(info.services)
    sim_slugs = set(info.slugs)
    sim_dmarc = info.dmarc_policy
    sim_mta_sts = info.mta_sts_mode

    fixes_lower = [f.lower() for f in fixes]

    for fix in fixes_lower:
        if "dmarc" in fix and "reject" in fix:
            sim_dmarc = "reject"
            applied.append("DMARC policy set to reject")
        elif "dmarc" in fix and "quarantine" in fix:
            if sim_dmarc != "reject":
                sim_dmarc = "quarantine"
                applied.append("DMARC policy set to quarantine")
        elif "dmarc" in fix:
            if sim_dmarc is None or sim_dmarc == "none":
                sim_dmarc = "reject"
                applied.append("DMARC policy set to reject")
        elif "dkim" in fix:
            sim_services.add("DKIM")
            sim_slugs.add("dkim")
            applied.append("DKIM configured")
        elif "mta-sts" in fix and "enforce" in fix:
            sim_mta_sts = "enforce"
            sim_services.add("MTA-STS")
            sim_slugs.add("mta-sts-enforce")
            applied.append("MTA-STS set to enforce")
        elif "mta-sts" in fix:
            if sim_mta_sts is None:
                sim_mta_sts = "enforce"
                sim_services.add("MTA-STS")
                sim_slugs.add("mta-sts-enforce")
                applied.append("MTA-STS set to enforce")
        elif "bimi" in fix:
            sim_services.add("BIMI")
            sim_slugs.add("bimi")
            applied.append("BIMI configured")
        elif "spf" in fix and ("strict" in fix or "hardfail" in fix or "-all" in fix):
            sim_services.add("SPF: strict (-all)")
            applied.append("SPF set to strict (-all)")
        elif "tls-rpt" in fix or "tlsrpt" in fix:
            sim_slugs.add("tls-rpt")
            applied.append("TLS-RPT configured")
        elif "caa" in fix:
            sim_slugs.add("letsencrypt")
            applied.append("CAA records configured")
        else:
            applied.append(f"Unrecognized fix: {fix}")

    # Build simulated TenantInfo
    sim_info = TenantInfo(
        tenant_id=info.tenant_id,
        display_name=info.display_name,
        default_domain=info.default_domain,
        queried_domain=info.queried_domain,
        confidence=info.confidence,
        region=info.region,
        sources=info.sources,
        services=tuple(sorted(sim_services)),
        slugs=tuple(sorted(sim_slugs)),
        auth_type=info.auth_type,
        dmarc_policy=sim_dmarc,
        domain_count=info.domain_count,
        tenant_domains=info.tenant_domains,
        related_domains=info.related_domains,
        insights=info.insights,
        degraded_sources=info.degraded_sources,
        cert_summary=info.cert_summary,
        evidence=info.evidence,
        evidence_confidence=info.evidence_confidence,
        inference_confidence=info.inference_confidence,
        detection_scores=info.detection_scores,
        bimi_identity=info.bimi_identity,
        site_verification_tokens=info.site_verification_tokens,
        mta_sts_mode=sim_mta_sts,
        google_auth_type=info.google_auth_type,
        google_idp_name=info.google_idp_name,
        merge_conflicts=info.merge_conflicts,
    )

    sim_assessment = assess_exposure_from_info(sim_info)
    simulated_score = sim_assessment.posture_score

    # Compute remaining gaps on simulated info
    sim_gap_report = find_gaps_from_info(sim_info)
    remaining_gaps = [
        {
            "category": gap.category,
            "severity": gap.severity,
            "observation": gap.observation,
            "recommendation": gap.recommendation,
        }
        for gap in sim_gap_report.gaps
    ]

    result: dict[str, object] = {
        "domain": domain,
        "current_score": current_score,
        "simulated_score": simulated_score,
        "score_delta": simulated_score - current_score,
        "applied_fixes": applied,
        "remaining_gaps": remaining_gaps,
        "disclaimer": (
            "This simulation is based on publicly observable configuration data. "
            "Consider these results as directional guidance for prioritizing "
            "hardening actions, not as a guarantee of security posture improvement."
        ),
    }
    return json_mod.dumps(result, indent=2)


# ── Ephemeral Fingerprint MCP Tools ─────────────────────────────────────


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    ),
)
async def inject_ephemeral_fingerprint(
    name: str,
    slug: str,
    category: str,
    confidence: str,
    detections: list[dict[str, str]],
) -> str:
    """Inject a temporary fingerprint for the current session.

    The fingerprint is validated through the same pipeline as built-in
    fingerprints (regex compilation, ReDoS safety, valid detection types).
    It lives in memory only and is discarded when the server process ends.

    Args:
        name: Display name for the fingerprint (e.g., "Acme Platform").
        slug: Unique identifier (e.g., "acme-platform").
        category: Category name (e.g., "SaaS").
        confidence: Detection confidence — "high", "medium", or "low".
        detections: List of detection rules, each with "type" and "pattern" keys.

    Returns:
        Confirmation message or validation error.
    """
    from recon_tool.fingerprints import _validate_fingerprint, inject_ephemeral  # pyright: ignore[reportPrivateUsage]

    fp_dict: dict[str, object] = {
        "name": name,
        "slug": slug,
        "category": category,
        "confidence": confidence,
        "detections": [{"type": d.get("type", ""), "pattern": d.get("pattern", "")} for d in detections],
    }
    validated = _validate_fingerprint(fp_dict, "ephemeral")
    if validated is None:
        return json_mod.dumps(
            {
                "error": f"Validation failed for fingerprint '{name}'. "
                "Check detection types, patterns, and confidence level."
            }
        )

    inject_ephemeral(validated)
    return json_mod.dumps(
        {
            "status": "ok",
            "name": validated.name,
            "slug": validated.slug,
            "detections_accepted": len(validated.detections),
        }
    )


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def list_ephemeral_fingerprints() -> str:
    """List all ephemeral fingerprints loaded in the current session.

    Returns a JSON array of fingerprint summaries.
    """
    from recon_tool.fingerprints import get_ephemeral

    fps = get_ephemeral()
    result = [
        {
            "name": fp.name,
            "slug": fp.slug,
            "category": fp.category,
            "confidence": fp.confidence,
            "detection_count": len(fp.detections),
        }
        for fp in fps
    ]
    return json_mod.dumps(result, indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def clear_ephemeral_fingerprints() -> str:
    """Remove all ephemeral fingerprints from the current session.

    Returns confirmation with the count of fingerprints removed.
    """
    from recon_tool.fingerprints import clear_ephemeral

    count = clear_ephemeral()
    return json_mod.dumps(
        {
            "status": "ok",
            "removed": count,
        }
    )


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def reevaluate_domain(domain: str) -> str:
    """Re-evaluate a previously looked-up domain against current fingerprints.

    Uses cached raw DNS data from a prior lookup — zero network calls.
    Useful after injecting ephemeral fingerprints to test detection hypotheses.

    Args:
        domain: Domain to re-evaluate (must have been looked up previously).

    Returns:
        Updated domain intelligence JSON, or error if domain not in cache.
    """
    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        return json_mod.dumps({"error": str(exc)})

    cached = _cache_get(validated)
    if cached is None:
        return json_mod.dumps({"error": f"No cached data for {domain}. Run lookup_tenant first."})

    _info, results = cached

    # Re-run merge pipeline with current fingerprint set (including ephemeral)
    from recon_tool.merger import merge_results

    try:
        new_info = merge_results(list(results), validated)
    except Exception as exc:
        return json_mod.dumps({"error": f"Re-evaluation failed: {exc}"})

    return format_tenant_json(new_info)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def cluster_verification_tokens(domains: list[str]) -> str:
    """Cluster a list of domains by shared site-verification tokens.

    For defensive OSINT and vendor due-diligence only.

    Looks up each domain (using the TTL cache when available) and
    computes a map of shared TXT verification tokens across the input
    set. When two domains share a ``google-site-verification=``,
    ``MS=``, Atlassian, Zoom, or similar token, it surfaces a hedged
    "possible relationship" observation — not a verdict.

    A reused token implies a shared operator scope: the same SaaS
    account provisioned the verification on both domains. Common
    interpretations include shared infrastructure, acquisition history,
    subsidiary relationships, managed-services providers, or
    historical residue. The tool does NOT commit to any of these —
    it reports the observation and leaves synthesis to the caller.

    Zero additional network calls beyond whatever initial resolves are
    required to populate the cache. Every result is computed from
    cached TenantInfo.

    Args:
        domains: List of domain names to cluster. Must contain at
            least two distinct domains to be useful. Invalid domains
            are skipped with an error entry in the response.

    Returns:
        JSON object with ``clusters`` (a map from each domain to its
        peers via shared tokens) and ``errors`` (a list of domains
        that could not be resolved). Empty ``clusters`` means no
        shared tokens were observed — not an error.
    """
    from recon_tool.clustering import compute_shared_tokens

    if not domains:
        return json_mod.dumps({"error": "At least one domain is required"})

    domain_tokens: dict[str, tuple[str, ...]] = {}
    errors: list[dict[str, str]] = []

    for raw in domains:
        resolved = await _resolve_or_cache(raw)
        if isinstance(resolved, str):
            errors.append({"domain": raw, "error": resolved})
            continue
        info, _results = resolved
        domain_tokens[info.queried_domain] = info.site_verification_tokens

    clusters = compute_shared_tokens(domain_tokens)

    # Serialize: domain → list of {token, peer}
    serialized: dict[str, list[dict[str, str]]] = {}
    for d, entries in clusters.items():
        serialized[d] = [{"token": e.token, "peer": e.peer} for e in entries]

    payload: dict[str, object] = {
        "clusters": serialized,
        "errors": errors,
        "disclaimer": (
            "Shared verification tokens imply operator-scoped credential "
            "reuse across domains. This is consistent with shared "
            "infrastructure, subsidiary relationships, or managed-services "
            "providers — it is not a corporate-identity verdict. Observation, "
            "not a verdict."
        ),
    }
    return json_mod.dumps(payload, indent=2)


@mcp.prompt()
def domain_report(domain: str) -> str:
    """Generate a domain intelligence report.

    Use this to get a comprehensive analysis of a company's email provider,
    tech stack, email security posture, and infrastructure.
    """
    return f"Look up {domain} using the lookup_tenant tool with format='markdown', then summarize the key findings."


def _print_mcp_banner() -> None:
    """Write the MCP server startup banner to stderr.

    stderr is used deliberately: the stdio transport owns stdout for
    JSON-RPC message framing, and any bytes written to stdout before
    or during server execution will corrupt that framing. stderr is
    safe — MCP clients either display it or discard it, but never
    parse it.
    """
    import sys

    from recon_tool import __version__

    try:
        from recon_tool.fingerprints import load_fingerprints
        from recon_tool.signals import load_signals

        fp_count = len(load_fingerprints())
        sig_count = len(load_signals())
    except Exception:
        fp_count = 0
        sig_count = 0

    lines = [
        f"recon MCP Server v{__version__} — ready for AI clients",
        "",
        "Listening on stdio transport.",
        f"Loaded {fp_count} fingerprints, {sig_count} signals.",
        "",
        "Available tools (17 total):",
        "  lookup_tenant               Full domain intelligence + tenant details",
        "  analyze_posture             Neutral posture observations (accepts --profile)",
        "  assess_exposure             Security posture score (0–100)",
        "  find_hardening_gaps         Categorized gaps + recommendations",
        "  simulate_hardening          What-if hardening simulation",
        "  compare_postures            Side-by-side posture comparison",
        "  chain_lookup                Recursive related-domain discovery",
        "  explain_signal              Signal trigger conditions + evidence",
        "  test_hypothesis             Evaluate a theory against cached data",
        "  cluster_verification_tokens Cluster domains by shared TXT tokens",
        "",
        "MCP server is running and waiting for tool calls from your AI client.",
        "Press Ctrl+C to stop.",
        "",
        "Tip: configure this in Claude Desktop, Cursor, or VS Code using the",
        "     instructions in docs/mcp.md",
        "",
    ]
    sys.stderr.write("\n".join(lines))
    sys.stderr.flush()


def main() -> None:
    """Run the MCP server with stdio transport.

    v0.9.3: prints a professional startup banner to stderr before
    handing control to the FastMCP loop, and handles Ctrl+C /
    CancelledError / BrokenPipe cleanly so the user sees
    ``"MCP server stopped"`` instead of a raw traceback. The stdio
    transport is still owned by stdout — the banner and shutdown
    message both go to stderr so JSON-RPC framing stays clean.
    """
    import sys

    _print_mcp_banner()

    try:
        mcp.run()
    except KeyboardInterrupt:
        sys.stderr.write("\nMCP server stopped.\n")
        sys.stderr.flush()
    except (BrokenPipeError, ConnectionResetError):
        # Client disconnected — this is a clean shutdown from the
        # stdio transport's perspective, not an error worth raising.
        sys.stderr.write("\nMCP client disconnected — server stopped.\n")
        sys.stderr.flush()
    except Exception as exc:  # noqa: BLE001
        # Any other unexpected failure: log a one-line summary, not
        # a traceback. Users see a calm error, not a Python scream.
        sys.stderr.write(f"\nMCP server exited unexpectedly: {exc}\n")
        sys.stderr.flush()
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
