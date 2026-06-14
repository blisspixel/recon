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
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from recon_tool import server_app, server_ephemeral
from recon_tool import server_runtime as _server_runtime
from recon_tool.exit_codes import EXIT_ERROR, EXIT_VALIDATION
from recon_tool.formatter import (
    detect_provider,
    format_tenant_dict,
    format_tenant_json,
    format_tenant_markdown,
)
from recon_tool.models import ReconLookupError, SourceResult, TenantInfo
from recon_tool.server_app import mcp
from recon_tool.validator import strip_control_chars, validate_domain

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

# Re-export facade: the FastMCP instance and instructions live in server_app
# now; preserve the recon_tool.server import path for the test surface.
_SERVER_INSTRUCTIONS = server_app.SERVER_INSTRUCTIONS

# Tool-group re-export facade (registration via the import above): preserve
# the recon_tool.server import path for the tool functions the tests import.
inject_ephemeral_fingerprint = server_ephemeral.inject_ephemeral_fingerprint
list_ephemeral_fingerprints = server_ephemeral.list_ephemeral_fingerprints
clear_ephemeral_fingerprints = server_ephemeral.clear_ephemeral_fingerprints
reevaluate_domain = server_ephemeral.reevaluate_domain

# Re-export facade for the server runtime state (see server_runtime.py).
# Preserves the recon_tool.server import path for the tools and tests.
CACHE_TTL = _server_runtime.CACHE_TTL
CACHE_MAX_SIZE = _server_runtime.CACHE_MAX_SIZE
RATE_LIMIT_WINDOW = _server_runtime.RATE_LIMIT_WINDOW
_RATE_LIMIT_MAX_SIZE = _server_runtime.RATE_LIMIT_MAX_SIZE
_cache = _server_runtime.cache
_rate_limit = _server_runtime.rate_limit
_cache_evict_expired = _server_runtime.cache_evict_expired
_cache_get = _server_runtime.cache_get
_cache_set = _server_runtime.cache_set
_cache_clear = _server_runtime.cache_clear
_cache_refresh_info = _server_runtime.cache_refresh_info
_remerge_cached_infos = _server_runtime.remerge_cached_infos
_rate_limit_evict_expired = _server_runtime.rate_limit_evict_expired
_rate_limit_check = _server_runtime.rate_limit_check
_rate_limit_record = _server_runtime.rate_limit_record
_rate_limit_try_acquire = _server_runtime.rate_limit_try_acquire
_rate_limit_release = _server_runtime.rate_limit_release
_rate_limit_clear = _server_runtime.rate_limit_clear
_log_structured = _server_runtime.log_structured


# ── Bounded TTL cache for resolved results ──────────────────────────────
# Prevents hammering upstream endpoints when an AI agent calls lookup_tenant
# repeatedly for the same domain. Cache entries expire after CACHE_TTL seconds.
# Max size prevents unbounded memory growth from unique domain lookups.
#
# The MCP server currently runs as a single-process stdio transport, so a small
# in-process state container is enough. Keeping cache and rate-limiter behavior
# together in one typed object makes the bounded-size and lifetime invariants
# easier to reason about and test.


# ── Bounded per-domain rate limiter ─────────────────────────────────────
# Prevents abuse by limiting how often the same domain can be looked up
# (cache misses only). Uses a simple timestamp-based approach with periodic
# eviction to prevent unbounded memory growth.


# ── MCP resources ────────────────────────────────────────────────────
# Catalog resources let agents browse "what can recon detect?" without
# spending a tool invocation on introspection. Read-only. The content
# is a deterministic projection over the already-loaded YAML catalogs;
# changes require reload_data to take effect. No network calls.


@mcp.resource(
    "recon://fingerprints",
    name="Fingerprint catalog",
    description=(
        "Full SaaS fingerprint catalog as JSON. Each entry carries slug, name, "
        "category, confidence tier, M365 flag, match_mode, provider/display "
        "group, detection count, and a compact detection summary. Use to "
        "answer 'what services can recon identify?'."
    ),
    mime_type="application/json",
)
def _resource_fingerprints() -> str:  # pyright: ignore[reportUnusedFunction]
    from recon_tool.fingerprints import load_fingerprints

    payload = [
        {
            "slug": fp.slug,
            "name": fp.name,
            "category": fp.category,
            "confidence": fp.confidence,
            "m365": fp.m365,
            "match_mode": fp.match_mode,
            "provider_group": fp.provider_group,
            "display_group": fp.display_group,
            "detection_count": len(fp.detections),
            "detection_types": sorted({d.type for d in fp.detections}),
        }
        for fp in load_fingerprints()
    ]
    return json_mod.dumps(
        {"count": len(payload), "fingerprints": payload},
        indent=2,
    )


@mcp.resource(
    "recon://signals",
    name="Signal catalog",
    description=(
        "Derived intelligence signals recon can emit, as JSON. Each entry "
        "carries name, category, confidence, description, min_matches, "
        "candidate slugs, contradicts/requires relationships, and the "
        "positive-when-absent inversion set. Use to answer 'what higher-"
        "order observations can recon derive from fingerprint matches?'."
    ),
    mime_type="application/json",
)
def _resource_signals() -> str:  # pyright: ignore[reportUnusedFunction]
    from recon_tool.signals import load_signals

    payload = [
        {
            "name": sig.name,
            "category": sig.category,
            "confidence": sig.confidence,
            "description": sig.description,
            "candidates": list(sig.candidates),
            "min_matches": sig.min_matches,
            "contradicts": list(sig.contradicts),
            "requires_signals": list(sig.requires_signals),
            "expected_counterparts": list(sig.expected_counterparts),
            "positive_when_absent": list(sig.positive_when_absent),
            "explain": sig.explain,
        }
        for sig in load_signals()
    ]
    return json_mod.dumps(
        {"count": len(payload), "signals": payload},
        indent=2,
    )


@mcp.resource(
    "recon://profiles",
    name="Posture profile catalog",
    description=(
        "Built-in posture profile lenses as JSON. Each entry carries name, "
        "description, focus categories, category/signal boost multipliers, "
        "excluded signals, and any profile-specific note. Use to answer "
        "'which posture lens fits this target?' before calling "
        "analyze_posture with a profile argument."
    ),
    mime_type="application/json",
)
def _resource_profiles() -> str:  # pyright: ignore[reportUnusedFunction]
    from recon_tool.profiles import list_profiles

    payload = [
        {
            "name": prof.name,
            "description": prof.description,
            "focus_categories": list(prof.focus_categories),
            "category_boost": dict(prof.category_boost),
            "signal_boost": dict(prof.signal_boost),
            "exclude_signals": list(prof.exclude_signals),
            "prepend_note": prof.prepend_note,
        }
        for prof in list_profiles()
    ]
    return json_mod.dumps(
        {"count": len(payload), "profiles": payload},
        indent=2,
    )


@mcp.resource(
    "recon://schema",
    name="JSON output schema",
    description=(
        "The recon JSON-output contract as a JSON Schema, the same document "
        "published at docs/recon-schema.json. Use it to self-describe the "
        "shape of `recon <domain> --json` output (and the batch / delta modes "
        "in its $defs) without an external fetch. The schema's own description "
        "field states the contract version and the additive-change policy."
    ),
    mime_type="application/json",
)
def _resource_schema() -> str:  # pyright: ignore[reportUnusedFunction]
    from recon_tool.schema_contract import packaged_schema_text

    return packaged_schema_text()


def _lookup_tenant_gws_lines(info: TenantInfo) -> list[str]:
    """Google Workspace auth + module lines for the text format; empty when not GWS."""
    gws_slugs = set(info.slugs)
    is_gws = any(s.lower().startswith("google workspace") for s in info.services) or "google-workspace" in gws_slugs
    if not is_gws:
        return []
    lines: list[str] = []
    if info.google_auth_type:
        auth_label = info.google_auth_type
        if info.google_idp_name:
            auth_label += f" ({info.google_idp_name})"
        lines.append(f"GWS Auth: {auth_label}")
    gws_modules = [s.replace("Google Workspace: ", "") for s in info.services if s.startswith("Google Workspace: ")]
    if gws_modules:
        lines.append(f"GWS Modules: {', '.join(gws_modules)}")
    return lines


def _lookup_tenant_text(info: TenantInfo) -> str:
    """Render the default human-readable text format for ``lookup_tenant``."""
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
    lines.extend(_lookup_tenant_gws_lines(info))
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
async def lookup_tenant(
    domain: str,
    format: str = "text",
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
        if not _rate_limit_try_acquire(validated):
            cached = _cache_get(validated)
            if cached is None:
                return f"Rate limited: {domain} was looked up recently. Try again in a few seconds."
            info, results = cached
        else:
            try:
                info, results = await server_app.resolve_tenant(validated)
            except ReconLookupError as exc:
                _rate_limit_release(validated)
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
                _rate_limit_release(validated)
                elapsed = time.monotonic() - start_time
                logger.exception(
                    "Unexpected error looking up %s (request_id=%s)",
                    domain,
                    request_id,
                )
                return f"Error looking up {domain}: an internal error occurred"

            _cache_set(validated, info, results)

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
    return _lookup_tenant_text(info)


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
) -> list[dict[str, Any]] | dict[str, Any]:
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
            adding new intelligence.

    Returns:
        JSON array of observations, each with category, salience, statement,
        and related_slugs. When explain is true, includes explanation data.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    info = await server_app.resolve_single_for_tool(domain, request_id)

    from recon_tool.formatter import format_posture_observations
    from recon_tool.posture import analyze_posture as _analyze_posture
    from recon_tool.profiles import apply_profile, list_profiles, load_profile

    observations = _analyze_posture(info)

    # Apply profile lens if requested. ``profile`` is typed
    # ``str | None``, but MCP arguments arrive unenforced at runtime (the same
    # caveat the detection-list guard below notes), so a truthy non-string would
    # raise ``TypeError`` on the ``profile[:100]`` slice. Guard the type and
    # treat a non-string as no lens, matching the ``None`` case.
    profile_note: str | None = None
    if isinstance(profile, str) and profile:  # pyright: ignore[reportUnnecessaryIsInstance]
        profile = profile[:100]
        prof = load_profile(profile)
        if prof is None:
            available = ", ".join(p.name for p in list_profiles()) or "(none)"
            raise ToolError(f"Unknown profile {profile!r}. Available profiles: {available}")
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
        payload: dict[str, Any] = {"observations": result_list, "explanations": explanations}
        if profile_note:
            payload["profile_note"] = profile_note
        return payload

    if profile_note:
        return {"observations": result_list, "profile_note": profile_note}
    return result_list


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

    # Rate limit: chain_lookup is the most expensive tool (up to
    # MAX_CHAIN_DOMAINS resolves per call), so an untrusted MCP caller
    # could otherwise use it to amplify outbound DNS/HTTP. Gate it on the
    # same per-domain limiter the single-domain tools use; release the
    # slot on error so a transient failure does not block a legitimate
    # retry.
    if not _rate_limit_try_acquire(validated):
        return f"Rate limited: {domain} was looked up recently. Try again in a few seconds."

    try:
        from recon_tool.chain import chain_resolve
        from recon_tool.formatter import format_chain_json

        report = await chain_resolve(validated, depth=depth)
    except Exception:
        _rate_limit_release(validated)
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
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def discover_fingerprint_candidates(
    domain: str,
    skip_ct: bool = False,
    keep_intra_org: bool = False,
    min_count: int = 1,
) -> list[dict[str, Any]]:
    """Mine a single domain for new-fingerprint candidates.

    Bundles ``recon discover`` into one tool call: resolves the domain with
    unclassified-CNAME-chain capture, applies intra-org and already-covered
    filters, and returns a ranked candidate list ready for triage. Each
    surviving entry is a real third-party SaaS or infrastructure pattern
    that recon does not yet recognize — propose it as a new ``cname_target``
    fingerprint or an extension of an existing one.

    Use after a regular ``lookup_tenant`` call when you notice unclassified
    subdomains in the result, or proactively on any domain where you want
    to grow the catalogue. Pair with the ``/recon-fingerprint-triage``
    Claude Code skill (or apply the same triage rubric inline) to turn the
    output into YAML stanzas for ``recon_tool/data/fingerprints/surface.yaml``.

    Args:
        domain: A domain name to mine (e.g., ``contoso.com``).
        skip_ct: When true, skip cert-transparency providers (crt.sh,
            CertSpotter). Discovery falls back to common-subdomain probes
            and apex CNAME walks. Use for high-volume runs.
        keep_intra_org: When true, retain CNAME chains that look intra-
            organizational. Default ``false`` — false-positive prone but
            more inclusive when ``true``.
        min_count: Drop suffixes seen fewer than N times. Default 1 — for
            single-domain runs, every distinct chain matters.

    Returns:
        JSON array of candidate dicts: ``[{suffix, count, samples: [{subdomain,
        terminal, chain}]}, ...]``. Sorted by count desc, then suffix.
    """
    from pathlib import Path

    from recon_tool.discovery import find_candidates

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
        raise ToolError(str(exc)) from exc

    # Mirror the lookup_tenant cache + per-domain rate-limit pattern so a
    # prompt-injected MCP client cannot force repeated full resolutions
    # against the same domain. Cache is keyed on validated domain only;
    # ``skip_ct`` doesn't shard because a cached result with CT data is
    # still usable for discover (the unclassified CNAME chains are the
    # discover surface, not the CT subdomain set).
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
        if not _rate_limit_try_acquire(validated):
            cached = _cache_get(validated)
            if cached is None:
                raise ToolError(f"Rate limited: {domain} was looked up recently. Try again in a few seconds.")
            info, _results = cached
        else:
            try:
                info, results = await server_app.resolve_tenant(validated, skip_ct=skip_ct)
            except ReconLookupError as exc:
                _rate_limit_release(validated)
                raise ToolError(str(exc)) from exc
            except Exception as exc:
                _rate_limit_release(validated)
                logger.exception(
                    "Unexpected error in discover for %s (request_id=%s)",
                    domain,
                    request_id,
                )
                raise ToolError(f"Error mining {domain}: an internal error occurred") from exc

            _cache_set(validated, info, list(results))

    unclassified = [{"subdomain": uc.subdomain, "chain": list(uc.chain)} for uc in info.unclassified_cname_chains]
    fingerprints_dir = Path(__file__).resolve().parent / "data" / "fingerprints"
    candidates = find_candidates(
        [(info.queried_domain, unclassified)],
        fingerprints_dir=fingerprints_dir,
        min_count=min_count,
        drop_intra_org=not keep_intra_org,
    )

    elapsed = time.monotonic() - start_time
    _log_structured(
        logging.INFO,
        "discover_completed",
        request_id=request_id,
        domain=domain,
        unclassified_total=len(unclassified),
        candidate_count=len(candidates),
        elapsed_s=round(elapsed, 2),
    )

    return candidates


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
    # The result cache is cleared because definitions changed. The
    # per-domain rate limiter is intentionally NOT cleared: resetting it
    # here would let a caller bypass the limiter by calling reload_data
    # between lookups of the same domain.

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
    return (
        f"Reloaded: {fp_count} fingerprints, {sig_count} signals, {posture_count} posture rules. "
        "Lookup cache cleared (rate limiter preserved)."
    )


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def assess_exposure(domain: str) -> dict[str, Any]:
    """Assess a domain's publicly observable security posture for defensive review.

    For defensive security posture assessment only.

    Returns a structured JSON object containing email security posture, identity
    posture, infrastructure footprint, configuration consistency observations,
    hardening status, and an overall posture score (0–100) based on publicly
    observable controls.

    The score counts only observed-present controls, so it is a lower bound: the
    ``observability`` block carries ``score_is_lower_bound``,
    ``unconfirmable_absent_points`` (points from controls whose absence the
    passive channel cannot confirm), and ``score_ceiling``. Report the score as
    a floor with its ceiling; a low score can mean "quiet", not "weak".

    Args:
        domain: A domain name to assess (e.g., "northwindtraders.com")

    Returns:
        JSON object with the full exposure assessment, or an error message.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    info = await server_app.resolve_single_for_tool(domain, request_id)

    from recon_tool.exposure import assess_exposure_from_info
    from recon_tool.formatter import format_exposure_dict

    assessment = assess_exposure_from_info(info)

    _log_structured(
        logging.INFO,
        "exposure_assessed",
        request_id=request_id,
        domain=domain,
        posture_score=assessment.posture_score,
        elapsed_s=round(time.monotonic() - start_time, 2),
    )

    return format_exposure_dict(assessment)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def find_hardening_gaps(domain: str) -> dict[str, Any]:
    """Identify hardening opportunities in a domain's public configuration.

    For defensive security posture assessment only.

    Returns a JSON array of hardening gaps, each with category, severity,
    observation, suggested action, supporting evidence references, and an
    ``absence_confirmable`` flag: true when the gap is a confirmed public-records
    fact (a declarative record is absent or observed-weak), false when it rests
    on not observing a hideable control and so may be a false positive. Report a
    false-flagged gap as "not observed", not as a confirmed gap.

    Args:
        domain: A domain name to analyze (e.g., "northwindtraders.com")

    Returns:
        JSON object with the gap report, or an error message.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    info = await server_app.resolve_single_for_tool(domain, request_id)

    from recon_tool.exposure import find_gaps_from_info
    from recon_tool.formatter import format_gaps_dict

    report = find_gaps_from_info(info)

    _log_structured(
        logging.INFO,
        "gaps_analyzed",
        request_id=request_id,
        domain=domain,
        gaps=len(report.gaps),
        elapsed_s=round(time.monotonic() - start_time, 2),
    )

    return format_gaps_dict(report)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def compare_postures(domain_a: str, domain_b: str) -> dict[str, Any]:
    """Compare the security postures of two domains side by side.

    For defensive security posture assessment only.

    Returns a structured comparison with side-by-side metrics,
    control differences, and relative posture assessment.

    Args:
        domain_a: First domain to compare (e.g., "northwindtraders.com")
        domain_b: Second domain to compare (e.g., "contoso.com")

    Returns:
        A structured posture comparison. Raises ToolError (isError) when either
        domain is invalid or cannot be resolved (both must resolve to compare).
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    info_a = await server_app.resolve_single_for_tool(domain_a, request_id)
    info_b = await server_app.resolve_single_for_tool(domain_b, request_id)

    from recon_tool.exposure import compare_postures_from_infos
    from recon_tool.formatter import format_comparison_dict

    comparison = compare_postures_from_infos(info_a, info_b)

    _log_structured(
        logging.INFO,
        "postures_compared",
        request_id=request_id,
        domain_a=domain_a,
        domain_b=domain_b,
        elapsed_s=round(time.monotonic() - start_time, 2),
    )

    return format_comparison_dict(comparison)


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

    # Third pass: absence signals + positive hardening observations
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

    # Structured provenance DAG in parallel with the flat list.
    # Both views are emitted so existing tooling keeps working.
    from recon_tool.explanation import build_explanation_dag

    all_records = [*signal_recs, *insight_recs, conf_rec]
    base["explanation_dag"] = build_explanation_dag(all_records, info.evidence)

    # Include conflicts when present
    if info.merge_conflicts and info.merge_conflicts.has_conflicts:
        base["conflicts"] = serialize_conflicts(info.merge_conflicts)

    return json_mod.dumps(base, indent=2)


# ── Helper: resolve or use cache ────────────────────────────────────────


# ── MCP Introspection Tools ─────────────────────────────────────────────


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def get_fingerprints(
    category: str | None = None, limit: int | None = None, offset: int = 0
) -> list[dict[str, Any]]:
    """List all loaded fingerprints with slugs, categories, and detection types.

    Returns a list of fingerprint summaries from both built-in and custom
    sources. Each entry includes name, slug, category, confidence, match_mode,
    provider_group, display_group, and the set of detection types used. The MCP
    layer surfaces the list as navigable ``structuredContent`` with an
    ``outputSchema``, alongside the serialized-JSON text block for compatibility.

    Args:
        category: Optional category filter (case-insensitive partial match).
        limit: Optional page size. With ~840 fingerprints loaded, an agent that
            only needs a slice can cap the response; omit (default) for the full
            list, which keeps the result shape backward-compatible.
        offset: Starting index for the page (default 0). Ignored without limit.

    Returns:
        A list of fingerprint summaries (a page of it when limit is given).
    """
    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    if category:
        cat_lower = category.lower()
        fps = tuple(fp for fp in fps if cat_lower in fp.category.lower())
    if limit is not None:
        start = max(0, offset)
        fps = fps[start : start + max(0, limit)]
    return [
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
async def get_signals(category: str | None = None, layer: int | None = None) -> list[dict[str, Any]]:
    """List all loaded signals with rules, layers, and conditions.

    Returns a list of signal definitions from both built-in and custom
    sources. Each entry includes name, category, confidence, description,
    candidates, min_matches, metadata conditions, contradicts, requires_signals,
    explain, and computed layer. The MCP layer surfaces the list as navigable
    ``structuredContent`` with an ``outputSchema``, alongside the serialized-JSON
    text block for compatibility.

    Layers: 1=basic, 2=composite (has metadata), 3=consistency, 4=meta (requires_signals).

    Args:
        category: Optional category filter (case-insensitive partial match).
        layer: Optional layer filter (1, 2, 3, or 4).

    Returns:
        A list of signal definitions.
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
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def explain_signal(signal_name: str, domain: str | None = None) -> dict[str, Any]:
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
        raise ToolError(f"Signal '{signal_name}' not found. Available signals: {', '.join(available)}")

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
        return definition

    # Resolve domain and evaluate signal
    resolved = await server_app.resolve_or_cache(domain)
    if isinstance(resolved, str):
        raise ToolError(resolved)

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
    return evaluation


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
async def test_hypothesis(domain: str, hypothesis: str) -> dict[str, Any]:
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
    # Bound the free-text hypothesis so a multi-megabyte argument cannot
    # multiply the per-signal substring scan cost.
    hypothesis = hypothesis[:4000]
    resolved = await server_app.resolve_or_cache(domain)
    if isinstance(resolved, str):
        raise ToolError(resolved)

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
    return result


@dataclass
class _SimState:
    """Mutable simulation state for ``simulate_hardening`` fix application."""

    services: set[str]
    slugs: set[str]
    dmarc: str | None
    mta_sts: str | None


def _apply_dmarc_fix(fix: str, state: _SimState) -> str | None:
    """Apply a DMARC fix; return the applied message, or None when it is a no-op."""
    if "reject" in fix:
        state.dmarc = "reject"
        return "DMARC policy set to reject"
    if "quarantine" in fix:
        if state.dmarc != "reject":
            state.dmarc = "quarantine"
            return "DMARC policy set to quarantine"
        return None
    if state.dmarc is None or state.dmarc == "none":
        state.dmarc = "reject"
        return "DMARC policy set to reject"
    return None


def _apply_mta_sts_fix(fix: str, state: _SimState) -> str | None:
    """Apply an MTA-STS fix; return the applied message, or None when already set.

    Mirrors the original: an explicit "enforce" always applies, while a bare
    "mta-sts" applies only when no mode is currently set.
    """
    if "enforce" in fix or state.mta_sts is None:
        state.mta_sts = "enforce"
        state.services.add("MTA-STS")
        state.slugs.add("mta-sts-enforce")
        return "MTA-STS set to enforce"
    return None


def _apply_one_fix(fix: str, state: _SimState) -> str | None:
    """Apply a single lowercased fix to the simulation state.

    Returns the applied message, or None when the fix is a recognised no-op.
    Keyword precedence mirrors the original elif chain: the first match wins.
    """
    if "dmarc" in fix:
        return _apply_dmarc_fix(fix, state)
    if "dkim" in fix:
        state.services.add("DKIM")
        state.slugs.add("dkim")
        return "DKIM configured"
    if "mta-sts" in fix:
        return _apply_mta_sts_fix(fix, state)
    if "bimi" in fix:
        state.services.add("BIMI")
        state.slugs.add("bimi")
        return "BIMI configured"
    if "spf" in fix and ("strict" in fix or "hardfail" in fix or "-all" in fix):
        state.services.add("SPF: strict (-all)")
        return "SPF set to strict (-all)"
    if "tls-rpt" in fix or "tlsrpt" in fix:
        state.slugs.add("tls-rpt")
        return "TLS-RPT configured"
    if "caa" in fix:
        state.slugs.add("letsencrypt")
        return "CAA records configured"
    # Note the unrecognized fix, but sanitize and bound the caller-supplied
    # string so it cannot inject control sequences into the response.
    return f"Unrecognized fix: {strip_control_chars(fix)[:80]}"


def _simulate_fixes(fixes_lower: list[str], info: TenantInfo) -> tuple[list[str], _SimState]:
    """Apply each fix to a fresh simulation state seeded from ``info``."""
    state = _SimState(
        services=set(info.services),
        slugs=set(info.slugs),
        dmarc=info.dmarc_policy,
        mta_sts=info.mta_sts_mode,
    )
    applied: list[str] = []
    for fix in fixes_lower:
        message = _apply_one_fix(fix, state)
        if message is not None:
            applied.append(message)
    return applied, state


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def simulate_hardening(domain: str, fixes: list[str]) -> dict[str, Any]:
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
    # Bound the fix list so a multi-million-element argument cannot drive
    # O(n) work and a proportionally huge response.
    fixes = fixes[:100]
    resolved = await server_app.resolve_or_cache(domain)
    if isinstance(resolved, str):
        raise ToolError(resolved)

    info, _results = resolved

    from recon_tool.exposure import assess_exposure_from_info, find_gaps_from_info

    current_assessment = assess_exposure_from_info(info)
    current_score = current_assessment.posture_score

    # Parse fixes and simulate by mutating a copy of TenantInfo fields
    applied, state = _simulate_fixes([f.lower() for f in fixes], info)

    # Build simulated TenantInfo
    sim_info = TenantInfo(
        tenant_id=info.tenant_id,
        display_name=info.display_name,
        default_domain=info.default_domain,
        queried_domain=info.queried_domain,
        confidence=info.confidence,
        region=info.region,
        sources=info.sources,
        services=tuple(sorted(state.services)),
        slugs=tuple(sorted(state.slugs)),
        auth_type=info.auth_type,
        dmarc_policy=state.dmarc,
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
        mta_sts_mode=state.mta_sts,
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
    return result


# ── Ephemeral Fingerprint MCP Tools ─────────────────────────────────────


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def cluster_verification_tokens(domains: list[str]) -> dict[str, Any]:
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
        raise ToolError("At least one domain is required")

    # Cap and dedup the input, matching the CLI batch path. Without this
    # the MCP tool lets a caller drive unbounded sequential resolves (each
    # distinct domain gets its own rate-limit slot, so the per-domain
    # limiter does not throttle a many-distinct-domain flood) and build a
    # proportionally large response.
    _MAX_CLUSTER_DOMAINS = 100
    seen_keys: set[str] = set()
    deduped: list[str] = []
    for raw in domains:
        key = raw.strip().lower()
        if key and key not in seen_keys:
            seen_keys.add(key)
            deduped.append(raw)
    if len(deduped) > _MAX_CLUSTER_DOMAINS:
        raise ToolError(f"Too many domains: {len(deduped)} distinct (max {_MAX_CLUSTER_DOMAINS})")
    domains = deduped

    domain_tokens: dict[str, tuple[str, ...]] = {}
    errors: list[dict[str, str]] = []

    for raw in domains:
        resolved = await server_app.resolve_or_cache(raw)
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
    return payload


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def get_infrastructure_clusters(domain: str) -> dict[str, Any]:
    """Return the CT co-occurrence community-detection report for a domain.

    Surfaces the same ``infrastructure_clusters`` envelope that ships in
    the default ``--json`` output: cluster membership, modularity score,
    algorithm path, and underlying graph metrics. The report describes
    observable structure — names that co-occur on the same certificates,
    grouped by Louvain community detection — never an ownership claim.

    No new network surface: the report was already computed during the
    last ``lookup_tenant`` (or implicit resolve). This tool just exposes
    what the deterministic graph pass produced.

    Args:
        domain: Domain to look up. Will use the existing TTL cache when
            available; otherwise resolves via the standard pipeline.

    Returns:
        JSON object matching the ``InfrastructureClusterReport`` schema
        in ``docs/recon-schema.json``. The ``algorithm`` field reflects
        which path produced the partition (``louvain`` |
        ``connected_components`` | ``skipped``); ``skipped`` means the
        graph was empty or had no edges. ``partition_stability`` (2.2.0+)
        is the Louvain seed-sweep consensus (mean pairwise adjusted Rand
        index over ``stability_runs`` seeds; null outside the Louvain
        path) — 1.0 means every seed produced the identical partition,
        lower values flag partition degeneracy a single modularity score
        cannot see.
    """
    resolved = await server_app.resolve_or_cache(domain)
    if isinstance(resolved, str):
        raise ToolError(resolved)
    info, _results = resolved
    ic = info.infrastructure_clusters
    if ic is None:
        return {
            "domain": info.queried_domain,
            "algorithm": "skipped",
            "modularity": 0.0,
            "partition_stability": None,
            "stability_runs": 0,
            "node_count": 0,
            "edge_count": 0,
            "clusters": [],
        }
    return {
        "domain": info.queried_domain,
        "algorithm": ic.algorithm,
        "modularity": ic.modularity,
        # 2.2.0 (additive): Louvain seed-sweep consensus (mean pairwise
        # ARI; CAL11). null outside the Louvain path.
        "partition_stability": ic.partition_stability,
        "stability_runs": ic.stability_runs,
        "node_count": ic.node_count,
        "edge_count": ic.edge_count,
        "clusters": [
            {
                "cluster_id": c.cluster_id,
                "size": c.size,
                "members": list(c.members),
                "shared_cert_count": c.shared_cert_count,
                "dominant_issuer": c.dominant_issuer,
            }
            for c in ic.clusters
        ],
    }


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def export_graph(domain: str) -> dict[str, Any]:
    """Return the raw CT co-occurrence graph (nodes + weighted edges).

    Companion to ``get_infrastructure_clusters``: surfaces the underlying
    graph that the Louvain pass partitioned. Nodes are SAN hostnames;
    edges carry the shared-cert count between each pair. Useful for
    Mermaid / GraphViz / CSV rendering pipelines that want to draw the
    structure directly.

    Edges are sorted by weight descending; both nodes and edges are
    capped — see ``recon_tool/infra_graph.MAX_GRAPH_NODES`` and
    ``MAX_EDGES_RETAINED`` for the bounds. ``cluster_assignment`` maps
    every surfaced node to the cluster id from the same report so
    downstream tools can colour the graph by community without re-
    running detection.

    No new network surface — the graph was already built during the
    last ``lookup_tenant``. Read-only exposure of computed state.

    Args:
        domain: Domain whose graph to export. Uses the TTL cache when
            available; otherwise resolves via the standard pipeline.

    Returns:
        JSON object with ``domain``, ``algorithm`` (mirroring the
        cluster report), ``node_count``, ``edge_count``, ``nodes`` (a
        sorted array of hostnames), ``edges`` (array of {source,
        target, shared_cert_count} records), and ``cluster_assignment``
        (object mapping each surfaced node to its cluster_id).
    """
    resolved = await server_app.resolve_or_cache(domain)
    if isinstance(resolved, str):
        raise ToolError(resolved)
    info, _results = resolved
    ic = info.infrastructure_clusters
    if ic is None:
        return {
            "domain": info.queried_domain,
            "algorithm": "skipped",
            "node_count": 0,
            "edge_count": 0,
            "nodes": [],
            "edges": [],
            "cluster_assignment": {},
        }

    cluster_assignment: dict[str, int] = {}
    for cluster in ic.clusters:
        for member in cluster.members:
            cluster_assignment[member] = cluster.cluster_id

    nodes_set: set[str] = set(cluster_assignment)
    for edge in ic.edges:
        nodes_set.add(edge.source)
        nodes_set.add(edge.target)
    nodes_sorted = sorted(nodes_set)

    return {
        "domain": info.queried_domain,
        "algorithm": ic.algorithm,
        "node_count": ic.node_count,
        "edge_count": ic.edge_count,
        "nodes": nodes_sorted,
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "shared_cert_count": e.shared_cert_count,
            }
            for e in ic.edges
        ],
        "cluster_assignment": cluster_assignment,
        "disclaimer": (
            "Graph describes observable certificate SAN co-occurrence. "
            "Edges are co-issuance evidence, not ownership claims."
        ),
    }


@mcp.prompt()
def domain_report(domain: str) -> str:
    """Generate a domain intelligence report.

    Use this to get a comprehensive analysis of a company's email provider,
    tech stack, email security posture, and infrastructure.
    """
    # Strip control bytes so a crafted domain cannot inject newlines or
    # escape sequences into the rendered prompt the agent consumes.
    safe_domain = strip_control_chars(domain)
    return (
        f"Look up {safe_domain} using the lookup_tenant tool with format='markdown', then summarize the key findings."
    )


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
        "=" * 80,
        f"recon MCP Server v{__version__}",
        "",
        "WARNING: This server runs with the privileges of the calling user.",
        "Treat connected AI agents as untrusted input.",
        "Start with manual approvals; only enable auto-approval for tools you",
        "deliberately trust. For production agent use, prefer an isolated",
        "workspace or container with filesystem and network restrictions.",
        "=" * 80,
        "",
        "Listening on stdio transport.",
        f"Loaded {fp_count} fingerprints, {sig_count} signals.",
        "",
        "Available tools (20 total):",
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
        "  get_infrastructure_clusters CT co-occurrence community report (v1.8)",
        "  export_graph                Raw CT co-occurrence graph + cluster map (v1.8)",
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


def _print_tty_misuse_panel() -> None:
    """Tell a human who launched the server in a terminal what to do instead.

    The MCP stdio transport expects JSON-RPC frames on stdin. When a human
    runs the server in a TTY and presses Enter, the loose newline reaches
    the JSON-RPC parser as ``'\\n'`` and surfaces as a Pydantic validation
    error — terrifying-looking, but not actually broken. This panel
    intercepts that case and explains the situation before any framing
    error has a chance to fire.
    """
    import sys

    lines = [
        "=" * 80,
        "recon MCP server — this is NOT an interactive REPL.",
        "=" * 80,
        "",
        "The server speaks JSON-RPC over stdio. It is meant to be launched",
        "by an MCP client (Claude Desktop, Claude Code, Cursor, VS Code,",
        "Windsurf, Kiro), not run by hand at a shell prompt.",
        "",
        "What to do:",
        "  • Configure your client to spawn `recon mcp` and let the client",
        "    drive the JSON-RPC handshake. Per-client scaffolds live under",
        "    the agents/ directory of the recon repo, and config snippets",
        "    are in the README and docs/mcp.md.",
        "  • Run `recon doctor` to verify your install is healthy.",
        "  • Run `recon <domain>` to use the CLI directly.",
        "",
        "Override (for debugging / piping JSON-RPC by hand):",
        "  set RECON_MCP_FORCE_STDIO=1 before launching, and the server",
        "  will start even with a TTY attached.",
        "",
        "=" * 80,
        "",
    ]
    sys.stderr.write("\n".join(lines))
    sys.stderr.flush()


def _stdin_is_tty() -> bool:
    """Return True if stdin looks like an interactive terminal.

    Wrapped in a helper so tests can monkeypatch it without poking at the
    real ``sys.stdin``.
    """
    import sys

    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        # Some embedded environments replace stdin with an object that
        # doesn't implement isatty(), close it outright (ValueError),
        # or hand back a handle in a state that makes the underlying
        # ioctl/GetFileType call fail (OSError). In every case the
        # right answer is "no human at the keyboard" — behave like a
        # client launched us and let the JSON-RPC loop run.
        return False


def _detect_cwd_shadow_install() -> str | None:
    """Return a non-None error message if the recon_tool package was
    loaded from a cwd-shadow path.

    Python's ``-m`` flag prepends the current working directory to
    ``sys.path`` before installed packages (on Python 3.10 — Python 3.11+
    supports ``PYTHONSAFEPATH=1`` / ``-P`` to disable this, which
    ``recon_tool.mcp_doctor`` and ``recon_tool.mcp_install`` now set
    when they spawn / persist the server launch command). A malicious
    workspace that contains ``recon_tool/server.py`` will, on Python 3.10
    or when ``PYTHONSAFEPATH`` is unset, shadow the installed package and
    execute the attacker's code rather than the legitimate install.

    This guard runs at server startup. If the loaded ``recon_tool``
    module's ``__file__`` resolves to a path under the current working
    directory AND that cwd does *not* look like the legitimate recon
    source repository, return an error message. The caller (``main()``)
    prints it and exits with a non-zero status before any tool
    handlers run.

    Legitimate development workflows (running ``python -m recon_tool.server``
    from the source repo) are preserved because the cwd check matches a
    real ``pyproject.toml`` whose ``name`` field is ``recon-tool``.

    Returns ``None`` when the install looks safe, or a human-readable
    error string when shadowing is detected.
    """
    from pathlib import Path

    import recon_tool  # the actually-imported package — what we want to verify

    try:
        pkg_dir = Path(recon_tool.__file__).resolve().parent
    except (AttributeError, OSError):
        # If we can't even resolve the package path, something is far
        # weirder than cwd-shadowing. Don't block startup on it.
        return None

    try:
        cwd = Path.cwd().resolve()
    except (OSError, ValueError):
        # No usable cwd → cwd-shadow attack cannot apply. Don't block.
        return None

    try:
        pkg_dir.relative_to(cwd)
    except ValueError:
        # Package directory is outside cwd. The cwd-prepend attack
        # cannot reach the package; safe.
        return None

    # Package is under cwd. Verify cwd looks like the legitimate
    # recon source checkout. Two signals — pyproject.toml exists at cwd
    # AND its ``[project] name`` is exactly ``recon-tool``. Both
    # required; an attacker who plants a fake pyproject.toml with the
    # right name has done enough work that they could plant arbitrary
    # files anyway, but the joint check raises the bar.
    pyproject = cwd / "pyproject.toml"
    if pyproject.is_file():
        try:
            content = pyproject.read_text(encoding="utf-8")
        except OSError:
            content = ""
        # Tolerate whitespace variations: ``name="recon-tool"``,
        # ``name = "recon-tool"``, etc. The literal substring covers
        # the common cases without pulling in a TOML parser.
        if 'name = "recon-tool"' in content or 'name="recon-tool"' in content:
            return None  # legitimate source checkout

    return (
        "recon mcp server: refusing to start — the recon_tool package "
        f"was loaded from {pkg_dir}, which is under the current working "
        f"directory ({cwd}). This is the cwd-shadow attack pattern "
        "audited in v1.9.3.4: Python's -m flag prepends cwd to sys.path "
        "on Python < 3.11 (and when PYTHONSAFEPATH is unset), so a "
        "malicious workspace containing a recon_tool/ directory would "
        "execute attacker code instead of the installed package.\n"
        "\n"
        "If you intended to run from a legitimate source checkout, the "
        "checkout's pyproject.toml at this directory does not have "
        '`name = "recon-tool"`. Either:\n'
        "  * Run from outside the workspace (cd to your home directory "
        "and re-invoke); or\n"
        "  * Set PYTHONSAFEPATH=1 in the environment (Python 3.11+); or\n"
        "  * Install recon-tool via pip and invoke it as `recon mcp`, "
        "not `python -m recon_tool.server`.\n"
    )


def main() -> None:
    """Run the MCP server with stdio transport.

    Prints a professional startup banner to stderr before
    handing control to the FastMCP loop, and handles Ctrl+C /
    CancelledError / BrokenPipe cleanly so the user sees
    ``"MCP server stopped"`` instead of a raw traceback. The stdio
    transport is still owned by stdout — the banner and shutdown
    message both go to stderr so JSON-RPC framing stays clean.

    When stdin is a TTY (a human running the server directly in a
    shell), prints a misuse panel and exits 0 instead of feeding the
    user's stray newlines into the JSON-RPC parser. Set the env var
    ``RECON_MCP_FORCE_STDIO=1`` to override.
    """
    import os
    import sys

    # Runtime guard against cwd-shadow installs. Runs BEFORE
    # the TTY check so an attacker cannot rely on stdin being non-TTY
    # to bypass the guard. Defense-in-depth on top of the
    # PYTHONSAFEPATH=1 and safe-cwd protections in mcp_doctor/install.
    shadow_error = _detect_cwd_shadow_install()
    if shadow_error is not None:
        sys.stderr.write(shadow_error)
        sys.stderr.flush()
        sys.exit(EXIT_VALIDATION)

    force_stdio_raw = os.environ.get("RECON_MCP_FORCE_STDIO", "").strip().lower()
    if _stdin_is_tty() and force_stdio_raw not in {"1", "true", "yes", "on"}:
        _print_tty_misuse_panel()
        return

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
    except Exception as exc:
        # Any other unexpected failure: log a one-line summary, not
        # a traceback. Users see a calm error, not a Python scream.
        sys.stderr.write(f"\nMCP server exited unexpectedly: {exc}\n")
        sys.stderr.flush()
        raise SystemExit(EXIT_ERROR) from exc


# ── Bayesian fusion MCP tools (v1.9, stable v2.0+) ─────────────────────


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def get_posteriors(domain: str) -> dict[str, Any]:
    """Compute v1.9 Bayesian-network posteriors over high-level claims.

    Runs a normal recon lookup (cached + rate-limited like ``lookup_tenant``),
    then layers the Bayesian network at
    ``recon_tool/data/bayesian_network.yaml`` over the resulting evidence
    set. Returns a JSON object with one entry per node:

      ``name`` (str), ``description`` (str),
      ``posterior`` (float in [0, 1]),
      ``interval_low`` / ``interval_high`` (float, 80% credible interval),
      ``evidence_used`` (list of slug/signal bindings that fired),
      ``n_eff`` (effective sample size used to derive the interval),
      ``sparse`` (bool — True flags the passive-observation ceiling),
      ``entropy_reduction_nats`` (float, 2.2.0+ — this node's share of the
      information the channel recovered, signed),
      ``unit_counterfactuals`` (list, 2.2.0+ — exact leave-one-unit-out
      re-inference per informative evidence unit: ``unit``, ``kind``,
      ``observed`` ("fired"/"absent"), ``posterior_without``, ``delta``;
      an evidence counterfactual over the model, never a causal claim,
      and deltas are not additive across units).

    The top level also carries ``sparse_count`` (how many nodes are sparse,
    i.e. resolved only to the passive-observation ceiling) beside
    ``evidence_count`` and ``conflict_count``.

    How to read it: each node's answer is the *interval*, not the point
    ``posterior``. ``sparse=true``, a 0.5-straddling interval, or an empty
    ``evidence_used`` means the passive channel could not resolve the claim —
    report it unresolved, do not collapse it to the point value. Absence of a
    fired signal is not evidence of absence (the adversarial missing-data rule);
    a low or sparse posterior reads as "we cannot tell", not "not present".

    Stable v2.0+. The Beta layer (``slug_confidences`` on
    ``lookup_tenant``) operates on raw evidence weights; this network
    layer propagates through chained claims and adds the per-node
    posterior + credible interval.

    Args:
        domain: Apex domain to evaluate (e.g. ``contoso.com``).

    Returns:
        JSON string with the posterior block for the queried domain.
    """
    from recon_tool.bayesian import infer_from_tenant_info

    request_id = uuid.uuid4().hex[:12]
    info = await server_app.resolve_single_for_tool(domain, request_id)

    inference = infer_from_tenant_info(info)
    payload: dict[str, Any] = {
        "domain": info.queried_domain,
        "entropy_reduction_nats": inference.entropy_reduction,
        "evidence_count": inference.evidence_count,
        "conflict_count": inference.conflict_count,
        # Tool-level uncertainty summary so a linear consumer sees how many
        # nodes the passive channel could not resolve before reading any point
        # estimate (see the "Reading the posteriors" server instruction).
        "sparse_count": sum(1 for p in inference.posteriors if p.sparse),
        "posteriors": [
            {
                "name": p.name,
                "description": p.description,
                "posterior": p.posterior,
                "interval_low": p.interval_low,
                "interval_high": p.interval_high,
                "evidence_used": list(p.evidence_used),
                "n_eff": p.n_eff,
                "sparse": p.sparse,
                # 2.2.0 evidence-semantics diagnostics (additive): the
                # node's share of the recovered information, and the exact
                # leave-one-unit-out counterfactual per informative unit.
                "entropy_reduction_nats": p.entropy_reduction_nats,
                "unit_counterfactuals": [
                    {
                        "unit": c.unit,
                        "kind": c.kind,
                        "observed": c.observed,
                        "posterior_without": c.posterior_without,
                        "delta": c.delta,
                    }
                    for c in p.unit_counterfactuals
                ],
            }
            for p in inference.posteriors
        ],
    }
    return payload


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def explain_dag(domain: str, output_format: str = "text") -> str:
    """Render the v1.9 Bayesian evidence DAG for a domain.

    Produces a human-readable narrative of the inference: each node's
    posterior, the evidence that fired, and the parent dependencies
    that shaped it. Pair with ``get_posteriors`` when you want both
    the structured posteriors and the prose explanation.

    Stable v2.0+. Output language stays hedged — "the posterior
    places X at probability ..." rather than "X is true". Sparse-
    evidence nodes are flagged so the consumer doesn't over-interpret
    a confident-looking number.

    Args:
        domain: Apex domain to evaluate.
        output_format: ``"text"`` (default, plain English) or ``"dot"``
            (Graphviz DOT for image rendering).

    Returns:
        Rendered DAG as a string in the requested format.
    """
    from recon_tool.bayesian import infer_from_tenant_info, load_network
    from recon_tool.bayesian_dag import render_dag_dot, render_dag_text

    request_id = uuid.uuid4().hex[:12]

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

    fmt = (output_format or "text").lower()
    if fmt not in ("text", "dot"):
        return f"Error: output_format must be 'text' or 'dot', got {output_format!r}"

    cached = _cache_get(validated)
    if cached is not None:
        info, _results = cached
    else:
        if not _rate_limit_try_acquire(validated):
            cached = _cache_get(validated)
            if cached is None:
                return f"Rate limited: {domain} was looked up recently. Try again in a few seconds."
            info, _results = cached
        else:
            try:
                info, results = await server_app.resolve_tenant(validated)
            except ReconLookupError as exc:
                _rate_limit_release(validated)
                return f"Error: {exc}"
            except Exception:
                _rate_limit_release(validated)
                logger.exception(
                    "Unexpected error in explain_dag for %s (request_id=%s)",
                    domain,
                    request_id,
                )
                return f"Error rendering DAG for {domain}: an internal error occurred"
            _cache_set(validated, info, list(results))

    network = load_network()
    inference = infer_from_tenant_info(info, network=network)
    if fmt == "dot":
        return render_dag_dot(network, inference, domain=validated)
    return render_dag_text(network, inference, domain=validated)


if __name__ == "__main__":
    main()
