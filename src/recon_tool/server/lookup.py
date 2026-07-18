"""Lookup MCP tool: the primary domain-intelligence panel.

Extracted from server.py (docs/roadmap.md god-file track, app-sharing variant).
Registers its tools on the shared ``mcp`` instance imported from
``recon_tool.server.app``; the server facade imports this module to trigger
registration and re-exports the tool functions for the test surface. Imports
``recon_tool.server.app`` and ``recon_tool.server.runtime``; never the reverse.
"""

from __future__ import annotations

import asyncio
import json as json_mod
import logging
import time
import uuid
from collections.abc import Sequence

from recon_tool.formatter import (
    format_tenant_dict,
    format_tenant_json,
    format_tenant_markdown,
)
from recon_tool.formatter.classify import (
    categorize_services,
    google_workspace_cse_indicators,
    google_workspace_module_indicators,
    provider_line,
)
from recon_tool.formatter.layout import compact_subdomain_summary_lines, subdomain_surface_summary_items
from recon_tool.mcp_client.sdk_compat import ToolAnnotations
from recon_tool.models import ReconLookupError, SourceResult, TenantInfo
from recon_tool.server import app as server_app
from recon_tool.server.app import mcp
from recon_tool.server.runtime import (
    cache_get,
    cache_set,
    log_structured,
    log_validation_failed,
    rate_limit_try_acquire,
)
from recon_tool.validator import validate_domain

logger = logging.getLogger("recon")


_VALID_FORMATS = frozenset({"text", "json", "markdown"})
_TEXT_WIDTH = 88
_SUBDOMAIN_SURFACE_LABEL = "Subdomain surface"


def _lookup_tenant_gws_lines(info: TenantInfo) -> list[str]:
    """Google Workspace auth + module lines for the text format; empty when not GWS."""
    gws_modules = google_workspace_module_indicators(info)
    cse_indicators = google_workspace_cse_indicators(info)
    if not any((info.google_auth_type, info.google_idp_name, gws_modules, cse_indicators)):
        return []
    lines: list[str] = []
    if info.google_auth_type:
        auth_label = info.google_auth_type
        if info.google_idp_name:
            auth_label += f" ({info.google_idp_name})"
        lines.append(f"GWS Auth: {auth_label}")
    if gws_modules:
        lines.append(f"GWS module indicators: {', '.join(gws_modules)}")
    if cse_indicators:
        lines.append(f"GWS CSE configuration indicators: {', '.join(cse_indicators)}")
    return lines


def _lookup_tenant_surface_lines(info: TenantInfo) -> list[str]:
    """Compact text summary of attributed subdomain hosting surfaces."""
    summary_items = subdomain_surface_summary_items(info.surface_attributions)
    if not summary_items:
        return []
    width = _TEXT_WIDTH - len(_SUBDOMAIN_SURFACE_LABEL) - 2
    wrapped = compact_subdomain_summary_lines(summary_items, width=width)
    if not wrapped:
        return []
    lines = [f"{_SUBDOMAIN_SURFACE_LABEL}: {wrapped[0]}"]
    continuation_indent = " " * (len(_SUBDOMAIN_SURFACE_LABEL) + 2)
    lines.extend(f"{continuation_indent}{line}" for line in wrapped[1:])
    return lines


def _lookup_tenant_text(info: TenantInfo) -> str:
    """Render the default human-readable text format for ``lookup_tenant``."""
    provider = provider_line(info)
    source_count = len(info.sources)
    source_noun = "source" if source_count == 1 else "sources"
    lines = [
        f"Display name: {info.display_name}",
        f"Domain: {info.queried_domain}",
        f"Provider: {provider}",
    ]
    if info.default_domain != info.queried_domain:
        lines.insert(2, f"Default domain: {info.default_domain}")
    if info.tenant_id:
        lines.append(f"Tenant ID: {info.tenant_id}")
    if info.region:
        lines.append(f"Region: {info.region}")
    if info.auth_type:
        lines.append(f"Auth: {info.auth_type}")
    lines.append(f"Confidence: {info.confidence.value} ({source_count} {source_noun})")
    categorized = categorize_services(info)
    service_labels = [service for services in categorized.values() for service in services]
    if service_labels:
        lines.append(f"Services: {', '.join(service_labels)}")
    if info.insights:
        lines.append(f"Insights: {' | '.join(info.insights)}")
    if info.domain_count > 0:
        lines.append(f"Domains in tenant: {info.domain_count}")
    if info.related_domains:
        lines.append(f"Related domains: {', '.join(info.related_domains)}")
    lines.extend(_lookup_tenant_surface_lines(info))
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
    """Look up public domain observations including display label, tenant ID,
    provider indicators, email-control records, and signal correlations.

    Works for any domain. Returns catalogued public SaaS and infrastructure
    indicators plus claim-safe co-observations. A fingerprint match does not
    establish active use, organizational intent, deployment scope, or maturity.

    Queries only public, unauthenticated endpoints and DNS records.
    No credentials or API keys required.

    Args:
        domain: A domain name to look up (e.g., alpha.invalid, gamma.invalid).
        format: Output format: "text" (default), "json" (structured), or "markdown" (full report).
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
        log_validation_failed(request_id)
        return f"Error: {exc}"

    # Check cache first — avoids hitting upstream endpoints for repeated lookups
    cached = cache_get(validated)
    if cached is not None:
        info, results = cached
        log_structured(
            logging.INFO,
            "cache_hit",
            request_id=request_id,
            domain=validated,
        )
    else:
        # Rate limit check — only for cache misses (actual network calls)
        if not rate_limit_try_acquire(validated):
            cached = cache_get(validated)
            if cached is None:
                return f"Rate limited: {validated} was looked up recently. Try again in a few seconds."
            info, results = cached
        else:
            try:
                info, results = await server_app.resolve_tenant(validated)
            except ReconLookupError as exc:
                elapsed = time.monotonic() - start_time
                event = "no_data" if exc.error_type == "no_data" else "lookup_failed"
                log_structured(
                    logging.INFO,
                    event,
                    request_id=request_id,
                    domain=validated,
                    elapsed_s=round(elapsed, 2),
                    error=exc.message,
                )
                return server_app.lookup_failure_message(validated, exc)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception(
                    "Unexpected error looking up %s (request_id=%s)",
                    validated,
                    request_id,
                )
                return server_app.internal_lookup_error(validated, request_id, exc)

            cache_set(validated, info, results)

    elapsed = time.monotonic() - start_time
    log_structured(
        logging.INFO,
        "resolved",
        request_id=request_id,
        domain=validated,
        display_name=info.display_name,
        services=len(info.services),
        elapsed_s=round(elapsed, 2),
    )

    return _format_lookup_tenant(info, results, output_format, explain)


def _format_lookup_tenant(
    info: TenantInfo,
    results: Sequence[SourceResult],
    output_format: str,
    explain: bool,
) -> str:
    """Render a resolved tenant in the requested output format.

    Split out of ``lookup_tenant`` so the tool body stays under the branch
    budget; the format dispatch lives here where it can grow independently.
    """
    from recon_tool.collection_view import collection_observable_info

    info = collection_observable_info(info)
    if output_format == "json":
        if explain:
            return _lookup_tenant_json_with_explain(info, list(results))
        return format_tenant_json(info)
    if output_format == "markdown":
        return format_tenant_markdown(info)
    return _lookup_tenant_text(info)


def _lookup_tenant_json_with_explain(info: TenantInfo, results: list[SourceResult]) -> str:
    """Build JSON response for lookup_tenant with explain=True.

    Includes explanations for insights, signals, confidence, and conflicts.
    """
    from recon_tool.absence import evaluate_absence_signals, evaluate_positive_absence
    from recon_tool.collection_view import collection_observable_evidence, collection_observable_results
    from recon_tool.email_security import signal_context_from_tenant_info, signal_context_metadata
    from recon_tool.explanation import (
        explain_confidence,
        explain_insights,
        explain_signals,
        serialize_explanation,
    )
    from recon_tool.models import serialize_conflicts
    from recon_tool.signals import evaluate_signals, load_signals

    base = format_tenant_dict(info)
    observable_evidence = collection_observable_evidence(info)

    context = signal_context_from_tenant_info(info)
    signal_matches = evaluate_signals(context)
    signals = load_signals()

    # Third pass: absence signals + positive hardening observations
    absence_matches = evaluate_absence_signals(signal_matches, signals, context.detected_slugs)
    positive_matches = evaluate_positive_absence(signal_matches, signals, context.detected_slugs)
    all_signal_matches = signal_matches + absence_matches + positive_matches

    context_metadata = signal_context_metadata(context)

    all_explanations: list[dict[str, object]] = []

    # Signal explanations
    signal_recs = explain_signals(
        all_signal_matches,
        signals,
        context.detected_slugs,
        context_metadata,
        observable_evidence,
        info.detection_scores,
    )
    all_explanations.extend(serialize_explanation(r) for r in signal_recs)

    # Insight explanations
    insight_recs = explain_insights(
        list(info.insights),
        frozenset(info.slugs),
        frozenset(info.services),
        observable_evidence,
        info.detection_scores,
    )
    all_explanations.extend(serialize_explanation(r) for r in insight_recs)

    # Confidence explanation
    conf_rec = explain_confidence(
        collection_observable_results(results),
        info.evidence_confidence,
        info.inference_confidence,
        info.confidence,
    )
    all_explanations.append(serialize_explanation(conf_rec))

    base["explanations"] = all_explanations

    # Structured provenance DAG in parallel with the flat list.
    # Both views are emitted so existing tooling keeps working.
    from recon_tool.explanation import build_explanation_dag

    all_records = [*signal_recs, *insight_recs, conf_rec]
    base["explanation_dag"] = build_explanation_dag(all_records, observable_evidence)

    # Include conflicts when present
    if info.merge_conflicts and info.merge_conflicts.has_conflicts:
        base["conflicts"] = serialize_conflicts(info.merge_conflicts)

    return json_mod.dumps(base, indent=2)
