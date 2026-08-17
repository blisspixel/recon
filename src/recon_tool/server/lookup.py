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
    compact_categorized_services,
    google_workspace_cse_indicators,
    google_workspace_module_indicators,
)
from recon_tool.formatter.layout import compact_subdomain_summary_lines, subdomain_surface_summary_items
from recon_tool.mcp_client.sdk_compat import ToolError, tool_annotations
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
    """Render the default human-readable text format for ``lookup_tenant``.

    The agent gets the same briefing a human does (ADR-0017): it leads with the
    vendor roles (ADR-0015), and cuts insights and related domains to the
    briefing with a note pointing at ``format="json"``, which carries the whole
    record. The surface was a roll call before, joining every insight and every
    related host, which is the drift the panel and ``--plain`` had already fixed.
    """
    from recon_tool.formatter.briefing import build_briefing

    view = build_briefing(info, confidence_mode="hedged", detailed=False)
    source_noun = "source" if view.source_count == 1 else "sources"
    lines = [
        f"Display name: {info.display_name}",
        f"Domain: {info.queried_domain}",
    ]
    if info.default_domain != info.queried_domain:
        lines.append(f"Default domain: {info.default_domain}")
    if view.is_split:
        lines.append(f"Mail: {view.mail}")
        lines.append(f"Identity: {view.identity}")
        lines.append(f"Provider: {view.provider_on_split}")
    else:
        lines.append(f"Provider: {view.provider}")
    if info.tenant_id:
        lines.append(f"Tenant ID: {info.tenant_id}")
    if info.region:
        lines.append(f"Region: {info.region}")
    if info.auth_type:
        lines.append(f"Auth: {info.auth_type}")
    lines.append(f"Confidence: {view.confidence_tier} ({view.source_count} {source_noun})")
    # Compact the evidence-role qualifiers out of the service labels, matching
    # the default panel and --plain (ADR-0012): the agent gets the briefing.
    categorized, _, _ = compact_categorized_services(categorize_services(info))
    service_labels = [service for services in categorized.values() for service in services]
    if service_labels:
        lines.append(f"Services: {', '.join(service_labels)}")
    if view.insights_display:
        lines.append(f"Insights: {' | '.join(view.insights_display)}")
        note = view.insights_note('format="json"')
        if note is not None:
            lines.append(f"  ({note})")
    if info.domain_count > 0:
        lines.append(f"Domains in tenant: {info.domain_count}")
    if view.related_shown:
        lines.append(f"Related domains: {', '.join(view.related_shown)}")
        note = view.related_note('format="json"')
        if note is not None:
            lines.append(f"  ({note})")
    lines.extend(_lookup_tenant_surface_lines(info))
    lines.extend(_lookup_tenant_gws_lines(info))
    if info.degraded_sources:
        lines.append(f"Degraded sources: {', '.join(info.degraded_sources)}")
    return "\n".join(lines)


@mcp.tool(
    annotations=tool_annotations(
        read_only=True,
        destructive=False,
        idempotent=True,
        open_world=True,
    ),
)
async def lookup_tenant(
    domain: str,
    format: str = "text",
    explain: bool = False,
) -> str:
    """Return compact text by default; JSON returns a detailed serialized record.

    The default is agent-readable text. Use ``format="json"`` for serialized
    JSON or ``markdown`` for the full report. Public observations can include
    display label, tenant ID, provider indicators, email-control records, and
    signal correlations.

    Works for any domain. Returns catalogued public SaaS and infrastructure
    indicators plus claim-safe co-observations. A fingerprint match does not
    establish active use, organizational intent, deployment scope, or maturity.

    Queries only public DNS and unauthenticated endpoints. Authoritative DNS
    may observe resolver traffic. MTA-STS is the only default target-owned HTTP
    request; Google CSE and BIMI certificate probes require explicit opt-in.
    No credentials or API keys are required.

    Args:
        domain: A domain name to look up (e.g., alpha.invalid, gamma.invalid).
        format: Output format: "text" (default), "json" (structured), or "markdown" (full report).
        explain: When true, include structured explanations for insights and signals in the response.

    Returns:
        Domain intelligence in the requested format, or an error message.
    """
    output_format = format
    if output_format not in _VALID_FORMATS:
        raise ToolError(f"Error: invalid format {output_format!r}. Must be one of: {', '.join(sorted(_VALID_FORMATS))}")

    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        log_validation_failed(request_id)
        raise ToolError(server_app.invalid_domain_message(exc)) from exc

    # Check cache first - avoids hitting upstream endpoints for repeated lookups
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
        # Rate limit check - only for cache misses (actual network calls)
        if not rate_limit_try_acquire(validated):
            cached = cache_get(validated)
            if cached is None:
                # ToolError so FastMCP marks isError=true; a success-shaped
                # rate-limit string looks like content to untrusted agents.
                raise ToolError(f"Rate limited: {validated} was looked up recently. Try again in a few seconds.")
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
                raise ToolError(server_app.lookup_failure_message(validated, exc)) from exc
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception(
                    "Unexpected error looking up %s (request_id=%s)",
                    validated,
                    request_id,
                )
                raise ToolError(server_app.internal_lookup_error(validated, request_id, exc)) from exc

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
    from recon_tool.fusion_apply import apply_fusion

    info = collection_observable_info(info)
    # Apply the fusion layer so the JSON payload carries the posteriors and
    # slug confidences its schema advertises, matching the CLI's fusion-on
    # default. Deterministic and network-free, so it is safe on the worker
    # thread. The text and markdown surfaces do not render posteriors, so this
    # only changes the JSON payload's populated fields.
    info = apply_fusion(info)
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
    from recon_tool.insight_explanation import InsightExplanationContext
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
        InsightExplanationContext(info.detection_scores, info.insight_claims),
    )
    all_explanations.extend(serialize_explanation(r) for r in insight_recs)

    # Confidence explanation
    conf_rec = explain_confidence(
        collection_observable_results(results),
        info.evidence_confidence,
        info.inference_confidence,
        info.confidence,
        identity_conflict=bool(info.merge_conflicts and info.merge_conflicts.tenant_id),
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
