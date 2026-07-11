"""Introspection MCP resources and tools: catalogs, signals, reload, diagnostics.

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
from typing import cast

from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from typing_extensions import TypedDict

from recon_tool.models import MetadataCondition, ReconLookupError
from recon_tool.server import app as server_app
from recon_tool.server.app import mcp
from recon_tool.server.runtime import (
    cache_clear,
    cache_get,
    cache_set,
    log_structured,
    rate_limit_try_acquire,
)
from recon_tool.validator import validate_domain

logger = logging.getLogger("recon")


class FingerprintSummary(TypedDict):
    """Structured MCP output item for ``get_fingerprints``."""

    name: str
    slug: str
    category: str
    confidence: str
    match_mode: str
    provider_group: str | None
    display_group: str | None
    detection_types: list[str]


class SignalMetadataSummary(TypedDict):
    """Metadata condition shape nested under ``get_signals`` entries."""

    field: str
    operator: str
    value: str | int


class SignalSummary(TypedDict):
    """Structured MCP output item for ``get_signals``."""

    name: str
    category: str
    confidence: str
    description: str
    candidates: list[str]
    min_matches: int
    metadata: list[SignalMetadataSummary]
    contradicts: list[str]
    requires_signals: list[str]
    explain: str
    layer: int


class SignalTriggerConditions(TypedDict):
    """Trigger-condition block returned by ``explain_signal``."""

    candidates: list[str]
    min_matches: int
    metadata: list[SignalMetadataSummary]
    contradicts: list[str]
    requires_signals: list[str]


class SignalEvidenceSummary(TypedDict):
    """Matched evidence item returned by ``explain_signal`` with a domain."""

    source_type: str
    raw_value: str
    rule_name: str
    slug: str


class SignalDefinitionResult(TypedDict):
    """Static ``explain_signal`` result when no domain is supplied."""

    name: str
    category: str
    confidence: str
    description: str
    explain: str
    layer: int
    trigger_conditions: SignalTriggerConditions
    weakening_conditions: list[str]


class SignalEvaluationResult(SignalDefinitionResult):
    """Domain-evaluation ``explain_signal`` result."""

    domain: str
    fired: bool
    matched_slugs: list[str]
    matched_evidence: list[SignalEvidenceSummary]
    domain_weakening_conditions: list[str]


class UnitCounterfactualSummary(TypedDict):
    """Leave-one-unit-out counterfactual item returned by ``get_posteriors``."""

    unit: str
    kind: str
    observed: str
    posterior_without: float
    delta: float


class PosteriorNodeSummary(TypedDict):
    """Per-node posterior summary returned by ``get_posteriors``."""

    name: str
    description: str
    posterior: float
    interval_low: float
    interval_high: float
    evidence_used: list[str]
    n_eff: float
    sparse: bool
    entropy_reduction_nats: float
    unit_counterfactuals: list[UnitCounterfactualSummary]


class PosteriorBlockResult(TypedDict):
    """Top-level posterior block returned by ``get_posteriors``."""

    domain: str
    degraded_sources: list[str]
    collection_masked_units: list[str]
    entropy_reduction_nats: float
    evidence_count: int
    conflict_count: int
    sparse_count: int
    posteriors: list[PosteriorNodeSummary]


class FingerprintCandidateSample(TypedDict):
    """Sample unclassified chain returned by ``discover_fingerprint_candidates``."""

    subdomain: str
    terminal: str
    chain: list[str]


class FingerprintCandidate(TypedDict):
    """Candidate suffix returned by ``discover_fingerprint_candidates``."""

    suffix: str
    count: int
    samples: list[FingerprintCandidateSample]


def _metadata_summary(condition: MetadataCondition) -> SignalMetadataSummary:
    return {"field": condition.field, "operator": condition.operator, "value": condition.value}


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
    from recon_tool.signals import public_signal_names, reportable_signals

    payload = [
        {
            "name": public_label,
            "category": sig.category,
            "confidence": sig.confidence,
            "description": sig.description,
            "candidates": list(sig.candidates),
            "min_matches": sig.min_matches,
            "contradicts": list(sig.contradicts),
            "requires_signals": public_signal_names(sig.requires_signals),
            "expected_counterparts": list(sig.expected_counterparts),
            "positive_when_absent": list(sig.positive_when_absent),
            "explain": sig.explain,
        }
        for sig, public_label in reportable_signals()
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


@mcp.resource(
    "recon://surface-inventory",
    name="Generated surface inventory",
    description=(
        "Generated, non-contractual map of recon's local CLI, MCP, JSON-schema, "
        "and agent-integration surfaces. Use it to choose local commands, tools, "
        "resources, and guidance files without reading repository files or "
        "making network calls."
    ),
    mime_type="application/json",
)
def _resource_surface_inventory() -> str:  # pyright: ignore[reportUnusedFunction]
    from recon_tool.surface_inventory import packaged_surface_inventory_text

    return packaged_surface_inventory_text()


def _dag_collection_prefix(degraded: list[str], masked: list[str], output_format: str) -> str:
    """Render standalone DAG collection provenance without affecting inference."""
    if not degraded:
        return ""
    degraded_text = ", ".join(degraded)
    masked_text = ", ".join(masked) if masked else "none"
    if output_format == "dot":
        return f"// degraded_sources: {degraded_text}\n// collection_masked_units: {masked_text}\n"
    return f"Collection provenance:\n- degraded_sources: {degraded_text}\n- collection-masked units: {masked_text}\n\n"


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
) -> list[FingerprintSummary]:
    """List all loaded fingerprints with slugs, categories, and detection types.

    Returns a list of fingerprint summaries from both built-in and custom
    sources. Each entry includes name, slug, category, confidence, match_mode,
    provider_group, display_group, and the set of detection types used. The MCP
    layer surfaces the list as navigable ``structuredContent`` with an
    ``outputSchema``, alongside the serialized-JSON text block for compatibility.

    Args:
        category: Optional category filter (case-insensitive partial match).
        limit: Optional page size. With 800+ fingerprints loaded, an agent that
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
async def get_signals(category: str | None = None, layer: int | None = None) -> list[SignalSummary]:
    """List reportable public signals with rules, layers, and conditions.

    Returns the public projection of signal definitions from both built-in and
    custom sources. Each entry includes name, category, confidence, description,
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
    from recon_tool.signals import public_signal_names, reportable_signals

    result: list[SignalSummary] = []
    for sig, public_label in reportable_signals():
        sig_layer = _classify_signal_layer(sig)
        if category and category.lower() not in sig.category.lower():
            continue
        if layer is not None and sig_layer != layer:
            continue
        result.append(
            {
                "name": public_label,
                "category": sig.category,
                "confidence": sig.confidence,
                "description": sig.description,
                "candidates": list(sig.candidates),
                "min_matches": sig.min_matches,
                "metadata": [_metadata_summary(m) for m in sig.metadata],
                "contradicts": list(sig.contradicts),
                "requires_signals": public_signal_names(sig.requires_signals),
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
async def explain_signal(
    signal_name: str,
    domain: str | None = None,
) -> SignalDefinitionResult | SignalEvaluationResult:
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
    from recon_tool.signals import public_signal_names, reportable_signals, resolve_reportable_signal

    resolved_signal = resolve_reportable_signal(signal_name)
    if resolved_signal is None:
        available = sorted(label for _, label in reportable_signals())
        raise ToolError(f"Signal '{signal_name}' not found. Available signals: {', '.join(available)}")
    sig, public_label = resolved_signal

    # Build base definition
    definition: SignalDefinitionResult = {
        "name": public_label,
        "category": sig.category,
        "confidence": sig.confidence,
        "description": sig.description,
        "explain": sig.explain,
        "layer": _classify_signal_layer(sig),
        "trigger_conditions": {
            "candidates": list(sig.candidates),
            "min_matches": sig.min_matches,
            "metadata": [_metadata_summary(m) for m in sig.metadata],
            "contradicts": list(sig.contradicts),
            "requires_signals": public_signal_names(sig.requires_signals),
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

    from recon_tool.collection_view import collection_observable_evidence, collection_observable_info
    from recon_tool.email_security import signal_context_from_observable_info, signal_context_metadata
    from recon_tool.signals import evaluate_signals

    info = collection_observable_info(info)
    observable_evidence = collection_observable_evidence(info)
    context = signal_context_from_observable_info(info)
    signal_matches = evaluate_signals(context)
    fired = any(m.name == sig.name for m in signal_matches)
    matched_slugs = [slug for slug in sig.candidates if slug in context.detected_slugs]

    # Build domain-specific weakening conditions
    from recon_tool.explanation import _weakening_conditions_for_signal  # pyright: ignore[reportPrivateUsage]

    context_metadata = signal_context_metadata(context)
    weakening = _weakening_conditions_for_signal(sig, matched_slugs, context_metadata)

    # Collect evidence for matched slugs
    evidence_list: list[SignalEvidenceSummary] = []
    for slug in matched_slugs:
        for ev in observable_evidence:
            if ev.slug == slug:
                evidence_list.append(
                    {
                        "source_type": ev.source_type,
                        "raw_value": ev.raw_value,
                        "rule_name": ev.rule_name,
                        "slug": ev.slug,
                    }
                )

    evaluation: SignalEvaluationResult = {
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
    from recon_tool.signals import Signal, public_signal_names

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
        required = public_signal_names(sig.requires_signals)
        if required:
            conditions.append(f"Requires all of these signals to fire first: {', '.join(required)}")
    return conditions


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
    cache_clear()
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

    log_structured(
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
async def discover_fingerprint_candidates(
    domain: str,
    skip_ct: bool = False,
    keep_intra_org: bool = False,
    min_count: int = 1,
) -> list[FingerprintCandidate]:
    """Mine a single domain for new-fingerprint candidates.

    Bundles ``recon discover`` into one tool call: resolves the domain with
    unclassified-CNAME-chain capture, applies intra-org and already-covered
    filters, and returns a ranked candidate list ready for triage. Each
    surviving entry is a real third-party SaaS or infrastructure pattern
    that recon does not yet recognize — propose it as a new ``cname_target``
    fingerprint or an extension of an existing one.

    Use after a regular ``lookup_tenant`` call when you notice unclassified
    subdomains in the result, or proactively on any domain where you want
    to grow the catalogue. Pair with the ``/recon-fingerprint-triage`` skill
    (or apply the same triage rubric inline) to turn the
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
        log_structured(
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
    cached = cache_get(validated)
    if cached is not None:
        info, _results = cached
        log_structured(
            logging.INFO,
            "cache_hit",
            request_id=request_id,
            domain=validated,
        )
    else:
        if not rate_limit_try_acquire(validated):
            cached = cache_get(validated)
            if cached is None:
                raise ToolError(f"Rate limited: {domain} was looked up recently. Try again in a few seconds.")
            info, _results = cached
        else:
            try:
                info, results = await server_app.resolve_tenant(validated, skip_ct=skip_ct)
            except ReconLookupError as exc:
                raise ToolError(str(exc)) from exc
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception(
                    "Unexpected error in discover for %s (request_id=%s)",
                    domain,
                    request_id,
                )
                raise ToolError(server_app.internal_lookup_error(domain, request_id, exc, action="mining")) from exc

            # Only populate the shared cache with a full (skip_ct=False)
            # resolution. A skip_ct result is CT-degraded (no cert_summary,
            # infrastructure clusters, or CT-derived subdomains); writing it
            # under the shared domain key would poison lookup_tenant, graph,
            # and infrastructure reads for the TTL window. discover still uses
            # the fresh result below; it simply does not share a degraded one.
            if not skip_ct:
                cache_set(validated, info, list(results))

    unclassified = [{"subdomain": uc.subdomain, "chain": list(uc.chain)} for uc in info.unclassified_cname_chains]
    fingerprints_dir = Path(__file__).resolve().parent / "data" / "fingerprints"
    candidates = find_candidates(
        [(info.queried_domain, unclassified)],
        fingerprints_dir=fingerprints_dir,
        min_count=min_count,
        drop_intra_org=not keep_intra_org,
    )

    elapsed = time.monotonic() - start_time
    log_structured(
        logging.INFO,
        "discover_completed",
        request_id=request_id,
        domain=domain,
        unclassified_total=len(unclassified),
        candidate_count=len(candidates),
        elapsed_s=round(elapsed, 2),
    )

    return cast(list[FingerprintCandidate], candidates)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def get_posteriors(domain: str) -> PosteriorBlockResult:
    """Compute v1.9 Bayesian-network posteriors over high-level claims.

    Runs a normal recon lookup (cached + rate-limited like ``lookup_tenant``),
    then layers the Bayesian network at
    ``recon_tool/data/bayesian_network.yaml`` over the resulting evidence
    set. Returns a JSON object with one entry per node:

      ``name`` (str), ``description`` (str),
      ``posterior`` (float in [0, 1], model-relative),
      ``interval_low`` / ``interval_high`` (float, 80% evidence-responsive
      uncertainty band, not a credible or confidence interval),
      ``evidence_used`` (list of slug/signal bindings that fired),
      ``n_eff`` (effective display mass used to derive the band),
      ``sparse`` (bool, True at the display-mass floor),
      ``entropy_reduction_nats`` (float, 2.2.0+, signed marginal entropy
      change, not pointwise information gain),
      ``unit_counterfactuals`` (list, 2.2.0+, exact leave-one-unit-out
      re-inference per informative evidence unit: ``unit``, ``kind``,
      ``observed`` ("fired"/"absent"), ``posterior_without``, ``delta``;
      an evidence counterfactual over the model, never a causal claim,
      and deltas are not additive across units).

    The top level includes ``degraded_sources`` and
    ``collection_masked_units`` so a standalone call preserves collection
    provenance. A masked unit was structurally unobserved and contributed
    neither fired evidence nor declarative absence.

    The top level also carries ``sparse_count`` (how many nodes use the minimum
    display mass) beside
    ``evidence_count`` and ``conflict_count``.

    How to read it: both the mean and band are model-relative diagnostics, not
    facts. ``sparse=true`` means the display mass is at its floor. Absence of a
    hideable signal is ignored by explicit policy, not treated as evidence of
    absence. Inspect evidence and report unresolved when the public channel
    does not support the claim.

    Stable v2.0+. The Beta layer (``slug_confidences`` on
    ``lookup_tenant``) operates on raw evidence weights; this network
    layer propagates through chained claims and adds the per-node model
    posterior plus uncertainty band.

    Args:
        domain: Apex domain to evaluate (e.g. ``contoso.com``).

    Returns:
        JSON string with the posterior block for the queried domain.
    """
    from recon_tool.bayesian import collection_masked_units, infer_from_tenant_info, load_network

    request_id = uuid.uuid4().hex[:12]
    info = await server_app.resolve_single_for_tool(domain, request_id)

    network = load_network()
    inference = infer_from_tenant_info(info, network=network)
    payload: PosteriorBlockResult = {
        "domain": info.queried_domain,
        "degraded_sources": sorted(set(info.degraded_sources)),
        "collection_masked_units": sorted(collection_masked_units(info.degraded_sources, network=network)),
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
    from recon_tool.bayesian import collection_masked_units, infer_from_tenant_info, load_network
    from recon_tool.bayesian_dag import render_dag_dot, render_dag_text

    request_id = uuid.uuid4().hex[:12]

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        log_structured(
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

    cached = cache_get(validated)
    if cached is not None:
        info, _results = cached
    else:
        if not rate_limit_try_acquire(validated):
            cached = cache_get(validated)
            if cached is None:
                return f"Rate limited: {domain} was looked up recently. Try again in a few seconds."
            info, _results = cached
        else:
            try:
                info, results = await server_app.resolve_tenant(validated)
            except ReconLookupError as exc:
                return f"Error: {exc}"
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception(
                    "Unexpected error in explain_dag for %s (request_id=%s)",
                    domain,
                    request_id,
                )
                return server_app.internal_lookup_error(domain, request_id, exc, action="rendering DAG for")
            cache_set(validated, info, list(results))

    network = load_network()
    inference = infer_from_tenant_info(info, network=network)
    degraded = sorted(set(info.degraded_sources))
    masked = sorted(collection_masked_units(degraded, network=network))
    provenance_prefix = _dag_collection_prefix(degraded, masked, fmt)
    if fmt == "dot":
        return provenance_prefix + render_dag_dot(network, inference, domain=validated)
    return provenance_prefix + render_dag_text(network, inference, domain=validated)
