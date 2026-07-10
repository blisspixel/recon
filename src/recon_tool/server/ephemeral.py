"""Ephemeral-fingerprint MCP tools: inject / list / clear, and reevaluate.

Extracted from server.py (docs/roadmap.md god-file track, app-sharing variant).
Registers its tools on the shared ``mcp`` instance imported from
``recon_tool.server.app``; the server facade imports this module to trigger
registration and re-exports the tool functions for the test surface. Imports
``recon_tool.server.app`` and ``recon_tool.server.runtime``; never the reverse.
"""

from __future__ import annotations

import logging
import uuid
from typing import Literal, cast

from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from typing_extensions import TypedDict

from recon_tool.formatter import format_tenant_dict
from recon_tool.server.app import internal_lookup_error, mcp
from recon_tool.server.runtime import cache, cache_get, cache_refresh_info, remerge_cached_infos
from recon_tool.validator import validate_domain

logger = logging.getLogger("recon")


class EphemeralInjectionResult(TypedDict):
    """Structured MCP output for ``inject_ephemeral_fingerprint``."""

    status: str
    name: str
    slug: str
    detections_accepted: int


class EphemeralFingerprintSummary(TypedDict):
    """Structured MCP output item for ``list_ephemeral_fingerprints``."""

    name: str
    slug: str
    category: str
    confidence: str
    detection_count: int


class EphemeralClearResult(TypedDict):
    """Structured MCP output for ``clear_ephemeral_fingerprints``."""

    status: str
    removed: int


class LookupEvidenceSummary(TypedDict):
    source_type: str
    raw_value: str
    rule_name: str
    slug: str


class LookupConflictCandidate(TypedDict):
    value: str
    source: str
    confidence: Literal["high", "medium", "low"]


class LookupConflictSummary(TypedDict):
    field: str
    candidates: list[LookupConflictCandidate]


class LookupWildcardClusterSummary(TypedDict):
    names: list[str]


class LookupCertBurstSummary(TypedDict):
    window_start: str
    window_end: str
    span_seconds: int
    names: list[str]


class LookupCertSummary(TypedDict):
    cert_count: int
    issuer_diversity: int
    issuance_velocity: int
    newest_cert_age_days: int
    oldest_cert_age_days: int
    top_issuers: list[str]
    wildcard_sibling_clusters: list[LookupWildcardClusterSummary]
    deployment_bursts: list[LookupCertBurstSummary]


class LookupBimiIdentitySummary(TypedDict):
    organization: str
    country: str | None
    state: str | None
    locality: str | None
    trademark: str | None


class LookupNodeConflictSummary(TypedDict):
    field: str
    sources: list[str]
    magnitude: float


class LookupEvidenceRankSummary(TypedDict):
    kind: str
    name: str
    llr: float
    influence_pct: float


class LookupUnitCounterfactualSummary(TypedDict):
    unit: str
    kind: str
    observed: str
    posterior_without: float
    delta: float


class LookupPosteriorObservationSummary(TypedDict):
    name: str
    description: str
    posterior: float
    interval_low: float
    interval_high: float
    evidence_used: list[str]
    n_eff: float
    sparse: bool
    conflict_provenance: list[LookupNodeConflictSummary]
    evidence_ranked: list[LookupEvidenceRankSummary]
    entropy_reduction_nats: float
    unit_counterfactuals: list[LookupUnitCounterfactualSummary]


class LookupChainMotifSummary(TypedDict):
    motif_name: str
    display_name: str
    confidence: Literal["high", "medium", "low"]
    subdomain: str
    chain: list[str]


class LookupInfrastructureClusterSummary(TypedDict):
    cluster_id: int
    size: int
    members: list[str]
    shared_cert_count: int
    dominant_issuer: str | None


class LookupInfrastructureClusterEnvelope(TypedDict):
    algorithm: str
    modularity: float
    partition_stability: float | None
    stability_runs: int
    node_count: int
    edge_count: int
    clusters: list[LookupInfrastructureClusterSummary]


class LookupFingerprintMetadataSummary(TypedDict):
    vendor_domain: str | None
    admin_root: str | None
    relationship_hint: str | None
    relationship_basis: str | None


class LookupSurfaceAttributionSummary(TypedDict):
    subdomain: str
    primary_slug: str
    primary_name: str
    primary_tier: str
    infra_slug: str | None
    infra_name: str | None


class LookupResult(TypedDict):
    """Structured MCP output for ``reevaluate_domain``.

    Mirrors ``format_tenant_dict`` for the default lookup record shape. The
    CLI schema remains the stable external contract; this TypedDict gives MCP
    clients a navigable schema for the same object.
    """

    tenant_id: str | None
    display_name: str
    default_domain: str
    queried_domain: str
    provider: str
    confidence: Literal["high", "medium", "low"]
    evidence_confidence: Literal["high", "medium", "low"]
    inference_confidence: Literal["high", "medium", "low"]
    region: str | None
    auth_type: Literal["Federated", "Managed"] | None
    dmarc_policy: Literal["reject", "quarantine", "none"] | None
    domain_count: int
    sources: list[str]
    services: list[str]
    slugs: list[str]
    insights: list[str]
    tenant_domains: list[str]
    related_domains: list[str]
    partial: bool
    degraded_sources: list[str]
    google_auth_type: Literal["Federated", "Managed"] | None
    google_idp_name: str | None
    mta_sts_mode: Literal["enforce", "testing", "none"] | None
    site_verification_tokens: list[str]
    primary_email_provider: str | None
    likely_primary_email_provider: str | None
    email_gateway: str | None
    dmarc_pct: int | None
    ct_provider_used: str | None
    ct_subdomain_count: int
    ct_cache_age_days: int | None
    ct_attempt_outcome: (
        Literal[
            "cache_hit",
            "live_success",
            "live_rate_limited",
            "breaker_open",
            "live_other_failure",
            "cache_miss",
            "skipped",
        ]
        | None
    )
    slug_confidences: dict[str, float]
    posterior_observations: list[LookupPosteriorObservationSummary]
    email_security_score: int
    cloud_instance: str | None
    tenant_region_sub_scope: Literal["GCC", "DOD", "USGov"] | None
    msgraph_host: Literal["graph.microsoft.com", "graph.microsoft.us"] | None
    lexical_observations: list[str]
    cert_summary: LookupCertSummary | None
    bimi_identity: LookupBimiIdentitySummary | None
    detection_scores: dict[str, Literal["low", "medium", "high"]]
    evidence_conflicts: list[LookupConflictSummary]
    chain_motifs: list[LookupChainMotifSummary]
    infrastructure_clusters: LookupInfrastructureClusterEnvelope
    fingerprint_metadata: dict[str, LookupFingerprintMetadataSummary]
    surface_attributions: list[LookupSurfaceAttributionSummary]
    fusion_enabled: bool
    schema_version: Literal["2.0"]
    record_type: Literal["lookup"]
    evidence: list[LookupEvidenceSummary]


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
) -> EphemeralInjectionResult:
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
    from recon_tool.fingerprints import (
        EphemeralCapacityError,
        _validate_fingerprint,  # pyright: ignore[reportPrivateUsage]
        inject_ephemeral,
        validate_ephemeral_input_size,
    )
    from recon_tool.specificity import evaluate_pattern

    try:
        validate_ephemeral_input_size(
            name=name,
            slug=slug,
            category=category,
            confidence=confidence,
            detection_count=len(detections),
        )
    except EphemeralCapacityError as exc:
        raise ToolError(str(exc)) from exc

    # detections is typed list[dict] but arrives over MCP unenforced; guard at runtime.
    if not all(isinstance(d, dict) for d in detections):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ToolError("Each detection must be a dict with 'type' and 'pattern' keys.")

    fp_dict: dict[str, object] = {
        "name": name,
        "slug": slug,
        "category": category,
        "confidence": confidence,
        "detections": [{"type": d.get("type", ""), "pattern": d.get("pattern", "")} for d in detections],
    }
    validated = _validate_fingerprint(fp_dict, "ephemeral")
    if validated is None:
        raise ToolError(
            f"Validation failed for fingerprint '{name}'. "
            "Check detection types, patterns, and confidence level."
        )

    # Ephemeral injection goes through the same specificity gate
    # as ``recon fingerprints check``. Schema-valid but over-broad
    # patterns (``cname:\.com$``) would false-positive on every
    # subsequent lookup in the session. Blast radius is small
    # (in-memory, per-session) but the gate is cheap and worth enforcing.
    for det in validated.detections:
        verdict = evaluate_pattern(det.pattern, det.type)
        if verdict.threshold_exceeded:
            raise ToolError(
                f"Pattern too broad — {det.type}:{det.pattern!r} matched "
                f"{verdict.matches}/{verdict.corpus_size} "
                f"({verdict.match_rate:.1%}) of the synthetic adversarial "
                f"corpus (>1% threshold). Tighten the regex before injecting."
            )

    try:
        inject_ephemeral(validated)
    except EphemeralCapacityError as exc:
        raise ToolError(str(exc)) from exc
    return {
        "status": "ok",
        "name": validated.name,
        "slug": validated.slug,
        "detections_accepted": len(validated.detections),
    }


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def list_ephemeral_fingerprints() -> list[EphemeralFingerprintSummary]:
    """List all ephemeral fingerprints loaded in the current session.

    Returns a list of fingerprint summaries (navigable ``structuredContent``
    plus the serialized-JSON text block at the MCP layer).
    """
    from recon_tool.fingerprints import get_ephemeral

    return [
        {
            "name": fp.name,
            "slug": fp.slug,
            "category": fp.category,
            "confidence": fp.confidence,
            "detection_count": len(fp.detections),
        }
        for fp in get_ephemeral()
    ]


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def clear_ephemeral_fingerprints() -> EphemeralClearResult:
    """Remove all ephemeral fingerprints from the current session.

    Returns confirmation with the count of fingerprints removed.
    """
    from recon_tool.fingerprints import clear_ephemeral

    count = clear_ephemeral()
    if count > 0 and cache:
        remerge_cached_infos()
    return {"status": "ok", "removed": count}


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def reevaluate_domain(domain: str) -> LookupResult:
    """Re-evaluate a previously looked-up domain against current fingerprints.

    Uses cached raw DNS data from a prior lookup — zero network calls.
    Useful after injecting ephemeral fingerprints to test detection hypotheses.

    Args:
        domain: Domain to re-evaluate (must have been looked up previously).

    Returns:
        Updated domain intelligence as a structured object. Raises ToolError
        (isError) when the domain is invalid or absent from the session cache.
    """
    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc

    cached = cache_get(validated)
    if cached is None:
        raise ToolError(f"No cached data for {domain}. Run lookup_tenant first.")

    _info, results = cached

    # Re-run merge pipeline with current fingerprint set (including ephemeral)
    from recon_tool.merger import merge_results

    try:
        new_info = merge_results(list(results), validated)
    except Exception as exc:
        request_id = uuid.uuid4().hex[:12]
        logger.exception(
            "Re-evaluation merge failed for %s (request_id=%s)",
            domain,
            request_id,
        )
        raise ToolError(
            internal_lookup_error(domain, request_id, exc, action="re-evaluating")
        ) from exc

    cache_refresh_info(validated, new_info, results)
    payload = format_tenant_dict(new_info)
    payload.setdefault("evidence", [])
    return cast(LookupResult, payload)
