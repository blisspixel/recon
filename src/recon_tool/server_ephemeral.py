"""Ephemeral-fingerprint MCP tools: inject / list / clear, and reevaluate.

Extracted from server.py (docs/roadmap.md god-file track, app-sharing variant).
Registers its tools on the shared ``mcp`` instance imported from server_app;
server.py imports this module to trigger registration and re-exports the tool
functions for the test surface. Imports server_app / server_runtime; never the
reverse.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from typing_extensions import TypedDict

from recon_tool.formatter import format_tenant_dict
from recon_tool.server_app import mcp
from recon_tool.server_runtime import cache, cache_get, cache_refresh_info, remerge_cached_infos
from recon_tool.validator import validate_domain


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
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def reevaluate_domain(domain: str) -> dict[str, Any]:
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
        raise ToolError(f"Re-evaluation failed: {exc}") from exc

    cache_refresh_info(validated, new_info, results)
    return format_tenant_dict(new_info)
