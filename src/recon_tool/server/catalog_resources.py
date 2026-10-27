"""MCP catalog resources registered on the shared server.

These read-only resources let an agent browse what recon can detect without
spending a tool call. They live outside ``introspection`` so that module stays
under the file-size cap. Importing this module attaches them to ``mcp``.
"""

from __future__ import annotations

import json

from recon_tool.server.app import mcp


@mcp.resource(
    "recon://fingerprints",
    name="Fingerprint catalog",
    title="List fingerprint catalog",
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
    return json.dumps(
        {"count": len(payload), "fingerprints": payload},
        indent=2,
    )


@mcp.resource(
    "recon://signals",
    name="Signal catalog",
    title="List signal catalog",
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
    return json.dumps(
        {"count": len(payload), "signals": payload},
        indent=2,
    )


@mcp.resource(
    "recon://profiles",
    name="Posture profile catalog",
    title="List posture profiles",
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
    return json.dumps(
        {"count": len(payload), "profiles": payload},
        indent=2,
    )


@mcp.resource(
    "recon://schema",
    name="JSON output schema",
    title="Read output schema",
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
    "recon://review-bundle-schema",
    name="Namespace ReviewBundle schema",
    title="Read review bundle schema",
    description=(
        "The separate Draft 2020-12 JSON Schema for NamespaceReviewBundle v1, "
        "byte-identical to docs/review-bundle-schema.json. Use it to validate "
        "artifacts returned by build_review_bundle without an external fetch."
    ),
    mime_type="application/json",
)
def _resource_review_bundle_schema() -> str:  # pyright: ignore[reportUnusedFunction]
    from recon_tool.review_bundle_schema import packaged_review_bundle_schema_text

    return packaged_review_bundle_schema_text()


@mcp.resource(
    "recon://surface-inventory",
    name="Generated surface inventory",
    title="Read surface inventory",
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
