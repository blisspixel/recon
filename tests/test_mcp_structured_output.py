"""Contract guard for the MCP structured-output revision (stable 2025-11-25 spec).

The data tools return objects rather than JSON strings, so FastMCP surfaces them
as navigable ``structuredContent`` with a generated ``outputSchema`` while still
including the serialized-JSON text block for backward compatibility. These tests
pin that contract through the same dispatch the stdio transport uses
(``mcp.call_tool`` / ``mcp.list_tools``), so a regression to string returns or a
dropped schema fails CI.

Narrative tools (lookup_tenant, chain_lookup, reload_data, explain_dag) render
prose/DOT and intentionally stay text; they are not asserted here.
"""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("mcp")

from recon_tool.server import get_fingerprints, get_signals, mcp

# The data tools converted to structured output. Each must advertise an
# outputSchema so a consuming agent can validate the result it gets back.
STRUCTURED_TOOLS = frozenset(
    {
        "get_fingerprints",
        "get_signals",
        "explain_signal",
        "cluster_verification_tokens",
        "get_infrastructure_clusters",
        "export_graph",
        "inject_ephemeral_fingerprint",
        "list_ephemeral_fingerprints",
        "clear_ephemeral_fingerprints",
        "reevaluate_domain",
        "assess_exposure",
        "find_hardening_gaps",
        "compare_postures",
        "analyze_posture",
        "discover_fingerprint_candidates",
        "test_hypothesis",
        "simulate_hardening",
        "get_posteriors",
    }
)


def test_structured_tools_advertise_output_schema() -> None:
    """Every converted data tool exposes an outputSchema in tools/list."""
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    missing = [name for name in STRUCTURED_TOOLS if name in tools and tools[name].outputSchema is None]
    assert not missing, f"these structured tools have no outputSchema: {missing}"


def _array_result_item_schema(tool_name: str) -> dict[str, object]:
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    schema = tools[tool_name].outputSchema
    assert isinstance(schema, dict)
    result = schema["properties"]["result"]
    assert isinstance(result, dict)
    item_ref = result["items"]["$ref"]
    assert isinstance(item_ref, str)
    def_name = item_ref.removeprefix("#/$defs/")
    item_schema = schema["$defs"][def_name]
    assert isinstance(item_schema, dict)
    return item_schema


def _tool_output_schema(tool_name: str) -> dict[str, object]:
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    schema = tools[tool_name].outputSchema
    assert isinstance(schema, dict)
    return schema


def test_get_fingerprints_output_schema_has_precise_items() -> None:
    """The catalog list output schema names the fields on each fingerprint."""
    item_schema = _array_result_item_schema("get_fingerprints")
    properties = item_schema["properties"]

    assert set(item_schema["required"]) == {
        "name",
        "slug",
        "category",
        "confidence",
        "match_mode",
        "provider_group",
        "display_group",
        "detection_types",
    }
    assert properties["slug"]["type"] == "string"
    assert properties["detection_types"]["items"]["type"] == "string"


def test_get_signals_output_schema_has_precise_items() -> None:
    """The signal list output schema names nested metadata conditions."""
    item_schema = _array_result_item_schema("get_signals")
    properties = item_schema["properties"]

    assert set(item_schema["required"]) == {
        "name",
        "category",
        "confidence",
        "description",
        "candidates",
        "min_matches",
        "metadata",
        "contradicts",
        "requires_signals",
        "explain",
        "layer",
    }
    assert properties["candidates"]["items"]["type"] == "string"
    metadata_items = properties["metadata"]["items"]
    assert metadata_items["$ref"] == "#/$defs/SignalMetadataSummary"


def test_ephemeral_fingerprint_output_schemas_are_precise() -> None:
    """Session-local ephemeral tools advertise their simple result shapes."""
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}

    inject_schema = tools["inject_ephemeral_fingerprint"].outputSchema
    assert isinstance(inject_schema, dict)
    assert inject_schema["title"] == "EphemeralInjectionResult"
    assert set(inject_schema["required"]) == {"status", "name", "slug", "detections_accepted"}
    assert inject_schema["properties"]["detections_accepted"]["type"] == "integer"

    clear_schema = tools["clear_ephemeral_fingerprints"].outputSchema
    assert isinstance(clear_schema, dict)
    assert clear_schema["title"] == "EphemeralClearResult"
    assert set(clear_schema["required"]) == {"status", "removed"}
    assert clear_schema["properties"]["removed"]["type"] == "integer"

    item_schema = _array_result_item_schema("list_ephemeral_fingerprints")
    assert set(item_schema["required"]) == {"name", "slug", "category", "confidence", "detection_count"}
    assert item_schema["properties"]["detection_count"]["type"] == "integer"


def test_graph_output_schemas_are_precise() -> None:
    """Graph data tools advertise their stable envelope fields."""
    cluster_schema = _tool_output_schema("cluster_verification_tokens")
    assert cluster_schema["title"] == "VerificationTokenClusterResult"
    assert set(cluster_schema["required"]) == {"clusters", "errors", "disclaimer"}
    cluster_props = cluster_schema["properties"]
    assert cluster_props["clusters"]["additionalProperties"]["items"]["$ref"] == "#/$defs/SharedVerificationPeer"
    assert cluster_props["errors"]["items"]["$ref"] == "#/$defs/DomainToolError"

    infra_schema = _tool_output_schema("get_infrastructure_clusters")
    assert infra_schema["title"] == "InfrastructureClusterEnvelope"
    assert set(infra_schema["required"]) == {
        "domain",
        "algorithm",
        "modularity",
        "partition_stability",
        "stability_runs",
        "node_count",
        "edge_count",
        "clusters",
    }
    infra_props = infra_schema["properties"]
    assert infra_props["clusters"]["items"]["$ref"] == "#/$defs/InfrastructureClusterSummary"

    export_schema = _tool_output_schema("export_graph")
    assert export_schema["title"] == "GraphExportEnvelope"
    assert set(export_schema["required"]) == {
        "domain",
        "algorithm",
        "node_count",
        "edge_count",
        "nodes",
        "edges",
        "cluster_assignment",
        "disclaimer",
    }
    export_props = export_schema["properties"]
    assert export_props["edges"]["items"]["$ref"] == "#/$defs/GraphEdgeSummary"
    assert export_props["cluster_assignment"]["additionalProperties"]["type"] == "integer"


def test_get_fingerprints_emits_navigable_structured_content() -> None:
    """call_tool surfaces the list as real structured data (not a JSON-string
    blob) plus a serialized-JSON text block for back-compat."""
    content, structured = asyncio.run(mcp.call_tool("get_fingerprints", {"limit": 3}))

    # structuredContent is the navigable object, not a stringified blob. FastMCP
    # wraps a top-level list under "result"; the entries are real dicts.
    assert isinstance(structured, dict)
    items = structured["result"]
    assert isinstance(items, list)
    assert items
    assert all(isinstance(entry, dict) for entry in items)
    assert "slug" in items[0]

    # Back-compat: FastMCP also emits the data as text content (one serialized
    # JSON block per list element), so a text-only consumer still sees it.
    assert content, "expected TextContent block(s) for backward compatibility"
    parsed_items = [json.loads(block.text) for block in content]
    assert parsed_items == items


def test_direct_call_returns_python_objects_not_strings() -> None:
    """Calling the tool functions directly yields Python objects, the basis for
    the structured surface (a regression to ``json.dumps`` would return str)."""
    fingerprints = asyncio.run(get_fingerprints(limit=1))
    signals = asyncio.run(get_signals(layer=1))
    assert isinstance(fingerprints, list)
    assert isinstance(signals, list)
