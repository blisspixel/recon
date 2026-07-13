from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from recon_tool.server import mcp

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "docs" / "recon-schema.json"
STABILITY = ROOT / "docs" / "stability.md"


def test_stability_json_field_counts_match_schema() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    text = STABILITY.read_text(encoding="utf-8")
    expected = (
        f"{len(schema['properties'])} top-level properties, "
        f"{len(schema['required'])} required on single-domain success output"
    )

    assert expected in text
    assert not re.search(r"\b47 stable fields\b", text)


def test_stability_mcp_tool_count_matches_registry() -> None:
    text = STABILITY.read_text(encoding="utf-8")
    tools = asyncio.run(mcp.list_tools())

    assert f"All {len(tools)} MCP tools are **stable**" in text


def test_stability_mcp_tool_table_matches_registry() -> None:
    text = STABILITY.read_text(encoding="utf-8")
    listed = set(re.findall(r"\| `(\w+)` \|", text))
    live = {tool.name for tool in asyncio.run(mcp.list_tools())}

    assert listed == live


def _mcp_stability_section() -> str:
    text = STABILITY.read_text(encoding="utf-8")
    start = text.index("### MCP tools")
    end = text.index("### JSON output fields", start)
    return text[start:end]


def test_stability_mcp_parameter_names_match_registry() -> None:
    documented: dict[str, set[str]] = {}
    for line in _mcp_stability_section().splitlines():
        match = re.match(r"\| `([a-z_][a-z0-9_]*)` \| (.+) \|$", line)
        if match:
            documented[match.group(1)] = set(re.findall(r"`([a-z_][a-z0-9_]*)`", match.group(2)))

    live = {tool.name: set(tool.inputSchema.get("properties", {})) for tool in asyncio.run(mcp.list_tools())}
    assert documented == live


def test_stability_fingerprint_pagination_types_and_defaults_match_registry() -> None:
    section = _mcp_stability_section()
    row = next(line for line in section.splitlines() if line.startswith("| `get_fingerprints` |"))
    assert "`category` (str, optional)" in row
    assert "`limit` (int, optional)" in row
    assert "`offset` (int, default 0; used with `limit`)" in row

    tool = next(tool for tool in asyncio.run(mcp.list_tools()) if tool.name == "get_fingerprints")
    properties = tool.inputSchema["properties"]
    assert {schema.get("type") for schema in properties["category"]["anyOf"]} == {"string", "null"}
    assert {schema.get("type") for schema in properties["limit"]["anyOf"]} == {"integer", "null"}
    assert properties["offset"]["type"] == "integer"
    assert properties["offset"]["default"] == 0


def test_stability_stateful_tool_list_matches_annotations() -> None:
    section = _mcp_stability_section()
    start = section.index("**Stateful tools:**")
    end = section.index("All other tools", start)
    documented = set(re.findall(r"^- `([a-z_][a-z0-9_]*)`", section[start:end], flags=re.MULTILINE))
    live: set[str] = set()
    for tool in asyncio.run(mcp.list_tools()):
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is not None
        if tool.annotations.readOnlyHint is False:
            live.add(tool.name)
    assert documented == live
