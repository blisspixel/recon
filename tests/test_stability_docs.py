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
