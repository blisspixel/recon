"""Pin MCP display titles and server identity.

Clients fall back to ``name`` when a title is missing, so a new tool, resource,
or prompt fails this test until its title is chosen and copied into the
surface inventory and ``docs/mcp.md``. Names stay the stable contract.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from recon_tool.mcp_client.sdk_compat import (
    SDK_FAMILY,
    SERVER_TITLE,
    SERVER_WEBSITE_URL,
    model_wire_dict,
    server_description,
)
from recon_tool.server import mcp
from recon_tool.server.app import mcp as application

_ROOT = Path(__file__).resolve().parents[1]
_DESCRIPTION = (
    "Public-metadata domain intelligence CLI and MCP server using DNS, "
    "certificate transparency, and unauthenticated identity discovery."
)
_TOOL_TITLES = {
    "analyze_posture": "Analyze posture",
    "assess_exposure": "Assess exposure",
    "build_review_bundle": "Build review bundle",
    "chain_lookup": "Follow related domains",
    "clear_ephemeral_fingerprints": "Clear ephemeral fingerprints",
    "cluster_verification_tokens": "Cluster verification tokens",
    "compare_postures": "Compare postures",
    "discover_fingerprint_candidates": "Discover fingerprint candidates",
    "explain_dag": "Explain inference graph",
    "explain_signal": "Explain signal",
    "export_graph": "Export infrastructure graph",
    "find_hardening_gaps": "Find hardening gaps",
    "get_fingerprints": "List fingerprints",
    "get_infrastructure_clusters": "List infrastructure clusters",
    "get_posteriors": "Read posteriors",
    "get_signals": "List signals",
    "inject_ephemeral_fingerprint": "Inject ephemeral fingerprint",
    "list_ephemeral_fingerprints": "List ephemeral fingerprints",
    "lookup_tenant": "Look up domain",
    "reevaluate_domain": "Reevaluate cached domain",
    "reload_data": "Reload catalogs",
    "simulate_hardening": "Simulate hardening",
    "test_hypothesis": "Test hypothesis",
}
_RESOURCE_TITLES = {
    "recon://fingerprints": "List fingerprint catalog",
    "recon://signals": "List signal catalog",
    "recon://profiles": "List posture profiles",
    "recon://schema": "Read output schema",
    "recon://review-bundle-schema": "Read review bundle schema",
    "recon://surface-inventory": "Read surface inventory",
}
_PROMPT_TITLES = {"domain_report": "Prepare domain briefing"}


def _titles() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    async def _list() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
        tools = {tool.name: str(model_wire_dict(tool).get("title", "")) for tool in await mcp.list_tools()}
        resources = {
            str(resource.uri): str(model_wire_dict(resource).get("title", ""))
            for resource in await mcp.list_resources()
        }
        prompts = {prompt.name: str(model_wire_dict(prompt).get("title", "")) for prompt in await mcp.list_prompts()}
        return tools, resources, prompts

    return asyncio.run(_list())


def _display_section() -> str:
    text = (_ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")
    start = text.index("## Display metadata")
    end = text.index("## Available Tools", start)
    return text[start:end]


def _tools_section() -> str:
    text = (_ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")
    start = text.index("## Available Tools")
    end = text.index("## Catalog Resources", start)
    return text[start:end]


def test_package_description_is_the_server_summary() -> None:
    pyproject = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'description = "{_DESCRIPTION}"' in pyproject
    assert server_description() == _DESCRIPTION


def test_server_identity_follows_the_installed_sdk_generation() -> None:
    assert application.website_url == SERVER_WEBSITE_URL
    assert not application.icons
    if SDK_FAMILY == "v1":
        return
    assert application.title == SERVER_TITLE
    assert application.description == _DESCRIPTION


def test_live_titles_match_the_pinned_map() -> None:
    tools, resources, prompts = _titles()
    assert tools == _TOOL_TITLES
    assert resources == _RESOURCE_TITLES
    assert prompts == _PROMPT_TITLES


def test_surface_inventory_shows_the_same_titles() -> None:
    inventory = json.loads((_ROOT / "docs" / "surface-inventory.json").read_text(encoding="utf-8"))
    mcp_inventory = inventory["mcp"]
    assert {item["name"]: item["title"] for item in mcp_inventory["tools"]} == _TOOL_TITLES
    assert {item["uri"]: item["title"] for item in mcp_inventory["resources"]} == _RESOURCE_TITLES
    assert {item["name"]: item["title"] for item in mcp_inventory["prompts"]} == _PROMPT_TITLES


def test_docs_show_the_tool_resource_and_prompt_titles() -> None:
    documented_tools: dict[str, str] = {}
    for line in _tools_section().splitlines():
        match = re.match(r"\|\s*`([a-z_][a-z0-9_]*)`[^|]*\|\s*([^|]+)\|", line)
        if match:
            documented_tools[match.group(1)] = match.group(2).strip()
    assert documented_tools == _TOOL_TITLES

    documented_rest: dict[str, str] = {}
    for line in _display_section().splitlines():
        match = re.match(r"\|\s*`([^`]+)`\s*\|\s*([^|]+)\|", line)
        if match:
            documented_rest[match.group(1)] = match.group(2).strip()
    assert documented_rest == {**_RESOURCE_TITLES, **_PROMPT_TITLES}
    assert "recon publishes no icon" in _display_section()
    assert SERVER_WEBSITE_URL in _display_section()
