from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]


def _load_generator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "surface_inventory_generator",
        ROOT / "scripts" / "generate_surface_inventory.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    cast(Any, spec.loader).exec_module(module)
    return module


GENERATOR = _load_generator()


def _inventory() -> dict[str, Any]:
    return cast(dict[str, Any], GENERATOR.build_inventory())


def test_surface_inventory_file_is_current() -> None:
    rendered = cast(str, GENERATOR.render_inventory_json())

    assert (ROOT / "docs" / "surface-inventory.json").read_text(encoding="utf-8") == rendered


def test_cli_surface_markdown_file_is_current() -> None:
    rendered = cast(str, GENERATOR.render_cli_surface_markdown())

    assert (ROOT / "docs" / "cli-surface.md").read_text(encoding="utf-8") == rendered


def test_cli_surface_markdown_has_expected_commands() -> None:
    rendered = cast(str, GENERATOR.render_cli_surface_markdown())

    assert rendered.startswith("# CLI Surface\n")
    assert '<a id="recon-lookup"></a>' in rendered
    assert "## `recon lookup`" in rendered
    assert "`--fusion`, `--no-fusion`" in rendered
    assert "## `recon mcp install`" in rendered
    assert "Summary: Install the recon MCP server config into a client's config file." in rendered


def test_surface_inventory_has_expected_cli_surface() -> None:
    commands = {tuple(command["path"]): command for command in _inventory()["cli"]["commands"]}

    assert commands[()]["kind"] == "group"
    assert commands[("lookup",)]["kind"] == "command"
    assert commands[("mcp", "install")]["usage"] == "recon mcp install"
    assert commands[("fingerprints", "check")]["usage"] == "recon fingerprints check"
    assert commands[("signals", "show")]["usage"] == "recon signals show"

    lookup_params = {param["name"]: param for param in commands[("lookup",)]["parameters"]}
    assert lookup_params["domain"]["kind"] == "argument"
    assert lookup_params["domain"]["required"] is True
    assert lookup_params["fusion"]["tokens"] == ["--fusion", "--no-fusion"]
    assert lookup_params["exact"]["tokens"] == ["--exact"]


def test_surface_inventory_has_expected_mcp_surface() -> None:
    mcp_inventory = _inventory()["mcp"]
    tools = {tool["name"]: tool for tool in mcp_inventory["tools"]}

    assert mcp_inventory["tool_count"] == len(tools)
    assert {"lookup_tenant", "assess_exposure", "get_posteriors", "inject_ephemeral_fingerprint"} <= set(tools)

    lookup = tools["lookup_tenant"]
    lookup_inputs = {param["name"]: param for param in lookup["input_parameters"]}
    assert lookup["structured_output"] is True
    assert lookup["annotations"]["readOnlyHint"] is True
    assert lookup_inputs["domain"]["required"] is True
    assert lookup_inputs["domain"]["types"] == ["string"]
    assert lookup["output_schema"]["properties"] == ["result"]

    assert tools["inject_ephemeral_fingerprint"]["annotations"]["readOnlyHint"] is False


def test_surface_inventory_summarizes_json_schema_contract() -> None:
    schema = _inventory()["json_schema"]

    assert schema["path"] == "docs/recon-schema.json"
    assert "tenant_id" in schema["required_top_level_fields"]
    assert "fingerprint_metadata" in schema["top_level_fields"]
    assert "DeltaReport" in schema["defs"]


def test_surface_inventory_has_agent_surfaces() -> None:
    agent_surfaces = _inventory()["agent_surfaces"]
    guidance_files = {entry["path"]: entry for entry in agent_surfaces["guidance_files"]}
    client_configs = {entry["client"]: entry for entry in agent_surfaces["client_configs"]}

    assert "AGENTS.md" in guidance_files
    assert "agents/claude-code/skills/recon/SKILL.md" in guidance_files
    assert guidance_files["agents/claude-code/skills/recon/SKILL.md"]["frontmatter"]["name"] == "recon"
    assert guidance_files["agents/claude-code/skills/recon-fingerprint-triage/SKILL.md"]["frontmatter"]["name"] == (
        "recon-fingerprint-triage"
    )

    assert client_configs["claude-code"]["server_key"] == "mcpServers"
    assert client_configs["vscode"]["server_key"] == "servers"
    assert client_configs["kiro"]["auto_approve_declared"] is True
    assert client_configs["kiro"]["auto_approve"] == []
    assert client_configs["cursor"]["auto_approve_declared"] is False

    approval = agent_surfaces["mcp_approval"]
    assert approval["stateful_tools"] == [
        "clear_ephemeral_fingerprints",
        "inject_ephemeral_fingerprint",
        "reload_data",
    ]
    assert "lookup_tenant" in approval["read_only_tools"]
    assert {"compare_postures", "reevaluate_domain", "simulate_hardening", "test_hypothesis"} <= set(
        approval["iterative_agent_tools"]
    )

    plugin = agent_surfaces["claude_code_plugin"]
    assert plugin["path"] == "agents/claude-code/.claude-plugin/plugin.json"
    assert plugin["name"] == "recon"


def test_surface_inventory_is_ascii_and_target_free() -> None:
    rendered = cast(str, GENERATOR.render_inventory_json())
    parsed = json.loads(rendered)

    assert parsed["private_data_policy"].startswith("Contains no target-domain output")
    assert "\u2014" not in rendered
    assert "\u2013" not in rendered
    assert "\u2192" not in rendered
    assert not re.search(r"\b[0-9a-f]{8}-[0-9a-f-]{27,36}\b", rendered.lower())
    assert not re.search(r"\b[a-z0-9-]+\.onmicrosoft\.com\b", rendered.lower())


def test_cli_surface_markdown_is_ascii_and_target_free() -> None:
    rendered = cast(str, GENERATOR.render_cli_surface_markdown())

    assert rendered.isascii()
    assert "\u2014" not in rendered
    assert "\u2013" not in rendered
    assert "\u2192" not in rendered
    assert not re.search(r"\b[0-9a-f]{8}-[0-9a-f-]{27,36}\b", rendered.lower())
    assert not re.search(r"\b[a-z0-9-]+\.onmicrosoft\.com\b", rendered.lower())
