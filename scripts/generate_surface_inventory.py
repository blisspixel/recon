#!/usr/bin/env python3
"""Generate the derived CLI, MCP, and JSON-schema surface inventory."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from collections.abc import Mapping, Sequence
from importlib import import_module
from pathlib import Path
from typing import Any, cast

import click
import typer

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_OUTPUT = _ROOT / "docs" / "surface-inventory.json"
_DEFAULT_CLI_SURFACE_OUTPUT = _ROOT / "docs" / "cli-surface.md"
_SCHEMA_PATH = _ROOT / "docs" / "recon-schema.json"
_AGENT_GUIDANCE_FILES: tuple[tuple[str, str], ...] = (
    ("AGENTS.md", "portable_agent_guidance"),
    ("agents/README.md", "agent_integration_overview"),
    ("agents/claude-code/README.md", "claude_code_plugin_docs"),
    ("agents/cursor/README.md", "cursor_docs"),
    ("agents/kiro/README.md", "kiro_docs"),
    ("agents/vscode/README.md", "vscode_docs"),
    ("agents/windsurf/README.md", "windsurf_docs"),
    ("agents/claude-code/skills/recon/SKILL.md", "skill"),
    ("agents/claude-code/skills/recon-fingerprint-triage/SKILL.md", "skill"),
)
_AGENT_CLIENT_CONFIGS: tuple[tuple[str, str, str], ...] = (
    ("claude-code", "agents/claude-code/.mcp.json", "plugin_bundle"),
    ("cursor", "agents/cursor/mcp.json", "template"),
    ("kiro", "agents/kiro/mcp.json", "template"),
    ("vscode", "agents/vscode/mcp.json", "template"),
    ("windsurf", "agents/windsurf/mcp_config.json", "template"),
)
_MAINTAINER_CONTEXT_PACKET: tuple[tuple[str, str, bool], ...] = (
    ("README.md", "product_scope_and_usage", False),
    ("AGENTS.md", "portable_agent_guidance", False),
    ("docs/agentic-balance.md", "rules_vs_agentic_boundary", False),
    ("docs/roadmap.md", "current_priority_order", False),
    ("docs/maintainer-validation.md", "validation_loop_boundary", False),
    ("validation/README.md", "local_validation_workspace", False),
    ("docs/.agent/PROGRESS-LOG.md", "local_loop_history", True),
    ("docs/.agent/SKILLS.md", "local_loop_learnings", True),
)
_CLAUDE_PLUGIN_MANIFEST = _ROOT / "agents" / "claude-code" / ".claude-plugin" / "plugin.json"
_ITERATIVE_MCP_TOOLS = {
    "chain_lookup",
    "clear_ephemeral_fingerprints",
    "cluster_verification_tokens",
    "compare_postures",
    "discover_fingerprint_candidates",
    "inject_ephemeral_fingerprint",
    "list_ephemeral_fingerprints",
    "reevaluate_domain",
    "reload_data",
    "simulate_hardening",
    "test_hypothesis",
}


def _normalize_text(value: str) -> str:
    replacements = {
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2192": "->",
        "\u2713": "OK",
    }
    for old, new in replacements.items():
        value = value.replace(old, new)
    return re.sub(r"\s+", " ", value).strip()


def _summary(value: str | None) -> str:
    if not value:
        return ""
    for line in value.splitlines():
        normalized = _normalize_text(line)
        if normalized:
            return normalized
    return ""


def _repo_path(path: Path) -> str:
    return path.relative_to(_ROOT).as_posix()


def _safe_json_value(value: object) -> object:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_safe_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _safe_json_value(item) for key, item in value.items()}
    return str(value)


def _frontmatter_fields(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}

    fields: dict[str, str] = {}
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if ":" not in stripped:
            continue
        key, raw_value = stripped.split(":", 1)
        value = raw_value.strip()
        if value:
            fields[key.strip()] = _normalize_text(value.strip("'\""))
    return fields


def _first_heading(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return _normalize_text(stripped.lstrip("#").strip())
    return ""


def _schema_types(schema: Mapping[str, Any]) -> list[str]:
    schema_type = schema.get("type")
    if isinstance(schema_type, str):
        return [schema_type]
    if isinstance(schema_type, Sequence) and not isinstance(schema_type, str | bytes | bytearray):
        return [str(item) for item in schema_type]
    if "$ref" in schema:
        return [str(schema["$ref"])]
    if "anyOf" in schema:
        values = schema.get("anyOf")
        if isinstance(values, Sequence):
            refs: list[str] = []
            for item in values:
                if isinstance(item, Mapping):
                    refs.extend(_schema_types(item))
            return refs
    return []


def _schema_parameters(schema: Mapping[str, Any] | None) -> list[dict[str, object]]:
    if not schema:
        return []
    raw_required = schema.get("required", ())
    required = (
        {str(item) for item in raw_required}
        if isinstance(raw_required, Sequence) and not isinstance(raw_required, str | bytes | bytearray)
        else set()
    )
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return []

    parameters: list[dict[str, object]] = []
    for name in sorted(str(key) for key in properties):
        raw_property = properties.get(name, {})
        property_schema = raw_property if isinstance(raw_property, Mapping) else {}
        entry: dict[str, object] = {
            "name": name,
            "required": name in required,
            "types": _schema_types(property_schema),
        }
        description = _summary(str(property_schema.get("description", "")))
        if description:
            entry["summary"] = description
        if "default" in property_schema:
            entry["default"] = _safe_json_value(property_schema["default"])
        parameters.append(entry)
    return parameters


def _schema_outline(schema: Mapping[str, Any] | None) -> dict[str, object]:
    if not schema:
        return {"type": None, "required": [], "properties": [], "definition_count": 0}
    properties = schema.get("properties", {})
    definitions = schema.get("$defs", {})
    return {
        "type": schema.get("type"),
        "required": sorted(str(item) for item in schema.get("required", ())),
        "properties": sorted(str(key) for key in properties) if isinstance(properties, Mapping) else [],
        "definition_count": len(definitions) if isinstance(definitions, Mapping) else 0,
    }


def _command_children(command: click.Command) -> Mapping[str, click.Command]:
    commands = getattr(command, "commands", {})
    return commands if isinstance(commands, Mapping) else {}


def _parameter_entry(param: click.Parameter) -> dict[str, object]:
    opts = [str(item) for item in getattr(param, "opts", ())]
    secondary_opts = [str(item) for item in getattr(param, "secondary_opts", ())]
    names = [*opts, *secondary_opts]
    kind = "option" if any(item.startswith("-") for item in names) else "argument"
    if not names:
        names = [param.human_readable_name]
    entry: dict[str, object] = {
        "name": param.name or param.human_readable_name,
        "kind": kind,
        "tokens": names,
        "required": bool(param.required),
        "type": getattr(param.type, "name", str(param.type)),
    }
    default = getattr(param, "default", None)
    if default is not None:
        entry["default"] = _safe_json_value(default)
    if kind == "option":
        entry["is_flag"] = bool(getattr(param, "is_flag", False))
        entry["multiple"] = bool(getattr(param, "multiple", False))
    choices = getattr(param.type, "choices", None)
    if choices:
        entry["choices"] = [str(choice) for choice in choices]
    return entry


def _click_command_entry(tokens: tuple[str, ...], command: click.Command) -> dict[str, object]:
    children = _command_children(command)
    entry: dict[str, object] = {
        "path": list(tokens),
        "usage": "recon" if not tokens else "recon " + " ".join(tokens),
        "kind": "group" if children else "command",
        "summary": _summary(command.help or command.short_help),
        "parameters": [_parameter_entry(param) for param in command.params],
    }
    if children:
        entry["children"] = sorted(children)
    return entry


def _walk_click_commands(tokens: tuple[str, ...], command: click.Command) -> list[dict[str, object]]:
    entries = [_click_command_entry(tokens, command)]
    for name, child in _command_children(command).items():
        entries.extend(_walk_click_commands((*tokens, name), child))
    return entries


def _cli_inventory() -> dict[str, object]:
    from recon_tool.cli import app

    root = cast(click.Command, typer.main.get_command(app))
    return {
        "entrypoint": "recon",
        "commands": _walk_click_commands((), root),
    }


async def _mcp_inventory_async() -> dict[str, object]:
    import_module("recon_tool.server")
    from recon_tool.server_app import mcp

    tools = await mcp.list_tools()
    resources = await mcp.list_resources()
    tool_entries: list[dict[str, object]] = []
    for tool in sorted(tools, key=lambda item: item.name):
        annotations = {}
        if tool.annotations is not None:
            annotations = tool.annotations.model_dump(mode="json", exclude_none=True)
        tool_entries.append(
            {
                "name": tool.name,
                "summary": _summary(tool.description),
                "annotations": annotations,
                "structured_output": tool.outputSchema is not None,
                "input_parameters": _schema_parameters(tool.inputSchema),
                "output_schema": _schema_outline(tool.outputSchema),
            }
        )
    resource_entries = [
        {
            "uri": str(resource.uri),
            "name": resource.name,
            "summary": _summary(resource.description),
            "mime_type": resource.mimeType,
        }
        for resource in sorted(resources, key=lambda item: str(item.uri))
    ]
    return {
        "transport": "stdio",
        "tool_count": len(tool_entries),
        "tools": tool_entries,
        "resource_count": len(resource_entries),
        "resources": resource_entries,
    }


def _mcp_inventory() -> dict[str, object]:
    return asyncio.run(_mcp_inventory_async())


def _json_schema_inventory() -> dict[str, object]:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    properties = schema.get("properties", {})
    definitions = schema.get("$defs", {})
    return {
        "path": "docs/recon-schema.json",
        "id": schema.get("$id"),
        "title": schema.get("title"),
        "required_top_level_fields": list(schema.get("required", ())),
        "top_level_fields": sorted(str(key) for key in properties) if isinstance(properties, Mapping) else [],
        "defs": sorted(str(key) for key in definitions) if isinstance(definitions, Mapping) else [],
    }


def _agent_guidance_inventory() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for relative_path, kind in _AGENT_GUIDANCE_FILES:
        path = _ROOT / relative_path
        text = path.read_text(encoding="utf-8")
        frontmatter = _frontmatter_fields(text)
        entry: dict[str, object] = {
            "path": _repo_path(path),
            "kind": kind,
            "title": _first_heading(text),
        }
        if frontmatter:
            entry["frontmatter"] = frontmatter
        entries.append(entry)
    return entries


def _client_config_inventory() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for client, relative_path, scope in _AGENT_CLIENT_CONFIGS:
        path = _ROOT / relative_path
        payload = json.loads(path.read_text(encoding="utf-8"))
        server_key = "mcpServers" if "mcpServers" in payload else "servers"
        servers = payload.get(server_key, {})
        recon_config: Mapping[str, object] | None = None
        if isinstance(servers, Mapping):
            raw_recon_config = servers.get("recon")
            if isinstance(raw_recon_config, Mapping):
                recon_config = raw_recon_config
        entry: dict[str, object] = {
            "client": client,
            "path": _repo_path(path),
            "scope": scope,
            "server_key": server_key,
            "has_recon_server": recon_config is not None,
        }
        if recon_config is not None:
            entry["command"] = _safe_json_value(recon_config.get("command"))
            entry["args"] = _safe_json_value(recon_config.get("args", []))
            entry["auto_approve_declared"] = "autoApprove" in recon_config
            if "autoApprove" in recon_config:
                entry["auto_approve"] = _safe_json_value(recon_config["autoApprove"])
            if "disabled" in recon_config:
                entry["disabled"] = _safe_json_value(recon_config["disabled"])
        entries.append(entry)
    return entries


def _claude_plugin_inventory() -> dict[str, object]:
    manifest = json.loads(_CLAUDE_PLUGIN_MANIFEST.read_text(encoding="utf-8"))
    return {
        "path": _repo_path(_CLAUDE_PLUGIN_MANIFEST),
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "description": _normalize_text(str(manifest.get("description", ""))),
        "keyword_count": len(manifest.get("keywords", [])),
    }


def _mcp_approval_inventory(mcp_inventory: Mapping[str, object]) -> dict[str, object]:
    raw_tools = mcp_inventory.get("tools", [])
    read_only_tools: list[str] = []
    stateful_tools: list[str] = []
    iterative_tools: list[str] = []

    if isinstance(raw_tools, Sequence) and not isinstance(raw_tools, str | bytes | bytearray):
        for raw_tool in raw_tools:
            if not isinstance(raw_tool, Mapping):
                continue
            name = str(raw_tool.get("name", ""))
            if not name:
                continue
            annotations = raw_tool.get("annotations", {})
            read_only = True
            if isinstance(annotations, Mapping) and "readOnlyHint" in annotations:
                read_only = bool(annotations["readOnlyHint"])
            if read_only:
                read_only_tools.append(name)
            else:
                stateful_tools.append(name)
            if name in _ITERATIVE_MCP_TOOLS:
                iterative_tools.append(name)

    return {
        "source": "live MCP tool annotations",
        "read_only_tools": sorted(read_only_tools),
        "stateful_tools": sorted(stateful_tools),
        "iterative_agent_tools": sorted(iterative_tools),
    }


def _maintainer_context_packet_inventory() -> dict[str, object]:
    files: list[dict[str, object]] = []
    for relative_path, role, optional_local in _MAINTAINER_CONTEXT_PACKET:
        path = _ROOT / relative_path
        entry: dict[str, object] = {
            "path": _repo_path(path),
            "role": role,
            "exists": False if optional_local else path.exists(),
        }
        if optional_local:
            entry["optional_local"] = True
        files.append(entry)
    return {
        "source": "docs/maintainer-loop-runbook.md shared loop contract",
        "stability": "non_contractual_maintainer_loop_context",
        "files": files,
    }


def _agent_surfaces_inventory(mcp_inventory: Mapping[str, object]) -> dict[str, object]:
    return {
        "stability": "non_contractual_generated_inventory",
        "guidance_files": _agent_guidance_inventory(),
        "client_configs": _client_config_inventory(),
        "claude_code_plugin": _claude_plugin_inventory(),
        "mcp_approval": _mcp_approval_inventory(mcp_inventory),
        "maintainer_context_packet": _maintainer_context_packet_inventory(),
    }


def build_inventory() -> dict[str, object]:
    """Build the derived inventory without reading any target data."""
    mcp_inventory = _mcp_inventory()
    return {
        "schema_version": 1,
        "stability": "non_contractual_generated_inventory",
        "purpose": (
            "Derived maintainer and agent-author map of recon's local CLI, MCP, "
            "and JSON-schema surfaces. This is a drift guard, not a runtime API contract."
        ),
        "sources": [
            "src/recon_tool/cli.py",
            "src/recon_tool/server*.py",
            "docs/recon-schema.json",
            "AGENTS.md",
            "agents/**",
        ],
        "private_data_policy": "Contains no target-domain output, corpus lines, tenant IDs, or validation results.",
        "cli": _cli_inventory(),
        "mcp": mcp_inventory,
        "json_schema": _json_schema_inventory(),
        "agent_surfaces": _agent_surfaces_inventory(mcp_inventory),
    }


def render_inventory_json() -> str:
    return json.dumps(build_inventory(), indent=2, sort_keys=True) + "\n"


def _markdown_cell(value: object) -> str:
    text = _normalize_text(str(value))
    return text.replace("|", "\\|")


def _markdown_code(value: object) -> str:
    text = _markdown_cell(value)
    escaped = text.replace("`", "\\`")
    return f"`{escaped}`"


def _command_sort_key(command: Mapping[str, object]) -> tuple[int, str]:
    path = command.get("path", [])
    path_length = len(path) if isinstance(path, Sequence) and not isinstance(path, str | bytes | bytearray) else 0
    return path_length, str(command.get("usage", ""))


def _command_anchor(command: Mapping[str, object]) -> str:
    usage = str(command.get("usage", "recon"))
    return re.sub(r"[^a-z0-9]+", "-", usage.lower()).strip("-")


def _format_default(parameter: Mapping[str, object]) -> str:
    if "default" not in parameter:
        return ""
    default = parameter["default"]
    if isinstance(default, bool):
        return "true" if default else "false"
    if isinstance(default, str):
        return default
    return json.dumps(default, sort_keys=True)


def _tokens_markdown(parameter: Mapping[str, object]) -> str:
    tokens = parameter.get("tokens", [])
    if not isinstance(tokens, Sequence) or isinstance(tokens, str | bytes | bytearray):
        return ""
    return ", ".join(_markdown_code(token) for token in tokens)


def _parameter_table(parameters: object) -> list[str]:
    if not isinstance(parameters, Sequence) or isinstance(parameters, str | bytes | bytearray) or not parameters:
        return ["No parameters."]

    lines = [
        "| Name | Kind | Tokens | Required | Type | Default | Choices |",
        "|---|---|---|---|---|---|---|",
    ]
    for parameter in parameters:
        if not isinstance(parameter, Mapping):
            continue
        choices = parameter.get("choices", [])
        if isinstance(choices, Sequence) and not isinstance(choices, str | bytes | bytearray):
            choices_text = ", ".join(_markdown_code(choice) for choice in choices)
        else:
            choices_text = ""
        lines.append(
            "| "
            + " | ".join(
                [
                    _markdown_code(parameter.get("name", "")),
                    _markdown_cell(parameter.get("kind", "")),
                    _tokens_markdown(parameter),
                    "yes" if parameter.get("required") else "no",
                    _markdown_cell(parameter.get("type", "")),
                    _markdown_cell(_format_default(parameter)),
                    choices_text,
                ]
            )
            + " |"
        )
    return lines


def render_cli_surface_markdown() -> str:
    cli = _cli_inventory()
    raw_commands = cli.get("commands", [])
    commands = (
        [command for command in raw_commands if isinstance(command, Mapping)]
        if isinstance(raw_commands, Sequence)
        else []
    )
    commands = sorted(commands, key=_command_sort_key)

    lines = [
        "# CLI Surface",
        "",
        "Generated from the live Typer command tree by `scripts/generate_surface_inventory.py`.",
        "Do not edit by hand.",
        "",
        "This is a derived maintainer and agent-author reference, not a stable runtime API contract.",
        "",
        "## Command Index",
        "",
    ]
    for command in commands:
        usage = str(command.get("usage", ""))
        lines.append(f"- [{_markdown_code(usage)}](#{_command_anchor(command)})")

    for command in commands:
        usage = str(command.get("usage", ""))
        summary = _summary(str(command.get("summary", "")))
        children = command.get("children", [])
        lines.extend(
            [
                "",
                f'<a id="{_command_anchor(command)}"></a>',
                f"## {_markdown_code(usage)}",
                "",
                f"Kind: {_markdown_cell(command.get('kind', ''))}",
            ]
        )
        if summary:
            lines.append(f"Summary: {_markdown_cell(summary)}")
        if isinstance(children, Sequence) and not isinstance(children, str | bytes | bytearray) and children:
            child_text = ", ".join(_markdown_code(child) for child in children)
            lines.append(f"Children: {child_text}")
        lines.extend(["", *_parameter_table(command.get("parameters", []))])

    return "\n".join(lines) + "\n"


def _check_rendered(path: Path, rendered: str, label: str, write_flag: str) -> int:
    if not path.exists():
        print(f"{label} is missing: {path}", file=sys.stderr)
        print(f"run: uv run python scripts/generate_surface_inventory.py {write_flag}", file=sys.stderr)
        return 1
    current = path.read_text(encoding="utf-8")
    if current != rendered:
        print(f"{label} is out of date: {path}", file=sys.stderr)
        print(f"run: uv run python scripts/generate_surface_inventory.py {write_flag}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the derived recon surface inventory.")
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT, help="Inventory path.")
    parser.add_argument(
        "--cli-surface-output", type=Path, default=_DEFAULT_CLI_SURFACE_OUTPUT, help="CLI surface path."
    )
    parser.add_argument("--write", action="store_true", help="Write the inventory file.")
    parser.add_argument("--check", action="store_true", help="Fail if the inventory file is stale.")
    parser.add_argument("--write-cli-surface", action="store_true", help="Write the CLI surface reference.")
    parser.add_argument("--check-cli-surface", action="store_true", help="Fail if the CLI surface reference is stale.")
    args = parser.parse_args(argv)

    rendered = render_inventory_json()
    rendered_cli_surface = render_cli_surface_markdown()
    output = args.output
    if not output.is_absolute():
        output = _ROOT / output
    cli_surface_output = args.cli_surface_output
    if not cli_surface_output.is_absolute():
        cli_surface_output = _ROOT / cli_surface_output

    status = 0
    if args.check:
        status |= _check_rendered(output, rendered, "surface inventory", "--write")
    if args.check_cli_surface:
        status |= _check_rendered(
            cli_surface_output,
            rendered_cli_surface,
            "CLI surface reference",
            "--write-cli-surface",
        )
    if args.write:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    if args.write_cli_surface:
        cli_surface_output.parent.mkdir(parents=True, exist_ok=True)
        cli_surface_output.write_text(rendered_cli_surface, encoding="utf-8")
    if args.check or args.check_cli_surface or args.write or args.write_cli_surface:
        return status
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
