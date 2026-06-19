#!/usr/bin/env python3
"""Generate the derived CLI, MCP, and JSON-schema surface inventory."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import click
import typer

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_OUTPUT = _ROOT / "docs" / "surface-inventory.json"
_SCHEMA_PATH = _ROOT / "docs" / "recon-schema.json"


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


def _safe_json_value(value: object) -> object:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_safe_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _safe_json_value(item) for key, item in value.items()}
    return str(value)


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
    required = set(schema.get("required", ()))
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

    root = typer.main.get_command(app)
    return {
        "entrypoint": "recon",
        "commands": _walk_click_commands((), root),
    }


async def _mcp_inventory_async() -> dict[str, object]:
    import recon_tool.server  # noqa: F401
    from recon_tool.server_app import mcp

    tools = await mcp.list_tools()
    tool_entries: list[dict[str, object]] = []
    for tool in tools:
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
    return {
        "transport": "stdio",
        "tool_count": len(tool_entries),
        "tools": tool_entries,
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


def build_inventory() -> dict[str, object]:
    """Build the derived inventory without reading any target data."""
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
        ],
        "private_data_policy": "Contains no target-domain output, corpus lines, tenant IDs, or validation results.",
        "cli": _cli_inventory(),
        "mcp": _mcp_inventory(),
        "json_schema": _json_schema_inventory(),
    }


def render_inventory_json() -> str:
    return json.dumps(build_inventory(), indent=2, sort_keys=True) + "\n"


def _check_inventory(path: Path, rendered: str) -> int:
    if not path.exists():
        print(f"surface inventory is missing: {path}", file=sys.stderr)
        print("run: uv run python scripts/generate_surface_inventory.py --write", file=sys.stderr)
        return 1
    current = path.read_text(encoding="utf-8")
    if current != rendered:
        print(f"surface inventory is out of date: {path}", file=sys.stderr)
        print("run: uv run python scripts/generate_surface_inventory.py --write", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the derived recon surface inventory.")
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT, help="Inventory path.")
    parser.add_argument("--write", action="store_true", help="Write the inventory file.")
    parser.add_argument("--check", action="store_true", help="Fail if the inventory file is stale.")
    args = parser.parse_args(argv)

    rendered = render_inventory_json()
    output = args.output
    if not output.is_absolute():
        output = _ROOT / output

    if args.check:
        return _check_inventory(output, rendered)
    if args.write:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        return 0
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
