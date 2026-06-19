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


def test_surface_inventory_is_ascii_and_target_free() -> None:
    rendered = cast(str, GENERATOR.render_inventory_json())
    parsed = json.loads(rendered)

    assert parsed["private_data_policy"].startswith("Contains no target-domain output")
    assert "\u2014" not in rendered
    assert "\u2013" not in rendered
    assert "\u2192" not in rendered
    assert not re.search(r"\b[0-9a-f]{8}-[0-9a-f-]{27,36}\b", rendered.lower())
    assert not re.search(r"\b[a-z0-9-]+\.onmicrosoft\.com\b", rendered.lower())
