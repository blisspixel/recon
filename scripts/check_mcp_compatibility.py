"""Characterize recon against exact MCP SDK pins in isolated environments.

The harness installs the working tree with a validation-only dependency
override under ``.agent/``. It never changes ``pyproject.toml``, ``uv.lock``, or
the active environment. Recon probes are local and network-free after package
installation.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, Literal, TextIO, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_ROOT = REPO_ROOT / ".agent"
DEFAULT_SDK_VERSIONS = ("1.28.1", "2.0.0b1")

ProbeStatus = Literal["pass", "fail", "blocked", "not_applicable"]


@dataclass(frozen=True, slots=True)
class ProbeCheck:
    """One evidence-bearing compatibility check."""

    name: str
    status: ProbeStatus
    detail: str


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Bounded subprocess result used by the isolated environment builder."""

    returncode: int
    stdout: str
    stderr: str


def _bounded_text(value: str, *, limit: int = 800) -> str:
    """Collapse arbitrary diagnostics to one bounded line."""
    collapsed = " ".join(value.split())
    if len(collapsed) <= limit:
        return collapsed
    return f"{collapsed[: limit - 3]}..."


def _exception_detail(exc: BaseException) -> str:
    """Return a stable, bounded exception description without a traceback."""
    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
        exc = exc.exceptions[0]
    message = _bounded_text(str(exc))
    qualified = f"{type(exc).__module__}.{type(exc).__name__}"
    return f"{qualified}: {message}" if message else qualified


def _wire_dict(model: object) -> dict[str, Any]:
    """Normalize v1 camel-case and v2 snake-case models through wire aliases."""
    dump = getattr(model, "model_dump", None)
    if not callable(dump):
        raise TypeError(f"{type(model).__name__} is not an MCP model")
    value = dump(by_alias=True, exclude_none=True)
    if not isinstance(value, dict):
        raise TypeError(f"{type(model).__name__}.model_dump() did not return a dictionary")
    return value


def _distribution_version(name: str) -> str | None:
    try:
        return package_version(name)
    except PackageNotFoundError:
        return None


def _sdk_server_class() -> tuple[type[Any], str]:
    """Return the installed generation's ergonomic server class."""
    try:
        module = importlib.import_module("mcp.server.fastmcp")
        return module.FastMCP, "v1"
    except (ImportError, AttributeError):
        module = importlib.import_module("mcp.server")
        return module.MCPServer, "v2"


async def _probe_sdk_server(server_class: type[Any], family: str) -> tuple[ProbeCheck, ProbeCheck]:
    """Probe SDK registration aliases and sync-handler execution location."""
    server = server_class("recon-sdk-boundary-probe")

    @server.tool()
    def echo(value: str) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"value": value}

    @server.resource("probe://thread")
    def handler_thread() -> str:  # pyright: ignore[reportUnusedFunction]
        return str(threading.get_ident())

    tools = await server.list_tools()
    if len(tools) != 1:
        raise ValueError(f"SDK probe registered {len(tools)} tools instead of 1")
    wire = _wire_dict(tools[0])
    if wire.get("name") != "echo" or not isinstance(wire.get("inputSchema"), dict):
        raise ValueError("tool wire aliases did not preserve name and inputSchema")

    event_loop_thread = threading.get_ident()
    resource_result = await server.read_resource("probe://thread")
    resource_items = list(resource_result)
    if len(resource_items) != 1:
        raise ValueError("SDK thread probe did not return exactly one resource item")
    handler_value = getattr(resource_items[0], "content", None)
    handler_thread_id = int(str(handler_value))
    execution = "event_loop" if handler_thread_id == event_loop_thread else "worker_thread"
    return (
        ProbeCheck("sdk_server_api", "pass", f"family={family} wire_aliases=valid"),
        ProbeCheck("sdk_sync_handler_execution", "pass", f"execution={execution}"),
    )


def _probe_cache_hint_api(family: str) -> ProbeCheck:
    if family == "v1":
        return ProbeCheck("sdk_cache_hint_api", "not_applicable", "legacy protocol has no complete-result cache hints")
    if family != "v2":
        return ProbeCheck("sdk_cache_hint_api", "blocked", "SDK server generation is unavailable")
    try:
        server_module = importlib.import_module("mcp.server")
        cache_hint = server_module.CacheHint
        hint = cache_hint()
        ttl_ms = getattr(hint, "ttl_ms", None)
        scope = getattr(hint, "scope", None)
        if ttl_ms != 0 or scope != "private":
            raise ValueError(f"unexpected defaults ttl_ms={ttl_ms!r} scope={scope!r}")
        return ProbeCheck("sdk_cache_hint_api", "pass", "default ttlMs=0 cacheScope=private")
    except Exception as exc:
        return ProbeCheck("sdk_cache_hint_api", "fail", _exception_detail(exc))


def _blocked_recon_checks(reason: str) -> list[ProbeCheck]:
    names = (
        "recon_registry_order",
        "recon_schema_conformance",
        "recon_direct_structured_success",
        "recon_direct_tool_error",
        "recon_reload_read_concurrency",
        "recon_cache_hint_configuration",
        "recon_stdio_discovery",
        "recon_stdio_listings",
        "recon_stdio_prompt_get",
        "recon_stdio_resource_reads",
        "recon_stdio_structured_success",
        "recon_stdio_tool_error",
        "recon_complete_result_metadata",
        "recon_live_doctor",
    )
    return [ProbeCheck(name, "blocked", reason) for name in names]


def _iter_refs(value: object) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str):
                refs.append(child)
            refs.extend(_iter_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(_iter_refs(child))
    return refs


def _canonical_inventory() -> tuple[set[str], set[str]]:
    """Load canonical tool names and resource URIs from the generated artifact."""
    from recon_tool.surface_inventory import packaged_surface_inventory_text

    inventory = json.loads(packaged_surface_inventory_text())
    mcp_inventory = inventory.get("mcp") if isinstance(inventory, dict) else None
    if not isinstance(mcp_inventory, dict):
        raise TypeError("generated surface inventory has no MCP object")
    tools = mcp_inventory.get("tools")
    resources = mcp_inventory.get("resources")
    if not isinstance(tools, list) or not isinstance(resources, list):
        raise TypeError("generated MCP inventory has invalid tool or resource lists")
    tool_names = {str(item["name"]) for item in tools if isinstance(item, dict) and "name" in item}
    resource_uris = {str(item["uri"]) for item in resources if isinstance(item, dict) and "uri" in item}
    if len(tool_names) != 22 or len(resource_uris) != 5:
        raise ValueError(f"canonical inventory has tools={len(tool_names)} resources={len(resource_uris)}")
    return tool_names, resource_uris


def _require_canonical_registry(
    tool_names: list[str],
    resource_uris: list[str],
    template_uris: list[str],
    prompt_names: list[str],
) -> None:
    expected_tools, expected_resources = _canonical_inventory()
    if set(tool_names) != expected_tools:
        raise ValueError(
            f"tool inventory mismatch missing={sorted(expected_tools - set(tool_names))!r} "
            f"extra={sorted(set(tool_names) - expected_tools)!r}"
        )
    if set(resource_uris) != expected_resources:
        raise ValueError(
            f"resource inventory mismatch missing={sorted(expected_resources - set(resource_uris))!r} "
            f"extra={sorted(set(resource_uris) - expected_resources)!r}"
        )
    if template_uris:
        raise ValueError(f"unexpected resource templates: {template_uris!r}")
    if prompt_names != ["domain_report"]:
        raise ValueError(f"unexpected prompt registry: {prompt_names!r}")


async def _check_recon_registry(mcp: Any) -> tuple[ProbeCheck, list[Any] | None]:
    try:
        tool_runs = [await mcp.list_tools(), await mcp.list_tools()]
        resource_runs = [await mcp.list_resources(), await mcp.list_resources()]
        prompt_runs = [await mcp.list_prompts(), await mcp.list_prompts()]
        template_runs = [await mcp.list_resource_templates(), await mcp.list_resource_templates()]
        tool_names = [[item.name for item in run] for run in tool_runs]
        resource_uris = [[str(item.uri) for item in run] for run in resource_runs]
        prompt_names = [[item.name for item in run] for run in prompt_runs]
        template_uris = [[str(_wire_dict(item).get("uriTemplate", "")) for item in run] for run in template_runs]
        if tool_names[0] != tool_names[1] or len(set(tool_names[0])) != len(tool_names[0]):
            raise ValueError("tool order is not deterministic and unique")
        if resource_uris[0] != resource_uris[1] or len(set(resource_uris[0])) != len(resource_uris[0]):
            raise ValueError("resource order is not deterministic and unique")
        if prompt_names[0] != prompt_names[1] or template_uris[0] != template_uris[1]:
            raise ValueError("prompt or resource-template order is not deterministic")
        _require_canonical_registry(tool_names[0], resource_uris[0], template_uris[0], prompt_names[0])
        return (
            ProbeCheck(
                "recon_registry_order",
                "pass",
                f"tools={len(tool_names[0])} resources={len(resource_uris[0])} "
                f"templates={len(template_uris[0])} prompts={len(prompt_names[0])}",
            ),
            tool_runs[0],
        )
    except Exception as exc:
        return ProbeCheck("recon_registry_order", "fail", _exception_detail(exc)), None


def _check_recon_schemas(tools: list[Any] | None) -> ProbeCheck:
    if tools is None:
        return ProbeCheck("recon_schema_conformance", "blocked", "registry probe failed")
    try:
        from jsonschema import Draft202012Validator

        missing_output: list[str] = []
        external_refs: list[str] = []
        for tool in tools:
            wire = _wire_dict(tool)
            input_schema = wire.get("inputSchema")
            output_schema = wire.get("outputSchema")
            if not isinstance(input_schema, dict):
                raise TypeError(f"{tool.name} inputSchema is not a dictionary")
            Draft202012Validator.check_schema(input_schema)
            if not isinstance(output_schema, dict):
                missing_output.append(tool.name)
                continue
            Draft202012Validator.check_schema(output_schema)
            external_refs.extend(ref for ref in _iter_refs(output_schema) if not ref.startswith("#"))
        if missing_output or external_refs:
            raise ValueError(f"missing_output={missing_output!r} external_refs={external_refs!r}")
        return ProbeCheck(
            "recon_schema_conformance",
            "pass",
            f"schemas={len(tools) * 2} draft=2020-12 external_refs=0",
        )
    except Exception as exc:
        return ProbeCheck("recon_schema_conformance", "fail", _exception_detail(exc))


async def _check_direct_structured_success(mcp: Any) -> ProbeCheck:
    try:
        direct = await mcp.call_tool("get_fingerprints", {"limit": 1})
        if isinstance(direct, tuple):
            content, structured = direct
            is_error = False
        else:
            direct_wire = _wire_dict(direct)
            content = getattr(direct, "content", [])
            structured = direct_wire.get("structuredContent")
            is_error = bool(direct_wire.get("isError", False))
        if is_error or not content or not isinstance(structured, dict):
            raise ValueError("structured success did not contain content and structuredContent")
        result = structured.get("result")
        if not isinstance(result, list) or len(result) != 1:
            raise ValueError("get_fingerprints(limit=1) returned an unexpected result")
        return ProbeCheck("recon_direct_structured_success", "pass", "get_fingerprints result_count=1")
    except Exception as exc:
        return ProbeCheck("recon_direct_structured_success", "fail", _exception_detail(exc))


async def _check_direct_tool_error(mcp: Any) -> ProbeCheck:
    try:
        from recon_tool.mcp_client.sdk_compat import ToolError

        try:
            direct_error = await mcp.call_tool("explain_signal", {"signal_name": "__definitely_missing__"})
        except ToolError:
            return ProbeCheck("recon_direct_tool_error", "pass", "raised ToolError")
        else:
            error_wire = _wire_dict(direct_error)
            if error_wire.get("isError") is not True:
                raise ValueError("missing-signal call was not marked isError")
            return ProbeCheck("recon_direct_tool_error", "pass", "returned isError=true")
    except Exception as exc:
        return ProbeCheck("recon_direct_tool_error", "fail", _exception_detail(exc))


async def _check_reload_read_concurrency(mcp: Any) -> ProbeCheck:
    try:

        async def read_catalogs() -> None:
            for uri in ("recon://fingerprints", "recon://signals", "recon://profiles"):
                contents = list(await mcp.read_resource(uri))
                if len(contents) != 1:
                    raise ValueError(f"{uri} returned {len(contents)} contents")
                payload = json.loads(str(getattr(contents[0], "content", "")))
                if not isinstance(payload, dict) or not isinstance(payload.get("count"), int):
                    raise ValueError(f"{uri} returned an invalid catalog envelope")

        async def reload_catalogs() -> None:
            for _ in range(4):
                result = await mcp.call_tool("reload_data", {})
                if not isinstance(result, tuple) and _wire_dict(result).get("isError", False):
                    raise RuntimeError("reload_data returned isError=true")

        await asyncio.gather(*(read_catalogs() for _ in range(6)), reload_catalogs())
        return ProbeCheck(
            "recon_reload_read_concurrency",
            "pass",
            "6 readers x 3 catalogs with 4 concurrent reloads",
        )
    except Exception as exc:
        return ProbeCheck("recon_reload_read_concurrency", "fail", _exception_detail(exc))


def _check_recon_cache_hint_configuration(mcp: Any, family: str) -> ProbeCheck:
    """Verify recon explicitly configures every v2 cacheable method."""
    if family == "v1":
        return ProbeCheck(
            "recon_cache_hint_configuration",
            "not_applicable",
            "legacy protocol has no complete-result cache hints",
        )
    try:
        low_level = getattr(mcp, "_lowlevel_server", None)
        hints = getattr(low_level, "cache_hints", None)
        expected = {
            "prompts/list",
            "resources/list",
            "resources/read",
            "resources/templates/list",
            "server/discover",
            "tools/list",
        }
        if not isinstance(hints, dict) or set(hints) != expected:
            raise ValueError(f"configured cache methods={sorted(hints) if isinstance(hints, dict) else hints!r}")
        invalid = [
            method
            for method, hint in hints.items()
            if getattr(hint, "ttl_ms", None) != 0 or getattr(hint, "scope", None) != "private"
        ]
        if invalid:
            raise ValueError(f"non-conservative cache hints={invalid!r}")
        return ProbeCheck(
            "recon_cache_hint_configuration",
            "pass",
            "methods=6 ttlMs=0 cacheScope=private",
        )
    except Exception as exc:
        return ProbeCheck("recon_cache_hint_configuration", "fail", _exception_detail(exc))


async def _probe_recon_direct(server_module: Any, family: str) -> list[ProbeCheck]:
    """Exercise deterministic in-process registry, schema, and state behavior."""
    mcp = server_module.mcp
    registry, tools = await _check_recon_registry(mcp)
    return [
        registry,
        _check_recon_schemas(tools),
        await _check_direct_structured_success(mcp),
        await _check_direct_tool_error(mcp),
        await _check_reload_read_concurrency(mcp),
        _check_recon_cache_hint_configuration(mcp, family),
    ]


def _complete_metadata(wire: dict[str, Any]) -> tuple[int, str, str]:
    ttl_ms = wire.get("ttlMs")
    cache_scope = wire.get("cacheScope")
    result_type = wire.get("resultType")
    if not isinstance(ttl_ms, int) or isinstance(ttl_ms, bool) or ttl_ms < 0:
        raise ValueError(f"invalid ttlMs={ttl_ms!r}")
    if cache_scope not in {"public", "private"}:
        raise ValueError(f"invalid cacheScope={cache_scope!r}")
    if result_type != "complete":
        raise ValueError(f"invalid resultType={result_type!r}")
    return ttl_ms, str(cache_scope), str(result_type)


@dataclass(frozen=True, slots=True)
class StdioListings:
    """Normalized repeated listing results from one live stdio session."""

    check: ProbeCheck
    result_wires: tuple[dict[str, Any], ...]
    resource_uris: tuple[str, ...]


def _listing_values(result: object, collection_key: str, item_key: str) -> list[str]:
    collection = _wire_dict(result).get(collection_key)
    if not isinstance(collection, list):
        raise TypeError(f"{collection_key} is not a list")
    if any(not isinstance(entry, dict) or item_key not in entry for entry in collection):
        raise TypeError(f"{collection_key} contains an invalid {item_key} entry")
    return [str(entry[item_key]) for entry in collection]


async def _stdio_discovery(session: Any) -> tuple[ProbeCheck, dict[str, Any]]:
    discover = getattr(session, "discover", None)
    if callable(discover):
        discovery = await cast(Callable[[], Awaitable[Any]], discover)()
        method = "server/discover"
    else:
        discovery = await session.initialize()
        method = "initialize"
    wire = _wire_dict(discovery)
    server_info = wire.get("serverInfo", {})
    server_name = server_info.get("name", "?") if isinstance(server_info, dict) else "?"
    return ProbeCheck("recon_stdio_discovery", "pass", f"method={method} server={server_name}"), wire


async def _stdio_listings(session: Any, discovery_wire: dict[str, Any]) -> StdioListings:
    tools = (await session.list_tools(), await session.list_tools())
    resources = (await session.list_resources(), await session.list_resources())
    templates = (await session.list_resource_templates(), await session.list_resource_templates())
    prompts = (await session.list_prompts(), await session.list_prompts())
    tool_names = [_listing_values(result, "tools", "name") for result in tools]
    resource_uris = [_listing_values(result, "resources", "uri") for result in resources]
    template_uris = [_listing_values(result, "resourceTemplates", "uriTemplate") for result in templates]
    prompt_names = [_listing_values(result, "prompts", "name") for result in prompts]
    if any(runs[0] != runs[1] for runs in (tool_names, resource_uris, template_uris, prompt_names)):
        raise ValueError("wire listing order changed between repeated calls")
    _require_canonical_registry(tool_names[0], resource_uris[0], template_uris[0], prompt_names[0])
    check = ProbeCheck(
        "recon_stdio_listings",
        "pass",
        (
            f"tools={len(tool_names[0])} resources={len(resource_uris[0])} "
            f"templates={len(template_uris[0])} prompts={len(prompt_names[0])}"
        ),
    )
    listed_results = (*tools, *resources, *templates, *prompts)
    return StdioListings(
        check=check,
        result_wires=(discovery_wire, *(_wire_dict(result) for result in listed_results)),
        resource_uris=tuple(resource_uris[0]),
    )


async def _stdio_resource_reads(
    session: Any, resource_uris: tuple[str, ...]
) -> tuple[ProbeCheck, list[dict[str, Any]]]:
    wires: list[dict[str, Any]] = []
    for uri in resource_uris:
        wire = _wire_dict(await session.read_resource(uri))
        contents = wire.get("contents")
        if not isinstance(contents, list) or len(contents) != 1:
            raise ValueError(f"{uri} did not return one content item")
        wires.append(wire)
    return ProbeCheck("recon_stdio_resource_reads", "pass", f"resources_read={len(wires)}"), wires


async def _stdio_prompt_get(session: Any) -> ProbeCheck:
    wire = _wire_dict(await session.get_prompt("domain_report", {"domain": "example.com"}))
    messages = wire.get("messages")
    if not isinstance(messages, list) or len(messages) != 1 or not isinstance(messages[0], dict):
        raise ValueError("domain_report did not return one prompt message")
    content = messages[0].get("content")
    if not isinstance(content, dict):
        raise ValueError("domain_report prompt content is not an object")
    text = content.get("text")
    if not isinstance(text, str) or "example.com" not in text or "lookup_tenant" not in text:
        raise ValueError("domain_report prompt content lost its domain or tool instruction")
    return ProbeCheck("recon_stdio_prompt_get", "pass", "domain_report messages=1")


async def _stdio_tool_results(session: Any) -> tuple[list[ProbeCheck], dict[str, Any], dict[str, Any]]:
    success_wire = _wire_dict(await session.call_tool("get_fingerprints", {"limit": 1}))
    structured = success_wire.get("structuredContent")
    if success_wire.get("isError", False) or not isinstance(structured, dict):
        raise ValueError("wire structured tool did not return a successful structuredContent object")
    structured_result = structured.get("result")
    if not isinstance(structured_result, list) or len(structured_result) != 1:
        raise ValueError("wire structured tool ignored limit=1")
    failure_wire = _wire_dict(await session.call_tool("explain_signal", {"signal_name": "__definitely_missing__"}))
    if failure_wire.get("isError") is not True:
        raise ValueError("wire missing-signal result was not marked isError")
    checks = [
        ProbeCheck("recon_stdio_structured_success", "pass", "get_fingerprints result_count=1"),
        ProbeCheck("recon_stdio_tool_error", "pass", "missing signal returned isError=true"),
    ]
    return checks, success_wire, failure_wire


def _stdio_metadata_check(
    family: str,
    cacheable_wires: tuple[dict[str, Any], ...],
    read_wires: list[dict[str, Any]],
    tool_wires: tuple[dict[str, Any], dict[str, Any]],
) -> ProbeCheck:
    if family == "v1":
        return ProbeCheck(
            "recon_complete_result_metadata",
            "not_applicable",
            "legacy protocol does not carry complete-result cache metadata",
        )
    for wire in (*cacheable_wires, *read_wires):
        _complete_metadata(wire)
    for wire in tool_wires:
        if wire.get("resultType") != "complete":
            raise ValueError(f"tool result has invalid resultType={wire.get('resultType')!r}")
    return ProbeCheck(
        "recon_complete_result_metadata",
        "pass",
        f"cacheable_results={len(cacheable_wires) + len(read_wires)} tool_results=2 type=complete",
    )


async def _probe_recon_stdio(family: str) -> list[ProbeCheck]:
    """Exercise the real stdio wire surface through the installed client SDK."""
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    env = dict(os.environ)
    env["RECON_MCP_FORCE_STDIO"] = "1"
    env["PYTHONSAFEPATH"] = "1"
    scratch = Path(env.get("RECON_AGENT_TMP", AGENT_ROOT))
    scratch.mkdir(parents=True, exist_ok=True)
    with (
        tempfile.TemporaryDirectory(prefix="recon-mcp-stdio-", dir=scratch) as safe_cwd,
        tempfile.TemporaryFile(mode="w+", encoding="utf-8", dir=scratch) as errlog,
    ):
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "recon_tool.server"],
            env=env,
            cwd=safe_cwd,
        )
        async with (
            stdio_client(params, errlog=cast(TextIO, errlog)) as streams,
            ClientSession(*streams) as session,
        ):
            discovery_check, discovery_wire = await _stdio_discovery(session)
            listings = await _stdio_listings(session, discovery_wire)
            prompt_check = await _stdio_prompt_get(session)
            resource_check, read_wires = await _stdio_resource_reads(session, listings.resource_uris)
            tool_checks, success_wire, failure_wire = await _stdio_tool_results(session)
            metadata_check = _stdio_metadata_check(
                family,
                listings.result_wires,
                read_wires,
                (success_wire, failure_wire),
            )
    return [discovery_check, listings.check, prompt_check, resource_check, *tool_checks, metadata_check]


def _probe_sdk_foundation() -> tuple[list[ProbeCheck], str]:
    checks: list[ProbeCheck] = []
    family = "unknown"
    try:
        server_class, family = _sdk_server_class()
        checks.extend(asyncio.run(_probe_sdk_server(server_class, family)))
    except Exception as exc:
        checks.append(ProbeCheck("sdk_server_api", "fail", _exception_detail(exc)))
        checks.append(ProbeCheck("sdk_sync_handler_execution", "blocked", "SDK server API unavailable"))
    checks.append(_probe_cache_hint_api(family))
    return checks, family


def _probe_client_discovery_api() -> ProbeCheck:
    try:
        from mcp import ClientSession

        method = "server/discover" if callable(getattr(ClientSession, "discover", None)) else "initialize"
        return ProbeCheck("sdk_client_discovery_api", "pass", f"method={method}")
    except Exception as exc:
        return ProbeCheck("sdk_client_discovery_api", "fail", _exception_detail(exc))


def _import_recon_server(family: str) -> tuple[ProbeCheck, Any | None]:
    try:
        server_module = importlib.import_module("recon_tool.server")
        from recon_tool.mcp_client.sdk_compat import SDK_FAMILY

        if family != SDK_FAMILY:
            raise ValueError(f"SDK family mismatch: raw={family} boundary={SDK_FAMILY}")
        return ProbeCheck(
            "recon_server_import", "pass", f"application={type(server_module.mcp).__name__}"
        ), server_module
    except Exception as exc:
        return ProbeCheck("recon_server_import", "fail", _exception_detail(exc)), None


def _failed_group(first_name: str, blocked_names: tuple[str, ...], reason: str, exc: BaseException) -> list[ProbeCheck]:
    return [
        ProbeCheck(first_name, "fail", _exception_detail(exc)),
        *[ProbeCheck(name, "blocked", reason) for name in blocked_names],
    ]


def _probe_recon_direct_group(server_module: Any, family: str) -> list[ProbeCheck]:
    try:
        return asyncio.run(_probe_recon_direct(server_module, family))
    except Exception as exc:
        return _failed_group(
            "recon_registry_order",
            (
                "recon_schema_conformance",
                "recon_direct_structured_success",
                "recon_direct_tool_error",
                "recon_reload_read_concurrency",
                "recon_cache_hint_configuration",
            ),
            "direct recon probe failed",
            exc,
        )


def _probe_recon_stdio_group(family: str) -> list[ProbeCheck]:
    try:
        return asyncio.run(_probe_recon_stdio(family))
    except Exception as exc:
        return _failed_group(
            "recon_stdio_discovery",
            (
                "recon_stdio_listings",
                "recon_stdio_prompt_get",
                "recon_stdio_resource_reads",
                "recon_stdio_structured_success",
                "recon_stdio_tool_error",
                "recon_complete_result_metadata",
            ),
            "stdio discovery failed",
            exc,
        )


def _probe_live_doctor() -> ProbeCheck:
    try:
        from recon_tool.mcp_client.doctor import run_doctor

        doctor = run_doctor()
        if not doctor.ok:
            failures = [f"{item.name}: {item.detail}" for item in doctor.checks if item.status == "fail"]
            raise RuntimeError("; ".join(failures))
        discovery = [item.name for item in doctor.checks if item.name in {"initialize handshake", "server/discover"}]
        return ProbeCheck(
            "recon_live_doctor",
            "pass",
            f"discovery={','.join(discovery)} registrations=verified resources=read",
        )
    except Exception as exc:
        return ProbeCheck("recon_live_doctor", "fail", _exception_detail(exc))


def _compatibility_status(checks: list[ProbeCheck], family: str) -> bool:
    required = {
        "sdk_server_api",
        "sdk_sync_handler_execution",
        "sdk_client_discovery_api",
        "recon_server_import",
        "recon_registry_order",
        "recon_schema_conformance",
        "recon_direct_structured_success",
        "recon_direct_tool_error",
        "recon_reload_read_concurrency",
        "recon_stdio_discovery",
        "recon_stdio_listings",
        "recon_stdio_prompt_get",
        "recon_stdio_resource_reads",
        "recon_stdio_structured_success",
        "recon_stdio_tool_error",
        "recon_live_doctor",
    }
    if family == "v2":
        required.update({"recon_cache_hint_configuration", "recon_complete_result_metadata"})
    by_name = {check.name: check for check in checks}
    return all(by_name.get(name) is not None and by_name[name].status == "pass" for name in required)


def probe_current_environment() -> dict[str, Any]:
    """Return one machine-readable report for the currently installed SDK."""
    checks, family = _probe_sdk_foundation()
    checks.append(_probe_client_discovery_api())
    import_check, server_module = _import_recon_server(family)
    checks.append(import_check)
    if server_module is None:
        checks.extend(_blocked_recon_checks("recon server import failed"))
    else:
        checks.extend(_probe_recon_direct_group(server_module, family))
        checks.extend(_probe_recon_stdio_group(family))
        checks.append(_probe_live_doctor())

    return {
        "sdk_version": _distribution_version("mcp"),
        "mcp_types_version": _distribution_version("mcp-types"),
        "sdk_family": family,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "compatible": _compatibility_status(checks, family),
        "checks": [asdict(check) for check in checks],
    }


def _run_command(args: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout: int = 240) -> CommandResult:
    completed = subprocess.run(  # noqa: S603 - executables are resolved or created by this harness
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _venv_python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _locked_constraints(uv: str, destination: Path) -> CommandResult:
    result = _run_command(
        [uv, "export", "--locked", "--no-dev", "--no-hashes", "--no-emit-project"],
        cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        return result
    lines = [line for line in result.stdout.splitlines() if not line.lower().startswith("mcp==")]
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def _probe_pin(uv: str, root: Path, constraints: Path, sdk_version: str) -> dict[str, Any]:
    slug = sdk_version.replace(".", "-")
    environment = root / f"sdk-{slug}"
    override = root / f"override-{slug}.txt"
    override.write_text(f"mcp=={sdk_version}\n", encoding="utf-8")

    create = _run_command(
        [uv, "venv", os.fspath(environment), "--python", sys.executable, "--clear"],
        cwd=REPO_ROOT,
    )
    if create.returncode != 0:
        return {
            "sdk_version": sdk_version,
            "compatible": False,
            "environment_status": "fail",
            "environment_detail": _bounded_text(create.stderr or create.stdout),
            "checks": [],
        }

    install_args = [
        uv,
        "pip",
        "install",
        "--python",
        os.fspath(_venv_python(environment)),
        "--constraints",
        os.fspath(constraints),
        "--overrides",
        os.fspath(override),
    ]
    if sdk_version.startswith("2."):
        install_args.extend(["--prerelease", "allow"])
    install_args.extend(["-e", os.fspath(REPO_ROOT)])
    install = _run_command(install_args, cwd=REPO_ROOT)
    if install.returncode != 0:
        return {
            "sdk_version": sdk_version,
            "compatible": False,
            "environment_status": "fail",
            "environment_detail": _bounded_text(install.stderr or install.stdout),
            "checks": [],
        }

    probe_env = dict(os.environ)
    config = root / f"config-{slug}"
    config.mkdir()
    probe_env["RECON_CONFIG_DIR"] = os.fspath(config)
    probe_env["RECON_AGENT_TMP"] = os.fspath(root)
    probe_env["PYTHONSAFEPATH"] = "1"
    probe = _run_command(
        [os.fspath(_venv_python(environment)), os.fspath(Path(__file__).resolve()), "--probe"],
        cwd=REPO_ROOT,
        env=probe_env,
    )
    if probe.returncode != 0:
        return {
            "sdk_version": sdk_version,
            "compatible": False,
            "environment_status": "fail",
            "environment_detail": _bounded_text(probe.stderr or probe.stdout),
            "checks": [],
        }
    try:
        report = json.loads(probe.stdout)
    except json.JSONDecodeError as exc:
        return {
            "sdk_version": sdk_version,
            "compatible": False,
            "environment_status": "fail",
            "environment_detail": _exception_detail(exc),
            "checks": [],
        }
    if report.get("sdk_version") != sdk_version:
        report["compatible"] = False
        report["environment_status"] = "fail"
        report["environment_detail"] = f"requested mcp {sdk_version}, probe imported {report.get('sdk_version')!r}"
        return report
    report["environment_status"] = "pass"
    report["environment_detail"] = "isolated editable install from the working tree"
    return report


def _git_metadata() -> dict[str, object]:
    git = shutil.which("git")
    if git is None:
        return {"commit": None, "working_tree_dirty": None}
    revision = _run_command([git, "rev-parse", "HEAD"], cwd=REPO_ROOT)
    status = _run_command([git, "status", "--porcelain"], cwd=REPO_ROOT)
    return {
        "commit": revision.stdout.strip() or None if revision.returncode == 0 else None,
        "working_tree_dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
    }


def characterize_versions(sdk_versions: tuple[str, ...]) -> dict[str, Any]:
    """Create isolated environments and return their compatibility reports."""
    if not sdk_versions:
        raise ValueError("at least one SDK version is required")
    if len(set(sdk_versions)) != len(sdk_versions):
        raise ValueError("SDK versions must be unique")
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required to build isolated compatibility environments")
    AGENT_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mcp-compat-", dir=AGENT_ROOT) as directory:
        root = Path(directory)
        constraints = root / "locked-constraints.txt"
        exported = _locked_constraints(uv, constraints)
        if exported.returncode != 0:
            raise RuntimeError(_bounded_text(exported.stderr or exported.stdout))
        reports = [_probe_pin(uv, root, constraints, sdk_version) for sdk_version in sdk_versions]
    return {
        "schema_version": 1,
        "observed_at": datetime.now(UTC).isoformat(),
        "repository": _git_metadata(),
        "method": {
            "sdk_versions": list(sdk_versions),
            "source": "isolated editable working tree",
            "constraints": "uv.lock production runtime versions except mcp",
            "network": "package-index installation only; recon probes are local",
            "production_dependency_changed": False,
        },
        "uv_lock_sha256": hashlib.sha256((REPO_ROOT / "uv.lock").read_bytes()).hexdigest(),
        "reports": reports,
    }


def _write_report(report: dict[str, Any], output: Path | None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(text)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sdk-version",
        action="append",
        dest="sdk_versions",
        help="Exact MCP SDK version to probe; repeat for a matrix.",
    )
    parser.add_argument(
        "--require-compatible",
        action="append",
        default=[],
        metavar="VERSION",
        help="Exit nonzero unless the named probed version is compatible.",
    )
    parser.add_argument("--output", type=Path, help="Write JSON to this path instead of stdout.")
    parser.add_argument("--probe", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.probe:
        _write_report(probe_current_environment(), args.output)
        return

    sdk_versions = tuple(args.sdk_versions or DEFAULT_SDK_VERSIONS)
    try:
        report = characterize_versions(sdk_versions)
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    _write_report(report, args.output)

    reports = {str(item.get("sdk_version")): item for item in report["reports"]}
    missing = [sdk_version for sdk_version in args.require_compatible if sdk_version not in reports]
    incompatible = [
        sdk_version
        for sdk_version in args.require_compatible
        if sdk_version in reports and reports[sdk_version].get("compatible") is not True
    ]
    if missing or incompatible:
        details: list[str] = []
        if missing:
            details.append(f"not probed: {', '.join(missing)}")
        if incompatible:
            details.append(f"incompatible: {', '.join(incompatible)}")
        parser.exit(1, f"MCP compatibility requirement failed: {'; '.join(details)}\n")


if __name__ == "__main__":
    main()
