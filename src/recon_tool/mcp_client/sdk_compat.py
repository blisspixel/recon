"""Narrow compatibility boundary for supported MCP SDK generations.

Production runs the v2 SDK line, which is what speaks MCP 2026-07-28. The v1
imports remain so the exact-pinned compatibility matrix can exercise the same
recon server on the legacy generation without copying registration or domain
logic into a second implementation, and so 1.28.1 stays a working rollback pin.

Type checking follows the production generation, so the annotations below
describe v2. The runtime branch still selects either generation by import, and
anything that differs between them is resolved here rather than at the call
sites.
"""

from __future__ import annotations

from importlib.metadata import version
from typing import TYPE_CHECKING, Any, Literal

from recon_tool import __version__ as _recon_version

SDKFamily = Literal["v1", "v2"]

if TYPE_CHECKING:
    from mcp.server import MCPServer as MCPApplication
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp_types import ToolAnnotations

    SDK_FAMILY: SDKFamily = "v2"
    _APPLICATION_OPTIONS: dict[str, Any] = {}
else:
    try:
        from mcp.server.fastmcp import FastMCP as MCPApplication
        from mcp.server.fastmcp.exceptions import ToolError
        from mcp.types import ToolAnnotations

        SDK_FAMILY = "v1"
        _APPLICATION_OPTIONS = {}
    except ModuleNotFoundError as exc:
        if exc.name not in {
            "mcp.server.fastmcp",
            "mcp.server.fastmcp.exceptions",
            "mcp.types",
        }:
            raise
        from mcp.server import CacheHint
        from mcp.server import MCPServer as MCPApplication
        from mcp.server.mcpserver.exceptions import ToolError
        from mcp_types import ToolAnnotations

        SDK_FAMILY = "v2"
        # MCP 2026-07-28 requires a caching hint with ttlMs >= 0 on every
        # complete result for these six methods. ttlMs=0 satisfies that and is
        # the deliberate choice: reload_data and ephemeral injection can change
        # what these methods return at any point in a process's life, so a
        # positive TTL would let a client serve a catalog recon knows is stale.
        # Raising it is a measured optimization, not a default; the
        # compatibility gate pins the conservative value so it cannot drift
        # without that measurement.
        conservative_hint = CacheHint(ttl_ms=0, scope="private")
        _APPLICATION_OPTIONS = {
            # Without this the server advertises an empty version string, so a
            # client cannot tell which recon it is connected to and a bug report
            # cannot be tied to a release.
            "version": _recon_version,
            "cache_hints": dict.fromkeys(
                (
                    "prompts/list",
                    "resources/list",
                    "resources/read",
                    "resources/templates/list",
                    "server/discover",
                    "tools/list",
                ),
                conservative_hint,
            )
        }

SDK_VERSION = version("mcp")


def mcp_application_options() -> dict[str, Any]:
    """Return generation-specific server options with isolated nested state.

    Nested values are copied so one application's options cannot mutate the
    module-level table shared with the next.
    """
    options: dict[str, Any] = {}
    server_version = _APPLICATION_OPTIONS.get("version")
    if isinstance(server_version, str) and server_version:
        options["version"] = server_version
    cache_hints = _APPLICATION_OPTIONS.get("cache_hints")
    if isinstance(cache_hints, dict):
        options["cache_hints"] = dict(cache_hints)
    return options


def tool_annotations(
    *,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
    open_world: bool,
) -> ToolAnnotations:
    """Build tool annotations with the field spelling both SDK generations read.

    The two generations disagree: v1 declares the camelCase names as the fields
    themselves, while v2 declares snake_case fields carrying camelCase aliases.
    Only the camelCase spelling is understood by both. Passing snake_case to v1
    is the dangerous case, because it does not raise: pydantic stores it as an
    unrelated extra attribute and leaves the real hint unset, so every tool
    would quietly lose its annotations on the rollback pin.

    Constructing from a mapping keeps one spelling here instead of at each of
    the tool registrations, and keeps the call sites free of a keyword name that
    is correct for only one generation's type stubs.
    """
    return ToolAnnotations.model_validate(
        {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": open_world,
        }
    )


def annotations_declare_read_only(annotations: Any) -> bool:
    """Whether tool annotations explicitly declare the tool read-only.

    Construction shares one spelling through :func:`tool_annotations`, but
    *reading* a constructed model cannot: the attribute names are disjoint
    across generations. v1 exposes ``readOnlyHint`` and v2 exposes
    ``read_only_hint``, with the camelCase form surviving only as a
    serialization alias that is not an attribute. Reading a single spelling
    therefore returns nothing on the other generation, which for the remote
    adapter's allow-list meant every tool looked non-read-only.

    Absent, false, or unreadable all mean not read-only, so a caller gating
    exposure on this fails closed.
    """
    return any(getattr(annotations, attribute, None) is True for attribute in ("readOnlyHint", "read_only_hint"))


def streamable_http_asgi_app(
    mcp_app: Any,
    *,
    host: str,
    json_response: bool,
    stateless_http: bool,
    transport_security: Any,
) -> Any:
    """Build the Streamable HTTP ASGI app with this generation's transport options.

    v1 carries these on a mutable ``settings`` object read when the app is
    built. v2 removed that object and takes the same values as keyword
    arguments. Both spellings are applied here so the optional remote adapter
    does not have to branch on the SDK generation.
    """
    if SDK_FAMILY == "v1":
        mcp_app.settings.host = host
        mcp_app.settings.json_response = json_response
        mcp_app.settings.stateless_http = stateless_http
        mcp_app.settings.transport_security = transport_security
        return mcp_app.streamable_http_app()
    return mcp_app.streamable_http_app(
        host=host,
        json_response=json_response,
        stateless_http=stateless_http,
        transport_security=transport_security,
    )


def tool_schemas(tool: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return ``(input_schema, output_schema)`` for one registered tool.

    Another disjoint-spelling case: v1 names these ``inputSchema`` and
    ``outputSchema``, v2 names them ``input_schema`` and ``output_schema``.
    Reading through the wire dictionary gives the protocol's own camelCase names
    on both generations, which is also the spelling the schema documents use.
    """
    wire = model_wire_dict(tool)
    input_schema = wire.get("inputSchema")
    output_schema = wire.get("outputSchema")
    return (input_schema if isinstance(input_schema, dict) else {}), (
        output_schema if isinstance(output_schema, dict) else None
    )


def call_tool_parts(result: Any) -> tuple[list[Any], Any]:
    """Return ``(content, structured_content)`` from a ``call_tool`` result.

    v1 returns that pair as a plain tuple. v2 returns a ``CallToolResult`` model
    carrying the same two values as fields, so unpacking it raises
    ``ValueError: too many values to unpack``. Callers that only want the two
    payloads go through here instead of destructuring.
    """
    content = getattr(result, "content", None)
    if content is not None and not isinstance(result, tuple):
        structured = getattr(result, "structured_content", None)
        if structured is None:
            structured = getattr(result, "structuredContent", None)
        return list(content), structured
    content_part, structured_part = result
    return list(content_part), structured_part


def model_wire_dict(model: object) -> dict[str, Any]:
    """Return one SDK model with protocol wire aliases as dictionary keys."""
    dump = getattr(model, "model_dump", None)
    if not callable(dump):
        raise TypeError(f"{type(model).__name__} is not an MCP model")
    value = dump(by_alias=True, exclude_none=True)
    if not isinstance(value, dict):
        raise TypeError(f"{type(model).__name__}.model_dump() did not return a dictionary")
    return value


__all__ = [
    "SDK_FAMILY",
    "SDK_VERSION",
    "MCPApplication",
    "ToolAnnotations",
    "ToolError",
    "mcp_application_options",
    "model_wire_dict",
]
