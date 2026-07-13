"""Narrow compatibility boundary for supported MCP SDK generations.

Production remains on the stable v1 SDK line. The v2 imports exist so the
exact-pinned compatibility matrix can exercise the same recon server without
copying registration or domain logic into a second implementation.
"""

from __future__ import annotations

from importlib.metadata import version
from typing import TYPE_CHECKING, Any, Literal

SDKFamily = Literal["v1", "v2"]

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP as MCPApplication
    from mcp.server.fastmcp.exceptions import ToolError
    from mcp.types import ToolAnnotations

    SDK_FAMILY: SDKFamily = "v1"
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
        conservative_hint = CacheHint(ttl_ms=0, scope="private")
        _APPLICATION_OPTIONS = {
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
    """Return generation-specific server options with isolated nested state."""
    cache_hints = _APPLICATION_OPTIONS.get("cache_hints")
    if isinstance(cache_hints, dict):
        return {"cache_hints": dict(cache_hints)}
    return {}


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
