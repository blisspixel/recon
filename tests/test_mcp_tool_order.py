"""Pin the advertised `tools/list` order to the documented reading order.

MCP clients hand the tool list to a model in advertised order, and an agent
that picks the first entry gets whatever registered first. Registration order
is import order in `recon_tool.server.__init__`, which the import sorter would
happily re-alphabetise back into `ephemeral, graph, introspection, lookup,
posture`, putting the four process-wide catalog mutators at the top and
`lookup_tenant` sixteenth, the exact inverse of the "start with lookup_tenant"
guidance in `docs/mcp.md` and the stderr startup banner.

These tests fail if that regresses.
"""

from __future__ import annotations

import asyncio

from recon_tool.server import mcp

# The four tools that mutate the shared server process's ephemeral catalog.
# docs/mcp.md warns that this state is process-wide, so they must never be what
# an agent meets first.
_EPHEMERAL_TOOLS = (
    "inject_ephemeral_fingerprint",
    "list_ephemeral_fingerprints",
    "clear_ephemeral_fingerprints",
    "reevaluate_domain",
)


def _tool_names() -> list[str]:
    """Registered tool names in advertised order."""

    async def _list() -> list[str]:
        return [tool.name for tool in await mcp.list_tools()]

    return asyncio.run(_list())


def test_lookup_tenant_is_advertised_first() -> None:
    names = _tool_names()

    assert names[0] == "lookup_tenant", (
        f"lookup_tenant must lead tools/list, got {names[0]!r}. "
        "Check the tool-group import order in recon_tool/server/__init__.py."
    )


def test_ephemeral_catalog_mutators_are_advertised_last() -> None:
    names = _tool_names()

    assert names[-len(_EPHEMERAL_TOOLS) :] == list(_EPHEMERAL_TOOLS)


def test_every_ephemeral_tool_follows_every_read_only_lookup_tool() -> None:
    names = _tool_names()
    first_ephemeral = min(names.index(name) for name in _EPHEMERAL_TOOLS)
    read_only = [name for name in names if name not in _EPHEMERAL_TOOLS]

    # No read-only tool may be buried behind a mutator in the advertised order.
    assert all(names.index(name) < first_ephemeral for name in read_only)
