"""Keep the MCP tool docs in sync with the live `readOnlyHint` annotations.

`docs/mcp.md` tells a consumer which tools are read-only (safe to auto-approve
if outbound passive queries are acceptable) and which are stateful. That
guidance is only trustworthy if it matches the annotations the server actually
advertises, so this test parses the doc and compares it to the registered
tools. A new tool, or a tool whose `readOnlyHint` flips, fails CI until the doc
is updated.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from recon_tool.server import mcp

_MCP_DOC = Path(__file__).resolve().parents[1] / "docs" / "mcp.md"


def _tool_hints() -> dict[str, bool]:
    """Map every registered tool name to its readOnlyHint (default True)."""

    async def _list() -> dict[str, bool]:
        hints: dict[str, bool] = {}
        for tool in await mcp.list_tools():
            ann = tool.annotations
            read_only = True if ann is None or ann.readOnlyHint is None else ann.readOnlyHint
            hints[tool.name] = read_only
        return hints

    return asyncio.run(_list())


def _available_tools_section() -> str:
    text = _MCP_DOC.read_text(encoding="utf-8")
    start = text.index("## Available Tools")
    end = text.index("## Catalog Resources", start)
    return text[start:end]


def _documented_table_names(section: str) -> set[str]:
    """Tool names from the Available Tools table (first backticked cell)."""
    names: set[str] = set()
    for line in section.splitlines():
        if line.startswith("| `"):
            match = re.match(r"\|\s*`([a-z_][a-z0-9_]*)`", line)
            if match:
                names.add(match.group(1))
    return names


def _documented_stateful_names(section: str) -> set[str]:
    """Tool names from the stateful bullet list under the autoApprove guidance."""
    names: set[str] = set()
    for line in section.splitlines():
        if line.startswith("- `"):
            match = re.match(r"-\s*`([a-z_][a-z0-9_]*)`", line)
            if match:
                names.add(match.group(1))
    return names


def test_available_tools_table_lists_every_tool() -> None:
    section = _available_tools_section()
    assert _documented_table_names(section) == set(_tool_hints())


def test_documented_stateful_set_matches_annotations() -> None:
    section = _available_tools_section()
    live_stateful = {name for name, read_only in _tool_hints().items() if not read_only}
    assert _documented_stateful_names(section) == live_stateful
