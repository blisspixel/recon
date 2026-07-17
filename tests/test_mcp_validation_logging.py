"""Privacy contract for MCP validation-failure diagnostics."""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable

import pytest

from recon_tool.mcp_client.sdk_compat import ToolError
from recon_tool.server.app import validate_domain_for_tool
from recon_tool.server.graph import chain_lookup
from recon_tool.server.introspection import discover_fingerprint_candidates, explain_dag
from recon_tool.server.lookup import lookup_tenant

_REJECTED_INPUT = "not a domain /private/path?token=fixture-secret"


async def _call_structured_tool_boundary() -> None:
    with pytest.raises(ToolError, match="Invalid domain format"):
        validate_domain_for_tool(_REJECTED_INPUT, "fixed-request")


async def _call_lookup_tenant() -> None:
    result = await lookup_tenant(_REJECTED_INPUT)
    assert result.startswith("Error: Invalid domain format")


async def _call_chain_lookup() -> None:
    result = await chain_lookup(_REJECTED_INPUT)
    assert result.startswith("Error: Invalid domain format")


async def _call_discover() -> None:
    with pytest.raises(ToolError, match="Invalid domain format"):
        await discover_fingerprint_candidates(_REJECTED_INPUT)


async def _call_explain_dag() -> None:
    result = await explain_dag(_REJECTED_INPUT)
    assert result.startswith("Error: Invalid domain format")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invoke",
    [
        _call_structured_tool_boundary,
        _call_lookup_tenant,
        _call_chain_lookup,
        _call_discover,
        _call_explain_dag,
    ],
    ids=("structured", "lookup", "chain", "discover", "explain-dag"),
)
async def test_rejected_domain_logs_one_target_free_event(
    invoke: Callable[[], Awaitable[None]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="recon"):
        await invoke()

    events = []
    for record in caplog.records:
        try:
            payload = json.loads(record.getMessage())
        except json.JSONDecodeError:
            continue
        if payload.get("msg") == "validation_failed":
            events.append(payload)

    assert len(events) == 1
    assert events[0]["error_type"] == "invalid_domain"
    assert events[0]["request_id"]
    assert "domain" not in events[0]
    assert "error" not in events[0]
    assert _REJECTED_INPUT not in caplog.text
    assert "fixture-secret" not in caplog.text
    assert "Invalid domain format" not in caplog.text
