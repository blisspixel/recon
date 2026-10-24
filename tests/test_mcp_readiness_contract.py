"""Offline startup diagnostics and pre-collection refusal contracts."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest
from typer.testing import CliRunner

from recon_tool.chain import MAX_CHAIN_DEPTH
from recon_tool.cli import app as cli_app
from recon_tool.mcp_client.dns_readiness import (
    DNS_CAPABILITY_PREFIX,
    DNS_CHECK_NAME,
    DNS_SETUP_GUIDE,
    DNS_SETUP_NEXT,
    advertised_dns_capability,
    collection_policy_readiness,
    dns_readiness_from_instructions,
)
from recon_tool.mcp_client.doctor import LaunchConfig, run_generated_launch_check
from recon_tool.mcp_client.sdk_compat import ToolError, tool_schemas
from recon_tool.models import ChainReport, ChainResult, TenantInfo
from recon_tool.network_policy import OPERATOR_POLICY, CollectionPolicy
from recon_tool.server import app, graph, lookup, review
from recon_tool.server.introspection import get_fingerprints
from recon_tool.server.posture import assess_exposure, find_hardening_gaps, simulate_hardening


@pytest.mark.parametrize("transport", ["https", "tls"])
def test_approved_view_reports_transport_and_identity_without_resolver_addresses(transport: str) -> None:
    policy = CollectionPolicy("caller-safe", ("192.0.2.53",), "dns.example.org", transport=transport)
    manifest = advertised_dns_capability(policy)
    readiness = dns_readiness_from_instructions("Ordinary instructions\n" + manifest)
    assert readiness.status == "ok"
    assert readiness.next is None
    assert json.loads(manifest.removeprefix(DNS_CAPABILITY_PREFIX)) == {
        "mode": "caller-safe",
        "available": True,
        "transport": transport,
        "policy_id": policy.identity,
    }
    label = "DNS-over-HTTPS" if transport == "https" else "DNS-over-TLS"
    assert readiness.detail == f"approved caller-safe view ({label}); policy {policy.identity[:12]}"


def test_operator_and_unavailable_views_are_explicit_without_a_network_probe() -> None:
    assert collection_policy_readiness(OPERATOR_POLICY).status == "ok"
    assert "operator DNS view" in collection_policy_readiness(OPERATOR_POLICY).detail
    unavailable = collection_policy_readiness(CollectionPolicy("caller-safe", available=False))
    assert unavailable.status == "warn"
    assert unavailable.next == DNS_SETUP_NEXT
    assert "local tools and resources remain usable" in unavailable.detail


@pytest.mark.parametrize(
    "instructions",
    [
        None,
        "ordinary legacy instructions",
        DNS_CAPABILITY_PREFIX + "not-json",
        DNS_CAPABILITY_PREFIX + "[]",
        DNS_CAPABILITY_PREFIX + "{}",
        DNS_CAPABILITY_PREFIX + "{}\n" + DNS_CAPABILITY_PREFIX + "{}",
        DNS_CAPABILITY_PREFIX + "[" * 600,
        "x" * 65537,
    ],
)
def test_missing_or_malformed_capability_never_claims_dns_readiness(instructions: object) -> None:
    result = dns_readiness_from_instructions(instructions)
    assert result.status == "warn"
    assert "did not advertise valid DNS readiness" in result.detail
    assert result.next is not None


@pytest.mark.parametrize(
    ("key", "value"),
    [("mode", []), ("mode", "other"), ("available", 1), ("transport", {}), ("transport", "udp"), ("policy_id", "bad")],
)
def test_capability_fields_have_closed_types_and_values(key: str, value: object) -> None:
    payload = json.loads(advertised_dns_capability(OPERATOR_POLICY).removeprefix(DNS_CAPABILITY_PREFIX))
    payload[key] = value
    assert dns_readiness_from_instructions(DNS_CAPABILITY_PREFIX + json.dumps(payload)).status == "warn"


@pytest.mark.asyncio
async def test_every_unavailable_lookup_retry_refuses_before_rate_limit_or_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app, "MCP_COLLECTION_POLICY", CollectionPolicy("caller-safe", available=False))
    reservations: list[str] = []

    def reserve(domain: str) -> bool:
        reservations.append(domain)
        return False

    def no_cached_result(_domain: str) -> None:
        return None

    for module in (app, lookup, graph, review):
        monkeypatch.setattr(module, "rate_limit_try_acquire", reserve)
    monkeypatch.setattr(app, "cache_get", no_cached_result)
    monkeypatch.setattr(lookup, "cache_get", no_cached_result)
    resolver = AsyncMock(side_effect=AssertionError("unavailable collection reached the resolver"))
    monkeypatch.setattr("recon_tool.server.app._resolve_tenant", resolver)
    invocations: list[Callable[[], Awaitable[object]]] = [
        lambda: lookup.lookup_tenant("example.com"),
        lambda: find_hardening_gaps("example.com"),
        lambda: assess_exposure("example.com"),
        lambda: simulate_hardening("example.com", ["DKIM"]),
        lambda: review.build_review_bundle("example.com"),
        lambda: graph.chain_lookup("example.com"),
    ]
    for invoke in invocations:
        for _ in range(2):
            with pytest.raises(ToolError, match="DNS-dependent lookup unavailable") as caught:
                await invoke()
            assert DNS_SETUP_GUIDE in str(caught.value)
            assert "Rate limited" not in str(caught.value)
    for _ in range(2):
        result = await app.resolve_or_cache("example.com")
        assert isinstance(result, str)
        assert "DNS-dependent lookup unavailable" in result
    assert await get_fingerprints(limit=1)
    assert not reservations
    resolver.assert_not_awaited()


@pytest.mark.asyncio
async def test_chain_schema_advertises_the_same_bound_as_the_cli() -> None:
    tools = {tool.name: tool for tool in await app.mcp.list_tools()}
    schema, _ = tool_schemas(tools["chain_lookup"])
    depth = schema["properties"]["depth"]
    assert depth["type"] == "integer"
    assert depth["minimum"] == 1
    assert depth["maximum"] == MAX_CHAIN_DEPTH == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("depth", [-1, 0, 4, 9, 10000])
async def test_invalid_depth_precedes_rate_limit_and_policy_checks(depth: int, monkeypatch: pytest.MonkeyPatch) -> None:
    reserve = Mock(return_value=True)
    monkeypatch.setattr(graph, "rate_limit_try_acquire", reserve)
    with pytest.raises(ToolError, match="depth must be an integer between 1 and 3"):
        await graph.chain_lookup("example.com", depth=depth)
    reserve.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.usefixtures("approved_mcp_dns")
@pytest.mark.parametrize("depth", [1, 3])
async def test_supported_depth_is_forwarded_unchanged(depth: int, monkeypatch: pytest.MonkeyPatch) -> None:
    info = TenantInfo(tenant_id=None, display_name="", default_domain="example.com", queried_domain="example.com")
    report = ChainReport(results=(ChainResult("example.com", info, 0),), max_depth_reached=0, truncated=False)
    collect = AsyncMock(return_value=report)
    monkeypatch.setattr("recon_tool.chain.chain_resolve", collect)
    await graph.chain_lookup("example.com", depth=depth)
    collect.assert_awaited_once_with("example.com", depth=depth)


def test_static_doctor_warns_without_contaminating_the_config_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app, "MCP_COLLECTION_POLICY", CollectionPolicy("caller-safe", available=False))
    result = CliRunner().invoke(cli_app, ["doctor", "--mcp", "--no-color"])
    assert result.exit_code == 0, result.output
    assert "mcpServers" in json.loads(result.stdout)
    assert DNS_CHECK_NAME in result.stderr
    assert DNS_SETUP_GUIDE in result.stderr
    assert "warn" in result.stderr
    assert "All checks passed" not in result.stderr


@pytest.mark.parametrize("available", [False, True])
def test_live_doctor_reports_the_checked_child_policy(available: bool, tmp_path: Path) -> None:
    settings = (
        {"RECON_DNS_SERVERS": "192.0.2.53", "RECON_DNS_TLS_NAME": "dns.example.org"}
        if available
        else {"RECON_DNS_VIEW": "unavailable"}
    )
    additions = {"PYTHONSAFEPATH": "1", "RECON_MCP_FORCE_STDIO": "1", **settings}
    launch = LaunchConfig(
        scope="generated",
        command=sys.executable,
        args=("-m", "recon_tool.server"),
        env=tuple(additions.items()),
        cwd=str(tmp_path),
    )
    base = {key: value for key, value in os.environ.items() if not key.startswith("RECON_DNS_")}
    report = run_generated_launch_check(launch=launch, base_env=base)
    assert report.ok, report
    row = next(check for check in report.checks if check.name == DNS_CHECK_NAME)
    assert row.status == ("ok" if available else "warn")
    assert row.next == (None if available else DNS_SETUP_NEXT)
    assert any(check.name == "resources/read" and check.status == "ok" for check in report.checks)
    if available:
        assert CollectionPolicy.from_environment(settings).identity[:12] in row.detail
