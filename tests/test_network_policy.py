# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportPrivateUsage=none
"""Collection authority, HTTP admission and cross-view cache regressions."""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.nameserver
import pytest

from recon_tool import cache, ct_cache, network_policy
from recon_tool.http import _destination_refusal_async, _public_addresses_async
from recon_tool.models import ReconLookupError, TenantInfo
from recon_tool.network_policy import CollectionPolicy, collection_scope
from recon_tool.server import app, runtime

_SAFE = CollectionPolicy("caller-safe", ("1.1.1.1",), "cloudflare-dns.com")


@pytest.mark.parametrize("failure", ["missing", "unreadable"])
def test_offline_server_starts_without_readable_host_dns_configuration(failure: str, tmp_path: Path) -> None:
    script = """
import asyncio
import sys
from unittest.mock import patch
import dns.asyncresolver
import dns.nameserver
import dns.resolver

original = dns.asyncresolver.Resolver
calls = []
def unavailable_host(*args, **kwargs):
    calls.append(kwargs.get("configure", True))
    if kwargs.get("configure", True):
        if sys.argv[1] == "missing":
            raise dns.resolver.NoResolverConfiguration()
        raise PermissionError("synthetic unreadable host DNS configuration")
    return original(*args, **kwargs)

with patch.object(dns.asyncresolver, "Resolver", unavailable_host):
    from recon_tool import network_policy
    from recon_tool.server import get_fingerprints, lookup_tenant
    from recon_tool.mcp_client.sdk_compat import ToolError
    assert network_policy.HOST_RESOLVER.nameservers == []
    assert not network_policy.MCP_COLLECTION_POLICY.available
    async def check():
        assert await get_fingerprints(limit=1)
        try:
            await lookup_tenant("example.com")
        except ToolError as exc:
            assert "DNS-dependent lookup unavailable" in str(exc)
        else:
            raise AssertionError("unapproved DNS collection was admitted")
    asyncio.run(check())
assert calls == [True, False]
"""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("RECON_DNS_")}
    environment["RECON_CONFIG_DIR"] = str(tmp_path)
    # Without host configuration the encrypted default would apply; the explicit
    # opt-out keeps this probe offline while exercising the refusal boundary.
    environment["RECON_DNS_VIEW"] = "none"
    result = subprocess.run(  # noqa: S603 - fixed offline probe with a bounded test parameter
        [sys.executable, "-I", "-c", script, failure],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_saved_policy_restarts_with_identical_authority() -> None:
    saved = {
        "RECON_DNS_SERVERS": "192.0.2.53",
        "RECON_DNS_TLS_NAME": "resolver.example.org",
    }
    first = CollectionPolicy.from_environment(saved)
    assert first.available
    assert first.servers == ("192.0.2.53",)
    assert first == CollectionPolicy.from_environment(saved)
    assert first.identity == CollectionPolicy.from_environment(saved).identity
    with pytest.raises(FrozenInstanceError):
        first.mode = "operator"  # pyright: ignore[reportAttributeAccessIssue]  # Assert frozen runtime enforcement.
    assert not CollectionPolicy.from_environment({"RECON_DNS_SERVERS": "1.1.1.1"}).available


@pytest.mark.parametrize(
    "system_servers",
    [(), ("127.0.0.53",), ("192.0.2.53",), ("1.1.1.1", "192.0.2.53"), ("1.1.1.1", "8.8.8.8")],
)
def test_unrecognized_host_resolver_uses_the_encrypted_default(system_servers: tuple[str, ...]) -> None:
    # A stub, enterprise or mixed host configuration is never reused; the
    # maintainer-approved encrypted public service is bound instead.
    selected = CollectionPolicy.from_environment({}, system_servers)
    assert selected.available
    assert selected.mode == "caller-safe"
    assert selected.servers == network_policy.DEFAULT_CALLER_SAFE_SERVERS == ("1.1.1.1", "1.0.0.1")
    assert selected.tls_name == network_policy.DEFAULT_CALLER_SAFE_TLS_NAME == "cloudflare-dns.com"
    assert selected.transport == "https"
    assert not {"127.0.0.53", "192.0.2.53", "8.8.8.8"} & set(selected.servers)
    with collection_scope(selected):
        resolver = network_policy.selected_resolver(network_policy.HOST_RESOLVER)
        assert [ns.url for ns in resolver.nameservers if isinstance(ns, dns.nameserver.DoHNameserver)] == [
            "https://cloudflare-dns.com/dns-query"
        ] * 2


def test_encrypted_default_honors_saved_transport() -> None:
    selected = CollectionPolicy.from_environment({"RECON_DNS_TRANSPORT": "tls"}, ("192.0.2.53",))
    assert selected.available
    assert selected.servers == network_policy.DEFAULT_CALLER_SAFE_SERVERS
    assert selected.transport == "tls"
    with collection_scope(selected):
        resolver = network_policy.selected_resolver(network_policy.HOST_RESOLVER)
        assert all(isinstance(ns, dns.nameserver.DoTNameserver) for ns in resolver.nameservers)


@pytest.mark.parametrize("system_servers", [(), ("1.1.1.1",), ("192.0.2.53",)])
def test_explicit_opt_out_disables_dns_collection(system_servers: tuple[str, ...]) -> None:
    disabled = CollectionPolicy.from_environment({"RECON_DNS_VIEW": "none"}, system_servers)
    assert not disabled.available
    assert disabled.identity != CollectionPolicy.from_environment({}, system_servers).identity


@pytest.mark.parametrize(
    ("servers", "hostname"),
    [(("1.1.1.1", "1.0.0.1"), "cloudflare-dns.com"), (("8.8.8.8",), "dns.google")],
)
def test_known_configured_public_service_is_reused(servers: tuple[str, ...], hostname: str) -> None:
    selected = CollectionPolicy.from_environment({}, servers)
    assert selected.servers == servers
    assert selected.tls_name == hostname
    assert selected.mode == "caller-safe"
    assert selected.available


def test_automatic_reuse_honors_saved_transport_and_rejects_invalid_transport() -> None:
    selected = CollectionPolicy.from_environment({"RECON_DNS_TRANSPORT": "tls"}, ("1.1.1.1",))
    assert selected.available
    assert selected.transport == "tls"
    with collection_scope(selected):
        resolver = network_policy.selected_resolver(network_policy.HOST_RESOLVER)
        assert all(isinstance(ns, dns.nameserver.DoTNameserver) for ns in resolver.nameservers)
    assert not CollectionPolicy.from_environment({"RECON_DNS_TRANSPORT": "udp"}, ("1.1.1.1",)).available


@pytest.mark.parametrize(
    "settings",
    [
        {"RECON_DNS_VIEW": "invalid"},
        {"RECON_DNS_TLS_NAME": "resolver.example.org"},
        {"RECON_DNS_SERVERS": "bad", "RECON_DNS_TLS_NAME": "resolver.example.org"},
        {"RECON_DNS_SERVERS": "192.0.2.53", "RECON_DNS_TLS_NAME": "bad/name"},
        {"RECON_DNS_SERVERS": "192.0.2.53", "RECON_DNS_TLS_NAME": ""},
        {"RECON_DNS_SERVERS": "192.0.2.53", "RECON_DNS_TLS_NAME": "resolver.example.org", "RECON_DNS_TRANSPORT": "udp"},
    ],
)
def test_invalid_approval_is_unavailable(settings: dict[str, str]) -> None:
    assert not CollectionPolicy.from_environment(settings).available


@pytest.mark.asyncio
async def test_unavailable_view_has_actionable_error_without_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = CollectionPolicy.from_environment({"RECON_DNS_VIEW": "none"})
    monkeypatch.setattr(app, "MCP_COLLECTION_POLICY", policy)

    async def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("unapproved collection reached the resolver")

    monkeypatch.setattr(app, "_resolve_tenant", forbidden)
    with pytest.raises(ReconLookupError) as caught:
        await app.resolve_tenant("example.com")
    assert caught.value.error_type == "dns_view_unavailable"
    message = app.lookup_failure_message("example.com", caught.value)
    assert "RECON_DNS_*" in message
    assert "unavailable" in message
    assert "mcp.md#dns-view-isolation" in message


@pytest.mark.asyncio
@pytest.mark.parametrize("addresses", [("8.8.8.8",), ("10.0.0.1",), ("8.8.8.8", "127.0.0.1")])
async def test_http_uses_selected_view_and_still_refuses_private_or_mixed_answers(
    monkeypatch: pytest.MonkeyPatch, addresses: tuple[str, ...]
) -> None:
    queries: list[tuple[str, str]] = []

    async def resolve(_self: dns.asyncresolver.Resolver, host: str, rdtype: str, **_kwargs: Any) -> list[str]:
        queries.append((host, rdtype))
        return list(addresses) if rdtype == "A" else []

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("HTTP consulted ambient system DNS")

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    with collection_scope(_SAFE):
        observed = await _public_addresses_async("app.example.com")
        refusal = await _destination_refusal_async("app.example.com")
    if addresses == ("8.8.8.8",):
        assert observed == addresses
        assert refusal is None
    else:
        assert observed == ()
        assert refusal is not None
        assert refusal.condition == "private_address"
    assert queries == [("app.example.com", "A"), ("app.example.com", "AAAA")] * 2


@pytest.mark.asyncio
async def test_one_unavailable_http_address_family_refuses_the_whole_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def resolve(_self: dns.asyncresolver.Resolver, _host: str, rdtype: str, **_kwargs: Any) -> list[str]:
        if rdtype == "AAAA":
            raise dns.exception.Timeout()
        return ["8.8.8.8"]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    with collection_scope(_SAFE):
        assert await _public_addresses_async("app.example.com") == ()


def test_disk_cache_cannot_cross_policy_identity(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    info = TenantInfo(None, "Synthetic namespace", "example.com", "example.com")
    cache.cache_put("example.com", info)
    assert cache.cache_get("example.com") is not None
    with collection_scope(_SAFE):
        assert cache.cache_get("example.com") is None
        cache.cache_put("example.com", info)
        assert cache.cache_get("example.com") is not None
    assert cache.cache_get("example.com") is None
    changed = replace(_SAFE, servers=("1.0.0.1",))
    with collection_scope(changed):
        assert cache.cache_get("example.com") is None


def test_ct_cache_reads_and_inspection_cannot_cross_policy_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import json

    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    ct_cache.ct_cache_put("example.com", ["private-route.example.com"], None, "crt.sh")
    path = tmp_path / "ct-cache" / "example.com.json"
    legacy = json.loads(path.read_text())
    legacy.pop("_resolution_policy_id")
    path.write_text(json.dumps(legacy))
    assert ct_cache.ct_cache_get("example.com") is not None
    with collection_scope(_SAFE):
        assert ct_cache.ct_cache_get("example.com") is None
        assert ct_cache.ct_cache_show("example.com") is None
        assert ct_cache.ct_cache_list() == []
        ct_cache.ct_cache_put("example.com", ["public.example.com"], None, "crt.sh")
        entry = ct_cache.ct_cache_get("example.com")
        assert entry is not None
        assert entry.subdomains == ("public.example.com",)
        assert ct_cache.ct_cache_show("example.com") is not None
    assert ct_cache.ct_cache_get("example.com") is None
    with collection_scope(replace(_SAFE, servers=("1.0.0.1",))):
        assert ct_cache.ct_cache_get("example.com") is None


def test_process_cache_and_retained_results_are_invalidated_by_policy_change(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime.cache_clear()
    try:
        monkeypatch.setattr(runtime, "MCP_COLLECTION_POLICY", _SAFE)
        info = TenantInfo(None, "Synthetic namespace", "example.com", "example.com")
        runtime.cache_set("example.com", info, [])
        assert runtime.cache_get("example.com") is not None
        monkeypatch.setattr(runtime, "MCP_COLLECTION_POLICY", replace(_SAFE, servers=("1.0.0.1",)))
        assert runtime.cache_get("example.com") is None
        assert "example.com" not in runtime.cache
        assert "example.com" not in runtime._STATE.cache_policies
    finally:
        runtime.cache_clear()


@pytest.mark.asyncio
async def test_later_environment_mutation_does_not_change_bound_startup_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    from recon_tool.server.introspection import reload_data

    captured = network_policy.MCP_COLLECTION_POLICY
    monkeypatch.setenv("RECON_DNS_VIEW", "operator")
    await reload_data()
    await asyncio.sleep(0)
    assert network_policy.MCP_COLLECTION_POLICY is captured
    assert CollectionPolicy.from_environment({"RECON_DNS_VIEW": "operator"}).mode == "operator"


def test_bare_cli_needs_no_dns_setup_when_mcp_has_no_approved_view(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from typer.testing import CliRunner

    from recon_tool import resolver
    from recon_tool.cli import app as cli
    from recon_tool.models import SourceResult

    calls: list[str] = []

    async def collect(domain: str, **_kwargs: Any) -> tuple[TenantInfo, list[SourceResult]]:
        assert network_policy.current_policy().mode == "operator"
        calls.append(domain)
        return TenantInfo(None, "Synthetic namespace", domain, domain), [SourceResult(source_name="dns")]

    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(app, "MCP_COLLECTION_POLICY", CollectionPolicy.from_environment({"RECON_DNS_VIEW": "none"}))
    monkeypatch.setattr(resolver, "resolve_tenant", collect)
    result = CliRunner().invoke(cli, ["example.com"])
    assert result.exit_code == 0, result.output
    assert calls == ["example.com"]
    assert "Synthetic namespace" in result.output
    assert "RECON_DNS_" not in result.output
