"""Exercise the MCP public DNS boundary without opening network sockets."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Generator
from typing import Any

import certifi
import dns.asyncquery
import dns.exception
import dns.message
import dns.nameserver
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from recon_tool import chain, resolver
from recon_tool.fingerprints import CnameTargetDetection
from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.models import SourceResult, TenantInfo
from recon_tool.motifs import ChainMotif, _MotifMarker
from recon_tool.network_policy import CollectionPolicy, collection_scope
from recon_tool.server import app, ephemeral, graph, introspection, lookup, posture, review, runtime
from recon_tool.sources import dns_base
from recon_tool.sources.dns import DNSSource

_PRIVATE = "private-route42.service.example.net"
_PUBLIC = "public.service.example.net"
_SAFE_POLICY = CollectionPolicy("caller-safe", ("1.1.1.1", "1.0.0.1"), "cloudflare-dns.com")


@pytest.fixture
def dns_views(monkeypatch: pytest.MonkeyPatch) -> Generator[list[tuple[bool, str, str]]]:
    """Use real dnspython response decoding, but stub both network transports."""
    queries: list[tuple[bool, str, str]] = []

    def answer(request: dns.message.Message, public: bool) -> dns.message.Message:
        question = request.question[0]
        name = question.name.to_text().rstrip(".")
        rdtype = dns.rdatatype.to_text(question.rdtype)
        queries.append((public, name, rdtype))
        response = dns.message.make_response(request)
        records = {
            ("help.example.com", "CNAME"): ["entry.example.org."],
            ("entry.example.org", "CNAME"): [(_PUBLIC if public else _PRIVATE) + "."],
            ("example.com", "TXT"): ['"public-declaration"' if public else '"private-view-value"'],
            ("related.example.net", "TXT"): ['"public-related"' if public else '"private-related"'],
        }.get((name, rdtype), [])
        if records:
            response.answer.append(dns.rrset.from_text(name + ".", 60, "IN", rdtype, *records))
        return dns.message.from_wire(response.to_wire())

    async def public_query(request: dns.message.Message, address: str, **kwargs: Any) -> dns.message.Message:
        assert address == "https://cloudflare-dns.com/dns-query"
        assert kwargs["bootstrap_address"] in _SAFE_POLICY.servers
        assert kwargs["verify"] == certifi.where()
        return answer(request, True)

    async def system_query(
        _self: dns.nameserver.Do53Nameserver, request: dns.message.Message, *_args: Any, **_kwargs: Any
    ) -> dns.message.Message:
        return answer(request, False)

    monkeypatch.setattr(dns.asyncquery, "https", public_query)
    for module in (app, graph, runtime):
        monkeypatch.setattr(module, "MCP_COLLECTION_POLICY", _SAFE_POLICY)
    monkeypatch.setattr(dns.nameserver.Do53Nameserver, "async_query", system_query)
    runtime.cache_clear()
    runtime.rate_limit_clear()
    yield queries
    runtime.cache_clear()
    runtime.rate_limit_clear()


@pytest.mark.asyncio
async def test_public_context_isolates_answers_and_restores_nested_state(
    dns_views: list[tuple[bool, str, str]],
) -> None:
    original = dns_base.get_resolver()
    assert await dns_base.safe_resolve("example.com", "TXT") == ["private-view-value"]
    with collection_scope(_SAFE_POLICY):
        selected = dns_base.get_resolver()
        assert selected is not original
        assert selected.search == []
        assert selected.cache is None
        assert all(isinstance(ns, dns.nameserver.DoHNameserver) for ns in selected.nameservers)
        assert await dns_base.safe_resolve("example.com", "TXT") == ["public-declaration"]
        with collection_scope(_SAFE_POLICY):
            assert dns_base.get_resolver() is not selected
        assert dns_base.get_resolver() is selected
    assert dns_base.get_resolver() is original
    assert {public for public, _, _ in dns_views} == {False, True}


@pytest.mark.asyncio
async def test_concurrent_trusted_and_mcp_collection_do_not_share_view(
    dns_views: list[tuple[bool, str, str]],
) -> None:
    async def collect(public: bool) -> list[str]:
        if public:
            with collection_scope(_SAFE_POLICY):
                await asyncio.sleep(0)
                return await dns_base.safe_resolve("example.com", "TXT")
        await asyncio.sleep(0)
        return await dns_base.safe_resolve("example.com", "TXT")

    assert await asyncio.gather(collect(True), collect(False)) == [["public-declaration"], ["private-view-value"]]
    assert {public for public, _, _ in dns_views} == {False, True}


@pytest.mark.asyncio
async def test_cancellation_restores_resolver_context() -> None:
    original = dns_base.get_resolver()
    started = asyncio.Event()
    restored: list[bool] = []

    async def collect() -> None:
        try:
            with collection_scope(_SAFE_POLICY):
                started.set()
                await asyncio.Event().wait()
        finally:
            restored.append(dns_base.get_resolver() is original)

    task = asyncio.create_task(collect())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert restored == [True]
    assert dns_base.get_resolver() is original


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [dns.exception.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer])
async def test_public_failure_never_falls_back_to_system(
    monkeypatch: pytest.MonkeyPatch,
    dns_views: list[tuple[bool, str, str]],
    failure: type[Exception],
) -> None:
    async def fail(request: dns.message.Message, *_args: Any, **_kwargs: Any) -> dns.message.Message:
        if failure is dns.exception.Timeout:
            raise dns.exception.Timeout()
        response = dns.message.make_response(request)
        if failure is dns.resolver.NXDOMAIN:
            response.set_rcode(dns.rcode.NXDOMAIN)
        return response

    monkeypatch.setattr(dns.asyncquery, "https", fail)
    degraded: set[str] = set()
    with collection_scope(_SAFE_POLICY), dns_base.dns_query_ledger() as ledger:
        assert (
            await dns_base.safe_resolve(
                "example.com", "TXT", timeout=0.02, degraded_sources=degraded, degraded_name="dns:txt"
            )
            == []
        )
    assert dns_views == []
    assert ledger.attempted == 1
    assert ("dns:txt" in degraded) is (failure is dns.exception.Timeout)


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["classified", "motif", "unclassified"])
async def test_mcp_lookup_cache_and_replay_exclude_split_view_records(
    monkeypatch: pytest.MonkeyPatch, dns_views: list[tuple[bool, str, str]], surface: str
) -> None:
    from recon_tool.sources import dns as dns_source

    rule = CnameTargetDetection(
        "service.example.net" if surface == "classified" else "unmatched.example.net",
        "Synthetic Service",
        "synthetic-service",
        "Infrastructure",
        "high",
        "infrastructure",
    )
    motif = ChainMotif(
        "synthetic-route",
        "Synthetic route",
        "Reserved fixture",
        "medium",
        (_MotifMarker("entry", ("entry.example.org",)), _MotifMarker("service", ("service.example.net",))),
    )
    monkeypatch.setattr(dns_source, "get_cname_target_rules", lambda: (rule,))
    monkeypatch.setattr(dns_source, "load_motifs", lambda: (motif,) if surface == "motif" else ())

    async def dns_only(domain: str, **_kwargs: Any) -> tuple[TenantInfo, list[SourceResult]]:
        return await resolver.resolve_tenant(domain, pool=resolver.SourcePool([DNSSource()]), skip_ct=True)

    monkeypatch.setattr(app, "_resolve_tenant", dns_only)
    trusted, _ = await dns_only("example.com")
    assert _PRIVATE in json.dumps(format_tenant_dict(trusted, include_unclassified=True))
    dns_views.clear()
    first = await lookup.lookup_tenant("example.com", format="json", explain=True)
    assert _PRIVATE not in first
    assert "private-view-value" not in first
    document = json.loads(first)
    assert document["resolution_vantage"] == "caller-safe"
    assert document["resolution_policy_id"] == _SAFE_POLICY.identity
    if surface != "unclassified":
        assert _PUBLIC in first
    assert dns_views
    assert all(public for public, _, _ in dns_views)
    count = len(dns_views)
    assert await lookup.lookup_tenant("example.com", format="json", explain=True) == first
    replayed = await ephemeral.reevaluate_domain("example.com")
    assert _PRIVATE not in json.dumps(replayed)
    assert "private-view-value" not in json.dumps(replayed)
    assert replayed["resolution_policy_id"] == _SAFE_POLICY.identity
    assert len(dns_views) == count
    cached = runtime.cache_get("example.com")
    assert cached is not None
    assert _PRIVATE not in repr(cached)
    assert "private-view-value" not in repr(cached)


@pytest.mark.asyncio
async def test_fingerprint_clear_preserves_cached_collection_provenance(
    dns_views: list[tuple[bool, str, str]],
) -> None:
    from recon_tool.fingerprints import clear_ephemeral

    info = TenantInfo(
        None,
        "Synthetic namespace",
        "example.com",
        "example.com",
        resolution_vantage="caller-safe",
        resolution_policy_id=_SAFE_POLICY.identity,
    )
    runtime.cache_set("example.com", info, [SourceResult(source_name="dns")])
    timestamp = runtime.cache["example.com"][0]
    try:
        await ephemeral.inject_ephemeral_fingerprint(
            name="Synthetic Platform",
            slug="synthetic-platform",
            category="SaaS",
            confidence="medium",
            detections=[{"type": "txt", "pattern": "synthetic-platform-verify="}],
        )
        await ephemeral.clear_ephemeral_fingerprints()
        cached = runtime.cache_get("example.com")
        assert cached is not None
        assert cached[0].resolution_vantage == "caller-safe"
        assert cached[0].resolution_policy_id == _SAFE_POLICY.identity
        assert runtime.cache["example.com"][0] == timestamp
        assert dns_views == []
    finally:
        clear_ephemeral()


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["lookup", "review", "discover", "dag", "posture", "chain"])
async def test_network_tool_entrypoints_use_public_view(
    monkeypatch: pytest.MonkeyPatch, dns_views: list[tuple[bool, str, str]], tool: str
) -> None:
    async def collect(domain: str, **_kwargs: Any) -> tuple[TenantInfo, list[SourceResult]]:
        values = await dns_base.safe_resolve(domain, "TXT")
        assert values == ["public-declaration"]
        return (
            TenantInfo(None, "Synthetic namespace", domain, domain),
            [SourceResult(source_name="dns", raw_dns_records=(("TXT", tuple(values)),))],
        )

    monkeypatch.setattr(app, "_resolve_tenant", collect)
    monkeypatch.setattr(chain, "resolve_tenant", collect)
    tools: dict[str, Callable[..., Any]] = {
        "lookup": lookup.lookup_tenant,
        "review": review.build_review_bundle,
        "discover": introspection.discover_fingerprint_candidates,
        "dag": introspection.explain_dag,
        "posture": posture.analyze_posture,
        "chain": graph.chain_lookup,
    }
    await tools[tool]("example.com")
    assert dns_views
    assert all(public for public, _, _ in dns_views)


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["review", "chain"])
async def test_fresh_and_recursive_artifacts_bind_real_related_enrichment(
    monkeypatch: pytest.MonkeyPatch, dns_views: list[tuple[bool, str, str]], tool: str
) -> None:
    class RelatedSeed:
        name = "synthetic-seed"

        async def lookup(self, _domain: str, **_kwargs: Any) -> SourceResult:
            return SourceResult(source_name=self.name, related_domains=("related.example.net",))

    async def collect(domain: str, **_kwargs: Any) -> tuple[TenantInfo, list[SourceResult]]:
        return await resolver.resolve_tenant(
            domain, pool=resolver.SourcePool([DNSSource(), RelatedSeed()]), skip_ct=True
        )

    monkeypatch.setattr(app, "_resolve_tenant", collect)
    monkeypatch.setattr(chain, "resolve_tenant", collect)
    runtime.cache_set("example.com", TenantInfo(None, "stale-sentinel", "example.com", "example.com"), [])
    if tool == "review":
        output = json.dumps(await review.build_review_bundle("example.com", no_ct=True))
    else:
        output = await graph.chain_lookup("example.com")
    assert "stale-sentinel" not in output
    assert _PRIVATE not in output
    assert "private-related" not in output
    assert "private-view-value" not in output
    assert (True, "related.example.net", "TXT") in dns_views
    assert all(public for public, _, _ in dns_views)


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["lookup", "review", "chain"])
async def test_missing_startup_approval_reports_capability_without_network(
    monkeypatch: pytest.MonkeyPatch, dns_views: list[tuple[bool, str, str]], tool: str
) -> None:
    from recon_tool.mcp_client.sdk_compat import ToolError

    policy = CollectionPolicy.from_environment({})
    for module in (app, graph, runtime):
        monkeypatch.setattr(module, "MCP_COLLECTION_POLICY", policy)
    tools: dict[str, Callable[..., Any]] = {
        "lookup": lookup.lookup_tenant,
        "review": review.build_review_bundle,
        "chain": graph.chain_lookup,
    }
    with pytest.raises(ToolError, match=r"DNS-dependent lookup unavailable.*once"):
        await tools[tool]("example.com")
    assert dns_views == []
    assert await introspection.get_fingerprints(limit=1)
