"""Offline hosting rules reject lookalikes and preserve observation roles."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from recon_tool.fingerprints import get_cname_target_rules, load_builtin_fingerprints, reload_fingerprints
from recon_tool.formatter.serialize import format_tenant_dict, format_tenant_plain
from recon_tool.merger import merge_results
from recon_tool.models import EvidenceRecord, SourceResult
from recon_tool.sources import dns as dns_source
from recon_tool.sources import dns_base, dns_infra
from recon_tool.sources.dns_replay import replay_cached_dns_fingerprints
from recon_tool.sources.dns_tables import classify_chain

_ROUTES = (
    ("flyio", "Fly.io", "synthetic.fly.dev"),
    ("railway", "Railway", "synthetic.up.railway.app"),
    ("netlify", "Netlify", "synthetic.netlify.app"),
    ("render", "Render", "synthetic.onrender.com"),
    ("vercel", "Vercel", "cname.vercel-dns.com"),
)
_LOOKALIKES = (
    "notfly.dev",
    "synthetic.flyXdev",
    "synthetic.fly.dev.attacker.invalid",
    "synthetic.edgeapp.net",  # No independently supported current routing basis.
    "notrailway.app",
    "synthetic.railway.app",  # Outside the documented up.railway.app zone.
    "synthetic.upXrailway.app",
    "synthetic.up.railway.app.attacker.invalid",
    "notnetlify.app",
    "synthetic.netlify.app.attacker.invalid",
    "notonrender.com",
    "synthetic.onrender.com.attacker.invalid",
    "notvercel-dns.com",
    "cname.vercel-dns.com.attacker.invalid",
)


@pytest.fixture(autouse=True)
def _catalog_state() -> Iterator[None]:
    reload_fingerprints()
    yield
    reload_fingerprints()


def _fixture(
    monkeypatch: pytest.MonkeyPatch,
    records: dict[tuple[str, str], list[str]],
    *,
    failed: bool = False,
) -> list[tuple[str, str]]:
    queries: list[tuple[str, str]] = []

    async def resolve(
        name: str,
        kind: str,
        *,
        degraded_sources: set[str] | None = None,
        degraded_name: str = "",
        **_kwargs: object,
    ) -> list[str]:
        key = (name.lower().rstrip("."), kind)
        queries.append(key)
        if failed:
            if degraded_sources is not None:
                degraded_sources.add(degraded_name)
            return []
        return records.get(key, [])

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    return queries


@pytest.mark.asyncio
@pytest.mark.parametrize(("slug", "name", "target"), _ROUTES)
@pytest.mark.parametrize("root_dot", ["", "."])
async def test_root_routes_keep_evidence_and_agree_with_network_free_replay(
    monkeypatch: pytest.MonkeyPatch, slug: str, name: str, target: str, root_dot: str
) -> None:
    value = target.upper() + root_dot
    queries = _fixture(monkeypatch, {("www.example.com", "CNAME"): [value, value]})
    ctx = dns_base.DetectionCtx()
    await dns_infra.detect_cname_infra(ctx, "example.com")
    assert ctx.slugs == {slug}
    assert set(ctx.evidence) == {EvidenceRecord("CNAME", value, name, slug)}
    assert sorted(queries) == [("example.com", "CNAME"), ("www.example.com", "CNAME")]

    retained = SourceResult(source_name="dns", raw_dns_records=(("CNAME", value), ("CNAME", value)))
    replayed = replay_cached_dns_fingerprints(retained)
    assert replayed.detected_slugs == (slug,)
    assert replayed.evidence == (EvidenceRecord("CNAME", value, name, slug),)
    assert replay_cached_dns_fingerprints(replayed) == replayed
    assert len(queries) == 2  # Replay adds no DNS calls.


@pytest.mark.asyncio
@pytest.mark.parametrize("target", _LOOKALIKES)
async def test_deceptive_and_retired_root_routes_remain_unclassified(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    _fixture(monkeypatch, {("example.com", "CNAME"): [target]})
    ctx = dns_base.DetectionCtx()
    await dns_infra.detect_cname_infra(ctx, "example.com")
    assert not ctx.slugs
    assert not ctx.evidence
    assert ctx.raw_dns_records["CNAME"] == [target]
    retained = SourceResult(source_name="dns", raw_dns_records=(("CNAME", target),))
    assert replay_cached_dns_fingerprints(retained) == retained


@pytest.mark.parametrize("target", ["apex-loadbalancer.netlify.com", "APEX-LOADBALANCER.NETLIFY.COM."])
def test_netlify_load_balancer_is_an_exact_target_with_rule_provenance(target: str) -> None:
    application, infrastructure = classify_chain([target], get_cname_target_rules())
    assert application is not None
    assert (application.slug, application.pattern) == ("netlify", r"^apex-loadbalancer\.netlify\.com\.?$")
    assert infrastructure is None


@pytest.mark.parametrize(
    "target",
    [
        "netlify.com",
        "www.netlify.com",
        "api.netlify.com",
        "child.apex-loadbalancer.netlify.com",
        "notapex-loadbalancer.netlify.com",
        "apex-loadbalancer.netlify.com.attacker.invalid",
    ],
)
def test_netlify_corporate_hosts_and_load_balancer_lookalikes_are_not_hosting_rules(target: str) -> None:
    assert classify_chain([target], get_cname_target_rules()) == (None, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("owner", ["_vercel", "@", "_vercel.lookalike", "_unrelated"])
@pytest.mark.parametrize(
    "value",
    [
        "vc-domain-verify=synthetic-token",
        "vc-domain-verify=",
        "vc-domain-verify= ",
        "note=vc-domain-verify=synthetic-token",
        "unrelated=synthetic-token",
    ],
)
async def test_vercel_marker_requires_the_documented_owner_and_nonempty_value(
    monkeypatch: pytest.MonkeyPatch, owner: str, value: str
) -> None:
    hostname = "example.com" if owner == "@" else f"{owner}.example.com"
    _fixture(monkeypatch, {(hostname, "TXT"): [value, value]})
    ctx = dns_base.DetectionCtx()
    await dns_infra.detect_subdomain_txt(ctx, "example.com")
    accepted = owner == "_vercel" and value == "vc-domain-verify=synthetic-token"
    assert ("vercel" in ctx.slugs) is accepted
    assert ctx.evidence == ([EvidenceRecord("SUBDOMAIN_TXT", value, "Vercel", "vercel")] if accepted else [])


@pytest.mark.asyncio
@pytest.mark.parametrize("failed", [False, True])
async def test_missing_or_failed_dns_retains_partial_status_without_a_service_claim(
    monkeypatch: pytest.MonkeyPatch, failed: bool
) -> None:
    _fixture(monkeypatch, {}, failed=failed)
    ctx = dns_base.DetectionCtx()
    await dns_infra.detect_cname_infra(ctx, "example.com")
    await dns_infra.detect_subdomain_txt(ctx, "example.com")
    assert not ctx.slugs
    assert not ctx.evidence
    assert ("dns:cname" in ctx.degraded_sources) is failed
    assert ("dns:subdomain_txt" in ctx.degraded_sources) is failed
    retained = SourceResult(
        source_name="dns", raw_dns_records=(("CNAME", "synthetic.fly.dev"),), degraded_sources=("dns:cname",)
    )
    assert replay_cached_dns_fingerprints(retained) == retained


@pytest.mark.asyncio
async def test_vercel_marker_survives_complete_dns_merge_without_claiming_completed_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = "vc-domain-verify=synthetic-token"
    queries = _fixture(monkeypatch, {("_vercel.example.com", "TXT"): [value, value]})
    source = await dns_source.DNSSource().lookup("example.com", skip_ct=True, active_probes=False)
    assert source.error is None
    assert source.detected_slugs == ("vercel",)
    assert source.evidence == (EvidenceRecord("SUBDOMAIN_TXT", value, "Vercel", "vercel"),)
    info = merge_results([source], "example.com")
    serialized = format_tenant_dict(info)
    assert serialized["slugs"] == ["vercel"]
    assert not serialized["partial"]
    rendered = format_tenant_plain(info).lower()
    assert "vercel" in rendered
    assert "completed verification" not in rendered
    assert "active hosting" not in rendered
    assert ("_vercel.example.com", "TXT") in queries
    rule = next(
        rule
        for fp in load_builtin_fingerprints()
        if fp.slug == "vercel"
        for rule in fp.detections
        if rule.type == "subdomain_txt"
    )
    assert rule.pattern == r"_vercel:^vc-domain-verify=\S+$"
    assert rule.verified == "2026-10-23"
    assert rule.reference.endswith("/claim-domain-ownership")
    assert "Publication does not establish" in rule.description
