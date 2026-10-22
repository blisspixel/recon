"""Specify resolver-view disclosure across the CNAME output surfaces.

The synthetic private view returns an alias absent from the public view.
This characterizes the current trust boundary; suffix admission is not proof
that a name or its answer is public. All DNS is stubbed, including the
classifier's wildcard probe, and both views use only reserved example names.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from recon_tool.fingerprints import CnameTargetDetection
from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.models import TenantInfo
from recon_tool.motifs import ChainMotif, _MotifMarker
from recon_tool.sources import dns as dns_source
from recon_tool.sources import dns_base

_HOST = "help.example.com"
_PUBLIC_HOP = "entry.example.org"
_PRIVATE_ALIAS = "private-route42.service.example.net"


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["classified", "motif", "unclassified"])
@pytest.mark.parametrize("private_view", [False, True], ids=["public-view", "split-view"])
async def test_resolver_view_alias_output(monkeypatch: pytest.MonkeyPatch, surface: str, private_view: bool) -> None:
    queries: list[tuple[str, str]] = []
    answers = {_HOST: [_PUBLIC_HOP]}
    if private_view:
        answers[_PUBLIC_HOP] = [_PRIVATE_ALIAS]

    async def resolve(host: str, rdtype: str, **_kwargs: Any) -> list[str]:
        queries.append((host, rdtype))
        assert rdtype == "CNAME", "the surface walker must not issue A/AAAA"
        return answers.get(host, [])

    # The nonmatching rule keeps unclassified collection active without
    # relying on the changing built-in catalog or any real provider name.
    rule = CnameTargetDetection(
        pattern="service.example.net" if surface == "classified" else "unmatched.example.net",
        name="Synthetic Service",
        slug="synthetic-service",
        category="Infrastructure",
        confidence="high",
        tier="infrastructure",
    )
    motif = ChainMotif(
        name="synthetic-route",
        display_name="Synthetic route",
        description="Reserved resolver-view fixture",
        confidence="medium",
        markers=(
            _MotifMarker(name="entry", patterns=("entry.example.org",)),
            _MotifMarker(name="service", patterns=("service.example.net",)),
        ),
    )
    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    monkeypatch.setattr(dns_source, "get_cname_target_rules", lambda: (rule,))
    monkeypatch.setattr(dns_source, "load_motifs", lambda: (motif,) if surface == "motif" else ())
    ctx = dns_base.DetectionCtx()
    ctx.related_domains.add(_HOST)
    await dns_source._classify_related_surface(ctx, "example.com")

    walked = [query for query in queries if not query[0].startswith("nonsense-classifier-guard-")]
    expected_queries = [(_HOST, "CNAME"), (_PUBLIC_HOP, "CNAME")]
    if private_view:
        expected_queries.append((_PRIVATE_ALIAS, "CNAME"))
    assert walked == expected_queries
    assert len(queries) == len(expected_queries) + 1  # one empty wildcard probe

    info = TenantInfo(
        tenant_id=None,
        display_name="Synthetic namespace",
        default_domain="example.com",
        queried_domain="example.com",
        evidence=tuple(ctx.evidence),
        surface_attributions=tuple(ctx.surface_attributions),
        chain_motifs=tuple(ctx.chain_motifs),
        unclassified_cname_chains=tuple(ctx.unclassified_cname_chains),
    )
    ordinary = format_tenant_dict(info)
    diagnostic = format_tenant_dict(info, include_unclassified=True)
    assert "unclassified_cname_chains" not in ordinary
    assert (_PRIVATE_ALIAS in json.dumps(diagnostic)) is private_view

    if surface == "classified" and private_view:
        assert ordinary["evidence"][0]["raw_value"] == f"{_HOST}: {_PUBLIC_HOP} -> {_PRIVATE_ALIAS}"
        assert len(ordinary["surface_attributions"]) == 1
        assert ordinary["chain_motifs"] == []
        assert diagnostic["unclassified_cname_chains"] == []
    elif surface == "motif" and private_view:
        assert ordinary["chain_motifs"][0]["chain"] == [_PUBLIC_HOP, _PRIVATE_ALIAS]
        assert "evidence" not in ordinary
        assert ordinary["surface_attributions"] == []
    else:
        assert _PRIVATE_ALIAS not in json.dumps(ordinary)
        assert "evidence" not in ordinary
        assert ordinary["chain_motifs"] == []
        assert ordinary["surface_attributions"] == []

    if surface != "classified" or not private_view:
        chain = [_PUBLIC_HOP, _PRIVATE_ALIAS] if private_view else [_PUBLIC_HOP]
        assert diagnostic["unclassified_cname_chains"] == [{"subdomain": _HOST, "chain": chain}]
