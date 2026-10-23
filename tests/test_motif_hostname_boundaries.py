"""Provider-domain motifs use hostname grammar, not arbitrary substrings."""

from __future__ import annotations

from typing import Any

import pytest

from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.models import TenantInfo
from recon_tool.motifs import (
    _BUILTIN_PATH,
    ChainMotif,
    _load_from_path,
    _parse_motif_marker,
    match_chain_motifs,
)
from recon_tool.sources import dns as dns_source
from recon_tool.sources import dns_base

_BUILTINS = tuple(_load_from_path(_BUILTIN_PATH))


@pytest.mark.parametrize("motif", _BUILTINS, ids=lambda motif: motif.name)
def test_every_builtin_rejects_deceptive_provider_names(motif: ChainMotif) -> None:
    chain = [marker.patterns[0] for marker in motif.markers]
    assert all(marker.match_mode == "dns_suffix" for marker in motif.markers)
    assert match_chain_motifs(chain, (motif,))
    for deceptive in ([hop + ".attacker.invalid" for hop in chain], ["not" + hop for hop in chain]):
        assert match_chain_motifs(deceptive, (motif,)) == []
    assert match_chain_motifs(chain[:-1], (motif,)) == []
    if len(chain) > 1:
        assert match_chain_motifs(list(reversed(chain)), (motif,)) == []


@pytest.mark.parametrize(
    ("motif", "position", "pattern"),
    [
        (motif, i, pattern)
        for motif in _BUILTINS
        for i, marker in enumerate(motif.markers)
        for pattern in marker.patterns
    ],
    ids=lambda value: value.name if isinstance(value, ChainMotif) else str(value),
)
def test_every_builtin_alternative_preserves_normalization_and_order(
    motif: ChainMotif, position: int, pattern: str
) -> None:
    chain = ["edge." + marker.patterns[0] for marker in motif.markers]
    chain[position] = "EDGE." + pattern.upper() + "."
    interleaved = [hop for item in chain for hop in ("intermediate.example.org", item)]
    match = match_chain_motifs(interleaved, (motif,), subdomain="api.example.com")
    assert len(match) == 1
    assert match[0].chain == tuple(chain)
    assert match[0].subdomain == "api.example.com"


@pytest.mark.parametrize(
    "hop",
    [
        "edge..cloudflare.net",
        ".cloudflare.net",
        "-edge.cloudflare.net",
        "edge-.cloudflare.net",
        "edge.cloudflare.net..",
        " edge.cloudflare.net",
        "edge.cloudflare.net\n",
        "https://edge.cloudflare.net",
        "*.cloudflare.net",
        "_edge.cloudflare.net",
        "\u00e9dge.cloudflare.net",
        "a" * 64 + ".cloudflare.net",
        ".".join(["a" * 60] * 4) + ".cloudflare.net",
    ],
)
def test_domain_marker_rejects_invalid_hostname(hop: str) -> None:
    motif = next(m for m in _BUILTINS if m.name == "cloudflare_to_aws")
    assert match_chain_motifs([hop, "origin.amazonaws.com"], (motif,)) == []


@pytest.mark.parametrize("mode", ["regex", "", None, [], {}])
def test_invalid_custom_mode_rejects_marker(mode: Any) -> None:
    assert _parse_motif_marker({"name": "invalid", "match": ["example.org"], "match_mode": mode}) is None


@pytest.mark.parametrize("pattern", ["edge-", "*.example.org", "example.org..", 42, ""])
def test_domain_marker_requires_valid_patterns(pattern: Any) -> None:
    assert _parse_motif_marker({"name": "invalid", "match": [pattern], "match_mode": "dns_suffix"}) is None


def test_legacy_custom_fragments_are_not_silently_reinterpreted() -> None:
    legacy = _parse_motif_marker({"name": "fragment", "match": ["edge-"]})
    explicit = _parse_motif_marker({"name": "fragment", "match": ["edge-"], "match_mode": "substring"})
    assert legacy == explicit
    assert legacy is not None
    motif = ChainMotif("custom", "Custom fragment", "Operator-defined observation", "low", (legacy,))
    assert match_chain_motifs(["my-edge-route.example.org"], (motif,))


@pytest.mark.asyncio
@pytest.mark.parametrize("deceptive", [False, True])
async def test_real_surface_pipeline_keeps_queried_host_provenance(
    monkeypatch: pytest.MonkeyPatch, deceptive: bool
) -> None:
    host = "help.example.com"
    chain = ["edge.cloudflare.net", "origin.amazonaws.com"]
    if deceptive:
        chain = [hop + ".attacker.example.org" for hop in chain]
    answers = dict(zip([host, *chain[:-1]], ([hop] for hop in chain), strict=True))

    async def resolve(name: str, rdtype: str, **_kwargs: Any) -> list[str]:
        assert rdtype == "CNAME"
        return answers.get(name, [])

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    monkeypatch.setattr(dns_source, "get_cname_target_rules", lambda: ())
    monkeypatch.setattr(dns_source, "load_motifs", lambda: _BUILTINS)
    ctx = dns_base.DetectionCtx()
    ctx.related_domains.add(host)
    await dns_source._classify_related_surface(ctx, "example.com")
    payload = format_tenant_dict(
        TenantInfo(
            tenant_id=None,
            display_name="Synthetic namespace",
            default_domain="example.com",
            queried_domain="example.com",
            chain_motifs=tuple(ctx.chain_motifs),
        )
    )
    assert payload["queried_domain"] == "example.com"
    if deceptive:
        assert payload["chain_motifs"] == []
    else:
        assert payload["chain_motifs"] == [
            {
                "motif_name": "cloudflare_to_aws",
                "display_name": "Cloudflare \u2192 AWS origin",
                "confidence": "medium",
                "subdomain": host,
                "chain": chain,
            }
        ]
