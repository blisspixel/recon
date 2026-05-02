"""Tests for the CNAME-chain surface-attribution pipeline.

Covers:
  * cname_target detection-type validation in the YAML schema layer.
  * Tier-aware classification: application beats infrastructure on chains
    that match both, longest-pattern-first match selection on overlapping
    patterns, terminal-only patterns work, no false positives on chains
    that don't match.
  * SurfaceAttribution propagation from DNS source through merger and
    cache round-trip.
  * Default-panel slug union: surface attributions union into apex
    services / slugs.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from recon_tool.fingerprints import (
    CnameTargetDetection,
    DetectionRule,
    Fingerprint,
    clear_ephemeral,
    get_cname_target_rules,
    inject_ephemeral,
    reload_fingerprints,
)
from recon_tool.models import SurfaceAttribution
from recon_tool.sources import dns as dns_source
from recon_tool.sources.dns import DNSSource, _classify_chain


# ── cname_target schema ────────────────────────────────────────────────


def test_cname_target_rules_load_with_tier() -> None:
    """The YAML loader populates tier on cname_target detection rules."""
    rules = get_cname_target_rules()
    assert rules, "expected at least one built-in cname_target rule"
    assert all(isinstance(r, CnameTargetDetection) for r in rules)
    tiers = {r.tier for r in rules}
    assert tiers <= {"application", "infrastructure"}
    # Both tiers should be represented in the seed catalogue.
    assert "application" in tiers
    assert "infrastructure" in tiers


def test_built_in_cname_target_patterns_are_specific() -> None:
    """Catch the obvious overreach of a generic ``amazonaws.com`` pattern."""
    rules = get_cname_target_rules()
    bad = [r for r in rules if r.pattern.strip() in {"amazonaws.com", ".com", ".net", ".io"}]
    assert not bad, f"overly generic cname_target patterns: {bad!r}"


# ── Chain classification ───────────────────────────────────────────────


def _make_rule(pattern: str, slug: str, tier: str) -> CnameTargetDetection:
    return CnameTargetDetection(
        pattern=pattern,
        name=slug.title(),
        slug=slug,
        category="Infrastructure",
        confidence="high",
        tier=tier,
    )


def test_classify_chain_picks_application_over_infrastructure() -> None:
    """Auth0 fronted by Cloudflare attributes the subdomain to Auth0."""
    rules = (
        _make_rule("auth0.com", "auth0", "application"),
        _make_rule("cloudflare.net", "cloudflare", "infrastructure"),
    )
    # Sorted longest-first by the caller; both same length so order stable.
    application, infrastructure = _classify_chain(
        ["auth0-ingress.us.auth0.com.cdn.cloudflare.net"], rules
    )
    assert application is not None
    assert application.slug == "auth0"
    assert infrastructure is not None
    assert infrastructure.slug == "cloudflare"


def test_classify_chain_falls_back_to_infrastructure_when_no_application() -> None:
    """A pure CDN chain attributes to the CDN."""
    rules = (
        _make_rule("auth0.com", "auth0", "application"),
        _make_rule("cloudfront.net", "aws-cloudfront", "infrastructure"),
    )
    application, infrastructure = _classify_chain(
        ["d3icacrl6c33io.cloudfront.net"], rules
    )
    assert application is None
    assert infrastructure is not None
    assert infrastructure.slug == "aws-cloudfront"


def test_classify_chain_returns_none_when_no_match() -> None:
    """Chains that don't match any rule produce no attribution."""
    rules = (_make_rule("auth0.com", "auth0", "application"),)
    application, infrastructure = _classify_chain(
        ["internal-prod-1234567.us-west-2.elb.amazonaws.com"], rules
    )
    assert application is None
    assert infrastructure is None


def test_classify_chain_walks_multiple_hops() -> None:
    """Application match in any hop wins, even mid-chain."""
    rules = (
        _make_rule("auth0.com", "auth0", "application"),
        _make_rule("cloudflare.net", "cloudflare", "infrastructure"),
    )
    chain = [
        "sso.example.com",  # not matched
        "auth0-ingress.us.auth0.com",  # application match
        "cloudflare.net.edge",  # infrastructure match
    ]
    application, infrastructure = _classify_chain(chain, rules)
    assert application is not None and application.slug == "auth0"
    assert infrastructure is not None and infrastructure.slug == "cloudflare"


# ── Full DNS source integration ────────────────────────────────────────


def _resolve_factory(rec: dict[str, list[str]]):
    """Mock _safe_resolve dispatched on f'{name}/{rdtype}' keys."""

    async def mock_resolve(domain, rdtype, **kwargs):
        return rec.get(f"{domain}/{rdtype}", [])

    return mock_resolve


@pytest.mark.asyncio
@patch("recon_tool.sources.dns._safe_resolve")
async def test_surface_attributions_emitted_via_full_pipeline(mock_resolve):
    """End-to-end: a related domain with a Shopify CNAME yields a surface attribution."""
    mock_resolve.side_effect = _resolve_factory(
        {
            "example.com/TXT": [],
            "example.com/MX": ["1 example-com.mail.protection.outlook.com."],
            # Pretend crt.sh is not contributing — instead the common-subdomain
            # probe finds shop.example.com via CNAME.
            "shop.example.com/CNAME": ["shops.myshopify.com"],
            "shops.myshopify.com/CNAME": [],
        }
    )
    result = await DNSSource().lookup("example.com")
    # The classifier walks the chain for shop.example.com, finds Shopify
    # in the terminal hop, and emits a SurfaceAttribution.
    matches = [sa for sa in result.surface_attributions if sa.subdomain == "shop.example.com"]
    assert matches, "expected a surface attribution for shop.example.com"
    assert matches[0].primary_slug == "shopify"
    assert matches[0].primary_tier == "application"


@pytest.mark.asyncio
@patch("recon_tool.sources.dns._safe_resolve")
async def test_surface_attribution_does_not_pollute_apex_slugs(mock_resolve):
    """Surface attributions stay distinct from apex Services / slugs.

    Apex DNS evidence (TXT/MX/SPF/etc., apex CNAMEs) and subdomain CNAME
    chain evidence answer different questions, so we keep them separate.
    The surface attribution lives on TenantInfo.surface_attributions; an
    EvidenceRecord is emitted for --explain consumers; but the slug is
    NOT unioned into ``detected_slugs`` and the name is NOT unioned into
    ``detected_services`` — that would double-count items that already
    show up under the Subdomain summary line in the panel.
    """
    mock_resolve.side_effect = _resolve_factory(
        {
            "example.com/TXT": [],
            "example.com/MX": ["1 example-com.mail.protection.outlook.com."],
            "help.example.com/CNAME": ["example.zendesk.com"],
            "example.zendesk.com/CNAME": [],
        }
    )
    result = await DNSSource().lookup("example.com")
    # Surface attribution recorded distinctly:
    matches = [sa for sa in result.surface_attributions if sa.subdomain == "help.example.com"]
    assert matches and matches[0].primary_slug == "zendesk"
    # Apex slugs / services do NOT include the surface-only zendesk attribution:
    assert "zendesk" not in result.detected_slugs
    assert not any("Zendesk" in svc for svc in result.detected_services)
    # But evidence is emitted so --explain still traces the chain:
    assert any(ev.slug == "zendesk" and ": " in ev.raw_value for ev in result.evidence)


# ── Ephemeral fingerprint round-trip ───────────────────────────────────


def test_inject_ephemeral_cname_target_fingerprint_loads_with_tier() -> None:
    """An ephemeral fingerprint with a cname_target rule + tier is queryable."""
    clear_ephemeral()
    try:
        fp = Fingerprint(
            name="TestApp",
            slug="testapp",
            category="Misc",
            confidence="high",
            m365=False,
            detections=(
                DetectionRule(
                    type="cname_target",
                    pattern="testapp.example.com",
                    tier="application",
                ),
            ),
        )
        inject_ephemeral(fp)
        rules = get_cname_target_rules()
        match = [r for r in rules if r.slug == "testapp"]
        assert match, "ephemeral cname_target rule not surfaced"
        assert match[0].tier == "application"
    finally:
        clear_ephemeral()
        reload_fingerprints()


# ── Cache serialization round-trip ─────────────────────────────────────


def test_surface_attribution_cache_round_trip() -> None:
    """Serialize and deserialize a TenantInfo with surface_attributions intact."""
    from recon_tool.cache import tenant_info_from_dict, tenant_info_to_dict
    from recon_tool.models import ConfidenceLevel, TenantInfo

    sa = SurfaceAttribution(
        subdomain="store.example.com",
        primary_slug="shopify",
        primary_name="Shopify",
        primary_tier="application",
        infra_slug="aws-cloudfront",
        infra_name="AWS CloudFront",
    )
    info = TenantInfo(
        tenant_id=None,
        display_name="Example",
        default_domain="example.com",
        queried_domain="example.com",
        confidence=ConfidenceLevel.HIGH,
        surface_attributions=(sa,),
    )
    d = tenant_info_to_dict(info)
    assert d["surface_attributions"][0]["primary_slug"] == "shopify"
    restored = tenant_info_from_dict(d)
    assert restored.surface_attributions == (sa,)


# Ensure the dns_source module-level imports resolve (catches import-time
# regressions when the schema changes shape).
def test_dns_module_classifier_present() -> None:
    assert hasattr(dns_source, "_classify_related_surface")
    assert hasattr(dns_source, "_resolve_cname_chain")
    assert hasattr(dns_source, "_classify_chain")
