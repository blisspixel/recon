"""Synthetic retained-record tests for narrowly supported catalog claims."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest

from recon_tool.fingerprints import (
    DetectionRule,
    clear_ephemeral,
    get_cname_target_rules,
    get_subdomain_txt_patterns,
    load_fingerprints,
    reload_fingerprints,
)
from recon_tool.models import EvidenceRecord, SignalContext, TenantInfo
from recon_tool.posture import analyze_posture, load_posture_rules, reload_posture
from recon_tool.signals import evaluate_signals, load_signals, reload_signals
from recon_tool.sources import dns as dns_source
from recon_tool.sources import dns_base, dns_email, dns_infra
from recon_tool.sources.dns_tables import classify_chain


@pytest.fixture(autouse=True)
def _clean_catalog_state() -> Iterator[None]:
    clear_ephemeral()
    reload_fingerprints()
    reload_signals()
    reload_posture()
    yield
    clear_ephemeral()
    reload_fingerprints()
    reload_signals()
    reload_posture()


def _dns_fixture(monkeypatch: pytest.MonkeyPatch, records: dict[tuple[str, str], list[str]]) -> list[tuple[str, str]]:
    queries: list[tuple[str, str]] = []

    async def resolve(name: str, record_type: str, **_kwargs: object) -> list[str]:
        key = (name.lower().rstrip("."), record_type)
        queries.append(key)
        return records.get(key, [])

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    return queries


def _rules(slug: str, kind: str) -> dict[str, DetectionRule]:
    return {
        rule.pattern: rule
        for fingerprint in load_fingerprints()
        if fingerprint.slug == slug
        for rule in fingerprint.detections
        if rule.type == kind
    }


@pytest.mark.parametrize(
    ("hostname", "pattern"),
    [
        ("synthetic.vercel-dns-017.com", "vercel-dns-017.com"),
        ("SYNTHETIC.VERCEL-DNS-017.COM.", "vercel-dns-017.com"),
        ("cname.vercel-dns-0.com", r"^cname\.vercel-dns-0\.com\.?$"),
        ("CNAME.VERCEL-DNS-0.COM.", r"^cname\.vercel-dns-0\.com\.?$"),
        ("cname.vercel-dns.com", "cname.vercel-dns.com"),
        ("synthetic.vercel.app", "vercel.app"),
    ],
)
def test_vercel_supported_targets_select_the_specific_rule(hostname: str, pattern: str) -> None:
    rules = tuple(sorted(get_cname_target_rules(), key=lambda rule: -len(rule.pattern)))
    application, infrastructure = classify_chain([hostname], rules)
    assert application is not None
    assert application.slug == "vercel"
    assert application.pattern == pattern
    assert infrastructure is None
    assert "vercel-dns-" not in _rules("vercel", "cname_target")


@pytest.mark.parametrize(
    "hostname",
    [
        "vercel-dns-attacker.invalid",
        "synthetic.vercel-dns-999.com",
        "synthetic.vercel-dns-017.com.lookalike.invalid",
        "synthetic.notvercel-dns-017.com",
        "synthetic.vercel-dns-017.com.evil.com",
        "cname.vercel-dns-0.com.lookalike.invalid",
        "prefix.cname.vercel-dns-0.com",
        "notcname.vercel-dns-0.com",
        "cnameXvercel-dns-0Xcom",
    ],
)
def test_vercel_fragments_and_unconfirmed_numbered_families_do_not_match(hostname: str) -> None:
    application, infrastructure = classify_chain([hostname], get_cname_target_rules())
    assert application is None or application.slug != "vercel"
    assert infrastructure is None or infrastructure.slug != "vercel"


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["synthetic.vercel-dns-017.com", "cname.vercel-dns-0.com"])
async def test_vercel_application_and_edge_keep_the_observed_chain_separate_from_apex(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    edge = "synthetic.cloudfront.net"
    queries = _dns_fixture(
        monkeypatch,
        {("app.example.com", "CNAME"): [target.upper() + "."], (target, "CNAME"): [edge]},
    )
    ctx = dns_base.DetectionCtx()
    ctx.related_domains.add("app.example.com")
    await dns_source._classify_related_surface(ctx, "example.com")

    (surface,) = ctx.surface_attributions
    assert surface.subdomain == "app.example.com"
    assert surface.primary_slug == "vercel"
    assert surface.primary_tier == "application"
    assert surface.infra_slug == "aws-cloudfront"
    assert not ctx.slugs
    assert not ctx.services
    assert ctx.evidence == [EvidenceRecord("CNAME", f"app.example.com: {target} -> {edge}", "Vercel", "vercel")]
    assert not ctx.unclassified_cname_chains
    assert all(record_type == "CNAME" for _, record_type in queries)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target", ["synthetic.awsapps.com", "SYNTHETIC.AWSAPPS.COM.", "synthetic.awsapps.com.lookalike.invalid"]
)
async def test_generic_awsapps_routing_does_not_establish_ses(monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    application, infrastructure = classify_chain([target], get_cname_target_rules())
    assert application is None or application.slug != "aws-ses"
    assert infrastructure is None or infrastructure.slug != "aws-ses"
    _dns_fixture(monkeypatch, {("example.com", "MX"): [f"10 {target}"]})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_mx(ctx, "example.com")
    assert "aws-ses" not in ctx.slugs
    assert not any(evidence.slug == "aws-ses" for evidence in ctx.evidence)
    assert "awsapps.com" not in _rules("aws-ses", "cname_target")


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["inbound-smtp.us-east-1.amazonaws.com", "INBOUND-SMTP.EU-WEST-1.AMAZONAWS.COM."])
async def test_specific_ses_receiving_mx_retains_exact_observed_record(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    value = f"10 {target}"
    _dns_fixture(monkeypatch, {("example.com", "MX"): [value]})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_mx(ctx, "example.com")
    assert "aws-ses" in ctx.slugs
    assert any(evidence.source_type == "MX" and evidence.raw_value == value for evidence in ctx.evidence)
    assert not ctx.m365


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["_oktaverification=synthetic", "_OKTAVERIFICATION=synthetic", "unrelated TXT"])
async def test_okta_owner_name_is_not_an_apex_value_fingerprint(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    _dns_fixture(monkeypatch, {("example.com", "TXT"): [value]})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    assert "okta" not in ctx.slugs
    assert not any(evidence.slug == "okta" for evidence in ctx.evidence)
    assert "^_oktaverification=" not in _rules("okta", "txt")


@pytest.mark.parametrize("target", ["synthetic.customdomains.okta.com", "SYNTHETIC.CUSTOMDOMAINS.OKTA.COM."])
def test_okta_supported_custom_domain_routing_remains(target: str) -> None:
    application, _infrastructure = classify_chain([target], get_cname_target_rules())
    assert application is not None
    assert application.slug == "okta"
    assert application.pattern == "customdomains.okta.com"
    lookalike = target.rstrip(".") + ".lookalike.invalid"
    application, infrastructure = classify_chain([lookalike], get_cname_target_rules())
    assert application is None
    assert infrastructure is None


@pytest.mark.asyncio
async def test_okta_separate_legacy_txt_rule_is_retained_without_a_verification_date(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = "okta-domain-verification=synthetic"
    _dns_fixture(monkeypatch, {("example.com", "TXT"): [value]})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    assert "okta" in ctx.slugs
    assert EvidenceRecord("TXT", value, "Okta", "okta") in ctx.evidence
    assert _rules("okta", "txt")["^okta-domain-verification"].verified == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("owner", ["_github-challenge", "_github-challenge-synthetic", "_github-challenge.lookalike"])
async def test_generic_github_challenge_does_not_claim_advanced_security_or_add_probes(
    monkeypatch: pytest.MonkeyPatch, owner: str
) -> None:
    queries = _dns_fixture(monkeypatch, {(f"{owner}.example.com", "TXT"): ["synthetic-verification-token"]})
    ctx = dns_base.DetectionCtx()
    await dns_infra.detect_subdomain_txt(ctx, "example.com")
    assert "github-advanced-security" not in ctx.slugs
    assert not any(evidence.slug == "github-advanced-security" for evidence in ctx.evidence)
    assert not any(name.startswith("_github-challenge") for name, _record_type in queries)
    assert not any(rule.slug == "github-advanced-security" for rule in get_subdomain_txt_patterns())


@pytest.mark.asyncio
@pytest.mark.parametrize("owner", ["_slack-challenge", "_slack-challenge.lookalike", "@"])
async def test_slack_challenge_is_an_owner_qualified_administrative_indicator(
    monkeypatch: pytest.MonkeyPatch, owner: str
) -> None:
    value = "synthetic-slack-verification-token"
    name = "example.com" if owner == "@" else f"{owner}.example.com"
    _dns_fixture(monkeypatch, {(name, "TXT"): [value]})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    await dns_infra.detect_subdomain_txt(ctx, "example.com")
    assert ("slack" in ctx.slugs) is (owner == "_slack-challenge")
    if owner == "_slack-challenge":
        assert ctx.services == {"Slack"}
        assert ctx.evidence == [EvidenceRecord("SUBDOMAIN_TXT", value, "Slack", "slack")]
    rule = _rules("slack", "subdomain_txt")["_slack-challenge:."]
    assert "Pro, Business+, and Enterprise" in rule.description
    assert "does not establish" in rule.description
    assert "active use" in rule.description


@pytest.mark.parametrize("target", ["synthetic.glitch.me", "SYNTHETIC.GLITCH.ME."])
def test_glitch_is_legacy_routing_not_application_hosting(target: str) -> None:
    application, infrastructure = classify_chain([target], get_cname_target_rules())
    assert application is None
    assert infrastructure is not None
    assert infrastructure.slug == "glitch"
    rule = _rules("glitch", "cname_target")["glitch.me"]
    assert "Legacy" in rule.description
    assert "redirect or stale configuration" in rule.description
    assert "does not establish a running Glitch application" in rule.description
    application, infrastructure = classify_chain([target.rstrip(".") + ".lookalike.invalid"], get_cname_target_rules())
    assert application is None
    assert infrastructure is None


def test_retired_security_slug_cannot_drive_signals_or_posture_even_from_old_retained_data() -> None:
    retired = "github-advanced-security"
    assert not any(retired in signal.candidates for signal in load_signals())
    assert not any(retired in rule.slugs_any for rule in load_posture_rules())
    info = TenantInfo(
        tenant_id=None,
        display_name="Synthetic Alpha",
        default_domain="alpha.invalid",
        queried_domain="alpha.invalid",
        slugs=(retired,),
        evidence=(EvidenceRecord("SUBDOMAIN_TXT", "synthetic", "GitHub Advanced Security", retired),),
    )
    assert not any("supply-chain" in observation.statement.lower() for observation in analyze_posture(info))
    for slugs, expected in [({retired, "snyk"}, False), ({"sonatype", "snyk"}, True)]:
        matches = evaluate_signals(SignalContext(detected_slugs=frozenset(slugs)))
        assert any(match.name == "Software Supply Chain Maturity" for match in matches) is expected
    current = replace(info, slugs=("snyk",), evidence=(EvidenceRecord("TXT", "snyk=synthetic", "Snyk", "snyk"),))
    assert any("supply-chain" in observation.statement.lower() for observation in analyze_posture(current))


@pytest.mark.asyncio
async def test_sparse_empty_records_do_not_synthesize_researched_vendor_claims(monkeypatch: pytest.MonkeyPatch) -> None:
    _dns_fixture(monkeypatch, {})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    await dns_email.detect_mx(ctx, "example.com")
    await dns_infra.detect_subdomain_txt(ctx, "example.com")
    assert not ctx.slugs.intersection({"okta", "slack", "github-advanced-security", "aws-ses"})
    assert classify_chain([], get_cname_target_rules()) == (None, None)
