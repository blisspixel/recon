"""Precision boundaries for fingerprint rules promoted from the regional round."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from unittest.mock import patch

import pytest

from recon_tool.fingerprints import get_cname_target_rules, load_fingerprints
from recon_tool.formatter import _CATEGORY_BY_SLUG, _CLOUD_VENDOR_ROLLUP_EXCLUSIONS
from recon_tool.models import EvidenceRecord
from recon_tool.sources import dns_base, dns_email, dns_infra
from recon_tool.sources.dns import DNSSource, _classify_chain


def _resolve_factory(records: dict[str, list[str]]):
    async def resolve(domain: str, record_type: str, **_kwargs: object) -> list[str]:
        return records.get(f"{domain}/{record_type}", [])

    return resolve


def _fingerprint(slug: str):
    return next(item for item in load_fingerprints() if item.slug == slug)


@pytest.mark.parametrize(
    ("slug", "expected_patterns"),
    [
        (
            "cloudflare-email-routing",
            {("mx", "mx.cloudflare.net"), ("spf", "_spf.mx.cloudflare.net")},
        ),
        (
            "locaweb-email",
            {
                ("mx", "mx.a.locaweb.com.br"),
                ("mx", "mx.b.locaweb.com.br"),
                ("mx", "mx.core.locaweb.com.br"),
                ("mx", "mx.jk.locaweb.com.br"),
                ("spf", "_spf.locaweb.com.br"),
                ("cname_target", "webmail-seguro.com.br"),
            },
        ),
        (
            "hostinger-email",
            {
                ("cname_target", "mail.hostinger.com"),
                ("mx", "mx1.hostinger.com"),
                ("mx", "mx2.hostinger.com"),
                ("spf", "_spf.mail.hostinger.com"),
            },
        ),
        ("hostinger-dns", {("ns", "dns-parking.com")}),
        ("ovhcloud-email", {("mx", "mail.ovh.net"), ("spf", "mx.ovh.com")}),
        (
            "titan-mail",
            {
                ("mx", "mx1.titan.email"),
                ("mx", "mx2.titan.email"),
                ("spf", "spf.titan.email"),
            },
        ),
    ],
)
def test_regional_rules_have_exact_shape_current_reference_and_review_date(
    slug: str,
    expected_patterns: set[tuple[str, str]],
) -> None:
    fingerprint = _fingerprint(slug)

    assert {(rule.type, rule.pattern) for rule in fingerprint.detections} == expected_patterns
    assert all(rule.reference.startswith("https://") for rule in fingerprint.detections)
    assert all(rule.verified == "2026-08-13" for rule in fingerprint.detections)


def test_regional_families_have_deliberate_panel_categories() -> None:
    assert _CATEGORY_BY_SLUG["hostinger-dns"] == "Cloud"
    assert "hostinger-dns" in _CLOUD_VENDOR_ROLLUP_EXCLUSIONS
    assert {_CATEGORY_BY_SLUG[slug] for slug in ("locaweb-email", "ovhcloud-email", "titan-mail")} == {"Email"}


@dataclass(frozen=True, slots=True)
class HostRuleCase:
    detector: Callable[[dns_base.DetectionCtx, str], Awaitable[None]]
    dns_type: str
    positive: str
    lookalike: str
    slug: str
    rule_name: str
    pattern: str


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        HostRuleCase(
            dns_email.detect_mx,
            "MX",
            "10 mx.a.locaweb.com.br.",
            "10 mx.a.locaweb.com.br.example.net.",
            "locaweb-email",
            "Locaweb Email",
            "mx.a.locaweb.com.br",
        ),
        HostRuleCase(
            dns_email.detect_mx,
            "MX",
            "5 mx1.hostinger.com.",
            "5 mx1.hostinger.com.example.net.",
            "hostinger-email",
            "Hostinger Email",
            "mx1.hostinger.com",
        ),
        HostRuleCase(
            dns_email.detect_mx,
            "MX",
            "1 mx0.mail.ovh.net.",
            "1 mx0.mail.ovh.net.example.net.",
            "ovhcloud-email",
            "OVHcloud Email",
            "mail.ovh.net",
        ),
        HostRuleCase(
            dns_email.detect_mx,
            "MX",
            "10 mx1.titan.email.",
            "10 mx1.titan.email.example.net.",
            "titan-mail",
            "Titan Mail",
            "mx1.titan.email",
        ),
        HostRuleCase(
            dns_infra.detect_ns,
            "NS",
            "ns1.dns-parking.com.",
            "ns1.dns-parking.com.example.net.",
            "hostinger-dns",
            "Hostinger DNS",
            "dns-parking.com",
        ),
    ],
)
async def test_regional_host_rules_are_label_bounded_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
    case: HostRuleCase,
) -> None:
    for value, expected in ((case.positive, True), (case.lookalike, False)):
        monkeypatch.setattr(
            dns_base,
            "safe_resolve",
            _resolve_factory({f"example.com/{case.dns_type}": [value]}),
        )
        context = dns_base.DetectionCtx()

        await case.detector(context, "example.com")

        assert (case.slug in context.slugs) is expected
        matching_evidence = [item for item in context.evidence if item.slug == case.slug]
        if expected:
            assert matching_evidence == [EvidenceRecord(case.dns_type, value, case.rule_name, case.slug)]
            assert (case.slug, case.dns_type.lower(), case.pattern) in context._matched_fp_detections
        else:
            assert matching_evidence == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "slug", "rule_name"),
    [
        ("_spf.mx.cloudflare.net", "cloudflare-email-routing", "Cloudflare Email Service"),
        ("_spf.locaweb.com.br", "locaweb-email", "Locaweb Email"),
        ("_spf.mail.hostinger.com", "hostinger-email", "Hostinger Email"),
        ("mx.ovh.com", "ovhcloud-email", "OVHcloud Email"),
        ("spf.titan.email", "titan-mail", "Titan Mail"),
    ],
)
async def test_regional_spf_rules_are_label_bounded_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    slug: str,
    rule_name: str,
) -> None:
    for candidate, expected in ((target, True), (f"{target}.example.net", False)):
        record = f"v=spf1 include:{candidate} ~all"
        monkeypatch.setattr(
            dns_base,
            "safe_resolve",
            _resolve_factory({"example.com/TXT": [record]}),
        )
        context = dns_base.DetectionCtx()

        await dns_email.detect_txt(context, "example.com")

        assert (slug in context.slugs) is expected
        matching_evidence = [item for item in context.evidence if item.slug == slug]
        if expected:
            assert matching_evidence == [EvidenceRecord("SPF", record, rule_name, slug)]
            assert (slug, "spf", target) in context._matched_fp_detections
        else:
            assert matching_evidence == []


def test_locaweb_email_rule_is_label_bounded_and_sparse_safe() -> None:
    rules = get_cname_target_rules()

    application, infrastructure = _classify_chain(
        ["webmail.example.com", "webmail-seguro.com.br"],
        rules,
    )
    lookalike_application, lookalike_infrastructure = _classify_chain(
        ["webmail-seguro.com.br.example.net"],
        rules,
    )
    sparse_application, sparse_infrastructure = _classify_chain([], rules)

    assert application is not None
    assert application.slug == "locaweb-email"
    assert infrastructure is None
    assert lookalike_application is None
    assert lookalike_infrastructure is None
    assert sparse_application is None
    assert sparse_infrastructure is None


@pytest.mark.asyncio
async def test_regional_promotions_remain_absent_on_sparse_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dns_base, "safe_resolve", _resolve_factory({}))
    contexts = [dns_base.DetectionCtx() for _ in range(3)]

    await dns_email.detect_mx(contexts[0], "example.com")
    await dns_email.detect_txt(contexts[1], "example.com")
    await dns_infra.detect_ns(contexts[2], "example.com")

    promoted_slugs = {
        "cloudflare-email-routing",
        "hostinger-dns",
        "hostinger-email",
        "locaweb-email",
        "ovhcloud-email",
        "titan-mail",
    }
    assert all(not (context.slugs & promoted_slugs) for context in contexts)


@pytest.mark.asyncio
@patch("recon_tool.sources.dns_base.safe_resolve")
async def test_locaweb_email_surface_retains_exact_cname_provenance(mock_resolve) -> None:
    mock_resolve.side_effect = _resolve_factory(
        {
            "example.com/TXT": [],
            "example.com/MX": [],
            "autodiscover.example.com/CNAME": ["autodiscover.example.net"],
            "autodiscover.example.net/CNAME": [],
            "webmail.example.com/CNAME": ["webmail-seguro.com.br"],
            "webmail-seguro.com.br/CNAME": [],
        }
    )

    result = await DNSSource().lookup("example.com", skip_ct=True)

    attributions = [item for item in result.surface_attributions if item.primary_slug == "locaweb-email"]
    assert len(attributions) == 1
    assert attributions[0].subdomain == "webmail.example.com"
    assert attributions[0].primary_name == "Locaweb Email"
    assert attributions[0].primary_tier == "application"
    assert "locaweb-email" not in result.detected_slugs
    assert any(
        item.source_type == "CNAME"
        and item.slug == "locaweb-email"
        and item.rule_name == "Locaweb Email"
        and item.raw_value == "webmail.example.com: webmail-seguro.com.br"
        for item in result.evidence
    )
    cname_summary = next(item for item in result.dns_catalog_summaries if item.record_type == "cname_target")
    assert cname_summary.opportunity_count == 2
    assert cname_summary.observed_count == 2
    assert cname_summary.classified_count == 1
    assert any(
        item.record_type == "cname_target"
        and item.owner == "autodiscover.example.com"
        and item.value == "autodiscover.example.net"
        for item in result.unclassified_dns_observations
    )
    assert not any(
        item.record_type == "cname_target" and item.value == "webmail-seguro.com.br"
        for item in result.unclassified_dns_observations
    )
