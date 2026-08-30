"""Evidence and precision boundaries for reviewed Cloudflare rules."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from recon_tool.fingerprints import get_cname_target_rules, load_fingerprints
from recon_tool.sources import dns_base, dns_email, dns_infra
from recon_tool.sources.dns import _classify_chain


def _resolver(
    records: dict[tuple[str, str], list[str]],
) -> Callable[..., Awaitable[list[str]]]:
    async def resolve(name: str, record_type: str, **_kwargs: object) -> list[str]:
        return records.get((name, record_type), [])

    return resolve


def _rule(slug: str, rule_type: str, pattern: str):
    matches = [
        rule
        for fingerprint in load_fingerprints()
        if fingerprint.slug == slug
        for rule in fingerprint.detections
        if rule.type == rule_type and rule.pattern == pattern
    ]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize(
    ("slug", "rule_type", "pattern", "reference", "description_fragment"),
    [
        (
            "cloudflare",
            "subdomain_txt",
            "cloudflare-verify:.",
            "https://developers.cloudflare.com/dns/zone-setups/partial-setup/setup/",
            "does not identify the account operator",
        ),
        (
            "cloudflare",
            "ns",
            "ns.cloudflare.com",
            "https://developers.cloudflare.com/dns/nameservers/",
            "does not prove that web traffic is proxied",
        ),
        (
            "cloudflare",
            "ns",
            "secondary.cloudflare.com",
            "https://developers.cloudflare.com/dns/nameservers/",
            "does not prove that web traffic is proxied",
        ),
        (
            "cloudflare",
            "cname",
            "cdn.cloudflare.net",
            "https://developers.cloudflare.com/dns/zone-setups/partial-setup/setup/",
            "does not identify enabled CDN",
        ),
        (
            "cloudflare",
            "cname_target",
            "cdn.cloudflare.net",
            "https://developers.cloudflare.com/dns/zone-setups/partial-setup/setup/",
            "does not identify enabled CDN",
        ),
        (
            "cloudflare",
            "cname_target",
            "cdn.cloudflareanycast.net",
            "https://developers.cloudflare.com/china-network/concepts/china-dns/",
            "does not prove current traffic",
        ),
        (
            "cloudflare",
            "cname_target",
            "cdn.cloudflarecn.net",
            "https://developers.cloudflare.com/china-network/concepts/china-dns/",
            "does not prove current traffic",
        ),
        (
            "cloudflare-pages",
            "cname_target",
            "pages.dev",
            "https://developers.cloudflare.com/pages/configuration/custom-domains/",
            "does not prove that the deployment remains published",
        ),
    ],
)
def test_current_cloudflare_rules_have_exact_scoped_evidence(
    slug: str,
    rule_type: str,
    pattern: str,
    reference: str,
    description_fragment: str,
) -> None:
    rule = _rule(slug, rule_type, pattern)

    assert rule.reference == reference
    assert rule.verified == "2026-08-30"
    assert description_fragment in rule.description


def test_unsupported_china_partner_rule_remains_undated() -> None:
    rule = _rule("cloudflare", "cname_target", "pacloudflare.com")

    assert rule.reference == ""
    assert rule.verified == ""
    assert "undated" in rule.description.lower()
    assert "current" in rule.description.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("records", "expected"),
    [
        ({("cloudflare-verify.example.com", "TXT"): ["966215192-518620144"]}, True),
        ({("example.com", "TXT"): ["cloudflare-verify=966215192-518620144"]}, False),
        ({("notcloudflare-verify.example.com", "TXT"): ["966215192-518620144"]}, False),
        ({("cloudflare-verify.example.com", "TXT"): [""]}, False),
    ],
)
async def test_cloudflare_verification_owner_is_exact_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
    records: dict[tuple[str, str], list[str]],
    expected: bool,
) -> None:
    monkeypatch.setattr(dns_base, "safe_resolve", _resolver(records))
    context = dns_base.DetectionCtx()

    await dns_infra.detect_subdomain_txt(context, "example.com")
    await dns_email.detect_txt(context, "example.com")

    assert ("cloudflare" in context.slugs) is expected
    assert (
        (
            "cloudflare",
            "subdomain_txt",
            "cloudflare-verify:.",
        )
        in context._matched_fp_detections
    ) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("adele.ns.cloudflare.com", True),
        ("ns1.secondary.cloudflare.com", True),
        ("api.cloudflare.com", False),
        ("adele.ns.cloudflare.com.example.org", False),
    ],
)
async def test_cloudflare_nameservers_match_only_documented_families(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    expected: bool,
) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "NS"): [target]}),
    )
    context = dns_base.DetectionCtx()

    await dns_infra.detect_ns(context, "example.com")

    assert ("cloudflare" in context.slugs) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("www.example.com.cdn.cloudflare.net", True),
        ("api.cloudflare.net", False),
        ("cloudflare.example.net", False),
        ("www.example.com.cdn.cloudflare.net.example.org", False),
    ],
)
async def test_cloudflare_apex_cname_is_exact_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    expected: bool,
) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver(
            {
                ("www.example.com", "CNAME"): [target],
                ("example.com", "CNAME"): [],
            }
        ),
    )
    context = dns_base.DetectionCtx()

    await dns_infra.detect_cname_infra(context, "example.com")

    assert ("cloudflare" in context.slugs) is expected
    assert (
        (
            "cloudflare",
            "cname",
            "cdn.cloudflare.net",
        )
        in context._matched_fp_detections
    ) is expected


@pytest.mark.parametrize(
    "target",
    [
        "www.example.com.cdn.cloudflare.net",
        "www.example.com.cdn.cloudflareanycast.net",
        "www.example.com.cdn.cloudflarecn.net",
    ],
)
def test_cloudflare_edge_targets_are_label_bounded(target: str) -> None:
    rules = get_cname_target_rules()

    application, infrastructure = _classify_chain([target], rules)
    lookalike_application, lookalike_infrastructure = _classify_chain(
        [f"{target}.example.org"],
        rules,
    )

    assert application is None
    assert infrastructure is not None
    assert infrastructure.slug == "cloudflare"
    assert lookalike_application is None
    assert lookalike_infrastructure is None


def test_legacy_cloudflare_partner_target_is_label_bounded() -> None:
    rules = get_cname_target_rules()
    target = "www.example.com.pacloudflare.com"

    application, infrastructure = _classify_chain([target], rules)
    lookalike_application, lookalike_infrastructure = _classify_chain(
        [f"{target}.example.org"],
        rules,
    )

    assert application is not None
    assert application.slug == "cloudflare"
    assert infrastructure is None
    assert lookalike_application is None
    assert lookalike_infrastructure is None


def test_generic_cloudflare_host_is_not_an_edge_target() -> None:
    application, infrastructure = _classify_chain(
        ["api.cloudflare.net"],
        get_cname_target_rules(),
    )

    assert application is None
    assert infrastructure is None


def test_cloudflare_pages_target_is_label_bounded() -> None:
    rules = get_cname_target_rules()

    application, infrastructure = _classify_chain(["fictional-project.pages.dev"], rules)
    lookalike_application, lookalike_infrastructure = _classify_chain(
        ["fictional-project.pages.dev.example.org"],
        rules,
    )

    assert application is None
    assert infrastructure is not None
    assert infrastructure.slug == "cloudflare-pages"
    assert lookalike_application is None
    assert lookalike_infrastructure is None
