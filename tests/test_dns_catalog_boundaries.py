"""Positive and deceptive-lookalike tests for researched DNS patterns."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from recon_tool.sources import dns_base, dns_email, dns_infra

HostRecordCase = tuple[
    Callable[[dns_base.DetectionCtx, str], Awaitable[None]],
    str,
    str,
    str,
    str,
]


def _resolver(
    records: dict[tuple[str, str], list[str]],
) -> Callable[..., Awaitable[list[str]]]:
    async def resolve(name: str, record_type: str, **_kwargs: object) -> list[str]:
        return records.get((name, record_type), [])

    return resolve


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("issuer", "slug"),
    [
        ("awstrust.com", "aws-acm"),
        ("amazonaws.com", "aws-acm"),
        ("ssl.com", "ssl-com-caa"),
        ("globalsign.com", "globalsign-caa"),
        ("godaddy.com", "godaddy-caa"),
        ("entrust.net", "entrust-caa"),
    ],
)
async def test_researched_caa_issuers_match(
    monkeypatch: pytest.MonkeyPatch,
    issuer: str,
    slug: str,
) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "CAA"): [f'0 issuewild "{issuer}"']}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_infra.detect_caa(ctx, "example.com")

    assert slug in ctx.slugs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "record",
    [
        '0 issue "ssl.com.evil.example"',
        '0 issue "notssl.invalid"',
        '0 iodef "mailto:security@ssl.com"',
    ],
)
async def test_caa_issuer_lookalikes_do_not_match(
    monkeypatch: pytest.MonkeyPatch,
    record: str,
) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "CAA"): [record]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_infra.detect_caa(ctx, "example.com")

    assert "ssl-com-caa" not in ctx.slugs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "slug"),
    [
        ("tenant._d.easydmarc.pro", "easydmarc"),
        ("tenant.example._nspf.vali.email", "valimail-legacy-spf"),
    ],
)
async def test_researched_spf_suffixes_match_on_dns_labels(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    slug: str,
) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "TXT"): [f"v=spf1 include:{target} -all"]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_txt(ctx, "example.com")

    assert slug in ctx.slugs


@pytest.mark.asyncio
async def test_spf_suffix_lookalike_does_not_match(monkeypatch: pytest.MonkeyPatch) -> None:
    target = "tenant._d.easydmarc.pro.evil.example"
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "TXT"): [f"v=spf1 include:{target} -all"]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_txt(ctx, "example.com")

    assert "easydmarc" not in ctx.slugs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        "spf-us.tmes.trendmicro.com",
        "spf.tmes.trendmicro.eu",
        "spf.tmes-anz.trendmicro.com",
        "spf.tmems-jp.trendmicro.com",
        "spf.tmes-sg.trendmicro.com",
        "spf.tmes-in.trendmicro.com",
        "spf.tmes-uae.trendmicro.com",
        "spf.tmes-uk.trendmicro.com",
        "spf.tmes-ca.trendmicro.com",
        "spf.tmes-za.trendmicro.com",
        "spf.tmes-id.trendmicro.com",
    ],
)
async def test_trendmicro_current_regional_spf_values_match(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "TXT"): [f"v=spf1 include:{target} -all"]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_txt(ctx, "example.com")

    assert "trendmicro" in ctx.slugs


@pytest.mark.asyncio
async def test_trendmicro_spf_lookalike_does_not_match(monkeypatch: pytest.MonkeyPatch) -> None:
    target = "spf-us.tmes.trendmicro.com.evil.example"
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "TXT"): [f"v=spf1 include:{target} -all"]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_txt(ctx, "example.com")

    assert "trendmicro" not in ctx.slugs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "region",
    [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "af-south-1",
        "ap-southeast-3",
        "ap-south-1",
        "ap-northeast-3",
        "ap-northeast-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-northeast-1",
        "ca-central-1",
        "eu-central-1",
        "eu-west-1",
        "eu-west-2",
        "eu-south-1",
        "eu-west-3",
        "eu-north-1",
        "il-central-1",
        "me-south-1",
        "sa-east-1",
    ],
)
async def test_aws_ses_current_regional_mx_values_match(
    monkeypatch: pytest.MonkeyPatch,
    region: str,
) -> None:
    target = f"inbound-smtp.{region}.amazonaws.com"
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "MX"): [f"10 {target}."]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_mx(ctx, "example.com")

    assert "aws-ses" in ctx.slugs


@pytest.mark.asyncio
async def test_aws_ses_mx_lookalike_does_not_match(monkeypatch: pytest.MonkeyPatch) -> None:
    target = "inbound-smtp.us-east-1.amazonaws.com.evil.example"
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "MX"): [f"10 {target}."]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_mx(ctx, "example.com")

    assert "aws-ses" not in ctx.slugs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        (
            dns_email.detect_mx,
            "MX",
            "10 tenant.mail.protection.outlook.com.",
            "10 tenant.mail.protection.outlook.com.evil.example.",
            "microsoft365",
        ),
        (
            dns_email.detect_mx,
            "MX",
            "10 inbound.ess.barracudanetworks.com.",
            "10 inbound.ess.barracudanetworks.com.evil.example.",
            "barracuda",
        ),
        (
            dns_email.detect_mx,
            "MX",
            "10 mx1.fictional-allocation.iphmx.com.",
            "10 mx1.fictional-allocation.iphmx.com.evil.example.",
            "cisco-ironport",
        ),
        (
            dns_infra.detect_ns,
            "NS",
            "ada.ns.cloudflare.com.",
            "ada.ns.cloudflare.com.evil.example.",
            "cloudflare",
        ),
    ],
)
async def test_host_record_patterns_require_dns_label_suffixes(
    monkeypatch: pytest.MonkeyPatch,
    case: HostRecordCase,
) -> None:
    detector, record_type, positive, lookalike, slug = case
    for value, expected in ((positive, True), (lookalike, False)):
        monkeypatch.setattr(
            dns_base,
            "safe_resolve",
            _resolver({("example.com", record_type): [value]}),
        )
        ctx = dns_base.DetectionCtx()
        await detector(ctx, "example.com")
        assert (slug in ctx.slugs) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("positive", "lookalike", "slug"),
    [
        ("ns-123.awsdns-45.com.", "ns-123.evilawsdns-45.invalid.", "aws-route53"),
        ("ns1-01.azure-dns.com.", "ns1-01.evilazure-dns.invalid.", "azure-dns"),
        ("pdns1.ultradns.net.", "pdns1.evilultradns.invalid.", "ultradns"),
    ],
)
async def test_ns_legacy_label_patterns_require_label_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    positive: str,
    lookalike: str,
    slug: str,
) -> None:
    for value, expected in ((positive, True), (lookalike, False)):
        monkeypatch.setattr(
            dns_base,
            "safe_resolve",
            _resolver({("example.com", "NS"): [value]}),
        )
        ctx = dns_base.DetectionCtx()
        await dns_infra.detect_ns(ctx, "example.com")
        assert (slug in ctx.slugs) is expected


@pytest.mark.asyncio
async def test_webflow_cname_and_owner_qualified_txt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver(
            {
                ("www.example.com", "CNAME"): ["cdn.webflow.com."],
                ("_webflow.example.com", "TXT"): ["one-time-verification=fictional-token"],
            }
        ),
    )
    cname_ctx = dns_base.DetectionCtx()
    txt_ctx = dns_base.DetectionCtx()

    await dns_infra.detect_cname_infra(cname_ctx, "example.com")
    await dns_infra.detect_subdomain_txt(txt_ctx, "example.com")

    assert "webflow" in cname_ctx.slugs
    assert "webflow" in txt_ctx.slugs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "slug"),
    [
        ("ibmid=00000000-0000-4000-8000-000000000000", "ibm-cloud"),
        ("tmes=00000000000000000000000000000000", "trendmicro"),
        ("elevenlabs=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "elevenlabs"),
        ("infoblox-domain-mastery=0000000000000000000000000000000000000000000000000000000000000000", "infoblox"),
        ("intersight=0000000000000000000000000000000000000000000000000000000000000000", "cisco-intersight"),
        ("QuoVadis=00000000-0000-4000-8000-000000000000", "quovadis"),
    ],
)
async def test_promoted_verification_tokens_match(monkeypatch: pytest.MonkeyPatch, value: str, slug: str) -> None:
    """Vendor-named apex verification TXT records promoted from a private round."""
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "TXT"): [value]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_txt(ctx, "example.com")

    assert slug in ctx.slugs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "slug"),
    [
        # The prefix must open the record, not appear inside another value.
        ("notibmid=00000000-0000-4000-8000-000000000000", "ibm-cloud"),
        ("x-tmes=00000000000000000000000000000000", "trendmicro"),
        ("v=spf1 include:elevenlabs=fictional -all", "elevenlabs"),
        ("prefix-infoblox-domain-mastery=0000", "infoblox"),
        ("cisco-intersight=0000", "cisco-intersight"),
        ("not-QuoVadis=00000000-0000-4000-8000-000000000000", "quovadis"),
    ],
)
async def test_promoted_verification_token_lookalikes_do_not_match(
    monkeypatch: pytest.MonkeyPatch, value: str, slug: str
) -> None:
    """A vendor prefix embedded in a longer value is not that vendor's token."""
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "TXT"): [value]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_txt(ctx, "example.com")

    assert slug not in ctx.slugs


@pytest.mark.asyncio
async def test_wildcard_txt_does_not_attribute_every_probed_vendor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wildcard TXT zone answers every probe label identically, so it is not evidence.

    Three catalog patterns accept any non-empty TXT (`_slack-challenge:.`,
    `_gitlab-pages-verification-code:.`, `_github-challenge:.+`). Against a zone
    that answers every owner with the same unrelated record, each one matched
    and the single zone was reported as running Slack, GitLab and GitHub
    Advanced Security at once.
    """
    wildcard = ["v=spf1 ip6:fdcf:abda:4154::/48 -all"]
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver(
            {
                ("_slack-challenge.example.com", "TXT"): list(wildcard),
                ("_gitlab-pages-verification-code.example.com", "TXT"): list(wildcard),
                ("_github-challenge.example.com", "TXT"): list(wildcard),
                ("_mcp.example.com", "TXT"): list(wildcard),
                ("_agent.example.com", "TXT"): list(wildcard),
                ("_webflow.example.com", "TXT"): list(wildcard),
            }
        ),
    )
    ctx = dns_base.DetectionCtx()

    await dns_infra.detect_subdomain_txt(ctx, "example.com")

    assert "slack" not in ctx.slugs
    assert "gitlab" not in ctx.slugs
    assert "github-advanced-security" not in ctx.slugs


@pytest.mark.asyncio
async def test_single_owner_txt_still_attributes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The wildcard guard must not suppress a genuine single-owner token."""
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("_slack-challenge.example.com", "TXT"): ["fictional-slack-token"]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_infra.detect_subdomain_txt(ctx, "example.com")

    assert "slack" in ctx.slugs


@pytest.mark.asyncio
async def test_distinct_tokens_at_two_owners_both_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two real tokens differ in value, so neither is suppressed as a wildcard."""
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver(
            {
                ("_slack-challenge.example.com", "TXT"): ["fictional-slack-token"],
                ("_github-challenge.example.com", "TXT"): ["fictional-github-token"],
            }
        ),
    )
    ctx = dns_base.DetectionCtx()

    await dns_infra.detect_subdomain_txt(ctx, "example.com")

    assert "slack" in ctx.slugs
    assert "github-advanced-security" in ctx.slugs


@pytest.mark.asyncio
async def test_webflow_cname_lookalike_does_not_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("www.example.com", "CNAME"): ["cdn.webflow.com.evil.example."]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_infra.detect_cname_infra(ctx, "example.com")

    assert "webflow" not in ctx.slugs


@pytest.mark.asyncio
async def test_hubspot_current_spf_and_cname_values_reject_lookalikes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for record_type, positive, lookalike, detector in (
        (
            "TXT",
            "v=spf1 include:123456.spf03.hubspotemail.net -all",
            "v=spf1 include:123456.spf03.hubspotemail.net.evil.example -all",
            dns_email.detect_txt,
        ),
        (
            "CNAME",
            "8675309.group39.sites.hubspot.net.",
            "8675309.group39.sites.hubspot.net.evil.example.",
            dns_infra.detect_cname_infra,
        ),
    ):
        owner = "example.com" if record_type == "TXT" else "www.example.com"
        for value, expected in ((positive, True), (lookalike, False)):
            monkeypatch.setattr(
                dns_base,
                "safe_resolve",
                _resolver({(owner, record_type): [value]}),
            )
            ctx = dns_base.DetectionCtx()
            await detector(ctx, "example.com")
            assert ("hubspot" in ctx.slugs) is expected


@pytest.mark.asyncio
async def test_marketo_current_spf_and_cname_values_reject_lookalikes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for record_type, positive, lookalike, detector in (
        (
            "TXT",
            "v=spf1 include:mktomail.com -all",
            "v=spf1 include:mktomail.com.evil.example -all",
            dns_email.detect_txt,
        ),
        (
            "CNAME",
            "123-abc-456.mktoweb.com.",
            "123-abc-456.mktoweb.com.evil.example.",
            dns_infra.detect_cname_infra,
        ),
    ):
        owner = "example.com" if record_type == "TXT" else "www.example.com"
        for value, expected in ((positive, True), (lookalike, False)):
            monkeypatch.setattr(
                dns_base,
                "safe_resolve",
                _resolver({(owner, record_type): [value]}),
            )
            ctx = dns_base.DetectionCtx()
            await detector(ctx, "example.com")
            assert ("marketo" in ctx.slugs) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        "mc.s7.exacttarget.com",
        "198h8bcs7n8hz798n.pub.sfmc-content.com",
        "tenant.sfmc-marketing.com",
    ],
)
async def test_salesforce_marketing_cloud_current_cnames_reject_lookalikes(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    for value, expected in ((target, True), (f"{target}.evil.example", False)):
        monkeypatch.setattr(
            dns_base,
            "safe_resolve",
            _resolver({("www.example.com", "CNAME"): [value + "."]}),
        )
        ctx = dns_base.DetectionCtx()

        await dns_infra.detect_cname_infra(ctx, "example.com")

        assert ("salesforce-mc" in ctx.slugs) is expected


@pytest.mark.asyncio
async def test_webflow_txt_lookalike_does_not_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("_webflow.example.com", "TXT"): ["xone-time-verification=fictional-token"]}),
    )
    ctx = dns_base.DetectionCtx()

    await dns_infra.detect_subdomain_txt(ctx, "example.com")

    assert "webflow" not in ctx.slugs


@pytest.mark.asyncio
async def test_cloudflare_dashboard_sso_token_and_lookalike(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for value, expected in (
        ("cloudflare_dashboard_sso=123456789", True),
        ("xcloudflare_dashboard_sso=123456789", False),
    ):
        monkeypatch.setattr(
            dns_base,
            "safe_resolve",
            _resolver({("example.com", "TXT"): [value]}),
        )
        ctx = dns_base.DetectionCtx()
        await dns_email.detect_txt(ctx, "example.com")
        assert ("cloudflare" in ctx.slugs) is expected
