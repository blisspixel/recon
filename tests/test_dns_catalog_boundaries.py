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
