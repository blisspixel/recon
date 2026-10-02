"""A no-mail claim requires the complete RFC 7505 MX record set."""

from __future__ import annotations

import pytest

from recon_tool.formatter import format_tenant_dict, format_tenant_plain
from recon_tool.formatter.classify import provider_line
from recon_tool.merger import merge_results
from recon_tool.models import SourceResult
from recon_tool.sources import dns_base, dns_email

NULL_LABEL = "Null MX (domain does not accept email)"


async def _detect(monkeypatch: pytest.MonkeyPatch, records: list[str]) -> dns_base.DetectionCtx:
    async def resolve(domain: str, record_type: str, **_kwargs: object) -> list[str]:
        assert (domain, record_type) == ("example.com", "MX")
        return records

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_mx(ctx, "example.com")
    return ctx


def _source(ctx: dns_base.DetectionCtx) -> SourceResult:
    return SourceResult(
        source_name="dns_records",
        detected_services=tuple(sorted(ctx.services)),
        detected_slugs=tuple(sorted(ctx.slugs)),
        evidence=tuple(ctx.evidence),
        raw_dns_records=tuple(("MX", value) for value in ctx.raw_dns_records["MX"]),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("records", [["0 ."], ["0\t."], ["0 .", "0 ."], ["0 .", " 0\t. "]])
async def test_standalone_null_mx_keeps_exact_evidence(monkeypatch: pytest.MonkeyPatch, records: list[str]) -> None:
    ctx = await _detect(monkeypatch, records)

    assert ctx.services == {NULL_LABEL}
    assert ctx.slugs == {"null-mx"}
    assert [(item.source_type, item.raw_value, item.slug) for item in ctx.evidence] == [
        ("MX", record, "null-mx") for record in records
    ]
    info = merge_results([_source(ctx)], "example.com")
    assert provider_line(info) == NULL_LABEL
    assert any("publisher declares" in insight for insight in info.insights)


@pytest.mark.asyncio
@pytest.mark.parametrize("record", ["0 ..", "0 unexpected .", "10 .", "0 . ."])
async def test_malformed_root_target_is_not_a_no_mail_or_delivery_claim(
    monkeypatch: pytest.MonkeyPatch, record: str
) -> None:
    ctx = await _detect(monkeypatch, [record])

    assert not ctx.slugs
    assert not ctx.services
    assert ctx.raw_dns_records["MX"] == [record]
    assert [(item.source_type, item.raw_value, item.slug) for item in ctx.evidence] == [("MX", record, "")]


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    ("route", "slug", "provider"),
    [
        ("10 aspmx.l.google.com", "google-workspace", "Google Workspace"),
        ("10 mx.example.net", "self-hosted-mail", "Custom or unclassified MX"),
    ],
)
async def test_mixed_null_mx_keeps_routes_without_no_mail_claim(
    monkeypatch: pytest.MonkeyPatch, reverse: bool, route: str, slug: str, provider: str
) -> None:
    records = ["0 .", route]
    if reverse:
        records.reverse()
    ctx = await _detect(monkeypatch, records)

    assert ctx.slugs == {slug}
    assert NULL_LABEL not in ctx.services
    assert ctx.raw_dns_records["MX"] == records
    assert any(item.raw_value == "0 ." and item.slug == "" for item in ctx.evidence)
    assert any(item.raw_value == route for item in ctx.evidence)
    info = merge_results([_source(ctx)], "example.com")
    assert provider in provider_line(info)
    assert not any("Null MX observed" in insight for insight in info.insights)
    assert "null-mx" not in format_tenant_dict(info)["slugs"]
    assert "does not accept email" not in format_tenant_plain(info)


@pytest.mark.asyncio
async def test_empty_mx_response_does_not_create_a_no_mail_declaration(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = await _detect(monkeypatch, [])

    assert not ctx.slugs
    assert not ctx.services
    assert not ctx.evidence


@pytest.mark.asyncio
@pytest.mark.parametrize("records", [["0 .", "10 ."], ["0 .", "0 .."]])
async def test_conflicting_root_targets_do_not_create_a_mail_role(
    monkeypatch: pytest.MonkeyPatch, records: list[str]
) -> None:
    ctx = await _detect(monkeypatch, records)

    assert not ctx.slugs
    assert not ctx.services
    assert [item.raw_value for item in ctx.evidence] == records
