"""Precision boundaries for fingerprint rules promoted from the rank round."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from recon_tool.fingerprints import get_cname_target_rules, load_fingerprints
from recon_tool.models import EvidenceRecord
from recon_tool.sources import dns_base, dns_email, dns_infra
from recon_tool.sources.dns import _classify_chain


def _resolver(
    records: dict[tuple[str, str], list[str]],
) -> Callable[..., Awaitable[list[str]]]:
    async def resolve(name: str, record_type: str, **_kwargs: object) -> list[str]:
        return records.get((name, record_type), [])

    return resolve


def _fingerprint(slug: str):
    return next(fp for fp in load_fingerprints() if fp.slug == slug)


@pytest.mark.parametrize(
    ("slug", "expected_patterns"),
    [
        ("cloudflare-email-routing", {("mx", "mx.cloudflare.net")}),
        ("alibaba-dns", {("ns", "alidns.com")}),
        (
            "alibaba-alb",
            {("cname_target", "alb.aliyuncsslbintl.com")},
        ),
        (
            "yandex-360",
            {("mx", "mx.yandex.net"), ("spf", "_spf.yandex.net")},
        ),
    ],
)
def test_rank_promotions_have_current_reference_and_review_date(
    slug: str,
    expected_patterns: set[tuple[str, str]],
) -> None:
    fingerprint = _fingerprint(slug)
    patterns = {(rule.type, rule.pattern) for rule in fingerprint.detections}

    assert patterns == expected_patterns
    assert all(rule.reference.startswith("https://") for rule in fingerprint.detections)
    assert all(rule.verified == "2026-08-13" for rule in fingerprint.detections)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("detector", "record_type", "positive", "lookalike", "slug", "rule_name", "pattern"),
    [
        (
            dns_email.detect_mx,
            "MX",
            "10 route1.mx.cloudflare.net.",
            "10 route1.mx.cloudflare.net.example.com.",
            "cloudflare-email-routing",
            "Cloudflare Email Routing",
            "mx.cloudflare.net",
        ),
        (
            dns_email.detect_mx,
            "MX",
            "10 mx.yandex.net.",
            "10 mx.yandex.net.example.com.",
            "yandex-360",
            "Yandex 360 for Business",
            "mx.yandex.net",
        ),
        (
            dns_infra.detect_ns,
            "NS",
            "vip3.alidns.com.",
            "vip3.alidns.com.example.com.",
            "alibaba-dns",
            "Alibaba Cloud DNS",
            "alidns.com",
        ),
    ],
)
async def test_rank_host_promotions_are_label_bounded_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
    detector: Callable[[dns_base.DetectionCtx, str], Awaitable[None]],
    record_type: str,
    positive: str,
    lookalike: str,
    slug: str,
    rule_name: str,
    pattern: str,
) -> None:
    for value, expected in ((positive, True), (lookalike, False)):
        monkeypatch.setattr(
            dns_base,
            "safe_resolve",
            _resolver({("example.com", record_type): [value]}),
        )
        ctx = dns_base.DetectionCtx()

        await detector(ctx, "example.com")

        assert (slug in ctx.slugs) is expected
        matching_evidence = [record for record in ctx.evidence if record.slug == slug]
        if expected:
            assert matching_evidence == [EvidenceRecord(record_type, value, rule_name, slug)]
            assert (slug, record_type.lower(), pattern) in ctx._matched_fp_detections
            summary = next(item for item in ctx.catalog_summaries() if item.record_type == record_type.lower())
            assert summary.classified_count == 1
        else:
            assert matching_evidence == []


@pytest.mark.asyncio
async def test_yandex_spf_promotion_is_label_bounded_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for target, expected in (
        ("_spf.yandex.net", True),
        ("_spf.yandex.net.example.com", False),
    ):
        record = f"v=spf1 include:{target} ~all"
        monkeypatch.setattr(
            dns_base,
            "safe_resolve",
            _resolver({("example.com", "TXT"): [record]}),
        )
        ctx = dns_base.DetectionCtx()

        await dns_email.detect_txt(ctx, "example.com")

        assert ("yandex-360" in ctx.slugs) is expected
        matching_evidence = [item for item in ctx.evidence if item.slug == "yandex-360"]
        if expected:
            assert matching_evidence == [EvidenceRecord("SPF", record, "Yandex 360 for Business", "yandex-360")]
            assert ("yandex-360", "spf", "_spf.yandex.net") in ctx._matched_fp_detections
        else:
            assert matching_evidence == []


def test_alibaba_alb_promotion_is_label_bounded_and_infrastructure_tier() -> None:
    rules = get_cname_target_rules()
    matching = [rule for rule in rules if rule.slug == "alibaba-alb"]

    assert len(matching) == 1
    assert matching[0].tier == "infrastructure"

    application, infrastructure = _classify_chain(
        ["service.example.com", "alb-fictional.eu-central-1.alb.aliyuncsslbintl.com"],
        rules,
    )
    lookalike_application, lookalike_infrastructure = _classify_chain(
        ["alb-fictional.eu-central-1.alb.aliyuncsslbintl.com.example.com"],
        rules,
    )

    assert application is None
    assert infrastructure is not None
    assert infrastructure.slug == "alibaba-alb"
    assert lookalike_application is None
    assert lookalike_infrastructure is None


@pytest.mark.asyncio
async def test_rank_promotions_remain_absent_on_sparse_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dns_base, "safe_resolve", _resolver({}))
    contexts = [dns_base.DetectionCtx() for _ in range(3)]

    await dns_email.detect_mx(contexts[0], "example.com")
    await dns_email.detect_txt(contexts[1], "example.com")
    await dns_infra.detect_ns(contexts[2], "example.com")

    promoted_slugs = {
        "cloudflare-email-routing",
        "alibaba-dns",
        "alibaba-alb",
        "yandex-360",
    }
    assert all(not (ctx.slugs & promoted_slugs) for ctx in contexts)
    application, infrastructure = _classify_chain([], get_cname_target_rules())
    assert application is None
    assert infrastructure is None
