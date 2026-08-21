"""Evidence and precision boundaries for reviewed Statuspage rules."""

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


def _statuspage_rule(rule_type: str, pattern: str):
    matches = [
        rule
        for fingerprint in load_fingerprints()
        if fingerprint.slug == "statuspage"
        for rule in fingerprint.detections
        if rule.type == rule_type and rule.pattern == pattern
    ]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize(
    ("rule_type", "pattern", "description_fragment"),
    [
        (
            "txt",
            "^status-page-domain-verification=",
            "does not establish status-page hosting",
        ),
        (
            "spf",
            "stspg-customer.com",
            "does not establish page hosting",
        ),
        (
            "cname_target",
            "stspg-customer.com",
            "does not prove the page is activated",
        ),
    ],
)
def test_current_statuspage_rules_have_exact_scoped_evidence(
    rule_type: str,
    pattern: str,
    description_fragment: str,
) -> None:
    rule = _statuspage_rule(rule_type, pattern)

    assert rule.reference == "https://support.atlassian.com/statuspage/docs/configure-your-dns/"
    assert rule.verified == "2026-08-21"
    assert description_fragment in rule.description


@pytest.mark.parametrize(
    ("rule_type", "pattern"),
    [
        ("txt", "^statuspage-domain-verification="),
        ("cname", "statuspage.io"),
        ("cname_target", "statuspage.io"),
        ("cname_target", "statuspageio.com"),
    ],
)
def test_unsupported_statuspage_variants_remain_undated(
    rule_type: str,
    pattern: str,
) -> None:
    rule = _statuspage_rule(rule_type, pattern)

    assert rule.reference == ""
    assert rule.verified == ""
    assert "undated" in rule.description.lower()
    assert "current" in rule.description.lower()
    assert "customize-your-status-page" not in rule.reference


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("status-page-domain-verification=example-code", True),
        ("xstatus-page-domain-verification=example-code", False),
    ],
)
async def test_statuspage_current_txt_is_exact_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
    expected: bool,
) -> None:
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "TXT"): [value]}),
    )
    context = dns_base.DetectionCtx()

    await dns_email.detect_txt(context, "example.com")

    assert ("statuspage" in context.slugs) is expected
    assert (
        (
            "statuspage",
            "txt",
            "^status-page-domain-verification=",
        )
        in context._matched_fp_detections
    ) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("stspg-customer.com", True),
        ("stspg-customer.com.example.net", False),
    ],
)
async def test_statuspage_spf_is_label_bounded_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    expected: bool,
) -> None:
    value = f"v=spf1 include:{target} -all"
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "TXT"): [value]}),
    )
    context = dns_base.DetectionCtx()

    await dns_email.detect_txt(context, "example.com")

    assert ("statuspage" in context.slugs) is expected
    assert (
        (
            "statuspage",
            "spf",
            "stspg-customer.com",
        )
        in context._matched_fp_detections
    ) is expected


def test_statuspage_current_cname_target_is_label_bounded() -> None:
    rules = get_cname_target_rules()

    application, infrastructure = _classify_chain(
        ["ABC123.stspg-customer.com"],
        rules,
    )
    lookalike_application, lookalike_infrastructure = _classify_chain(
        ["ABC123.stspg-customer.com.example.net"],
        rules,
    )

    assert application is not None
    assert application.slug == "statuspage"
    assert application.pattern == "stspg-customer.com"
    assert infrastructure is None
    assert lookalike_application is None
    assert lookalike_infrastructure is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("example.statuspage.io", True),
        ("example.statuspage.io.example.net", False),
    ],
)
async def test_retained_statuspage_cname_is_label_bounded(
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

    assert ("statuspage" in context.slugs) is expected
    assert (
        (
            "statuspage",
            "cname",
            "statuspage.io",
        )
        in context._matched_fp_detections
    ) is expected
