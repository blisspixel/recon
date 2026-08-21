"""Evidence and precision boundaries for reviewed Zendesk rules."""

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


def _zendesk_rule(rule_type: str, pattern: str):
    matches = [
        rule
        for fingerprint in load_fingerprints()
        if fingerprint.slug == "zendesk"
        for rule in fingerprint.detections
        if rule.type == rule_type and rule.pattern == pattern
    ]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize(
    ("rule_type", "pattern", "reference", "description_fragment"),
    [
        (
            "subdomain_txt",
            "zendeskverification:.",
            "https://support.zendesk.com/hc/en-us/articles/4811307516954-How-to-fix-the-email-error-messages-on-forwarding-SPF-DNS-and-TXT-records",
            "does not establish help-center hosting",
        ),
        (
            "spf",
            "mail.zendesk.com",
            "https://support.zendesk.com/hc/en-us/articles/4408832543770-Allowing-Zendesk-to-send-email-on-behalf-of-your-email-domain",
            "does not establish inbound routing",
        ),
        (
            "cname",
            "zendesk.com",
            "https://support.zendesk.com/hc/en-us/articles/4408838571930-Host-mapping-Changing-the-URL-of-your-help-center",
            "does not prove the help center is activated",
        ),
        (
            "cname_target",
            "zendesk.com",
            "https://support.zendesk.com/hc/en-us/articles/4408838571930-Host-mapping-Changing-the-URL-of-your-help-center",
            "does not prove activation",
        ),
    ],
)
def test_current_zendesk_rules_have_exact_scoped_evidence(
    rule_type: str,
    pattern: str,
    reference: str,
    description_fragment: str,
) -> None:
    rule = _zendesk_rule(rule_type, pattern)

    assert rule.reference == reference
    assert rule.verified == "2026-08-21"
    assert description_fragment in rule.description


@pytest.mark.parametrize(
    ("rule_type", "pattern"),
    [
        ("txt", "^zendesk-domain-verification="),
        ("spf", "zendesk.com"),
    ],
)
def test_unsupported_zendesk_variants_remain_undated(
    rule_type: str,
    pattern: str,
) -> None:
    rule = _zendesk_rule(rule_type, pattern)

    assert rule.reference == ""
    assert rule.verified == ""
    assert "undated" in rule.description.lower()
    assert "current" in rule.description.lower()
    assert "4408822492698" not in rule.reference


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("records", "expected"),
    [
        ({("zendeskverification.example.com", "TXT"): ["synthetic-token-001"]}, True),
        ({("example.com", "TXT"): ["zendeskverification=synthetic-token-001"]}, False),
        ({("notzendeskverification.example.com", "TXT"): ["synthetic-token-001"]}, False),
        ({("zendeskverification.example.com", "TXT"): [""]}, False),
    ],
)
async def test_zendesk_current_txt_owner_is_exact_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
    records: dict[tuple[str, str], list[str]],
    expected: bool,
) -> None:
    monkeypatch.setattr(dns_base, "safe_resolve", _resolver(records))
    context = dns_base.DetectionCtx()

    await dns_infra.detect_subdomain_txt(context, "example.com")

    assert ("zendesk" in context.slugs) is expected
    assert (
        (
            "zendesk",
            "subdomain_txt",
            "zendeskverification:.",
        )
        in context._matched_fp_detections
    ) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("mail.zendesk.com", True),
        ("mail.zendesk.com.example.net", False),
    ],
)
async def test_zendesk_current_spf_is_label_bounded_and_traceable(
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

    assert ("zendesk" in context.slugs) is expected
    assert (
        (
            "zendesk",
            "spf",
            "mail.zendesk.com",
        )
        in context._matched_fp_detections
    ) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("tenant.zendesk.com", True),
        ("tenant.zendesk.com.example.net", False),
    ],
)
async def test_zendesk_current_cname_is_label_bounded_and_traceable(
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

    assert ("zendesk" in context.slugs) is expected
    assert (
        (
            "zendesk",
            "cname",
            "zendesk.com",
        )
        in context._matched_fp_detections
    ) is expected


def test_zendesk_current_cname_target_is_label_bounded() -> None:
    rules = get_cname_target_rules()

    application, infrastructure = _classify_chain(
        ["tenant.zendesk.com"],
        rules,
    )
    lookalike_application, lookalike_infrastructure = _classify_chain(
        ["tenant.zendesk.com.example.net"],
        rules,
    )

    assert application is not None
    assert application.slug == "zendesk"
    assert application.pattern == "zendesk.com"
    assert infrastructure is None
    assert lookalike_application is None
    assert lookalike_infrastructure is None
