"""Evidence and precision boundaries for reviewed Microsoft residual rules."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from recon_tool.fingerprints import get_cname_target_rules, load_fingerprints
from recon_tool.sources import dns_base, dns_email
from recon_tool.sources.dns import _classify_chain


def _resolver(
    records: dict[tuple[str, str], list[str]],
) -> Callable[..., Awaitable[list[str]]]:
    async def resolve(name: str, record_type: str, **_kwargs: object) -> list[str]:
        return records.get((name, record_type), [])

    return resolve


def _microsoft_rule(rule_type: str, pattern: str):
    matches = [
        rule
        for fingerprint in load_fingerprints()
        if fingerprint.slug == "microsoft365"
        for rule in fingerprint.detections
        if rule.type == rule_type and rule.pattern == pattern
    ]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize(
    ("rule_type", "pattern", "reference_fragment", "description_fragment"),
    [
        (
            "cname_target",
            "tm-3.office.com",
            "urls-and-ip-address-ranges",
            "does not identify a workload, tenant, or active use",
        ),
        (
            "cname_target",
            "svc.cloud.microsoft",
            "cloud-microsoft-domain",
            "does not identify a workload, tenant, or active use",
        ),
        (
            "cname_target",
            "svc.sovcloud.cn",
            "urls-and-ip-address-ranges-21vianet",
            "not a tenant's location, workload, data residency",
        ),
        (
            "mx",
            "mail.eo.outlook.com",
            "how-dane-secures-email",
            "not a current recommended configuration or DANE enablement",
        ),
    ],
)
def test_documented_microsoft_residuals_have_current_scoped_evidence(
    rule_type: str,
    pattern: str,
    reference_fragment: str,
    description_fragment: str,
) -> None:
    rule = _microsoft_rule(rule_type, pattern)

    assert reference_fragment in rule.reference
    assert rule.verified == "2026-08-20"
    assert description_fragment in rule.description


def test_msv1_invalid_remains_undated_and_does_not_claim_mail_routing() -> None:
    rule = _microsoft_rule("mx", "msv1.invalid")

    assert rule.reference == ""
    assert rule.verified == ""
    assert "non-routable" in rule.description.lower()
    assert "does not evidence Exchange Online inbound routing" in rule.description
    assert "mid-migration" not in rule.description


@pytest.mark.parametrize(
    ("target", "pattern"),
    [
        ("teams.tm-3.office.com", "tm-3.office.com"),
        (
            "atm.autodiscover.mira.tm.svc.cloud.microsoft",
            "svc.cloud.microsoft",
        ),
        ("common.svc.sovcloud.cn", "svc.sovcloud.cn"),
    ],
)
def test_microsoft_cname_residuals_are_label_bounded(
    target: str,
    pattern: str,
) -> None:
    rules = get_cname_target_rules()

    application, infrastructure = _classify_chain([target], rules)
    lookalike_application, lookalike_infrastructure = _classify_chain(
        [f"{target}.example.net"],
        rules,
    )

    assert application is not None
    assert application.slug == "microsoft365"
    assert application.pattern == pattern
    assert infrastructure is None
    assert lookalike_application is None
    assert lookalike_infrastructure is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "pattern"),
    [
        ("ms12345678.msv1.invalid", "msv1.invalid"),
        ("example-com.mail.eo.outlook.com", "mail.eo.outlook.com"),
    ],
)
async def test_microsoft_mx_residuals_are_label_bounded_and_traceable(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    pattern: str,
) -> None:
    for candidate, expected in ((target, True), (f"{target}.example.net", False)):
        record = f"10 {candidate}."
        monkeypatch.setattr(
            dns_base,
            "safe_resolve",
            _resolver({("example.com", "MX"): [record]}),
        )
        context = dns_base.DetectionCtx()

        await dns_email.detect_mx(context, "example.com")

        assert ("microsoft365" in context.slugs) is expected
        matching = [item for item in context.evidence if item.slug == "microsoft365"]
        if expected:
            assert len(matching) == 1
            assert matching[0].raw_value == record
            assert ("microsoft365", "mx", pattern) in context._matched_fp_detections
        else:
            assert matching == []


@pytest.mark.asyncio
async def test_legacy_exchange_mx_does_not_match_an_undocumented_sibling_zone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = "10 arbitrary.eo.outlook.com."
    monkeypatch.setattr(
        dns_base,
        "safe_resolve",
        _resolver({("example.com", "MX"): [record]}),
    )
    context = dns_base.DetectionCtx()

    await dns_email.detect_mx(context, "example.com")

    assert "microsoft365" not in context.slugs
    assert [item for item in context.evidence if item.slug == "microsoft365"] == []
