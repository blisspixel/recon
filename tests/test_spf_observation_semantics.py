"""SPF provider observations must respect version and directive boundaries."""

from __future__ import annotations

import pytest

from recon_tool.fingerprints import Detection
from recon_tool.models import SourceResult
from recon_tool.sources import dns_base, dns_email, dns_replay
from recon_tool.sources.dns_tables import is_spf_record, spf_redirect_target, spf_targets


def _dns_fixture(monkeypatch: pytest.MonkeyPatch, records: dict[str, list[str]]) -> list[str]:
    queries: list[str] = []

    async def resolve(domain: str, record_type: str, **_kwargs: object) -> list[str]:
        assert record_type == "TXT"
        queries.append(domain)
        return records.get(domain, [])

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    return queries


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "record",
    [
        "v=spf10 include:sendgrid.net -all",
        "v=spf1-invalid include:sendgrid.net -all",
        "v=spf1 -all redirect=sendgrid.net",
        "v=spf1 redirect=sendgrid.net ?all",
        "v=spf1 +all include:sendgrid.net",
    ],
)
async def test_ignored_or_non_spf_terms_do_not_attribute_provider_live_or_cached(
    monkeypatch: pytest.MonkeyPatch, record: str
) -> None:
    queries = _dns_fixture(monkeypatch, {"example.com": [record]})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    cached = SourceResult(source_name="dns_records", raw_dns_records=(("TXT", record),))
    replayed = dns_replay.replay_cached_dns_fingerprints(cached)

    assert "sendgrid" not in ctx.slugs
    assert "sendgrid" not in replayed.detected_slugs
    assert not any(item.slug == "sendgrid" for item in (*ctx.evidence, *replayed.evidence))
    assert ctx.raw_dns_records["TXT"] == [record]
    assert replayed.raw_dns_records == cached.raw_dns_records
    assert queries == ["example.com"]
    if not record.startswith("v=spf1 "):
        assert not any(item.source_type == "SPF" for item in (*ctx.evidence, *replayed.evidence))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 include:sendgrid.net -all",
        "v=spf1 -include:sendgrid.net -all",
        "v=spf1 ~include:sendgrid.net -all",
        "v=spf1 ?include:sendgrid.net -all",
        "V=SPF1 +INCLUDE:SENDGRID.NET. ~ALL",
        "v=spf1 redirect=sendgrid.net",
        "v=spf1 include:sendgrid.net include:mailgun.org -all",
    ],
)
async def test_supported_provider_terms_keep_raw_provenance_and_live_replay_parity(
    monkeypatch: pytest.MonkeyPatch, record: str
) -> None:
    _dns_fixture(monkeypatch, {"example.com": [record]})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    replayed = dns_replay.replay_cached_dns_fingerprints(
        SourceResult(source_name="dns_records", raw_dns_records=(("TXT", record),))
    )
    assert "sendgrid" in ctx.slugs
    assert ctx.slugs == set(replayed.detected_slugs)
    assert set(ctx.evidence) == set(replayed.evidence)
    assert any(item.slug == "sendgrid" and item.raw_value == record for item in ctx.evidence)
    assert dns_replay.replay_cached_dns_fingerprints(replayed) == replayed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 exp=redirect=policy.example.net",
        "v=spf1 unknownredirect=policy.example.net",
        "v=spf1 redirect=policy.example.net redirect=second.example.net",
    ],
)
async def test_only_one_exact_redirect_modifier_can_schedule_dns(monkeypatch: pytest.MonkeyPatch, record: str) -> None:
    queries = _dns_fixture(
        monkeypatch,
        {"example.com": [record], "policy.example.net": ["v=spf1 include:sendgrid.net -all"]},
    )
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    assert queries == ["example.com"]
    assert "sendgrid" not in ctx.slugs
    assert "SPF: strict (-all)" not in ctx.services


@pytest.mark.asyncio
@pytest.mark.parametrize("qualifier", ["", "+", "?", "~", "-"])
async def test_all_stops_redirect_at_every_hop(monkeypatch: pytest.MonkeyPatch, qualifier: str) -> None:
    queries = _dns_fixture(
        monkeypatch,
        {
            "example.com": ["v=spf1 redirect=policy.example.net"],
            "policy.example.net": [f"v=spf1 {qualifier}all redirect=second.example.net"],
            "second.example.net": ["v=spf1 include:sendgrid.net -all"],
        },
    )
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    assert queries == ["example.com", "policy.example.net"]
    assert "sendgrid" not in ctx.slugs
    assert ("SPF: strict (-all)" in ctx.services) == (qualifier == "-")


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse_rules", [False, True])
@pytest.mark.parametrize(
    ("terms", "expected"),
    [
        ("include:mail.example.net", {"parent-mail"}),
        ("include:special.mail.example.net", {"specific-mail"}),
        ("include:mail.example.net include:special.mail.example.net", {"parent-mail", "specific-mail"}),
        ("include:special.mail.example.net include:mail.example.net", {"parent-mail", "specific-mail"}),
        ("include:special.mail.example.net include:special.mail.example.net", {"specific-mail"}),
    ],
)
async def test_specificity_is_per_target_not_per_spf_record(
    monkeypatch: pytest.MonkeyPatch, reverse_rules: bool, terms: str, expected: set[str]
) -> None:
    rules = (
        Detection("mail.example.net", "Parent Mail", "parent-mail", "Email", "high"),
        Detection("special.mail.example.net", "Specific Mail", "specific-mail", "Email", "high"),
    )
    if reverse_rules:
        rules = tuple(reversed(rules))
    monkeypatch.setattr(dns_email, "get_spf_patterns", lambda: rules)
    monkeypatch.setattr(dns_replay, "get_spf_patterns", lambda: rules)
    record = f"v=spf1 {terms} -all"
    _dns_fixture(monkeypatch, {"example.com": [record]})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    replayed = dns_replay.replay_cached_dns_fingerprints(
        SourceResult(source_name="dns_records", raw_dns_records=(("TXT", record),))
    )

    assert ctx.slugs == expected
    assert set(replayed.detected_slugs) == expected
    assert set(ctx.evidence) == set(replayed.evidence)
    assert len([item for item in ctx.evidence if item.slug in expected]) == len(expected)


@pytest.mark.parametrize(
    ("record", "is_spf", "targets", "redirect"),
    [
        ("", False, (), None),
        ("v=spf1", True, (), None),
        ("v=spf1   ", True, (), None),
        ("v=spf1\tinclude:sendgrid.net", False, (), None),
        (" v=spf1 include:sendgrid.net", False, (), None),
        ("v=spf1 include: -all", True, (), None),
        ("v=spf1 redirect=", True, (), None),
        ("v=spf1 redirect=.", True, (), None),
        (
            "V=SPF1 REDIRECT=POLICY.EXAMPLE.NET. +INCLUDE:MAIL.EXAMPLE.NET.",
            True,
            ("mail.example.net", "policy.example.net"),
            "policy.example.net",
        ),
        ("v=spf1 ?include:sendgrid.net include:mailgun.org ~all", True, ("sendgrid.net", "mailgun.org"), None),
        ("v=spf1 include:sendgrid.net -all exp=explain.example.net", True, ("sendgrid.net",), None),
    ],
)
def test_bounded_spf_term_projection(record: str, is_spf: bool, targets: tuple[str, ...], redirect: str | None) -> None:
    assert is_spf_record(record) is is_spf
    assert spf_targets(record) == targets
    assert spf_redirect_target(record) == redirect


@pytest.mark.asyncio
@pytest.mark.parametrize("record", ["v=spf10 include:mailgun.org -all", "unrelated TXT", ""])
async def test_redirect_without_selected_spf_keeps_origin_evidence_only(
    monkeypatch: pytest.MonkeyPatch, record: str
) -> None:
    origin = "v=spf1 include:sendgrid.net redirect=policy.example.net"
    queries = _dns_fixture(monkeypatch, {"example.com": [origin], "policy.example.net": [record]})
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    assert queries == ["example.com", "policy.example.net"]
    assert ctx.slugs == {"sendgrid"}
    assert "SPF: strict (-all)" not in ctx.services
    assert all(item.raw_value == origin for item in ctx.evidence)


@pytest.mark.parametrize("marker", ["dns", "dns:apex_txt", "detector:txt"])
def test_failed_cached_channel_cannot_restore_spf_provider(marker: str) -> None:
    original = SourceResult(
        source_name="dns_records",
        raw_dns_records=(("TXT", "v=spf1 include:sendgrid.net -all"),),
        degraded_sources=(marker,),
    )
    assert dns_replay.replay_cached_dns_fingerprints(original) is original
