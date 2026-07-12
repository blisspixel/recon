"""Deterministic DNS fingerprint replay regressions."""

from __future__ import annotations

from recon_tool.fingerprints import Detection
from recon_tool.models import SourceResult
from recon_tool.sources import dns_replay
from recon_tool.sources.dns_base import DetectionCtx


def _detection(pattern: str, *, name: str, slug: str) -> Detection:
    return Detection(pattern, name, slug, "cloud", "high")


def test_record_match_uses_longest_case_insensitive_regex() -> None:
    ctx = DetectionCtx()
    rules = (
        _detection(r"example\.test$", name="Short Match", slug="short-match"),
        _detection(r"service\.example\.test$", name="Exact Service", slug="exact-service"),
    )

    dns_replay._record_match(ctx, "CNAME", "SERVICE.EXAMPLE.TEST", rules, regex=True)

    assert ctx.services == {"Exact Service"}
    assert ctx.slugs == {"exact-service"}
    assert [(item.slug, item.source_type, item.raw_value) for item in ctx.evidence] == [
        ("exact-service", "CNAME", "SERVICE.EXAMPLE.TEST")
    ]


def test_record_match_skips_invalid_regex_before_valid_match() -> None:
    ctx = DetectionCtx()
    rules = (
        _detection("[invalid-pattern", name="Invalid", slug="invalid"),
        _detection(r"service\.example\.test$", name="Exact Service", slug="exact-service"),
    )

    dns_replay._record_match(ctx, "CNAME", "service.example.test", rules, regex=True)

    assert ctx.services == {"Exact Service"}
    assert ctx.slugs == {"exact-service"}


def test_record_match_preserves_substring_semantics_for_non_regex_records() -> None:
    ctx = DetectionCtx()
    rules = (_detection("mail.example.test", name="Mail Service", slug="mail-service"),)

    dns_replay._record_match(ctx, "MX", "10 MAIL.EXAMPLE.TEST", rules)

    assert ctx.services == {"Mail Service"}
    assert ctx.slugs == {"mail-service"}


def test_cached_cname_replay_is_network_free_and_idempotent(monkeypatch) -> None:
    rules = (_detection(r"service\.example\.test$", name="Exact Service", slug="exact-service"),)
    monkeypatch.setattr(dns_replay, "get_cname_patterns", lambda: rules)
    original = SourceResult(
        source_name="DNS",
        raw_dns_records=(("CNAME", "SERVICE.EXAMPLE.TEST"),),
    )

    replayed = dns_replay.replay_cached_dns_fingerprints(original)
    replayed_again = dns_replay.replay_cached_dns_fingerprints(replayed)

    assert replayed.detected_services == ("Exact Service",)
    assert replayed.detected_slugs == ("exact-service",)
    assert [(item.slug, item.source_type) for item in replayed.evidence] == [("exact-service", "CNAME")]
    assert replayed_again == replayed


def test_cached_txt_replay_preserves_txt_and_spf_evidence(monkeypatch) -> None:
    txt_rules = (_detection(r"verification=abc123", name="Verification Service", slug="verification-service"),)
    spf_rules = (_detection("include:spf.example.test", name="Mail Gateway", slug="mail-gateway"),)
    monkeypatch.setattr(dns_replay, "get_txt_patterns", lambda: txt_rules)
    monkeypatch.setattr(dns_replay, "get_spf_patterns", lambda: spf_rules)
    original = SourceResult(
        source_name="DNS",
        raw_dns_records=(
            ("TXT", "verification=abc123"),
            ("TXT", "v=spf1 include:spf.example.test -all"),
        ),
    )

    replayed = dns_replay.replay_cached_dns_fingerprints(original)

    assert replayed.detected_services == ("Mail Gateway", "Verification Service")
    assert replayed.detected_slugs == ("mail-gateway", "verification-service")
    assert {(item.slug, item.source_type) for item in replayed.evidence} == {
        ("mail-gateway", "SPF"),
        ("verification-service", "TXT"),
    }


def test_cached_replay_does_not_project_unavailable_dns() -> None:
    original = SourceResult(
        source_name="DNS",
        source_unavailable=True,
        raw_dns_records=(("CNAME", "service.example.test"),),
    )

    assert dns_replay.replay_cached_dns_fingerprints(original) is original
