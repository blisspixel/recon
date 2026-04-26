from __future__ import annotations

from recon_tool.fingerprint_audit import (
    audit_multi_detection_fingerprints,
    format_fingerprint_audit_dict,
    render_fingerprint_audit_markdown,
)
from recon_tool.fingerprints import DetectionRule, Fingerprint


def _fp(
    slug: str,
    detections: tuple[DetectionRule, ...],
    match_mode: str = "any",
) -> Fingerprint:
    return Fingerprint(
        name=slug.title(),
        slug=slug,
        category="Test",
        confidence="high",
        m365=False,
        detections=detections,
        match_mode=match_mode,
    )


def test_audit_classifies_verification_alternatives_as_keep_any() -> None:
    entries = audit_multi_detection_fingerprints(
        (
            _fp(
                "notion-like",
                (
                    DetectionRule(type="txt", pattern="^notion-domain-verification="),
                    DetectionRule(type="txt", pattern="^notion-verification-code"),
                ),
            ),
        )
    )

    assert len(entries) == 1
    assert entries[0].classification == "alternative"
    assert entries[0].recommendation == "keep_any"


def test_audit_flags_mixed_verification_and_routing_for_review() -> None:
    entries = audit_multi_detection_fingerprints(
        (
            _fp(
                "vercel-like",
                (
                    DetectionRule(type="txt", pattern="^vercel-domain-verification="),
                    DetectionRule(type="cname", pattern="vercel-dns.com"),
                ),
            ),
        )
    )

    assert entries[0].classification == "corroborating"
    assert entries[0].recommendation == "review_for_all"


def test_audit_flags_routing_only_patterns_as_too_broad() -> None:
    entries = audit_multi_detection_fingerprints(
        (
            _fp(
                "edge-like",
                (
                    DetectionRule(type="ns", pattern="akamai"),
                    DetectionRule(type="cname", pattern="edgekey.net"),
                ),
            ),
        )
    )

    assert entries[0].classification == "too_broad"
    assert entries[0].recommendation == "tighten_patterns"


def test_audit_marks_existing_all_mode_as_already_all() -> None:
    entries = audit_multi_detection_fingerprints(
        (
            _fp(
                "corroborated",
                (
                    DetectionRule(type="txt", pattern="^example-domain-verification="),
                    DetectionRule(type="cname", pattern="example.com"),
                ),
                match_mode="all",
            ),
        )
    )

    assert entries[0].classification == "corroborating"
    assert entries[0].recommendation == "already_all"


def test_audit_output_formats_summary_and_entries() -> None:
    entries = audit_multi_detection_fingerprints(
        (
            _fp(
                "notion-like",
                (
                    DetectionRule(type="txt", pattern="^notion-domain-verification="),
                    DetectionRule(type="txt", pattern="^notion-verification-code"),
                ),
            ),
        )
    )

    payload = format_fingerprint_audit_dict(entries)
    rendered = render_fingerprint_audit_markdown(entries)

    assert payload["total_multi_detection_fingerprints"] == 1
    assert payload["classifications"] == {"alternative": 1}
    assert "`notion-like`" in rendered
    assert "keep_any" in rendered
