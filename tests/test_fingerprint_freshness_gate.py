"""Regressions for the diff-aware fingerprint verification-date gate."""

from __future__ import annotations

from datetime import date

from scripts.check_fingerprint_freshness import audit_new_detections, parse_catalog_text


def _catalog(*, pattern: str, verified: str | None) -> str:
    verified_line = f"        verified: {verified}\n" if verified is not None else ""
    return (
        "fingerprints:\n"
        "  - name: Example Service\n"
        "    slug: example-service\n"
        "    category: Misc\n"
        "    confidence: high\n"
        "    detections:\n"
        "      - type: txt\n"
        f"        pattern: '{pattern}'\n"
        f"{verified_line}"
    )


def _audit(*, baseline: str, current: str):
    return audit_new_detections(
        parse_catalog_text(baseline, source="example.yaml"),
        parse_catalog_text(current, source="example.yaml"),
        today=date(2026, 7, 17),
    )


def test_legacy_undated_detection_is_exempt() -> None:
    document = _catalog(pattern="^example-verification=", verified=None)

    assert _audit(baseline=document, current=document) == []


def test_new_undated_detection_is_rejected() -> None:
    violations = _audit(
        baseline=_catalog(pattern="^old-example=", verified=None),
        current=_catalog(pattern="^new-example=", verified=None),
    )

    assert [violation.reason for violation in violations] == ["missing verified date"]


def test_new_yaml_date_is_accepted() -> None:
    violations = _audit(
        baseline=_catalog(pattern="^old-example=", verified=None),
        current=_catalog(pattern="^new-example=", verified="2026-07-17"),
    )

    assert violations == []


def test_new_impossible_or_future_date_is_rejected() -> None:
    impossible = _audit(
        baseline=_catalog(pattern="^old-example=", verified=None),
        current=_catalog(pattern="^new-example=", verified="'2026-13-40'"),
    )
    future = _audit(
        baseline=_catalog(pattern="^old-example=", verified=None),
        current=_catalog(pattern="^new-example=", verified="2026-07-18"),
    )

    assert [violation.reason for violation in impossible] == ["verified is not a real calendar date"]
    assert [violation.reason for violation in future] == ["verified date 2026-07-18 is in the future"]
