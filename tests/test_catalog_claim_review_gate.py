# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportArgumentType=none
"""Semantic review cannot be bypassed by retaining a rule's matching key."""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import date
from pathlib import Path

import pytest
import yaml

from scripts.check_fingerprint_freshness import (
    ClaimReview,
    DetectionKey,
    DetectionMetadata,
    audit_changed_detections,
    load_claim_reviews,
    parse_catalog_text,
)

TODAY = date(2026, 10, 23)


def _catalog(**changes: object) -> dict[DetectionKey, DetectionMetadata]:
    rule = {
        "type": "txt",
        "pattern": "^synthetic-verification=.+$",
        "description": "Published verification marker.",
        "reference": "https://example.com/vendor-guide",
        "verified": "2026-07-17",
    }
    entry = {"name": "Synthetic Service", "slug": "synthetic", "category": "Cloud", "detections": [rule]}
    for key, value in changes.items():
        if key in {
            "name",
            "category",
            "confidence",
            "m365",
            "match_mode",
            "provider_group",
            "display_group",
            "parent_vendor",
            "product_family",
        }:
            entry[key] = value
        else:
            rule[key] = value
    return parse_catalog_text(yaml.safe_dump({"fingerprints": [entry]}), source="synthetic.yaml")


def _review(
    before: dict[DetectionKey, DetectionMetadata], after: dict[DetectionKey, DetectionMetadata], **changes: object
) -> ClaimReview:
    key = next(iter(after))
    return replace(
        ClaimReview(
            key,
            before[key].review_digest,
            after[key].review_digest,
            "semantic",
            "2026-10-23",
            None,
            "Synthetic claim refinement; existing source date retained, not rechecked.",
        ),
        **changes,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("description", "Active service deployment confirmed."),
        ("reference", "https://example.com/different-guide"),
        ("category", "Identity"),
        ("name", "Synthetic Active Identity Provider"),
        ("confidence", "high"),
        ("m365", True),
        ("match_mode", "all"),
        ("tier", "infrastructure"),
        ("weight", 2),
        ("provider_group", "identity"),
        ("display_group", "identity"),
        ("parent_vendor", "Synthetic Parent"),
        ("product_family", "Synthetic Identity"),
    ],
)
def test_same_key_claim_role_or_provenance_change_requires_exact_disposition(field: str, value: object) -> None:
    before, after = _catalog(), _catalog(**{field: value})
    assert before.keys() == after.keys()
    failures = audit_changed_detections(before, after, ())
    assert len(failures) == 1
    assert "needs review" in failures[0].reason
    assert next(iter(before.values())).review_digest in failures[0].reason
    assert audit_changed_detections(before, after, (_review(before, after),)) == []


def test_layout_only_is_free_and_spelling_review_does_not_invent_vendor_verification() -> None:
    before = _catalog()
    assert audit_changed_detections(before, _catalog(description="Published\n  verification marker."), ()) == []
    spelling = _catalog(description="Published verification markers.")
    review = _review(
        before, spelling, disposition="editorial", reason="Plural wording correction only; source not rechecked."
    )
    assert audit_changed_detections(before, spelling, (review,)) == []
    assert next(iter(spelling.values())).verified == "2026-07-17"
    assert review.source_checked_on is None


@pytest.mark.parametrize("change", [{"reference": "https://example.com/other"}, {"match_mode": "all"}, {"weight": 2}])
def test_editorial_disposition_cannot_authorize_structural_semantics(change: dict[str, object]) -> None:
    before, after = _catalog(), _catalog(**change)
    failures = audit_changed_detections(before, after, (_review(before, after, disposition="editorial"),))
    assert "require semantic review" in failures[0].reason


def test_verified_edit_needs_actual_check_date_but_claim_edit_does_not_refresh_it() -> None:
    before, after = _catalog(), _catalog(verified="2026-10-22")
    review = _review(before, after)
    assert "actual source_checked_on" in audit_changed_detections(before, after, (review,))[0].reason
    assert audit_changed_detections(before, after, (replace(review, source_checked_on="2026-10-22"),)) == []
    # Retiring an unsupported date is reviewable without inventing a source check.
    cleared = _catalog(verified=None)
    assert audit_changed_detections(before, cleared, (_review(before, cleared),)) == []


def test_matching_key_changes_require_addition_and_removal_dispositions() -> None:
    before, after = _catalog(), _catalog(pattern="^narrow-synthetic-verification=.+$")
    failures = audit_changed_detections(before, after, ())
    assert len(failures) == 2
    old, new = next(iter(before.values())), next(iter(after.values()))
    removed = ClaimReview(
        old.key, old.review_digest, None, "semantic", "2026-10-23", None, "Retired broad synthetic rule."
    )
    added = ClaimReview(
        new.key,
        None,
        new.review_digest,
        "semantic",
        "2026-10-23",
        "2026-07-17",
        "Scoped replacement; basis checked on the retained source date.",
    )
    assert audit_changed_detections(before, after, (removed, added)) == []
    assert (
        "semantic review"
        in audit_changed_detections(before, after, (replace(removed, disposition="editorial"), added))[0].reason
    )


def test_review_is_bound_to_exact_before_after_metadata() -> None:
    before, after = _catalog(), _catalog(description="Narrowed claim.")
    wrong = replace(_review(before, after), after="0" * 64)
    assert "needs review" in audit_changed_detections(before, after, (wrong,))[0].reason


def _row() -> dict[str, object]:
    before, after = _catalog(), _catalog(description="Narrowed claim.")
    result = asdict(_review(before, after))
    result["rule"] = result.pop("key")
    return result


@pytest.mark.parametrize(
    "change",
    [
        {"reason": ""},
        {"reviewed_on": "2026-10-24"},
        {"reviewed_on": "2026-02-30"},
        {"source_checked_on": "2026-10-24"},
        {"source_checked_on": "not-a-date"},
        {"before": "wrong"},
        {"after": None, "before": None},
        {"disposition": "automatic"},
        {"extra": True},
    ],
)
def test_review_ledger_rejects_malformed_or_fabricated_metadata(change: dict[str, object], tmp_path: Path) -> None:
    path = tmp_path / "reviews.json"
    row = _row() | change
    path.write_text(json.dumps({"version": 1, "reviews": [row]}))
    with pytest.raises(ValueError, match=r"review|source"):
        load_claim_reviews(path, today=TODAY)


def test_review_ledger_loads_typed_dispositions_and_rejects_duplicate_binding(tmp_path: Path) -> None:
    path = tmp_path / "reviews.json"
    row = _row()
    path.write_text(json.dumps({"version": 1, "reviews": [row]}))
    reviews = load_claim_reviews(path, today=TODAY)
    assert len(reviews) == 1
    assert reviews[0].source_checked_on is None
    path.write_text(json.dumps({"version": 1, "reviews": [row, row]}))
    with pytest.raises(ValueError, match="duplicate"):
        load_claim_reviews(path, today=TODAY)
