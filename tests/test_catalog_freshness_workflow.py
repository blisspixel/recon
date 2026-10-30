# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportGeneralTypeIssues=none, reportIndexIssue=none, reportUnknownArgumentType=none
# pyright: reportUnknownVariableType=none
"""Monthly work is bounded, resumable and distinct from verification dates."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
import yaml

from scripts.check_fingerprint_freshness import DetectionKey, DetectionMetadata, parse_catalog_text
from validation import catalog_freshness as freshness

TODAY = date(2026, 10, 23)


@pytest.fixture
def catalog(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[DetectionMetadata]:
    rows = [
        {
            "name": f"Synthetic {name}",
            "slug": f"synthetic-{name}",
            "category": "Cloud",
            "detections": [
                {
                    "type": "txt",
                    "pattern": f"^synthetic-{name}=.+$",
                    "reference": f"https://docs.example.com/{name}",
                    "verified": TODAY.isoformat(),
                    "description": "Published synthetic marker only.",
                }
            ],
        }
        for name in ("a", "b", "c")
    ]
    parsed: dict[DetectionKey, DetectionMetadata] = parse_catalog_text(
        yaml.safe_dump({"fingerprints": rows}), source="synthetic.yaml"
    )
    monkeypatch.setattr(freshness, "load_working_catalog", lambda: parsed)
    monkeypatch.setattr(freshness, "catalog_digest_sha256", lambda: "a" * 64)
    history = tmp_path / "history.json"
    history.write_text('{"schema_version":1,"reviews":[]}')
    monkeypatch.setattr(freshness, "HISTORY", history)
    return list(parsed.values())


def _row(metadata: DetectionMetadata, **changes: object) -> dict[str, object]:
    return {
        "rule_id": freshness.rule_id(metadata.key),
        "source_status": "checked",
        "source_checked_on": TODAY.isoformat(),
        "reviewed_on": TODAY.isoformat(),
        "next_review": "2026-11-23",
        "prior_reference": metadata.reference,
        "new_reference": metadata.reference,
        "disposition": "unchanged",
        "basis": "Synthetic local documentation fixture explicitly supports this rule and role.",
    } | changes


def _admit(root: Path, *, proposals: int = 8) -> Path:
    freshness.due_work(root, "2026-10", as_of=TODAY, review_limit=2, proposal_limit=proposals)
    return root / "freshness" / "2026-10" / "admission.json"


def _input(root: Path, rows: list[dict[str, object]]) -> Path:
    path = root / "input.json"
    path.write_text(json.dumps({"schema_version": 1, "reviews": rows}))
    return path


def test_changed_claim_is_due_even_before_previous_next_review(
    catalog: list[DetectionMetadata],
    tmp_path: Path,
) -> None:
    history_row = _row(catalog[0]) | {"review_digest": "stale"}
    freshness.HISTORY.write_text(json.dumps({"schema_version": 1, "reviews": [history_row]}))
    receipt = freshness.due_work(tmp_path, "2026-10", as_of=TODAY)
    assert freshness.rule_id(catalog[0].key) in {row["rule_id"] for row in receipt["rules"]}


def test_future_history_cannot_claim_a_completed_source_review(
    catalog: list[DetectionMetadata],
    tmp_path: Path,
) -> None:
    history_row = _row(catalog[0], source_checked_on="2099-01-01", reviewed_on="2099-01-01")
    freshness.HISTORY.write_text(json.dumps({"schema_version": 1, "reviews": [history_row]}))
    with pytest.raises(ValueError, match="future"):
        freshness.due_work(tmp_path, "2026-10", as_of=TODAY)


def test_proposal_claim_serializes_rule_intents_and_requires_remote_resolution(tmp_path: Path) -> None:
    from validation.prepare_catalog_round import canonical_json_digest

    first: dict[str, object] = {
        "rule_id": "synthetic.yaml/rule/txt/pattern",
        "basis_revision": "first",
        "status": "pending",
    }
    first["proposal_id"] = canonical_json_digest(first)
    second = {**first, "basis_revision": "second"}
    second["proposal_id"] = canonical_json_digest({key: value for key, value in second.items() if key != "proposal_id"})
    created, claim = freshness.claim_proposal(tmp_path, first)
    assert created
    assert freshness.claim_proposal(tmp_path, second) == (False, claim)
    freshness.resolve_proposal(
        tmp_path, claim, pr_url="https://github.com/pueo-labs/recon/pull/274", conclusion="merged"
    )
    assert freshness.claim_proposal(tmp_path, first) == (False, claim)
    created_second, claim_second = freshness.claim_proposal(tmp_path, second)
    assert created_second
    assert claim_second["slot"] == 2
    forged = {**second, "basis_revision": "unbound"}
    with pytest.raises(ValueError, match="differs from its contents"):
        freshness.claim_proposal(tmp_path, forged)


def test_repeated_monthly_wake_preserves_one_frozen_bounded_scope(
    catalog: list[DetectionMetadata], tmp_path: Path
) -> None:
    first = freshness.due_work(tmp_path, "2026-10", as_of=TODAY, review_limit=2)
    assert first["due_total"] == len(catalog)
    assert first["deferred_by_budget"] == 1
    path = tmp_path / "freshness" / "2026-10" / "admission.json"
    original = path.read_bytes()
    assert freshness.due_work(tmp_path, "2026-10", as_of=date(2026, 10, 24), review_limit=2) == first
    assert path.read_bytes() == original
    with pytest.raises(ValueError, match="without expanding scope"):
        freshness.due_work(tmp_path, "2026-10", as_of=TODAY, review_limit=3)


def test_partial_review_resumes_without_overwriting_original_or_repeating_work(
    catalog: list[DetectionMetadata], tmp_path: Path
) -> None:
    admission = _admit(tmp_path)
    first = freshness.review_cycle(admission, _input(tmp_path, [_row(catalog[0])]), as_of=TODAY)
    assert first["status"] == "partial"
    assert first["unknown_count"] == 1
    events = admission.parent / "reviews"
    original = {path: path.read_bytes() for path in events.glob("*.json")}
    complete_rows = [_row(catalog[0]), _row(catalog[1])]
    complete = freshness.review_cycle(admission, _input(tmp_path, complete_rows), as_of=TODAY)
    assert complete["status"] == "no_change"
    assert complete["checked_count"] == 2
    assert complete["unknown_count"] == complete["unresolved_count"] == 0
    assert complete["proposal_queue"] == []
    assert all(path.read_bytes() == raw for path, raw in original.items())
    repeated = freshness.review_cycle(admission, _input(tmp_path, list(reversed(complete_rows))), as_of=TODAY)
    assert repeated == complete
    assert len(list(events.glob("*.json"))) == 2


def test_changed_reference_with_same_key_is_a_pending_proposal_not_automatic_catalog_edit(
    catalog: list[DetectionMetadata], tmp_path: Path
) -> None:
    admission = _admit(tmp_path)
    source_before = catalog[0]
    result = freshness.review_cycle(
        admission,
        _input(tmp_path, [_row(catalog[0], new_reference="https://docs.example.com/new-reference"), _row(catalog[1])]),
        as_of=TODAY,
    )
    assert result["status"] == "completed"
    queue = result["proposal_queue"]
    assert isinstance(queue, list)
    assert len(queue) == 1
    assert queue[0]["reference_changed"] is True
    assert queue[0]["status"] == "pending"
    assert catalog[0] == source_before
    assert catalog[0].verified == TODAY.isoformat()
    assert catalog[0].reference.endswith("/a")


@pytest.mark.parametrize("status", ["unreachable", "unreviewed"])
def test_unknown_reference_never_becomes_unchanged_or_reverified(
    status: str, catalog: list[DetectionMetadata], tmp_path: Path
) -> None:
    admission = _admit(tmp_path)
    rows = [
        _row(
            item,
            source_status=status,
            disposition="deferred",
            source_checked_on=None,
            reviewed_on=TODAY.isoformat() if status == "unreachable" else None,
            next_review=None,
        )
        for item in catalog[:2]
    ]
    result = freshness.review_cycle(admission, _input(tmp_path, rows), as_of=TODAY)
    assert result["status"] == "blocked"
    assert result["checked_count"] == 0
    assert result["unknown_count"] == 2
    assert result["proposal_queue"] == []
    assert all(item.verified == TODAY.isoformat() for item in catalog)


def test_deferred_checked_work_can_resume_and_cannot_advance_a_verified_date(
    catalog: list[DetectionMetadata], tmp_path: Path
) -> None:
    admission = _admit(tmp_path)
    deferred = _row(catalog[0], disposition="deferred")
    first = freshness.review_cycle(admission, _input(tmp_path, [deferred]), as_of=TODAY)
    assert first["unresolved_count"] == 2
    assert first["proposal_queue"] == []
    final = freshness.review_cycle(admission, _input(tmp_path, [_row(catalog[0]), _row(catalog[1])]), as_of=TODAY)
    assert final["status"] == "no_change"


@pytest.mark.parametrize(
    "change",
    [
        {"source_checked_on": "2026-10-24", "reviewed_on": "2026-10-24"},
        {"source_checked_on": "2026-02-30"},
        {"source_status": "unreachable", "disposition": "unchanged"},
        {"source_status": "unreviewed", "source_checked_on": None, "disposition": "deferred"},
        {"prior_reference": "https://docs.example.com/wrong"},
        {"new_reference": "https://user:secret@docs.example.com/private"},
    ],
)
def test_invalid_review_is_rejected_before_writing_an_event(
    change: dict[str, object], catalog: list[DetectionMetadata], tmp_path: Path
) -> None:
    admission = _admit(tmp_path)
    with pytest.raises(ValueError, match=r"review|source|reference|maintenance|basis"):
        freshness.review_cycle(admission, _input(tmp_path, [_row(catalog[0], **change)]), as_of=TODAY)
    assert not list((admission.parent / "reviews").glob("*.json"))


def test_duplicate_and_unadmitted_rule_reviews_are_rejected(catalog: list[DetectionMetadata], tmp_path: Path) -> None:
    admission = _admit(tmp_path)
    for rows in ([_row(catalog[0]), _row(catalog[0])], [_row(catalog[2])]):
        with pytest.raises(ValueError, match="outside admission or repeated"):
            freshness.review_cycle(admission, _input(tmp_path, rows), as_of=TODAY)


def test_partial_cycle_owns_unfinished_rules_and_next_cycle_respects_completed_dates(
    catalog: list[DetectionMetadata], tmp_path: Path
) -> None:
    admission = _admit(tmp_path)
    freshness.review_cycle(admission, _input(tmp_path, [_row(catalog[0])]), as_of=TODAY)
    next_cycle = freshness.due_work(tmp_path, "2026-11", as_of=date(2026, 11, 1), review_limit=2)
    assert next_cycle["owned_by_other_cycle"] == 1
    assert next_cycle["due_total"] == 1
    assert next_cycle["rules"][0]["rule_id"] == freshness.rule_id(catalog[2].key)


def test_skip_is_distinct_from_no_change_and_leaves_source_dates_untouched(
    catalog: list[DetectionMetadata], tmp_path: Path
) -> None:
    admission = _admit(tmp_path)
    result = freshness.skip_cycle(admission, "Synthetic operator skipped this bounded review window.")
    assert result["status"] == "skipped"
    assert result["checked_count"] == 0
    assert (admission.parent / "skip.json").is_file()
    next_cycle = freshness.due_work(tmp_path, "2026-11", as_of=date(2026, 11, 1), review_limit=2)
    assert next_cycle["owned_by_other_cycle"] == 0
    assert next_cycle["due_total"] == len(catalog)


def test_proposal_budget_is_bounded_and_claim_is_not_repeated(catalog: list[DetectionMetadata], tmp_path: Path) -> None:
    admission = _admit(tmp_path, proposals=1)
    result = freshness.review_cycle(
        admission, _input(tmp_path, [_row(item, disposition="narrowed") for item in catalog[:2]]), as_of=TODAY
    )
    queue = result["proposal_queue"]
    assert isinstance(queue, list)
    assert len(queue) == 1
    assert result["proposals_deferred_by_budget"] == 1
    admitted, claim = freshness.claim_proposal(tmp_path, queue[0])
    assert admitted
    repeated, same_claim = freshness.claim_proposal(tmp_path, queue[0])
    assert not repeated
    assert same_claim == claim


def test_checked_decision_and_catalog_context_are_frozen(
    catalog: list[DetectionMetadata], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admission = _admit(tmp_path)
    freshness.review_cycle(admission, _input(tmp_path, [_row(catalog[0])]), as_of=TODAY)
    with pytest.raises(ValueError, match="checked review is frozen"):
        freshness.review_cycle(
            admission,
            _input(tmp_path, [_row(catalog[0], basis="A different synthetic review decision replaces the first.")]),
            as_of=TODAY,
        )
    monkeypatch.setattr(freshness, "catalog_digest_sha256", lambda: "b" * 64)
    with pytest.raises(ValueError, match="catalog changed"):
        freshness.review_cycle(admission, _input(tmp_path, [_row(catalog[1])]), as_of=TODAY)
