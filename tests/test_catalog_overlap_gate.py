"""Synthetic witnesses expose equal and non-textual matcher collisions."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.check_catalog_overlaps import Rule, Witness, canonical_rules, find_overlaps, review_overlaps, witnesses
from scripts.check_fingerprint_freshness import DetectionKey


def _rule(slug: str, pattern: str, kind: str = "txt", tier: str = "application") -> Rule:
    return Rule(DetectionKey("synthetic.yaml", slug, kind, pattern), tier)


def _ledger(path: Path, rules: tuple[Rule, Rule], *, disposition: str, retained: tuple[Rule, ...]) -> Path:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "reviews": [
                    {
                        "rules": [rule.identifier for rule in rules],
                        "disposition": disposition,
                        "reason": "Synthetic explicit role/specificity test, one observation with retained provenance.",
                        "retained": [rule.identifier for rule in retained],
                        "source_type": "CNAME",
                        "scope": "related_host",
                    }
                ],
            }
        )
    )
    return path


@pytest.mark.parametrize(
    "patterns",
    [(r"^synthetic-verification=.+$", r"^synthetic-verification=.+$"), (r"^synthetic-[a-z]+$", r"^synthetic-.*$")],
)
def test_equal_or_differently_written_regexes_produce_actionable_witnesses(
    patterns: tuple[str, str], tmp_path: Path
) -> None:
    rules = (_rule("service-a", patterns[0]), _rule("service-b", patterns[1]))
    sample = "synthetic-verification=token" if patterns[0] == patterns[1] else "synthetic-token"
    overlaps = find_overlaps(rules, (Witness("txt", sample), Witness("txt", "lookalike:" + sample)))
    assert len(overlaps) == 1
    assert overlaps[0].witness == Witness("txt", sample)
    ledger = tmp_path / "reviews.json"
    ledger.write_text('{"version":1,"reviews":[]}')
    errors = review_overlaps(overlaps, rules, ledger)
    assert len(errors) == 1
    assert sample in errors[0]
    assert all(rule.identifier in errors[0] for rule in rules)


def test_equal_rules_cannot_hide_behind_missing_witness_coverage(tmp_path: Path) -> None:
    rules = (_rule("service-a", "^synthetic=.+$"), _rule("service-b", "^synthetic=.+$"))
    overlaps = find_overlaps(rules, ())
    assert len(overlaps) == 1
    assert overlaps[0].witness is None
    ledger = _ledger(tmp_path / "reviews.json", rules, disposition="distinct_roles", retained=rules)
    assert "add one to review equal rules" in review_overlaps(overlaps, rules, ledger)[0]


def test_same_slug_aliases_and_anchored_lookalikes_do_not_create_cross_slug_collisions() -> None:
    rules = (_rule("same", "^synthetic=.+$"), _rule("same", "^synthetic=.*$"), _rule("other", "^other=.+$"))
    assert find_overlaps(rules, (Witness("txt", "synthetic=token"), Witness("txt", "note=synthetic=token"))) == ()


def test_specificity_exception_replays_actual_cname_selection_and_provenance(tmp_path: Path) -> None:
    rules = (_rule("platform", "vendor.invalid", "cname_target"), _rule("app", "app.vendor.invalid", "cname_target"))
    sample = Witness("cname_target", "tenant.app.vendor.invalid")
    overlaps = find_overlaps(rules, (sample,))
    ledger = _ledger(tmp_path / "reviews.json", rules, disposition="specificity", retained=(rules[1],))
    assert review_overlaps(overlaps, rules, ledger) == []
    _ledger(ledger, rules, disposition="specificity", retained=(rules[0],))
    assert "provenance differs" in review_overlaps(overlaps, rules, ledger)[0]


def test_intentional_dual_tier_roles_retain_one_observation_with_two_scopes_of_attribution(tmp_path: Path) -> None:
    rules = (
        _rule("app", "vendor.invalid", "cname_target"),
        _rule("edge", "vendor.invalid", "cname_target", tier="infrastructure"),
    )
    overlaps = find_overlaps(rules, (Witness("cname_target", "tenant.vendor.invalid"),))
    ledger = _ledger(tmp_path / "reviews.json", rules, disposition="distinct_roles", retained=rules)
    assert review_overlaps(overlaps, rules, ledger) == []
    # Moving both to one tier changes actual retained provenance and invalidates
    # the reviewed multi-role exception. It cannot count two corroborators.
    changed = (rules[0], replace(rules[1], tier="application"))
    assert overlaps[0].witness is not None
    assert "provenance differs" in review_overlaps(find_overlaps(changed, (overlaps[0].witness,)), changed, ledger)[0]


def test_review_exceptions_must_not_become_stale(tmp_path: Path) -> None:
    rules = (_rule("a", "vendor.invalid", "cname_target"), _rule("b", "app.vendor.invalid", "cname_target"))
    ledger = _ledger(tmp_path / "reviews.json", rules, disposition="specificity", retained=(rules[1],))
    assert "Stale overlap review" in review_overlaps((), rules, ledger)[0]


def test_canonical_catalog_has_no_unreviewed_witnessed_overlap() -> None:
    rules = canonical_rules()
    samples = witnesses(rules)
    assert len(samples) > 3000
    assert review_overlaps(find_overlaps(rules, samples), rules) == []
