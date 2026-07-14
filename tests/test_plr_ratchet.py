"""Tests for the PLR size-rule ratchet."""

from __future__ import annotations

from scripts.check_plr_ratchet import MAX_COUNTS, find_improvements, find_regressions, parse_statistics


def test_parse_statistics_extracts_selected_plr_counts() -> None:
    output = """51\tPLR0913\ttoo-many-arguments
22\tPLR0911\ttoo-many-return-statements
14\tPLR0912\ttoo-many-branches
9\tPLR0915\ttoo-many-statements
3\tPLW0603\tglobal-statement
"""

    assert parse_statistics(output) == {
        "PLR0911": 22,
        "PLR0912": 14,
        "PLR0913": 51,
        "PLR0915": 9,
    }


def test_parse_statistics_defaults_missing_rules_to_zero() -> None:
    assert parse_statistics("All checks passed!") == {
        "PLR0911": 0,
        "PLR0912": 0,
        "PLR0913": 0,
        "PLR0915": 0,
    }


def test_find_regressions_reports_only_counts_above_ceiling() -> None:
    counts = dict(MAX_COUNTS)
    counts["PLR0913"] = MAX_COUNTS["PLR0913"] + 1

    assert find_regressions(counts) == {"PLR0913": (MAX_COUNTS["PLR0913"] + 1, MAX_COUNTS["PLR0913"])}


def test_find_improvements_reports_stale_ceiling() -> None:
    counts = dict(MAX_COUNTS)
    counts["PLR0912"] = MAX_COUNTS["PLR0912"] - 1

    assert find_improvements(counts) == {"PLR0912": (MAX_COUNTS["PLR0912"] - 1, MAX_COUNTS["PLR0912"])}
