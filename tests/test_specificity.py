"""Specificity-gate safety regressions."""

from __future__ import annotations

from recon_tool.specificity import evaluate_pattern


def test_evaluate_pattern_rejects_oversized_regex_before_matching() -> None:
    verdict = evaluate_pattern("a" * 501, "txt")

    assert verdict.matches == 0
    assert verdict.threshold_exceeded is False


def test_evaluate_pattern_rejects_redos_shaped_regex_before_matching() -> None:
    verdict = evaluate_pattern("(a+)+", "txt")

    assert verdict.matches == 0
    assert verdict.threshold_exceeded is False
