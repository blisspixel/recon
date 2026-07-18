"""Characterization tests for the `recon signals show` command.

`signals_show` had no direct coverage before its C901 decomposition.
These pin the JSON payload shape and each text-mode section against the
real built-in catalog (loaded dynamically, so the tests survive catalog
growth), plus the not-found suggestion path and its exit code.
"""

from __future__ import annotations

import json
import re

import pytest
from typer.testing import CliRunner

from recon_tool.cli import EXIT_VALIDATION, app
from recon_tool.signals import public_signal_names, reportable_signals, signal_observation_label

runner = CliRunner()
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _plain(text: str) -> str:
    return ANSI_RE.sub("", text)


def _first_with(attr: str):
    """Return the first signal whose ``attr`` is non-empty, or None."""
    for signal, label in reportable_signals():
        if getattr(signal, attr):
            return signal, label
    return None


def _name_only_query() -> str:
    for sig, label in reportable_signals():
        excluded = " ".join([sig.category, sig.description, *sig.candidates]).lower()
        for token in re.findall(r"[a-z0-9]+", label.lower()):
            if len(token) >= 4 and token not in excluded:
                return token
    pytest.fail("expected at least one signal with a searchable name-only token")


def _description_only_query() -> str:
    for sig, label in reportable_signals():
        excluded = " ".join([label, sig.category, *sig.candidates]).lower()
        for token in re.findall(r"[a-z0-9]+", sig.description.lower()):
            if len(token) >= 6 and token not in excluded:
                return token
    pytest.fail("expected at least one signal with a searchable description-only token")


def test_list_json_payload_matches_signal_summaries() -> None:
    result = runner.invoke(app, ["signals", "list", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == [
        {
            "name": label,
            "category": sig.category,
            "confidence": sig.confidence,
            "candidate_count": len(sig.candidates),
            "min_matches": sig.min_matches,
            "description": sig.description,
        }
        for sig, label in reportable_signals()
    ]


def test_list_text_mode_prints_catalog_rows() -> None:
    sig, label = reportable_signals()[0]

    result = runner.invoke(app, ["signals", "list"])

    assert result.exit_code == 0
    plain_output = _plain(result.output)
    assert "signal" in plain_output
    assert label in plain_output
    assert sig.category in plain_output


def test_list_category_filter_is_word_prefix_aware() -> None:
    category = reportable_signals()[0][0].category
    short_query = re.findall(r"[a-z0-9]+", category.lower())[0][:3]

    result = runner.invoke(app, ["signals", "list", "--category", short_query, "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload
    assert all(
        any(word.startswith(short_query) for word in re.findall(r"[a-z0-9]+", entry["category"].lower()))
        for entry in payload
    )


def test_list_category_filter_with_no_matches_exits_cleanly() -> None:
    result = runner.invoke(app, ["signals", "list", "--category", "zzz-no-such-category"])

    assert result.exit_code == 0
    assert "No signals match those filters" in result.output


@pytest.mark.parametrize("value", ["", "   "])
def test_list_rejects_explicitly_empty_category(value: str) -> None:
    result = runner.invoke(app, ["signals", "list", "--category", value])

    assert result.exit_code == EXIT_VALIDATION
    assert "category filter cannot be empty" in result.output.lower()


def test_search_empty_query_exits_validation() -> None:
    result = runner.invoke(app, ["signals", "search", "   "])

    assert result.exit_code == EXIT_VALIDATION
    assert "Empty search query" in result.output


def test_search_json_covers_name_category_candidate_and_description_matches() -> None:
    found = _first_with("candidates")
    assert found is not None
    sig_with_candidate, _label = found
    queries = [
        _name_only_query(),
        reportable_signals()[0][0].category,
        sig_with_candidate.candidates[0],
        _description_only_query(),
    ]

    for query in queries:
        result = runner.invoke(app, ["signals", "search", query, "--json"])
        assert result.exit_code == 0
        assert json.loads(result.stdout), query


def test_list_and_search_json_use_the_same_summary_fields() -> None:
    _signal, label = reportable_signals()[0]
    listed = runner.invoke(app, ["signals", "list", "--json"])
    searched = runner.invoke(app, ["signals", "search", label, "--json"])

    assert listed.exit_code == 0
    assert searched.exit_code == 0
    list_row = next(row for row in json.loads(listed.stdout) if row["name"] == label)
    search_row = next(row for row in json.loads(searched.stdout) if row["name"] == label)
    assert search_row == list_row


def test_search_text_mode_prints_matches() -> None:
    _sig, label = reportable_signals()[0]

    result = runner.invoke(app, ["signals", "search", label])

    assert result.exit_code == 0
    plain_output = _plain(result.output)
    assert "match" in plain_output
    assert label in plain_output


def test_search_text_preserves_rank_without_false_category_groups() -> None:
    structured = runner.invoke(app, ["signals", "search", "email", "--json"])
    rendered = runner.invoke(app, ["signals", "search", "email"])

    assert structured.exit_code == 0
    assert rendered.exit_code == 0
    payload = json.loads(structured.stdout)
    plain_output = _plain(rendered.output)
    assert len(payload) > 1
    assert plain_output.count("Category:") == len(payload)
    assert plain_output.count("Confidence:") == len(payload)
    cursor = 0
    for row in payload:
        cursor = plain_output.index(row["name"], cursor) + len(row["name"])


def test_search_no_matches_exits_cleanly() -> None:
    result = runner.invoke(app, ["signals", "search", "zzz-no-such-signal"])

    assert result.exit_code == 0
    assert "No signals match" in result.output
    assert "recon signals list" in result.output


def test_show_json_payload_matches_signal_object() -> None:
    """`signals show <name> --json` emits the full signal definition."""
    sig, label = reportable_signals()[0]
    result = runner.invoke(app, ["signals", "show", label, "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "name": label,
        "category": sig.category,
        "confidence": sig.confidence,
        "description": sig.description,
        "candidates": list(sig.candidates),
        "min_matches": sig.min_matches,
        "metadata_conditions": [{"field": m.field, "operator": m.operator, "value": m.value} for m in sig.metadata],
        "contradicts": list(sig.contradicts),
        "requires_signals": public_signal_names(sig.requires_signals),
        "expected_counterparts": list(sig.expected_counterparts),
        "positive_when_absent": list(sig.positive_when_absent),
        "explain": sig.explain,
    }


def test_show_text_mode_header() -> None:
    """Text mode prints the name, category, and confidence header."""
    _sig, label = reportable_signals()[0]
    result = runner.invoke(app, ["signals", "show", label])
    assert result.exit_code == 0
    plain_output = _plain(result.output)
    assert label in plain_output
    assert "Category:" in plain_output
    assert "Confidence:" in plain_output


def test_show_text_mode_candidates_section() -> None:
    found = _first_with("candidates")
    assert found is not None, "expected at least one signal with candidate slugs"
    sig, label = found
    result = runner.invoke(app, ["signals", "show", label])
    assert result.exit_code == 0
    plain_output = _plain(result.output)
    assert "Candidate slugs" in plain_output
    assert f"min_matches={sig.min_matches}" in plain_output


@pytest.mark.parametrize(
    ("attr", "heading"),
    [
        ("metadata", "Metadata conditions"),
        ("contradicts", "Contradicts"),
        ("requires_signals", "Requires other signals"),
        ("expected_counterparts", "Expected counterparts"),
        ("positive_when_absent", "Positive-when-absent"),
        ("explain", "Explain"),
    ],
)
def test_show_text_mode_optional_sections(attr: str, heading: str) -> None:
    """Each optional section renders when the signal populates that field."""
    found = _first_with(attr)
    if found is None:
        pytest.skip(f"no built-in signal exercises {attr!r}")
    _sig, label = found
    result = runner.invoke(app, ["signals", "show", label])
    assert result.exit_code == 0
    assert heading in _plain(result.output)


def test_show_unknown_signal_exits_validation_with_suggestion() -> None:
    """An unknown name exits EXIT_VALIDATION; a near-miss offers a suggestion."""
    _sig, label = reportable_signals()[0]
    # A prefix of a real name is unknown but suggests the real one.
    needle = label[: max(3, len(label) - 2)]
    result = runner.invoke(app, ["signals", "show", needle])
    assert result.exit_code == EXIT_VALIDATION
    assert "No signal named" in result.output
    assert "Did you mean" in result.output
    assert "recon signals search" in result.output


def test_show_unknown_signal_no_suggestion() -> None:
    """A name with no substring match still exits cleanly without a suggestion."""
    result = runner.invoke(app, ["signals", "show", "zzz-no-such-signal-zzz"])
    assert result.exit_code == EXIT_VALIDATION
    assert "No signal named" in result.output
    assert "Did you mean" not in result.output


def test_public_catalog_omits_nonreportable_rule_identifiers() -> None:
    hidden_names = {"Dual Email Delivery Path", "Incomplete Identity Migration"}

    listed = runner.invoke(app, ["signals", "list", "--json"])
    searched = runner.invoke(app, ["signals", "search", "Incomplete Identity Migration", "--json"])

    assert listed.exit_code == 0
    assert hidden_names.isdisjoint(entry["name"] for entry in json.loads(listed.stdout))
    assert json.loads(searched.stdout) == []
    assert all(signal_observation_label(name) is None for name in hidden_names)


@pytest.mark.parametrize("hidden_name", ["Dual Email Delivery Path", "Incomplete Identity Migration"])
def test_show_rejects_nonreportable_rule_identifier(hidden_name: str) -> None:
    result = runner.invoke(app, ["signals", "show", hidden_name, "--json"])

    assert result.exit_code == EXIT_VALIDATION
    assert "Did you mean" not in result.output
