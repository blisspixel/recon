"""Characterization tests for the `recon signals show` command.

`signals_show` had no direct coverage before its C901 decomposition.
These pin the JSON payload shape and each text-mode section against the
real built-in catalog (loaded dynamically, so the tests survive catalog
growth), plus the not-found suggestion path and its exit code.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from recon_tool.cli import EXIT_VALIDATION, app
from recon_tool.signals import load_signals

runner = CliRunner()


def _first_with(attr: str):
    """Return the first signal whose ``attr`` is non-empty, or None."""
    for s in load_signals():
        if getattr(s, attr):
            return s
    return None


def test_show_json_payload_matches_signal_object() -> None:
    """`signals show <name> --json` emits the full signal definition."""
    sig = load_signals()[0]
    result = runner.invoke(app, ["signals", "show", sig.name, "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "name": sig.name,
        "category": sig.category,
        "confidence": sig.confidence,
        "description": sig.description,
        "candidates": list(sig.candidates),
        "min_matches": sig.min_matches,
        "metadata_conditions": [
            {"field": m.field, "operator": m.operator, "value": m.value} for m in sig.metadata
        ],
        "contradicts": list(sig.contradicts),
        "requires_signals": list(sig.requires_signals),
        "expected_counterparts": list(sig.expected_counterparts),
        "positive_when_absent": list(sig.positive_when_absent),
        "explain": sig.explain,
    }


def test_show_text_mode_header() -> None:
    """Text mode prints the name, category, and confidence header."""
    sig = load_signals()[0]
    result = runner.invoke(app, ["signals", "show", sig.name])
    assert result.exit_code == 0
    assert sig.name in result.output
    assert "Category:" in result.output
    assert "Confidence:" in result.output


def test_show_text_mode_candidates_section() -> None:
    sig = _first_with("candidates")
    assert sig is not None, "expected at least one signal with candidate slugs"
    result = runner.invoke(app, ["signals", "show", sig.name])
    assert result.exit_code == 0
    assert "Candidate slugs" in result.output
    assert f"min_matches={sig.min_matches}" in result.output


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
    sig = _first_with(attr)
    if sig is None:
        pytest.skip(f"no built-in signal exercises {attr!r}")
    result = runner.invoke(app, ["signals", "show", sig.name])
    assert result.exit_code == 0
    assert heading in result.output


def test_show_unknown_signal_exits_validation_with_suggestion() -> None:
    """An unknown name exits EXIT_VALIDATION; a near-miss offers a suggestion."""
    sig = load_signals()[0]
    # A prefix of a real name is unknown but suggests the real one.
    needle = sig.name[: max(3, len(sig.name) - 2)]
    result = runner.invoke(app, ["signals", "show", needle])
    assert result.exit_code == EXIT_VALIDATION
    assert "No signal named" in result.output
    assert "Did you mean" in result.output


def test_show_unknown_signal_no_suggestion() -> None:
    """A name with no substring match still exits cleanly without a suggestion."""
    result = runner.invoke(app, ["signals", "show", "zzz-no-such-signal-zzz"])
    assert result.exit_code == EXIT_VALIDATION
    assert "No signal named" in result.output
    assert "Did you mean" not in result.output
