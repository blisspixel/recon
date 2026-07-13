"""Regression checks for the maintainer loop runbook."""

from __future__ import annotations

from pathlib import Path

DOC = Path(__file__).resolve().parent.parent / "docs" / "maintainer-loop-runbook.md"


def _text() -> str:
    return DOC.read_text(encoding="utf-8")


def test_runbook_covers_approved_loop_shapes() -> None:
    text = _text()

    assert "## CI Failure Triage Loop" in text
    assert "## Private Calibration Loop" in text
    assert "## Fingerprint Proposal Loop" in text


def test_runbook_pins_agentic_boundary_and_gates() -> None:
    text = _text()
    normalized = " ".join(text.split())

    for required in (
        "does not change recon runtime behavior",
        "success is decided by a deterministic gate",
        "target data and per-domain artifacts stay in ignored local paths",
        "semantic changes still receive maintainer review",
        "uv run python scripts/check.py",
    ):
        assert required in normalized


def test_runbook_requires_spend_tracking_and_local_state() -> None:
    text = _text()

    assert ".agent/maintainer-loop-state.json" in text
    assert "validation/local/maintainer-loop-state.json" not in text
    assert "Default spend is 0 USD" in text
    assert "The loop stops before the cap is exceeded" in text
    assert "not raw model reasoning" in text


def test_runbook_requires_side_effect_boundaries_and_resume_keys() -> None:
    text = _text()
    normalized = " ".join(text.split())

    assert "Action boundary" in text
    assert "Resume key" in text
    assert "externally visible" in normalized
    assert "checks this key before repeating a write" in normalized
    assert "Release, distribution, schema, CPT, and catalog changes require maintainer approval" in normalized


def test_runbook_private_calibration_uses_preflight_and_hygiene_gate() -> None:
    text = _text()

    assert "python -m validation.run_calibration_bundle --dry-run" in text
    assert "at least one publishable stratum" in text
    assert "uv run python scripts/check_validation_hygiene.py" in text
