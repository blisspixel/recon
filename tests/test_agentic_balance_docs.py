from __future__ import annotations

from pathlib import Path

DOC = Path(__file__).resolve().parent.parent / "docs" / "agentic-balance.md"


def test_agentic_balance_requires_bounded_side_effects_and_resume_keys() -> None:
    text = DOC.read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    assert "Side effects are named and bounded before they run" in text
    assert "separate planning from execution" in normalized
    assert "idempotency key or run stamp" in normalized
    assert "externally visible" in normalized


def test_agentic_balance_records_traces_not_raw_reasoning() -> None:
    text = DOC.read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    assert "Trace outcomes, not hidden reasoning" in text
    assert "commands, inputs by path, outputs by path" in normalized
    assert "must not persist raw model reasoning or target data" in normalized
