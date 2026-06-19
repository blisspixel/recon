"""Guards for committed aggregate-only validation memos."""

from __future__ import annotations

import re
from pathlib import Path

from scripts.check_validation_hygiene import find_violations

ROOT = Path(__file__).resolve().parents[1]
MEMO = ROOT / "validation" / "2026-06-19-paper-reproduction-smoke.md"


def test_public_paper_reproduction_smoke_memo_is_aggregate_only() -> None:
    text = MEMO.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", text)

    assert "Private corpora read: no." in text
    assert "Network required by default: no." in text
    assert "External spend: 0 USD." in text
    assert "No apex domains, organization names, tenant IDs, per-domain JSON" in text
    assert "smoke run for harness health" in text
    assert "not an empirical calibration claim" in text
    assert "not that the smoke sample should be quoted as a headline result" in compact

    for step in (
        "adversarial-properties",
        "differential-verification",
        "interval-coverage",
        "likelihood-sensitivity",
        "layer-ablation",
    ):
        assert f"| `{step}` | pass |" in text

    assert "validation/local" not in text
    assert "run_dir" not in text


def test_public_paper_reproduction_smoke_memo_passes_validation_hygiene() -> None:
    violations = find_violations(ROOT, ["validation/2026-06-19-paper-reproduction-smoke.md"])

    assert violations == []
