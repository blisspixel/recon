"""Guards for committed aggregate-only validation memos."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from scripts.check_validation_hygiene import find_violations

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class PublicMemo:
    path: Path
    profile: str
    required_phrases: tuple[str, ...]


MEMOS = (
    PublicMemo(
        path=ROOT / "validation" / "2026-06-19-paper-reproduction-smoke.md",
        profile="smoke",
        required_phrases=(
            "smoke run for harness health",
            "not an empirical calibration claim",
            "not that the smoke sample should be quoted as a headline result",
        ),
    ),
    PublicMemo(
        path=ROOT / "validation" / "2026-06-28-hybrid-interval-smoke.md",
        profile="smoke",
        required_phrases=(
            "smoke run for harness health",
            "not an empirical calibration claim",
            "not that the smoke sample should be quoted as a headline result",
        ),
    ),
    PublicMemo(
        path=ROOT / "validation" / "2026-06-28-hybrid-interval-paper.md",
        profile="paper",
        required_phrases=(
            "full public proof run",
            "model-internal perturbation coverage",
            "not ground-truth frequentist coverage",
            "not real-world validity claims",
        ),
    ),
    PublicMemo(
        path=ROOT / "validation" / "2026-06-28-adversarial-perturbation-paper.md",
        profile="paper",
        required_phrases=(
            "full public proof run",
            "planted evidence boundary",
            "774 paired add/remove cases",
            "synthetic model-internal perturbation",
            "not real-world validity claims",
        ),
    ),
    PublicMemo(
        path=ROOT / "validation" / "2026-06-28-final-claim-audit.md",
        profile="paper",
        required_phrases=(
            "final claim audit",
            "full public proof run",
            "model-internal perturbation coverage",
            "not ground-truth frequentist coverage",
            "not real-world validity claims",
        ),
    ),
    PublicMemo(
        path=ROOT / "validation" / "2026-06-29-final-claim-audit-refresh.md",
        profile="paper",
        required_phrases=(
            "final claim audit refresh",
            "full public proof run",
            "metric-lineage wording check",
            "model-internal perturbation coverage",
            "not ground-truth frequentist coverage",
            "not real-world validity claims",
        ),
    ),
    PublicMemo(
        path=ROOT / "validation" / "2026-06-29-scorecard-gate-claim-audit.md",
        profile="paper",
        required_phrases=(
            "Scorecard gate final claim audit",
            "full public proof run",
            "public Scorecard API freshness check",
            "model-internal perturbation coverage",
            "not ground-truth frequentist coverage",
            "not real-world validity claims",
        ),
    ),
    PublicMemo(
        path=ROOT / "validation" / "2026-06-29-submission-freeze-local-proof.md",
        profile="paper",
        required_phrases=(
            "submission freeze local proof",
            "full public proof run",
            "does not claim an external submission",
            "model-internal perturbation coverage",
            "not ground-truth frequentist coverage",
            "not real-world validity claims",
        ),
    ),
)


def test_public_paper_reproduction_memos_are_aggregate_only() -> None:
    for memo in MEMOS:
        text = memo.path.read_text(encoding="utf-8")
        compact = re.sub(r"\s+", " ", text)

        assert "Private corpora read: no." in text
        assert "Network required by default: no." in text
        assert "External spend: 0 USD." in text
        assert "No apex domains, organization names, tenant IDs, per-domain JSON" in text
        assert f"--profile {memo.profile}" in text
        for required in memo.required_phrases:
            assert required in compact

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


def test_public_paper_reproduction_memos_pass_validation_hygiene() -> None:
    violations = find_violations(ROOT, [str(memo.path.relative_to(ROOT)) for memo in MEMOS])

    assert violations == []
