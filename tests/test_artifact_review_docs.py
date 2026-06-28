from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "artifact-review.md"


def test_artifact_review_guide_is_linked_from_research_docs() -> None:
    for path in (
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "external-writeup-plan.md",
        ROOT / "docs" / "paper-draft.md",
        ROOT / "docs" / "roadmap.md",
    ):
        assert "artifact-review.md" in path.read_text(encoding="utf-8")


def test_public_label_snapshot_decision_is_linked_from_research_docs() -> None:
    for path in (
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "external-writeup-plan.md",
        ROOT / "docs" / "paper-draft.md",
    ):
        assert "public-label-snapshot-decision.md" in path.read_text(encoding="utf-8")


def test_artifact_review_guide_names_required_public_commands() -> None:
    text = GUIDE.read_text(encoding="utf-8")

    for command in (
        "uv sync",
        "validation.reproduce_paper_numbers --profile smoke",
        "validation.reproduce_paper_numbers --profile paper",
        "scripts/generate_paper_figures.py --check",
        "uv run python scripts/check.py",
        "uv run python scripts/release_readiness.py",
    ):
        assert command in text


def test_artifact_review_guide_separates_private_and_public_results() -> None:
    text = GUIDE.read_text(encoding="utf-8")

    assert "What Is Not Publicly Reproducible" in text
    assert "Private-corpus rows are aggregate evidence" in text
    assert "scripts/check_validation_hygiene.py" in text
    assert "paper-claim-map.md" in text
    assert "Evidence-removal and planting boundary" in text
    assert "planted evidence can raise posteriors" in text


def test_artifact_review_guide_names_figure_package() -> None:
    text = GUIDE.read_text(encoding="utf-8")

    assert "paper-figures.md" in text
    assert "assets/paper/*.svg" in text
    assert "deterministic aggregate-safe generator" in text


def test_external_writeup_plan_names_latest_full_proof() -> None:
    text = (ROOT / "docs" / "external-writeup-plan.md").read_text(encoding="utf-8")

    assert "adversarial-perturbation-paper-20260628" in text
    assert "2026-06-28-adversarial-perturbation-paper.md" in (
        ROOT / "docs" / "artifact-review.md"
    ).read_text(encoding="utf-8")


def test_public_label_snapshot_decision_defers_real_apex_snapshot() -> None:
    text = (ROOT / "docs" / "public-label-snapshot-decision.md").read_text(encoding="utf-8")

    for required in (
        "Do not publish a frozen real-apex",
        "real target list",
        "current data-handling policy",
        "architecture review",
        "Public-list numbers are robustness checks",
        "not as\npopulation rates",
    ):
        assert required in text
