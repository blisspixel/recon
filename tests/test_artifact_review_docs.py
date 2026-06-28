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


def test_artifact_review_guide_names_required_public_commands() -> None:
    text = GUIDE.read_text(encoding="utf-8")

    for command in (
        "uv sync",
        "validation.reproduce_paper_numbers --profile smoke",
        "validation.reproduce_paper_numbers --profile paper",
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
