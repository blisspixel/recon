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
        ROOT / "README.md",
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "artifact-review.md",
        ROOT / "docs" / "data-handling-policy.md",
        ROOT / "docs" / "external-writeup-plan.md",
        ROOT / "docs" / "paper-draft.md",
        ROOT / "docs" / "paper-claim-map.md",
        ROOT / "docs" / "roadmap.md",
    ):
        assert "public-label-snapshot-decision.md" in path.read_text(encoding="utf-8")


def test_m365_tenancy_decision_is_linked_from_research_docs() -> None:
    for path in (
        ROOT / "README.md",
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "artifact-review.md",
        ROOT / "docs" / "external-writeup-plan.md",
        ROOT / "docs" / "paper-draft.md",
        ROOT / "docs" / "paper-claim-map.md",
        ROOT / "docs" / "paper-outline.md",
        ROOT / "docs" / "roadmap.md",
        ROOT / "docs" / "statistical-assurance.md",
    ):
        assert "m365-tenancy-decision.md" in path.read_text(encoding="utf-8")


def test_artifact_review_guide_names_required_public_commands() -> None:
    text = GUIDE.read_text(encoding="utf-8")

    for command in (
        "uv sync",
        "validation.reproduce_paper_numbers --profile smoke",
        "validation.reproduce_paper_numbers --profile paper",
        "scripts/generate_paper_figures.py --check",
        "uv run python scripts/check.py",
        "uv run python scripts/release_readiness.py",
        "uv run python scripts/release_readiness.py --remote",
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
    assert "Published artifact integrity" in text
    assert "release state, not empirical paper results" in text
    assert "public Scorecard API state matches `HEAD`" in text
    assert "PyPI plus GitHub provenance verify" in text


def test_artifact_review_guide_names_figure_package() -> None:
    text = GUIDE.read_text(encoding="utf-8")

    assert "paper-figures.md" in text
    assert "assets/paper/*.svg" in text
    assert "deterministic aggregate-safe generator" in text


def test_artifact_review_guide_names_archive_boundary() -> None:
    text = GUIDE.read_text(encoding="utf-8")

    assert "archive-readiness.md" in text
    assert "does not claim a DOI" in text
    assert ".zenodo.json" in text


def test_artifact_review_guide_names_replication_boundary() -> None:
    text = " ".join(GUIDE.read_text(encoding="utf-8").split())

    assert "replication-runbook.md" in text
    assert "Outside replication status is also separate" in text
    assert "aggregate outcome notes" in text


def test_external_writeup_plan_names_latest_full_proof() -> None:
    text = (ROOT / "docs" / "external-writeup-plan.md").read_text(encoding="utf-8")

    assert "submission-freeze-paper-20260629-cycle9b" in text
    assert "2026-06-29-submission-freeze-local-proof.md" in (
        ROOT / "docs" / "artifact-review.md"
    ).read_text(encoding="utf-8")
    assert "2026-06-29-scorecard-gate-claim-audit.md" in text
    assert "adversarial-perturbation-paper-20260628" in text


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


def test_public_sampling_boundary_is_consistent_across_docs() -> None:
    docs = {
        "README.md": (ROOT / "README.md").read_text(encoding="utf-8"),
        "docs/roadmap.md": (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8"),
        "docs/external-writeup-plan.md": (ROOT / "docs" / "external-writeup-plan.md").read_text(encoding="utf-8"),
        "docs/artifact-review.md": (ROOT / "docs" / "artifact-review.md").read_text(encoding="utf-8"),
        "docs/data-handling-policy.md": (ROOT / "docs" / "data-handling-policy.md").read_text(encoding="utf-8"),
        "docs/paper-claim-map.md": (ROOT / "docs" / "paper-claim-map.md").read_text(encoding="utf-8"),
    }

    for path, text in docs.items():
        normalized = " ".join(text.split())
        assert "robustness checks" in normalized, path
        assert "population rates" in normalized, path
