from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "replication-runbook.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_replication_runbook_is_linked_from_current_research_docs() -> None:
    for path in (
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "artifact-review.md",
        ROOT / "docs" / "external-writeup-plan.md",
        ROOT / "docs" / "roadmap.md",
        ROOT / "docs" / "strategic-gap-audit.md",
    ):
        assert "replication-runbook.md" in _read(path), path


def test_replication_runbook_names_public_commands_and_preconditions() -> None:
    text = " ".join(_read(RUNBOOK).split())

    for required in (
        "does not claim that an outside replication pass has occurred",
        "GitHub CI, Secrets scan, and Scorecard pass",
        "uv run python scripts/check.py",
        "uv run python scripts/release_readiness.py --remote",
        "validation.reproduce_paper_numbers --profile smoke",
        "validation.reproduce_paper_numbers --profile paper",
        "scripts/generate_paper_figures.py --check",
        "outside-replication-smoke",
        "outside-replication-paper",
    ):
        assert required in text


def test_replication_runbook_defines_reviewer_handoff_packet() -> None:
    text = " ".join(_read(RUNBOOK).split())

    for required in (
        "Reviewer Handoff Packet",
        "Repository URL plus exact commit SHA or release tag",
        "Public-artifact functional replication only",
        "No private corpus, target list, real-domain row, or credential",
        "OS family, shell family, Python version",
        "final local gate test count, skipped count, and coverage percentage",
        "Keep raw logs local until personal paths",
        "Raw logs, screenshots, and machine-local paths are not requested by default",
        "stop and report the first blocking environment error",
        "a locally patched run is a different experiment",
    ):
        assert required in text


def test_replication_runbook_preserves_private_data_boundary() -> None:
    text = " ".join(_read(RUNBOOK).split())

    for required in (
        "not a request to validate private-corpus rows",
        "private-corpus rows remain aggregate evidence",
        "Outcome Record Discipline",
        "Record failures as useful environment feedback",
        "Keep raw logs local unless they have been reviewed",
        "Do not include screenshots",
        "machine-local absolute paths",
        "Do not send private corpora",
        "Do not ask a reviewer to query real organizations",
        "per-domain outputs",
        "tenant IDs",
        "unsuppressed small strata",
    ):
        assert required in text


def test_replication_runbook_blocks_premature_validation_claims() -> None:
    text = " ".join(_read(RUNBOOK).split())

    for required in (
        "acceptable only after that pass happens",
        "Private-corpus rows were independently reproduced",
        "is not acceptable",
        "release-state evidence, not empirical result validation",
        "Results validated",
        "only to rows the reviewer actually reran",
    ):
        assert required in text


def test_replication_runbook_cites_current_artifact_sources() -> None:
    text = _read(RUNBOOK)

    for required in (
        "https://www.acm.org/publications/policies/artifact-review-and-badging-current",
        "artifact-review.md",
        "2026-06-29-submission-freeze-local-proof.md",
        "2026-06-29-scorecard-gate-claim-audit.md",
        "archive-readiness.md",
        "https://arxiv.org/abs/2605.06508",
    ):
        assert required in text
