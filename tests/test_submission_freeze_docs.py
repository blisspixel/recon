from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FREEZE = ROOT / "docs" / "submission-freeze-checklist.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_submission_freeze_checklist_is_linked_from_current_docs() -> None:
    for path in (
        ROOT / "README.md",
        ROOT / "ROADMAP.md",
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "roadmap.md",
        ROOT / "docs" / "external-writeup-plan.md",
        ROOT / "docs" / "strategic-gap-audit.md",
        ROOT / "docs" / "artifact-review.md",
        ROOT / "validation" / "README.md",
    ):
        assert "submission-freeze-checklist.md" in _read(path), path


def test_submission_freeze_checklist_names_required_gates() -> None:
    text = _read(FREEZE)

    for required in (
        "uv run python scripts/check_paper_claims.py",
        "uv run python scripts/generate_paper_figures.py --check",
        "uv run python -m validation.reproduce_paper_numbers --profile smoke",
        "uv run python -m validation.reproduce_paper_numbers --profile paper",
        "uv run python scripts/check_validation_hygiene.py",
        "uv run python scripts/check_text_hygiene.py",
        "uv run python scripts/check.py",
        "uv run python scripts/release_readiness.py --allow-dirty",
        "uv run python scripts/release_readiness.py --remote",
        "2026-06-29-scorecard-gate-claim-audit.md",
        "2026-06-30-submission-freeze-local-proof.md",
    ):
        assert required in text


def test_submission_freeze_checklist_preserves_claim_boundaries() -> None:
    normalized = " ".join(_read(FREEZE).split())

    for required in (
        "No new empirical language may enter the draft without an explicit support tier",
        "Public-list numbers are robustness checks rather than population rates",
        "M365 tenancy evidence remains corroboration rather than independent calibration",
        "does not claim ground-truth frequentist coverage",
        "Do not describe private-corpus rows as externally reproduced",
        (
            "Do not add DOI, archive-badge, OpenSSF badge, reviewed-PR, "
            "contributor diversity, or outside-replication claims"
        ),
        "Do not create `.zenodo.json`, DOI metadata, archive badges, or OpenSSF badge links as placeholders",
        "Do not publish a new PyPI or GitHub release for docs-only or tests-only work",
    ):
        assert required in normalized


def test_submission_freeze_checklist_cites_current_external_guidance() -> None:
    text = _read(FREEZE)

    assert "Checked: 2026-06-30." in text

    for url in (
        "https://www.acm.org/publications/policies/artifact-review-and-badging-current",
        "https://info.arxiv.org/help/submit/index.html",
        "https://info.arxiv.org/help/ancillary_files.html",
        "https://github.com/ossf/scorecard/blob/main/docs/checks.md",
        "https://www.bestpractices.dev/en/criteria/0",
        "https://slsa.dev/spec/v1.2/",
        "https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations",
        "https://docs.pypi.org/attestations/",
        "https://help.zenodo.org/docs/github/describe-software/citation-file/",
        "https://help.zenodo.org/docs/github/describe-software/zenodo-json/",
    ):
        assert url in text


def test_submission_freeze_checklist_does_not_claim_external_events() -> None:
    normalized = " ".join(_read(FREEZE).split()).lower()

    for forbidden in (
        "submission is complete",
        "submitted to arxiv",
        "doi minted",
        "openssf badge achieved",
        "outside replication complete",
        "externally reproduced private-corpus",
    ):
        assert forbidden not in normalized
