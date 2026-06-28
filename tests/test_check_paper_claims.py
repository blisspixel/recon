from __future__ import annotations

import shutil
from pathlib import Path

from scripts.check_paper_claims import collect_issues

ROOT = Path(__file__).resolve().parents[1]


def _copy_paper_docs(dst: Path) -> None:
    (dst / "docs").mkdir(parents=True)
    for name in (
        "paper-draft.md",
        "paper-outline.md",
        "paper-claim-map.md",
        "artifact-review.md",
        "external-writeup-plan.md",
        "roadmap.md",
        "m365-tenancy-decision.md",
        "data-handling-policy.md",
    ):
        shutil.copyfile(ROOT / "docs" / name, dst / "docs" / name)


def test_paper_claim_audit_passes_current_docs() -> None:
    assert collect_issues(ROOT) == []


def test_paper_claim_audit_rejects_missing_latest_public_proof(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    plan = tmp_path / "docs" / "external-writeup-plan.md"
    text = plan.read_text(encoding="utf-8").replace("2026-06-28-final-claim-audit.md", "")
    plan.write_text(text, encoding="utf-8")

    issues = collect_issues(tmp_path)

    assert "external-plan does not link latest public proof memo" in issues


def test_paper_claim_audit_rejects_missing_claim_map_row(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    claim_map = tmp_path / "docs" / "paper-claim-map.md"
    text = claim_map.read_text(encoding="utf-8").replace(
        "Planted evidence can move posteriors across the decision boundary",
        "Planted evidence placeholder",
    )
    claim_map.write_text(text, encoding="utf-8")

    issues = collect_issues(tmp_path)

    assert any("Planted evidence can move posteriors" in issue for issue in issues)


def test_paper_claim_audit_rejects_m365_calibration_drift(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    draft = tmp_path / "docs" / "paper-draft.md"
    text = draft.read_text(encoding="utf-8").replace(
        "M365 corroboration and Google\none-sided tenancy check",
        "M365 and Google tenancy calibrations",
    )
    draft.write_text(text, encoding="utf-8")

    issues = collect_issues(tmp_path)

    assert any("forbidden M365 calibration wording" in issue for issue in issues)


def test_paper_claim_audit_rejects_reopened_m365_blocker(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    outline = tmp_path / "docs" / "paper-outline.md"
    text = outline.read_text(encoding="utf-8").replace(
        "Final claim audit is complete",
        "Blocking open item: M365 independent-instrument check.\n\nFinal claim audit is complete",
    )
    outline.write_text(text, encoding="utf-8")

    issues = collect_issues(tmp_path)

    assert "outline still lists the M365 instrument decision as an open blocker" in issues
