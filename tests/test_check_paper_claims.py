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
    ):
        shutil.copyfile(ROOT / "docs" / name, dst / "docs" / name)


def test_paper_claim_audit_passes_current_docs() -> None:
    assert collect_issues(ROOT) == []


def test_paper_claim_audit_rejects_missing_latest_public_proof(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    plan = tmp_path / "docs" / "external-writeup-plan.md"
    text = plan.read_text(encoding="utf-8").replace("2026-06-28-adversarial-perturbation-paper.md", "")
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
