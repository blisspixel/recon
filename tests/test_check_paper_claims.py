from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts.check_paper_claims import collect_issues

ROOT = Path(__file__).resolve().parents[1]


def _copy_paper_docs(dst: Path) -> None:
    (dst / "docs").mkdir(parents=True)
    (dst / "validation").mkdir(parents=True)
    for name in ("README.md", "ROADMAP.md"):
        shutil.copyfile(ROOT / name, dst / name)
    for name in (
        "README.md",
        "paper-draft.md",
        "paper-outline.md",
        "paper-claim-map.md",
        "artifact-review.md",
        "submission-freeze-checklist.md",
        "archive-readiness.md",
        "replication-runbook.md",
        "external-writeup-plan.md",
        "roadmap.md",
        "strategic-gap-audit.md",
        "m365-tenancy-decision.md",
        "data-handling-policy.md",
    ):
        shutil.copyfile(ROOT / "docs" / name, dst / "docs" / name)
    shutil.copyfile(ROOT / "validation" / "README.md", dst / "validation" / "README.md")


def test_paper_claim_audit_passes_current_docs() -> None:
    assert collect_issues(ROOT) == []


def test_paper_claim_audit_rejects_missing_latest_public_proof(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    plan = tmp_path / "docs" / "external-writeup-plan.md"
    text = plan.read_text(encoding="utf-8").replace("2026-06-30-submission-freeze-local-proof.md", "")
    plan.write_text(text, encoding="utf-8")

    issues = collect_issues(tmp_path)

    assert "external-plan does not link latest public proof memo" in issues


def test_paper_claim_audit_rejects_root_docs_without_latest_public_proof(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    readme = tmp_path / "README.md"
    text = readme.read_text(encoding="utf-8").replace("2026-06-30-submission-freeze-local-proof.md", "")
    readme.write_text(text, encoding="utf-8")

    issues = collect_issues(tmp_path)

    assert "readme-root does not link latest public proof memo" in issues


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
    text = draft.read_text(encoding="utf-8")
    original = "M365 corroboration, Google one-sided tenancy check"
    assert original in text
    text = text.replace(original, "M365 and Google tenancy calibrations")
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


@pytest.mark.parametrize(
    ("phrase", "category"),
    [
        ("The reported credible interval widens on hardened targets.", "band widening overclaim"),
        (
            "Hiding any signal can only move a claim toward its all-absent baseline.",
            "suppression baseline overclaim",
        ),
        ("One carries a clean two-class external reference.", "tier-4 calibration overclaim"),
        (
            "We report a conformal set beside the Bayesian interval.",
            "conformal scope overclaim",
        ),
        (
            "The Bayesian network is verified exhaustively against its full joint.",
            "global exhaustiveness overclaim",
        ),
        (
            "One planted record can force a confident false positive.",
            "forced false positive overclaim",
        ),
        (
            "Every empirical claim is reproducible from the artifact.",
            "result reproducibility overclaim",
        ),
        (
            "This construction makes a predictor disjoint from its label.",
            "training-disjoint evaluation overclaim",
        ),
        (
            "The layer ablation is drawn from the model's own generative process.",
            "synthetic generator overclaim",
        ),
        (
            "The selected-sample marginal coverage is 0.99.",
            "conformal training scope overclaim",
        ),
    ],
)
def test_paper_claim_audit_rejects_statistical_overclaims(
    tmp_path: Path,
    phrase: str,
    category: str,
) -> None:
    _copy_paper_docs(tmp_path)
    draft = tmp_path / "docs" / "paper-draft.md"
    draft.write_text(f"{draft.read_text(encoding='utf-8')}\n{phrase}\n", encoding="utf-8")

    issues = collect_issues(tmp_path)

    assert any(category in issue for issue in issues)


def test_paper_claim_audit_rejects_overclaim_across_markdown_wrap(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    draft = tmp_path / "docs" / "paper-draft.md"
    draft.write_text(
        f"{draft.read_text(encoding='utf-8')}\nEvery empirical claim is\n"
        "reproducible from the artifact.\n",
        encoding="utf-8",
    )

    issues = collect_issues(tmp_path)

    assert any("result reproducibility overclaim" in issue for issue in issues)


def test_paper_claim_audit_rejects_wrapped_m365_calibration_wording(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    outline = tmp_path / "docs" / "paper-outline.md"
    outline.write_text(
        f"{outline.read_text(encoding='utf-8')}\nThe score is calibrated against Microsoft's\n"
        "own endpoint attestation.\n",
        encoding="utf-8",
    )

    issues = collect_issues(tmp_path)

    assert any("forbidden M365 calibration wording" in issue for issue in issues)


def test_paper_claim_audit_requires_conformal_band_boundary(tmp_path: Path) -> None:
    _copy_paper_docs(tmp_path)
    draft = tmp_path / "docs" / "paper-draft.md"
    text = draft.read_text(encoding="utf-8").replace(
        "does not validate the Bayesian uncertainty band",
        "is reported with the Bayesian uncertainty band",
    )
    draft.write_text(text, encoding="utf-8")

    issues = collect_issues(tmp_path)

    assert any("missing current statistical boundary" in issue for issue in issues)
