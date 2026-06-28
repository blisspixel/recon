from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAIM_MAP = ROOT / "docs" / "paper-claim-map.md"
PAPER_DRAFT = ROOT / "docs" / "paper-draft.md"


def test_paper_claim_map_is_linked_from_research_docs() -> None:
    required_links = {
        ROOT / "docs" / "README.md": "paper-claim-map.md",
        ROOT / "docs" / "external-writeup-plan.md": "paper-claim-map.md",
        ROOT / "docs" / "paper-outline.md": "paper-claim-map.md",
        ROOT / "docs" / "paper-draft.md": "paper-claim-map.md",
        ROOT / "docs" / "roadmap.md": "paper-claim-map.md",
    }

    for path, link in required_links.items():
        assert link in path.read_text(encoding="utf-8")


def test_claim_map_covers_required_evidence_tiers_and_gates() -> None:
    text = CLAIM_MAP.read_text(encoding="utf-8")

    for required in (
        "Invariant",
        "Public proof harness",
        "Public validation memo",
        "Aggregate-only private memo",
        "Requires further evidence",
        "validation.reproduce_paper_numbers",
        "scripts/check.py",
        "scripts/release_readiness.py --allow-dirty",
    ):
        assert required in text


def test_claim_map_names_load_bearing_paper_claims() -> None:
    text = CLAIM_MAP.read_text(encoding="utf-8")

    for claim in (
        "Suppression monotonicity",
        "Planted evidence",
        "Exact inference",
        "DMARC-held-out residual",
        "residual collapse",
        "M365 tenancy",
        "Split conformal coverage",
        "ECE estimator uncertainty",
        "Entropy reduction",
        "2026-06-28-full-corpus-calibration-refresh.md",
        "public-list-calibration.md",
        "Public artifacts exclude target identifiers",
    ):
        assert claim in text


def test_paper_draft_uses_current_disclosure_reviewed_calibration_numbers() -> None:
    text = PAPER_DRAFT.read_text(encoding="utf-8")

    for stale in (
        "run 2026-06-15",
        "n=4,284",
        "n=5,182",
        "ECE 0.339",
        "ECE 0.045",
        "agreement 0.221",
        "validation/2026-06-23-full-corpus-calibration.md",
        "ECE 0.373",
        "ECE 0.048",
        "n=2,905",
        "n=3,309",
        "one-sided recall 0.58",
    ):
        assert stale not in text

    for current in (
        "validation/2026-06-28-full-corpus-calibration-refresh.md",
        "fixed-bin ECE 0.3747",
        "equal-mass ECE 0.3263",
        "fixed-bin ECE 0.0471",
        "equal-mass ECE 0.0440",
        "n=2,906",
        "n=3,296",
        "one-sided recall 0.3636",
    ):
        assert current in text


def test_paper_draft_diagnoses_dmarc_residual_collapse_without_overclaiming() -> None:
    text = "\n".join(
        (
            PAPER_DRAFT.read_text(encoding="utf-8"),
            CLAIM_MAP.read_text(encoding="utf-8"),
            (ROOT / "docs" / "paper-outline.md").read_text(encoding="utf-8"),
        )
    )

    for required in (
        "MTA-STS",
        "strict SPF",
        "too rare",
        "too weak",
        "causal proof",
        "src/recon_tool/data/bayesian_network.yaml",
    ):
        assert required in text


def test_paper_discussion_and_conclusion_preserve_final_evidence_tiers() -> None:
    text = " ".join(
        (
            PAPER_DRAFT.read_text(encoding="utf-8"),
            CLAIM_MAP.read_text(encoding="utf-8"),
            (ROOT / "docs" / "external-writeup-plan.md").read_text(encoding="utf-8"),
        )
    ).replace("\n", " ")

    for required in (
        "no clean independent calibration result",
        "DMARC-held-out residual is the clean",
        "disjoint-predictor attempt and it fails",
        "channel-split corroboration",
        "Google Workspace remains one-sided recall",
        "not a broadly calibrated truth oracle",
        "do not claim broad calibration",
    ):
        assert required in text

    for forbidden in (
        "recon is a broadly calibrated classifier",
        "has a clean independent calibration result today",
    ):
        assert forbidden not in text


def test_paper_submission_state_records_final_claim_audit_closure() -> None:
    draft = PAPER_DRAFT.read_text(encoding="utf-8")
    outline = (ROOT / "docs" / "paper-outline.md").read_text(encoding="utf-8")
    combined = "\n".join((draft, outline))

    for required in (
        "public probability-sampling path is",
        "Public-list numbers remain robustness checks",
        "M365 independent-instrument decision is closed",
        "m365-tenancy-decision.md",
        "Final claim audit is complete",
        "figure drift check",
        "full public proof",
        "2026-06-28-final-claim-audit.md",
    ):
        assert required in combined

    for vague in (
        "Blocking open item",
        "Minimum closure",
        "Stratified public probability-sampling protocol",
        "Adversarial planting and stripping harness",
        "mark unresolved empirical cells as pending",
        "use the committed figure package during the final writing pass",
        "Keep the posture-stratified and per-vertical claim-map rows synchronized",
        "| M365 independent-instrument check |",
        "M365 and Google tenancy calibrations",
    ):
        assert vague not in combined

    for closed in (
        "Adversarial add/remove perturbation",
        "774 paired add/remove cases",
        "planted-evidence movement",
    ):
        assert closed in combined
