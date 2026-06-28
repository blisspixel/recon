from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAIM_MAP = ROOT / "docs" / "paper-claim-map.md"


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
        "Exact inference",
        "DMARC-held-out residual",
        "M365 tenancy",
        "Split conformal coverage",
        "Entropy reduction",
        "Public artifacts exclude target identifiers",
    ):
        assert claim in text
