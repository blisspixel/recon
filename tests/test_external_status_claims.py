from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PUBLIC_STATUS_SURFACES = (
    ROOT / "README.md",
    ROOT / "ROADMAP.md",
    ROOT / "docs" / "README.md",
    ROOT / "docs" / "roadmap.md",
    ROOT / "docs" / "strategic-gap-audit.md",
    ROOT / "docs" / "artifact-review.md",
    ROOT / "docs" / "archive-readiness.md",
    ROOT / "docs" / "replication-runbook.md",
    ROOT / "docs" / "submission-freeze-checklist.md",
    ROOT / "docs" / "openssf-posture.md",
    ROOT / "docs" / "supply-chain.md",
)

FORBIDDEN_EXTERNAL_STATUS_CLAIMS = (
    "bestpractices.dev/projects/",
    "zenodo.org/badge",
    "doi.org/10.5281/zenodo",
    "doi minted",
    "openssf badge achieved",
    "passing best practices badge",
    "outside replication complete",
    "independently reproduced private-corpus",
    "externally reproduced private-corpus",
    "contributor diversity achieved",
)


def test_public_status_surfaces_do_not_claim_missing_external_events() -> None:
    for path in PUBLIC_STATUS_SURFACES:
        normalized = " ".join(path.read_text(encoding="utf-8").lower().split())

        for forbidden in FORBIDDEN_EXTERNAL_STATUS_CLAIMS:
            assert forbidden not in normalized, f"{path.relative_to(ROOT)} contains {forbidden!r}"
