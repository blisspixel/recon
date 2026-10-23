from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# First-party project JSON and SVG checked 2026-10-23; see openssf-posture.md.
# This permits only the actual project, while unverified external events stay blocked.
APPROVED_BADGE = (
    "[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15800/badge)]"
    "(https://www.bestpractices.dev/projects/15800)"
)
APPROVED_PROJECT_LINK = "[project 15800](https://www.bestpractices.dev/projects/15800)"
APPROVED_STATUS_LINKS = {
    "README.md": APPROVED_BADGE,
    "docs/openssf-posture.md": APPROVED_PROJECT_LINK,
}

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


def _unverified_claims(text: str, path: str) -> list[str]:
    approved = APPROVED_STATUS_LINKS.get(path)
    if approved is not None:
        text = text.replace(approved, "")
    normalized = " ".join(text.lower().split())
    return [claim for claim in FORBIDDEN_EXTERNAL_STATUS_CLAIMS if claim in normalized]


def test_public_status_surfaces_do_not_claim_missing_external_events() -> None:
    for path in PUBLIC_STATUS_SURFACES:
        relative = path.relative_to(ROOT).as_posix()
        assert _unverified_claims(path.read_text(encoding="utf-8"), relative) == [], relative


def test_best_practices_links_name_only_the_verified_project_and_keep_scorecard() -> None:
    for path, link in APPROVED_STATUS_LINKS.items():
        assert (ROOT / path).read_text(encoding="utf-8").count(link) == 1
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "[![OpenSSF Scorecard]" in readme
    posture = (ROOT / "docs/openssf-posture.md").read_text(encoding="utf-8")
    assert "Passing at 100 percent on 2026-10-23" in posture
    assert "not an independent security audit or a security guarantee" in posture


@pytest.mark.parametrize(
    "claim",
    [APPROVED_BADGE.replace("15800", "99999"), "Outside replication complete", "DOI minted", "OpenSSF badge achieved"],
)
def test_other_projects_and_unverified_events_remain_rejected(claim: str) -> None:
    assert _unverified_claims(claim, "README.md")
