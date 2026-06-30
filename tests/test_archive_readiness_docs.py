from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "docs" / "archive-readiness.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _active_citation_lines() -> list[str]:
    return [
        line.strip()
        for line in _read(ROOT / "CITATION.cff").splitlines()
        if not line.lstrip().startswith("#")
    ]


def test_archive_readiness_is_linked_from_current_research_docs() -> None:
    for path in (
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "artifact-review.md",
        ROOT / "docs" / "external-writeup-plan.md",
        ROOT / "docs" / "roadmap.md",
        ROOT / "docs" / "strategic-gap-audit.md",
    ):
        assert "archive-readiness.md" in _read(path), path


def test_archive_readiness_preserves_no_premature_archive_policy() -> None:
    text = " ".join(_read(ARCHIVE).split())

    for required in (
        "Do not add `.zenodo.json` yet",
        "Do not add DOI language yet",
        "Use `CITATION.cff` as the public citation metadata source",
        "Metadata Decision Discipline",
        "Archive metadata changes are release-policy changes",
        "Do not add root archive metadata files in preparatory commits",
        "Do not add a `preferred-citation` block",
        "After a real archive exists",
        "a policy choice, not a harmless metadata addition",
        "No `.zenodo.json` until an archive policy is chosen",
        "No DOI field or badge claim until the archived object exists",
    ):
        assert required in text


def test_archive_readiness_defines_archive_path_decision_packet() -> None:
    text = " ".join(_read(ARCHIVE).split())

    for required in (
        "Archive Path Decision Packet",
        "Exact commit SHA, release tag, and package version",
        "Zenodo GitHub integration, venue supplement, or another reviewed repository",
        "Whether `CITATION.cff` remains sufficient or `.zenodo.json` is needed",
        "`grants`, `communities`, `access_right`, `related_identifiers`, or contributor roles",
        "Only the real DOI state may be cited in public docs",
        "Claim audit, public proof profile stamps, local gate, remote readiness",
        "outside-replication status",
        "no private corpora, real target lists, tenant IDs, per-domain rows",
        "Default to `CITATION.cff` plus the GitHub release",
        "`.zenodo.json` overrides `CITATION.cff`",
        "name the actual release object rather than a future intended deposit",
    ):
        assert required in text


def test_archive_readiness_names_freeze_and_security_review_gates() -> None:
    text = " ".join(_read(ARCHIVE).split())

    for required in (
        "Freeze the paper package against",
        "Rerun the public smoke and full paper proof profiles",
        "uv run python scripts/check.py",
        "uv run python scripts/release_readiness.py --remote",
        "Security Review",
        "static, typing, coverage, validation, text, and release gates",
        "dependency audit and workflow-pin checks",
        "context-aware security review",
    ):
        assert required in text


def test_archive_readiness_cites_current_archive_sources() -> None:
    text = _read(ARCHIVE)

    for url in (
        "https://docs.github.com/repositories/archiving-a-github-repository/referencing-and-citing-content",
        "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-citation-files",
        "https://help.zenodo.org/docs/github/describe-software/citation-file/",
        "https://help.zenodo.org/docs/github/describe-software/zenodo-json/",
        "https://www.acm.org/publications/policies/artifact-review-and-badging-current",
        "https://arxiv.org/abs/2605.06508",
    ):
        assert url in text


def test_no_archive_metadata_is_claimed_before_policy_choice() -> None:
    assert not (ROOT / ".zenodo.json").exists()
    assert not (ROOT / "zenodo.json").exists()

    active_citation = "\n".join(_active_citation_lines()).lower()
    assert "doi:" not in active_citation
    assert "identifiers:" not in active_citation
    assert "preferred-citation:" not in active_citation
