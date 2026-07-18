from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "docs" / "strategic-gap-audit.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_strategic_gap_audit_is_linked_from_reader_docs() -> None:
    for path in (
        ROOT / "README.md",
        ROOT / "ROADMAP.md",
        ROOT / "docs" / "README.md",
        ROOT / "docs" / "roadmap.md",
        ROOT / "docs" / "external-writeup-plan.md",
    ):
        assert "strategic-gap-audit.md" in _read(path), path


def test_strategic_gap_audit_prioritizes_product_quality_without_runtime_expansion() -> None:
    text = " ".join(_read(AUDIT).split())

    for required in (
        "The highest-value work is not runtime expansion",
        "evidence semantics, measured utility, catalog quality",
        "completed MCP candidate matrix",
        "aggregate-safe product-quality baseline",
        "does not add CLI, MCP, JSON, fingerprint, schema, dependency, or network behavior",
        "Runtime expansion, broad catalog growth, stable-surface promotion, "
        "and public real-data release remain blocked",
    ):
        assert required in text


def test_strategic_gap_audit_names_real_remaining_gaps_without_fake_progress() -> None:
    text = " ".join(_read(AUDIT).split())

    for required in (
        "Evidence-semantic integrity",
        "MCP v2 compatibility",
        "Measured product utility",
        "Catalog quality and freshness",
        "Latency and degradation contract",
        "OpenSSF Best Practices Badge",
        "manual answer queue",
        "openssf-badge-readiness.md",
        "Reviewed PR signal",
        "Artifact archive and DOI",
        "archive-readiness.md",
        "archive path decision packet",
        "Independent public replication",
        "handoff packet",
        "replication-runbook.md",
        "Pre-submission claim freeze",
        "remote release readiness now verifies Scorecard API freshness plus PyPI and GitHub provenance",
        "consumer verification quick path",
        "Future dataset release model",
        "Do not add a placeholder badge",
        "Do not manufacture review history or contributor diversity",
    ):
        assert required in text


def test_strategic_gap_audit_preserves_private_data_and_release_boundaries() -> None:
    text = " ".join(_read(AUDIT).split())

    for required in (
        "No private corpus, real target list, per-domain result rows, or tenant IDs are committed or published",
        "Remote release readiness passed for the published main branch",
        "public Scorecard API freshness and code-owned control scores",
        "public Scorecard API passed on the published main branch",
        "must not describe a version as published until its local and remote release gates pass",
        "requires fresh local and remote evidence before publication",
        "GitHub Release wheel, sdist, SBOM, and attestation export assets",
        "verifies PyPI provenance for the release wheel and sdist",
        "current GitHub provenance check for the completed SBOM",
        "historical evidence predates that subject expansion",
        "Documentation and proof-memo refreshes do not require a new package release",
        "Release when package behavior, public package metadata, or release artifacts change",
        "release state and provenance aligned",
        "Do not commit apex lists, organization names, tenant IDs, per-domain rows, or unsuppressed small strata",
    ):
        assert required in text

    for stale in (
        "Current local hardening commits are ahead of the pushed branch",
        "The last published remote release-readiness pass covered the pushed",
    ):
        assert stale not in text


def test_strategic_gap_audit_cites_current_external_standards() -> None:
    text = _read(AUDIT)

    assert "Checked: 2026-07-17." in text

    for url in (
        "https://www.acm.org/publications/policies/artifact-review-and-badging-current",
        "https://github.com/ossf/scorecard/blob/main/docs/checks.md",
        "https://www.bestpractices.dev/en/criteria/0",
        "https://slsa.dev/spec/v1.2/",
        "https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations",
        "https://docs.pypi.org/trusted-publishers/",
        "https://docs.pypi.org/attestations/",
        "https://help.zenodo.org/docs/github/describe-software/citation-file/",
        "https://help.zenodo.org/docs/github/describe-software/zenodo-json/",
        "https://arxiv.org/abs/2605.06508",
        "https://modelcontextprotocol.io/development/roadmap",
        "https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/about-issue-and-pull-request-templates",
    ):
        assert url in text
