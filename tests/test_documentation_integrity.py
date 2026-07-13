"""Regression checks for current maintainer and architecture documentation."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_historical_commit_references_resolve_to_corrected_ids() -> None:
    security = _read("docs/security-audit-resolutions.md")
    roadmap = _read("docs/roadmap-history.md")
    combined = "\n".join((security, roadmap))

    for invalid in (
        "f9b3415",
        "6abbae1",
        "722220f",
        "f8b12dd",
        "b81a701",
        "ec14bdc",
        "cca815c",
    ):
        assert f"`{invalid}`" not in combined

    for corrected in (
        "3e09a42",
        "e3c5965",
        "332534d",
        "07c2bb4",
        "8abc036",
        "8799840",
        "c116abf",
    ):
        assert f"`{corrected}`" in combined


def test_backticked_commit_receipts_exist() -> None:
    paths = [
        ROOT / "CHANGELOG.md",
        *(ROOT / "docs").rglob("*.md"),
        *(ROOT / "validation").rglob("*.md"),
    ]
    hashes = {
        match.group(1)
        for path in paths
        for match in re.finditer(r"`([0-9a-f]{7,40})`", path.read_text(encoding="utf-8"))
    }
    missing = []
    for commit_hash in sorted(hashes):
        result = subprocess.run(  # noqa: S603 - validated hex receipt from tracked docs
            ["git", "cat-file", "-e", f"{commit_hash}^{{commit}}"],  # noqa: S607
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            missing.append(commit_hash)

    assert missing == []


def test_active_contributor_paths_use_src_layout() -> None:
    contributing = _read("CONTRIBUTING.md")
    validation = _read("validation/README.md")

    assert re.search(r"(?<!src/)recon_tool/", contributing) is None
    assert re.search(r"(?<!src/)recon_tool/", validation) is None

    for filename in (
        "ai.yaml",
        "crm-marketing.yaml",
        "data-analytics.yaml",
        "discovered-signals.yaml",
        "email.yaml",
        "infrastructure.yaml",
        "productivity.yaml",
        "security.yaml",
        "surface.yaml",
        "verifications.yaml",
        "verticals.yaml",
    ):
        assert filename in contributing


def test_security_and_maintainer_docs_name_current_runtime_surfaces() -> None:
    security = _read("docs/security.md")
    resolutions = _read("docs/security-audit-resolutions.md")
    loop = _read("docs/maintainer-loop-runbook.md")

    for required in (
        "src/recon_tool/data/fingerprints.generated.json",
        "src/recon_tool/server/app.py",
        "blocking `pip-audit` gates",
        "MTA-STS",
        "explicit opt-in direct probes",
    ):
        assert required in security

    assert ".agent/maintainer-loop-state.json" in loop
    assert "validation/local/maintainer-loop-state.json" not in loop
    for receipt in (
        "src/recon_tool/sources/dns_tables.py::is_public_dns_name",
        "src/recon_tool/sources/dns.py::_resolve_cname_chain",
        "src/recon_tool/sources/dns_infra.py::detect_m365_cnames",
    ):
        assert receipt in resolutions


def test_traceability_records_current_mutation_gate() -> None:
    traceability = _read("docs/traceability-matrix.md")

    for required in (
        "Round 6",
        "91.35%",
        "655 killed",
        "62 survivors of 717",
        "88% floor",
    ):
        assert required in traceability

    assert "102 survivors of 1,083" not in traceability


def test_historical_v18_summary_does_not_link_unpublished_raw_results() -> None:
    summary = _read("validation/v1.8-validation-summary.md")
    normalized = " ".join(summary.split())

    for unpublished in (
        "v1.8-validation-results.json",
        "v1.8-validation-results-v2.json",
    ):
        assert unpublished not in summary

    for required in (
        "intentionally kept private",
        "cannot be independently reproduced from the public checkout",
        "does not reproduce this historical cohort",
    ):
        assert required in normalized


def test_math_docs_distinguish_semantic_baseline_from_current_review() -> None:
    for path in ("docs/correlation.md", "docs/statistical-assurance.md"):
        text = _read(path)
        assert "Semantic baseline established for recon v2.4.0" in text
        assert "Reviewed against v2.5.8 on\n2026-07-13" in text
