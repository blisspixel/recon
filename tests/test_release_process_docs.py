from __future__ import annotations

import tomllib
from pathlib import Path

from scripts import release_readiness

ROOT = Path(__file__).resolve().parents[1]


def _normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_release_process_docs_include_supply_chain_recipe_guard() -> None:
    text = _normalized(ROOT / "docs" / "release-process.md")

    for required in (
        "supply-chain consumer-verification recipe",
        "README usage anchors, supply-chain recipe anchors, and repository hygiene",
        "docs/supply-chain.md",
        "consumer verification quick path",
        "current version and release asset names",
        "After publishing the current version from the exact checked-out tag",
    ):
        assert required in text


def test_reviewer_and_loop_docs_name_supply_chain_recipe_freshness() -> None:
    for path in (
        ROOT / "docs" / "artifact-review.md",
        ROOT / "docs" / "agentic-balance.md",
    ):
        assert "supply-chain recipe freshness" in _normalized(path), path


def test_release_yank_guidance_uses_supported_pypi_flow() -> None:
    text = _normalized(ROOT / "docs" / "release-process.md")

    assert "Twine does not provide a yank command" in text
    assert "PyPI project management UI" in text
    assert "twine yank" not in text


def test_partial_release_recovery_is_exact_and_evidence_preserving() -> None:
    text = _normalized(ROOT / "docs" / "release-process.md")

    for required in (
        "Recovery after partial publication",
        'gh run rerun "${RUN_ID}" --failed',
        'gh run watch "${RUN_ID}" --exit-status',
        "scripts/release_readiness.py --remote",
        "original `GITHUB_SHA` and `GITHUB_REF`",
        "Never manually rebuild or replace evidence",
        "before `gh release upload --clobber` can execute",
        'test "$(git branch --show-current)" = "main"',
        'test -z "$(git status --porcelain --untracked-files=normal)"',
        "--json databaseId,headSha",
        'test "${RUN_HEAD_SHA}" = "${HEAD_SHA}"',
        "remote tag against the original workflow SHA",
        "immutable release",
    ):
        assert required in text


def test_consumer_verification_acquires_exact_tag_and_attests_sbom() -> None:
    text = _normalized(ROOT / "docs" / "supply-chain.md")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]

    for required in (
        f"git clone --branch v{version} --single-branch",
        'ATTESTATION_ARTIFACTS+=("${EVIDENCE_DIR}/recon-tool-${VERSION}.cdx.json")',
        "$AttestationArtifacts += $Sbom",
        "Failure and recovery map",
        "valid SBOM",
    ):
        assert required in text


def test_consumer_recipe_matches_exact_legacy_attestation_exceptions() -> None:
    text = (ROOT / "docs" / "supply-chain.md").read_text(encoding="utf-8")

    for version, digest in release_readiness._LEGACY_SBOM_ATTESTATION_EXCEPTIONS.items():
        assert f'if [ "${{VERSION}}" = "{version}" ]; then' in text
        assert f'if ($Version -eq "{version}")' in text
        assert f"LEGACY_SBOM_ATTESTATION_SHA={digest}" in text
        assert f'$LegacySbomAttestationSha = "{digest}"' in text
