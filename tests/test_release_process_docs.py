from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from scripts import release_readiness

ROOT = Path(__file__).resolve().parents[1]


def _normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _recovery_block() -> str:
    text = (ROOT / "docs" / "release-process.md").read_text(encoding="utf-8")
    section = text.split("### Recovery after partial publication", 1)[1].split("## Pre-release checklist", 1)[0]
    blocks = re.findall(r"```bash\n(.*?)\n```", section, flags=re.DOTALL)
    assert len(blocks) == 1
    return blocks[0]


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
        "git branch --show-current",
        'git status --porcelain --untracked-files=normal',
        "--json databaseId,headSha",
        '"${RUN_HEAD_SHA}" = "${HEAD_SHA}"',
        "remote tag against the original workflow SHA",
        "immutable release",
    ):
        assert required in text

    block = _recovery_block()
    assert block.startswith("set -euo pipefail\n")
    assert "recovery_fail" in block
    assert "PASS: release recovery preconditions hold" in block
    assert (
        'TAG_SHA="$(git rev-list -n 1 "refs/tags/v${VERSION}" 2>/dev/null)" '
        '|| recovery_fail "git to resolve the local tag v${VERSION}"'
    ) in block
    assert 'git rev-list -n 1 "refs/tags/v${VERSION}" 2>/dev/null || true' not in block


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX CI executes the Bash recovery contract")
@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("branch", "clean main branch"),
        ("dirty", "clean worktree"),
        ("status_error", "inspect the worktree"),
        ("tag", "local tag"),
        ("tag_error_output", "git to resolve the local tag"),
        ("run_error_output", "GitHub CLI to list"),
        ("missing_run", "Release workflow run"),
        ("run_sha", "selected Release run"),
    ],
)
def test_partial_release_recovery_stops_before_rerun(
    tmp_path: Path,
    scenario: str,
    message: str,
) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    trace = tmp_path / "trace.txt"
    scripts = {
        "uv": """#!/usr/bin/env bash
if [ "${3:-}" = "-c" ]; then
  printf '2.6.3\\n'
else
  printf 'readiness\\n' >> "${TRACE}"
fi
""",
        "git": """#!/usr/bin/env bash
case "$1 ${2:-}" in
  'branch --show-current') [ "${SCENARIO}" = branch ] && printf 'topic\\n' || printf 'main\\n' ;;
  'status --porcelain')
    [ "${SCENARIO}" = status_error ] && exit 2
    [ "${SCENARIO}" = dirty ] && printf ' M tracked-file\\n' || true
    ;;
  'rev-parse HEAD') printf 'head-sha\\n' ;;
  'rev-list -n')
    if [ "${SCENARIO}" = tag_error_output ]; then printf 'head-sha\\n'; exit 9; fi
    [ "${SCENARIO}" = tag ] && printf 'other-sha\\n' || printf 'head-sha\\n'
    ;;
  *) exit 2 ;;
esac
""",
        "gh": """#!/usr/bin/env bash
case "$1 ${2:-}" in
  'run list')
    if [ "${SCENARIO}" = run_error_output ]; then printf '42\thead-sha\n'; exit 9; fi
    [ "${SCENARIO}" = missing_run ] && exit 0
    [ "${SCENARIO}" = run_sha ] && printf '42\\tother-sha\\n' || printf '42\\thead-sha\\n'
    ;;
  'run view') printf 'view\\n' >> "${TRACE}" ;;
  'run rerun') printf 'rerun\\n' >> "${TRACE}" ;;
  'run watch') printf 'watch\\n' >> "${TRACE}" ;;
  *) exit 2 ;;
esac
""",
    }
    for name, content in scripts.items():
        path = fake_bin / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    result = subprocess.run(  # noqa: S603
        [bash, "-c", _recovery_block()],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "SCENARIO": scenario,
            "TRACE": str(trace),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert "rerun" not in (trace.read_text(encoding="utf-8") if trace.exists() else "")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX CI executes the Bash recovery contract")
def test_partial_release_recovery_valid_path_reaches_readiness(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    trace = tmp_path / "trace.txt"
    scripts = {
        "uv": """#!/usr/bin/env bash
if [ "${3:-}" = "-c" ]; then printf '2.6.3\\n'; else printf 'readiness\\n' >> "${TRACE}"; fi
""",
        "git": """#!/usr/bin/env bash
case "$1 ${2:-}" in
  'branch --show-current') printf 'main\\n' ;;
  'status --porcelain') true ;;
  'rev-parse HEAD'|'rev-list -n') printf 'head-sha\\n' ;;
  *) exit 2 ;;
esac
""",
        "gh": """#!/usr/bin/env bash
case "$1 ${2:-}" in
  'run list') printf '42\\thead-sha\\n' ;;
  'run view') printf 'view\\n' >> "${TRACE}" ;;
  'run rerun') printf 'rerun\\n' >> "${TRACE}" ;;
  'run watch') printf 'watch\\n' >> "${TRACE}" ;;
  *) exit 2 ;;
esac
""",
    }
    for name, content in scripts.items():
        path = fake_bin / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    result = subprocess.run(  # noqa: S603
        [bash, "-c", _recovery_block()],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "SCENARIO": "ok",
            "TRACE": str(trace),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "PASS: release recovery preconditions hold for run 42 at head-sha" in result.stdout
    assert trace.read_text(encoding="utf-8").splitlines() == ["view", "rerun", "watch", "readiness"]


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
