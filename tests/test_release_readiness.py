"""Release-readiness gate regressions."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scripts import release_readiness


def _cp(cmd: list[str], returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)


def _write_file(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_minimal_root(root: Path, version: str = "2.2.8") -> None:
    _write_file(root, "pyproject.toml", f'[project]\nname = "recon-tool"\nversion = "{version}"\n')
    _write_file(root, "src/recon_tool/__init__.py", f'_FALLBACK_VERSION = "{version}"\n')
    for relative in (
        "scripts/check.py",
        "scripts/release.py",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
    ):
        _write_file(root, relative, "pytest tests/ --cov=src/recon_tool --cov-branch --cov-fail-under=82\n")
    _write_file(root, "docs/roadmap.md", f"# Roadmap\n\n> **Status:** v{version} is current.\n")
    _write_file(
        root,
        "README.md",
        "\n".join(
            [
                "recon contoso.com",
                "recon batch domains.txt --json",
                "recon mcp install --client=",
                "Examples use [Microsoft's fictional company names]",
                "python scripts/check.py",
                "no AI attribution",
                "no em-dashes or emojis",
            ]
        ),
    )
    _write_file(root, "packaging/homebrew/recon.rb", f'url "https://example.test/recon_tool-{version}.tar.gz"\n')
    _write_file(root, "CHANGELOG.md", f"# Changelog\n\n## [{version}] - 2026-06-26\n")
    _write_file(root, "CITATION.cff", f'version: {version}\ndate-released: "2026-06-26"\n')


def _happy_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    if cmd == ["git", "branch", "--show-current"]:
        return _cp(cmd, stdout="main\n")
    if cmd == ["git", "status", "--porcelain"]:
        return _cp(cmd)
    if cmd == ["git", "status", "--short", "--branch"]:
        return _cp(cmd, stdout="## main...origin/main\n")
    if cmd == ["uv", "lock", "--check"]:
        return _cp(cmd, stdout="Resolved 1 package\n")
    if cmd == ["git", "ls-files"]:
        return _cp(cmd, stdout="README.md\nsrc/recon_tool/__init__.py\n")
    if cmd == ["git", "log", "-1", "--pretty=%B"]:
        return _cp(cmd, stdout="Add release readiness gate\n")
    raise AssertionError(f"unexpected command: {cmd}")


def test_collect_checks_passes_local_happy_path(tmp_path: Path) -> None:
    _write_minimal_root(tmp_path)

    checks = release_readiness.collect_checks(tmp_path, runner=_happy_runner)

    assert not release_readiness._has_failure(checks)
    statuses = {check.name: check.status for check in checks}
    assert statuses["remote CI"] == "skip"
    assert statuses["coverage gates"] == "pass"
    assert statuses["commit hygiene"] == "pass"


def test_version_consistency_fails_on_mismatch(tmp_path: Path) -> None:
    _write_minimal_root(tmp_path, version="2.2.8")
    _write_file(tmp_path, "src/recon_tool/__init__.py", '_FALLBACK_VERSION = "2.2.7"\n')

    check = release_readiness._check_version_consistency(tmp_path)

    assert check.status == "fail"
    assert "pyproject.toml=2.2.8" in check.detail


def test_coverage_gate_rejects_stale_src_layout_target(tmp_path: Path) -> None:
    _write_minimal_root(tmp_path)
    _write_file(tmp_path, "scripts/check.py", "pytest tests/ --cov=recon_tool --cov-fail-under=82\n")

    check = release_readiness._check_coverage_targets(tmp_path)

    assert check.status == "fail"
    assert "stale --cov=recon_tool" in check.detail


def test_readme_usage_rejects_enterprise_contact_line(tmp_path: Path) -> None:
    _write_minimal_root(tmp_path)
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    retired_contact = "nick" + "@pueo.io"
    readme += f"\nFor commercial or enterprise use, contact Nick Seal ({retired_contact}).\n"
    _write_file(tmp_path, "README.md", readme)

    check = release_readiness._check_readme_usage(tmp_path)

    assert check.status == "fail"
    assert "enterprise use, contact" in check.detail
    assert "Apache 2.0 only" in check.action


def test_readme_usage_accepts_plain_apache_license(tmp_path: Path) -> None:
    _write_minimal_root(tmp_path)
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    readme += "\nApache 2.0. Free to use, build on, fork, and share. See LICENSE for the full terms.\n"
    _write_file(tmp_path, "README.md", readme)

    check = release_readiness._check_readme_usage(tmp_path)

    assert check.status == "pass"


def test_citation_metadata_accepts_current_release(tmp_path: Path) -> None:
    _write_minimal_root(tmp_path, version="2.2.14")

    check = release_readiness._check_citation_metadata(tmp_path)

    assert check.status == "pass"
    assert "2.2.14" in check.detail


def test_citation_metadata_rejects_stale_version(tmp_path: Path) -> None:
    _write_minimal_root(tmp_path, version="2.2.14")
    _write_file(tmp_path, "CITATION.cff", 'version: 2.2.13\ndate-released: "2026-06-26"\n')

    check = release_readiness._check_citation_metadata(tmp_path)

    assert check.status == "fail"
    assert "version=2.2.13" in check.detail


def test_citation_metadata_rejects_stale_release_date(tmp_path: Path) -> None:
    _write_minimal_root(tmp_path, version="2.2.14")
    _write_file(tmp_path, "CITATION.cff", 'version: 2.2.14\ndate-released: "2026-06-25"\n')

    check = release_readiness._check_citation_metadata(tmp_path)

    assert check.status == "fail"
    assert "2026-06-25" in check.detail
    assert "2026-06-26" in check.detail


def test_private_tracked_files_fail() -> None:
    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        assert cmd == ["git", "ls-files"]
        return _cp(
            cmd,
            stdout="README.md\nvalidation/corpus-private/acme.txt\nvalidation/live_runs/run/results.json\nexample.com.json\n",
        )

    check = release_readiness._check_private_tracked_files(runner)

    assert check.status == "fail"
    assert "validation/corpus-private/acme.txt" in check.detail
    assert "validation/live_runs/run/results.json" in check.detail
    assert "example.com.json" in check.detail


def test_private_data_check_rejects_target_domain_fields(tmp_path: Path) -> None:
    _write_file(tmp_path, "validation/new-calibration.md", "queried_domain: acme.com\n")

    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        assert cmd == ["git", "ls-files"]
        return _cp(cmd, stdout="validation/new-calibration.md\n")

    check = release_readiness._check_private_tracked_files(runner, tmp_path)

    assert check.status == "fail"
    assert "acme.com" in check.detail


def test_commit_hygiene_rejects_attribution_marker() -> None:
    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        if cmd == ["git", "status", "--short", "--branch"]:
            return _cp(cmd, stdout="## main...origin/main\n")
        assert cmd == ["git", "log", "-1", "--pretty=%B"]
        return _cp(cmd, stdout="Ship thing\n\nCo-authored-by: tool <tool@example.test>\n")

    check = release_readiness._check_latest_commit_message(runner)

    assert check.status == "fail"
    assert "co-authored-by:" in check.detail


def test_commit_hygiene_checks_ahead_stack() -> None:
    bad_marker = "Generated with " + "Claude"

    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        if cmd == ["git", "status", "--short", "--branch"]:
            return _cp(cmd, stdout="## main...origin/main [ahead 2]\n")
        assert cmd == ["git", "log", "--format=%H%x00%B%x00%x1e", "origin/main..HEAD"]
        return _cp(
            cmd,
            stdout=("abc123456789\x00Clean commit\x00\x1e" f"def123456789\x00Ship thing\n\n{bad_marker}\x00\x1e"),
        )

    check = release_readiness._check_latest_commit_message(runner)

    assert check.status == "fail"
    assert "def123456789" in check.detail
    assert "generated with claude" in check.detail


def test_commit_hygiene_rejects_pictograph() -> None:
    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        if cmd == ["git", "status", "--short", "--branch"]:
            return _cp(cmd, stdout="## main...origin/main\n")
        assert cmd == ["git", "log", "-1", "--pretty=%B"]
        return _cp(cmd, stdout="Ship thing \U0001f680\n")

    check = release_readiness._check_latest_commit_message(runner)

    assert check.status == "fail"
    assert "pictograph" in check.detail


def test_repo_name_from_origin_supports_https_and_ssh() -> None:
    assert release_readiness._repo_name_from_origin("https://github.com/blisspixel/recon.git") == "blisspixel/recon"
    assert release_readiness._repo_name_from_origin("git@github.com:blisspixel/recon.git") == "blisspixel/recon"
    assert release_readiness._repo_name_from_origin("https://example.test/blisspixel/recon.git") is None


def test_remote_workflows_require_required_successes() -> None:
    records = [
        {"workflowName": "CI", "status": "completed", "conclusion": "success", "databaseId": 1},
        {"workflowName": "Secrets scan", "status": "completed", "conclusion": "success", "databaseId": 2},
        {
            "workflowName": "Scorecard supply-chain security",
            "status": "completed",
            "conclusion": "success",
            "databaseId": 3,
        },
    ]

    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        if cmd == ["git", "remote", "get-url", "origin"]:
            return _cp(cmd, stdout="https://github.com/blisspixel/recon.git\n")
        if cmd == ["git", "rev-parse", "HEAD"]:
            return _cp(cmd, stdout="abc123\n")
        if cmd[:3] == ["gh", "run", "list"]:
            return _cp(cmd, stdout=json.dumps(records))
        raise AssertionError(f"unexpected command: {cmd}")

    check = release_readiness._check_remote_workflows(runner)

    assert check.status == "pass"


def test_remote_workflows_fail_when_pending_or_missing() -> None:
    records = [
        {"workflowName": "CI", "status": "completed", "conclusion": "success", "databaseId": 1},
        {"workflowName": "Secrets scan", "status": "in_progress", "conclusion": None, "databaseId": 2},
    ]

    problems = release_readiness._remote_workflow_problems(
        {str(record["workflowName"]): record for record in records}
    )

    assert "Secrets scan#2: in_progress" in problems
    assert "Scorecard supply-chain security: missing" in problems


def test_json_renderer_reports_overall_failure(tmp_path: Path) -> None:
    _write_minimal_root(tmp_path)
    checks = [
        release_readiness.CheckResult("one", "pass", "ok"),
        release_readiness.CheckResult("two", "fail", "broken"),
    ]

    payload = json.loads(release_readiness._render_json(checks))

    assert payload["ok"] is False
    assert payload["checks"][1]["name"] == "two"
