#!/usr/bin/env python3
"""Check maintainer release readiness before relying on remote CI.

Default mode is local only. It checks the repository state, version references,
coverage gate wiring, lockfile freshness, docs anchors, citation metadata,
private-corpus hygiene, Homebrew formula freshness, and local commit-message
hygiene.

Use ``--remote`` after pushing when you want the same report to include GitHub
Actions status for the current commit, PyPI publication state, PyPI provenance
verification, GitHub Release asset completeness, GitHub build-provenance
verification for the current version, and public Scorecard API freshness.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

try:
    from scripts import check_validation_hygiene
except ImportError:
    import check_validation_hygiene  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]

Status = Literal["pass", "fail", "warn", "skip"]
Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]

_INIT_VERSION_RE = re.compile(r'_FALLBACK_VERSION\s*=\s*"([^"]+)"')
_FORMULA_VERSION_RE = re.compile(r"recon_tool-([0-9A-Za-z.-]+)\.tar\.gz")
_CITATION_VERSION_RE = re.compile(r"^version:\s*\"?([^\"\s]+)\"?\s*$", re.MULTILINE)
_CITATION_RELEASE_DATE_RE = re.compile(
    r"^date-released:\s*\"?([0-9]{4}-[0-9]{2}-[0-9]{2})\"?\s*$",
    re.MULTILINE,
)
_EXPECTED_COVERAGE_TARGET = "--cov=src/recon_tool"
_STALE_COVERAGE_TARGET = "--cov=recon_tool"
_COVERAGE_FLOOR = "--cov-fail-under=82"
_REQUIRED_REMOTE_WORKFLOWS = ("CI", "Secrets scan", "Scorecard supply-chain security")
_MIN_SCORECARD_SCORE = 7.5
_REQUIRED_SCORECARD_TENS = (
    "Binary-Artifacts",
    "Dangerous-Workflow",
    "Dependency-Update-Tool",
    "Fuzzing",
    "License",
    "Packaging",
    "Pinned-Dependencies",
    "SAST",
    "Security-Policy",
    "Signed-Releases",
    "Token-Permissions",
    "Vulnerabilities",
)
_PYPI_PACKAGE = "recon-tool"
_PYPI_RELEASE_URL = f"https://pypi.org/pypi/{_PYPI_PACKAGE}/json"
_PYPI_ATTESTATION_REPOSITORY = "https://github.com/blisspixel/recon"
_README_FORBIDDEN_FRAGMENTS = (
    "enterprise use, contact",
    "commercial or\nenterprise use",
    "commercial or enterprise use",
    "contact Nick Seal",
    "nick" + "@pueo.io",
)
_ATTRIBUTION_MARKERS = (
    "co-authored-by:",
    "generated-by:",
    "generated with codex",
    "generated with claude",
    "generated with github copilot",
    "made by codex",
    "made by claude",
    "made by github copilot",
)
_PICTOGRAPH_RANGES = (
    (0x1F000, 0x1FAFF),
    (0x2600, 0x27BF),
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: Status
    detail: str
    action: str = ""


def _result(name: str, status: Status, detail: str, action: str = "") -> CheckResult:
    return CheckResult(name=name, status=status, detail=detail, action=action)


def _make_runner(root: Path) -> Runner:
    def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(  # noqa: S603
                cmd,
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError as exc:
            return subprocess.CompletedProcess(cmd, 127, "", str(exc))

    return _run


def _read_text(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def _read_project_version(root: Path) -> str:
    data = tomllib.loads(_read_text(root, "pyproject.toml"))
    project = data.get("project")
    if not isinstance(project, dict):
        msg = "pyproject.toml is missing [project]"
        raise ValueError(msg)
    version = project.get("version")
    if not isinstance(version, str) or not version:
        msg = "pyproject.toml is missing project.version"
        raise ValueError(msg)
    return version


def _read_init_version(root: Path) -> str:
    match = _INIT_VERSION_RE.search(_read_text(root, "src/recon_tool/__init__.py"))
    if match is None:
        msg = "src/recon_tool/__init__.py is missing _FALLBACK_VERSION"
        raise ValueError(msg)
    return match.group(1)


def _read_changelog_release_date(root: Path, version: str) -> str:
    text = _read_text(root, "CHANGELOG.md")
    pattern = re.compile(rf"^## \[{re.escape(version)}\] - ([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})\s*$", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        msg = f"CHANGELOG.md is missing a release section for {version}"
        raise ValueError(msg)
    return match.group(1)


def _check_git_branch(runner: Runner, allow_non_main: bool) -> CheckResult:
    result = runner(["git", "branch", "--show-current"])
    if result.returncode != 0:
        return _result("git branch", "fail", result.stderr.strip() or "could not read current branch")
    branch = result.stdout.strip()
    if branch == "main":
        return _result("git branch", "pass", "on main")
    detail = f"current branch is {branch or 'detached HEAD'}"
    action = "switch to main before release readiness"
    return _result("git branch", "warn" if allow_non_main else "fail", detail, action)


def _check_worktree(runner: Runner, allow_dirty: bool) -> CheckResult:
    result = runner(["git", "status", "--porcelain"])
    if result.returncode != 0:
        return _result("worktree", "fail", result.stderr.strip() or "could not read git status")
    changes = [line for line in result.stdout.splitlines() if line.strip()]
    if not changes:
        return _result("worktree", "pass", "clean")
    detail = f"{len(changes)} uncommitted change(s)"
    action = "commit, stash, or discard local changes before strict readiness"
    return _result("worktree", "warn" if allow_dirty else "fail", detail, action)


def _check_upstream_state(runner: Runner) -> CheckResult:
    result = runner(["git", "status", "--short", "--branch"])
    if result.returncode != 0:
        return _result("upstream", "warn", result.stderr.strip() or "could not read upstream state")
    first = result.stdout.splitlines()[0] if result.stdout.splitlines() else ""
    if "...origin/main" not in first:
        return _result("upstream", "skip", "no origin/main tracking state in git status")
    if "behind" in first or "diverged" in first:
        return _result("upstream", "fail", first, "pull or reconcile origin/main before release readiness")
    if "ahead" in first:
        return _result("upstream", "warn", first, "push main when local checks pass")
    return _result("upstream", "pass", "main matches origin/main tracking state")


def _check_version_consistency(root: Path) -> CheckResult:
    try:
        project_version = _read_project_version(root)
        init_version = _read_init_version(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return _result("version consistency", "fail", str(exc))
    if project_version != init_version:
        return _result(
            "version consistency",
            "fail",
            f"pyproject.toml={project_version}, __init__.py={init_version}",
            "make both version references match",
        )
    return _result("version consistency", "pass", project_version)


def _check_uv_lock(runner: Runner) -> CheckResult:
    result = runner(["uv", "lock", "--check"])
    if result.returncode == 0:
        return _result("uv.lock", "pass", "lockfile is current")
    detail = (result.stderr or result.stdout).strip() or "uv lock --check failed"
    return _result("uv.lock", "fail", detail, "run uv lock and commit uv.lock")


def _check_coverage_targets(root: Path) -> CheckResult:
    files = (
        "scripts/check.py",
        "scripts/release.py",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
    )
    problems: list[str] = []
    for relative in files:
        try:
            text = _read_text(root, relative)
        except OSError as exc:
            problems.append(f"{relative}: {exc}")
            continue
        if _STALE_COVERAGE_TARGET in text:
            problems.append(f"{relative}: stale {_STALE_COVERAGE_TARGET}")
        if _EXPECTED_COVERAGE_TARGET not in text:
            problems.append(f"{relative}: missing {_EXPECTED_COVERAGE_TARGET}")
        if _COVERAGE_FLOOR not in text:
            problems.append(f"{relative}: missing {_COVERAGE_FLOOR}")
    if problems:
        return _result("coverage gates", "fail", "; ".join(problems), "align local, release, and CI coverage args")
    return _result("coverage gates", "pass", f"{_EXPECTED_COVERAGE_TARGET} with {_COVERAGE_FLOOR}")


def _check_roadmap_version(root: Path) -> CheckResult:
    try:
        version = _read_project_version(root)
        text = _read_text(root, "docs/roadmap.md")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return _result("roadmap version", "fail", str(exc))
    header = "\n".join(text.splitlines()[:80])
    if f"v{version}" not in header:
        return _result("roadmap version", "fail", f"v{version} missing from roadmap status block")
    return _result("roadmap version", "pass", f"docs/roadmap.md status mentions v{version}")


def _check_citation_metadata(root: Path) -> CheckResult:
    try:
        version = _read_project_version(root)
        expected_date = _read_changelog_release_date(root, version)
        text = _read_text(root, "CITATION.cff")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return _result("citation metadata", "fail", str(exc))

    version_match = _CITATION_VERSION_RE.search(text)
    if version_match is None:
        return _result("citation metadata", "fail", "CITATION.cff is missing version")
    citation_version = version_match.group(1)
    if citation_version != version:
        return _result(
            "citation metadata",
            "fail",
            f"CITATION.cff version={citation_version}, project is {version}",
            "update CITATION.cff before release readiness",
        )

    date_match = _CITATION_RELEASE_DATE_RE.search(text)
    if date_match is None:
        return _result("citation metadata", "fail", "CITATION.cff is missing date-released")
    citation_date = date_match.group(1)
    if citation_date != expected_date:
        return _result(
            "citation metadata",
            "fail",
            f"CITATION.cff date-released={citation_date}, changelog has {expected_date}",
            "align CITATION.cff with the current CHANGELOG release section",
        )

    return _result("citation metadata", "pass", f"CITATION.cff matches {version} ({expected_date})")


def _check_readme_usage(root: Path) -> CheckResult:
    try:
        text = _read_text(root, "README.md")
    except OSError as exc:
        return _result("README usage", "fail", str(exc))
    anchors = (
        "recon contoso.com",
        "recon batch domains.txt --json",
        "recon mcp install --client=",
        "Examples use [Microsoft's fictional company names]",
        "python scripts/check.py",
        "Project hygiene: keep examples fictional or synthetic",
        "keep validation artifacts",
        "avoid dead code or placeholders",
    )
    missing = [anchor for anchor in anchors if anchor not in text]
    if missing:
        return _result("README usage", "fail", "missing anchors: " + ", ".join(missing))
    forbidden = [fragment for fragment in _README_FORBIDDEN_FRAGMENTS if fragment in text]
    if forbidden:
        detail = "forbidden README wording: " + ", ".join(forbidden)
        return _result("README usage", "fail", detail, "keep the license section Apache 2.0 only")
    return _result("README usage", "pass", "core usage, MCP install, project hygiene, and validation boundaries")


def _check_homebrew_formula(root: Path) -> CheckResult:
    try:
        version = _read_project_version(root)
        formula = _read_text(root, "packaging/homebrew/recon.rb")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return _result("Homebrew formula", "fail", str(exc))
    match = _FORMULA_VERSION_RE.search(formula)
    if match is None:
        return _result("Homebrew formula", "fail", "formula does not pin a recon_tool sdist URL")
    formula_version = match.group(1)
    if formula_version != version:
        return _result(
            "Homebrew formula",
            "warn",
            f"formula pins {formula_version}, project is {version}",
            "after PyPI publish, run scripts/update_homebrew_formula.py and update the tap",
        )
    return _result("Homebrew formula", "pass", f"formula pins {version}")


def _check_private_tracked_files(runner: Runner, root: Path = ROOT) -> CheckResult:
    result = runner(["git", "ls-files"])
    if result.returncode != 0:
        return _result("private data", "fail", result.stderr.strip() or "could not list tracked files")
    tracked = [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]
    violations = check_validation_hygiene.find_violations(root, tracked)
    if violations:
        leaked = sorted(violation.render() for violation in violations)
        return _result(
            "private data",
            "fail",
            "; ".join(leaked),
            "remove private validation artifacts or target-specific fields from git",
        )
    return _result("private data", "pass", "no tracked private corpus, run output, or target-domain validation fields")


def _has_pictograph(text: str) -> bool:
    return any(start <= ord(char) <= end for char in text for start, end in _PICTOGRAPH_RANGES)


def _message_markers(message: str) -> list[str]:
    lowered = message.lower()
    markers = [marker for marker in _ATTRIBUTION_MARKERS if marker in lowered]
    if "\u2014" in message:
        markers.append("em dash")
    if _has_pictograph(message):
        markers.append("pictograph")
    return markers


def _commit_messages_to_check(runner: Runner) -> tuple[str, list[tuple[str, str]]] | CheckResult:
    status = runner(["git", "status", "--short", "--branch"])
    if status.returncode == 0:
        first = status.stdout.splitlines()[0] if status.stdout.splitlines() else ""
        if "origin/main" in first and "[ahead " in first:
            result = runner(["git", "log", "--format=%H%x00%B%x00%x1e", "origin/main..HEAD"])
            if result.returncode != 0:
                return _result("commit hygiene", "warn", result.stderr.strip() or "could not read ahead commits")
            messages: list[tuple[str, str]] = []
            for record in result.stdout.split("\x1e"):
                if not record.strip():
                    continue
                parts = record.split("\x00", 2)
                if len(parts) >= 2:
                    messages.append((parts[0][:12], parts[1].strip()))
            return "local ahead commit", messages

    result = runner(["git", "log", "-1", "--pretty=%B"])
    if result.returncode != 0:
        return _result("commit hygiene", "warn", result.stderr.strip() or "could not read latest commit")
    return "latest commit", [("HEAD", result.stdout.strip())]


def _check_latest_commit_message(runner: Runner) -> CheckResult:
    scoped_messages = _commit_messages_to_check(runner)
    if isinstance(scoped_messages, CheckResult):
        return scoped_messages

    scope, messages = scoped_messages
    failures: list[str] = []
    for label, message in messages:
        markers = _message_markers(message)
        if markers:
            failures.append(f"{label}: {', '.join(markers)}")
    if failures:
        return _result("commit hygiene", "fail", "forbidden marker(s): " + "; ".join(failures))
    return _result(
        "commit hygiene",
        "pass",
        f"{scope} message(s) have no generated-author markers, em dash, or pictograph",
    )


def _repo_name_from_origin(url: str) -> str | None:
    cleaned = url.strip()
    match = re.match(r"https://github\.com/([^/]+/[^/.]+)(?:\.git)?$", cleaned)
    if match is not None:
        return match.group(1)
    match = re.match(r"git@github\.com:([^/]+/[^/.]+)(?:\.git)?$", cleaned)
    if match is not None:
        return match.group(1)
    return None


def _check_remote_workflows(runner: Runner) -> CheckResult:
    repo_result = _read_github_repo(runner, "remote CI")
    if isinstance(repo_result, CheckResult):
        return repo_result
    repo = repo_result
    records_result = _load_remote_workflow_records(runner, repo)
    if isinstance(records_result, CheckResult):
        return records_result
    latest_by_workflow = _latest_remote_workflows(records_result)
    problems = _remote_workflow_problems(latest_by_workflow)
    if problems:
        return _result("remote CI", "fail", "; ".join(problems), "wait for GitHub checks or inspect the failing run")
    return _result("remote CI", "pass", "required workflows completed successfully for HEAD")


def _check_scorecard_api(runner: Runner) -> CheckResult:
    repo_result = _read_github_repo(runner, "Scorecard API")
    if isinstance(repo_result, CheckResult):
        return repo_result
    sha_result = runner(["git", "rev-parse", "HEAD"])
    if sha_result.returncode != 0:
        return _result("Scorecard API", "fail", sha_result.stderr.strip() or "could not read HEAD")
    sha = sha_result.stdout.strip()
    payload_result = _load_scorecard_payload(runner, repo_result, sha)
    if isinstance(payload_result, CheckResult):
        return payload_result
    problem = _scorecard_problem(payload_result, sha)
    if problem is not None:
        return _result("Scorecard API", "fail", problem, "wait for Scorecard API refresh or inspect the Scorecard run")
    return _result("Scorecard API", "pass", f"scorecard reports {sha[:7]} at score >= {_MIN_SCORECARD_SCORE}")


def _load_scorecard_payload(runner: Runner, repo: str, sha: str) -> dict[str, object] | CheckResult:
    url = f"https://api.securityscorecards.dev/projects/github.com/{repo}?commit={sha}"
    script = (
        "import json, urllib.request; "
        f"data=json.load(urllib.request.urlopen({url!r}, timeout=30)); "
        "print(json.dumps(data))"
    )
    result = runner([sys.executable, "-c", script])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "could not query Scorecard API"
        return _result("Scorecard API", "fail", detail)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return _result("Scorecard API", "fail", f"could not parse Scorecard JSON: {exc}")
    if not isinstance(payload, dict):
        return _result("Scorecard API", "fail", "Scorecard JSON was not an object")
    return payload


def _scorecard_problem(payload: dict[str, object], sha: str) -> str | None:
    repo = payload.get("repo")
    reported_commit = repo.get("commit") if isinstance(repo, dict) else None
    if reported_commit != sha:
        return f"Scorecard commit is {reported_commit!r}, expected {sha}"
    score = payload.get("score")
    if not isinstance(score, int | float):
        return "Scorecard score is missing or not numeric"
    if score < _MIN_SCORECARD_SCORE:
        return f"Scorecard score is {score}, below {_MIN_SCORECARD_SCORE}"
    checks = payload.get("checks")
    if not isinstance(checks, list):
        return "Scorecard checks were not a list"
    scores: dict[str, object] = {}
    for check in checks:
        if isinstance(check, dict) and isinstance(check.get("name"), str):
            scores[check["name"]] = check.get("score")
    missing = [name for name in _REQUIRED_SCORECARD_TENS if name not in scores]
    if missing:
        return "missing Scorecard check(s): " + ", ".join(missing)
    weak = [f"{name}={scores[name]!r}" for name in _REQUIRED_SCORECARD_TENS if scores[name] != 10]
    if weak:
        return "code-owned Scorecard check(s) regressed: " + ", ".join(weak)
    return None


def _read_github_repo(runner: Runner, check_name: str) -> str | CheckResult:
    origin = runner(["git", "remote", "get-url", "origin"])
    if origin.returncode != 0:
        return _result(check_name, "fail", origin.stderr.strip() or "could not read origin URL")
    repo = _repo_name_from_origin(origin.stdout)
    if repo is None:
        return _result(check_name, "fail", f"unsupported GitHub origin URL: {origin.stdout.strip()}")
    return repo


def _load_remote_workflow_records(runner: Runner, repo: str) -> list[object] | CheckResult:
    sha_result = runner(["git", "rev-parse", "HEAD"])
    if sha_result.returncode != 0:
        return _result("remote CI", "fail", sha_result.stderr.strip() or "could not read HEAD")
    runs = runner(
        [
            "gh",
            "run",
            "list",
            "--repo",
            repo,
            "--commit",
            sha_result.stdout.strip(),
            "--limit",
            "30",
            "--json",
            "databaseId,workflowName,status,conclusion,name",
        ]
    )
    if runs.returncode != 0:
        return _result("remote CI", "fail", (runs.stderr or runs.stdout).strip() or "gh run list failed")
    try:
        records = json.loads(runs.stdout)
    except json.JSONDecodeError as exc:
        return _result("remote CI", "fail", f"could not parse gh JSON: {exc}")
    if not isinstance(records, list):
        return _result("remote CI", "fail", "gh JSON was not a list")
    return records


def _latest_remote_workflows(records: list[object]) -> dict[str, dict[str, object]]:
    latest_by_workflow: dict[str, dict[str, object]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        workflow = record.get("workflowName") or record.get("name")
        if isinstance(workflow, str) and workflow not in latest_by_workflow:
            latest_by_workflow[workflow] = record
    return latest_by_workflow


def _remote_workflow_problems(latest_by_workflow: dict[str, dict[str, object]]) -> list[str]:
    problems: list[str] = []
    for workflow in _REQUIRED_REMOTE_WORKFLOWS:
        record = latest_by_workflow.get(workflow)
        if record is None:
            problems.append(f"{workflow}: missing")
            continue
        status = record.get("status")
        conclusion = record.get("conclusion")
        run_id = record.get("databaseId")
        label = f"{workflow}#{run_id}" if run_id else workflow
        if status != "completed":
            problems.append(f"{label}: {status}")
            continue
        if conclusion != "success":
            problems.append(f"{label}: {conclusion}")
    return problems


def _check_pypi_release(root: Path, runner: Runner) -> CheckResult:
    try:
        version = _read_project_version(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return _result("PyPI release", "fail", str(exc))

    payload = _load_pypi_release_payload(runner)
    if isinstance(payload, CheckResult):
        return payload
    latest = payload.get("version")
    if latest != version:
        return _result("PyPI release", "fail", f"PyPI latest is {latest!r}, project is {version}")
    expected = _expected_distribution_names(version)
    missing = sorted(set(expected) - _pypi_file_names(payload))
    if missing:
        return _result("PyPI release", "fail", "missing file(s): " + ", ".join(missing))
    return _result("PyPI release", "pass", f"PyPI reports {_PYPI_PACKAGE} {version} with wheel and sdist")


def _load_pypi_release_payload(runner: Runner) -> dict[str, object] | CheckResult:
    script = (
        "import json, urllib.request; "
        f"data=json.load(urllib.request.urlopen({_PYPI_RELEASE_URL!r}, timeout=30)); "
        "print(json.dumps({'version': data['info']['version'], "
        "'files': [{'filename': f.get('filename'), 'url': f.get('url')} "
        "for f in data.get('releases', {}).get(data['info']['version'], [])]}))"
    )
    result = runner([sys.executable, "-c", script])
    if result.returncode != 0:
        return _result("PyPI release", "fail", (result.stderr or result.stdout).strip() or "could not query PyPI")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return _result("PyPI release", "fail", f"could not parse PyPI JSON: {exc}")
    if not isinstance(payload, dict):
        return _result("PyPI release", "fail", "PyPI JSON was not an object")
    return payload


def _expected_distribution_names(version: str) -> tuple[str, str]:
    return (f"recon_tool-{version}-py3-none-any.whl", f"recon_tool-{version}.tar.gz")


def _pypi_file_names(payload: dict[str, object]) -> set[str]:
    files = payload.get("files")
    if not isinstance(files, list):
        return set()
    names: set[str] = set()
    for file in files:
        if isinstance(file, str):
            names.add(file)
        elif isinstance(file, dict) and isinstance(file.get("filename"), str):
            names.add(file["filename"])
    return names


def _pypi_file_urls(payload: dict[str, object]) -> dict[str, str]:
    files = payload.get("files")
    if not isinstance(files, list):
        return {}
    urls: dict[str, str] = {}
    for file in files:
        if (
            isinstance(file, dict)
            and isinstance(file.get("filename"), str)
            and isinstance(file.get("url"), str)
        ):
            urls[file["filename"]] = file["url"]
    return urls


def _check_pypi_attestations(root: Path, runner: Runner) -> CheckResult:
    try:
        version = _read_project_version(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return _result("PyPI attestations", "fail", str(exc))
    payload = _load_pypi_release_payload(runner)
    if isinstance(payload, CheckResult):
        return _result("PyPI attestations", payload.status, payload.detail, payload.action)
    latest = payload.get("version")
    if latest != version:
        return _result("PyPI attestations", "fail", f"PyPI latest is {latest!r}, project is {version}")
    urls = _pypi_file_urls(payload)
    expected = _expected_distribution_names(version)
    for subject in expected:
        url = urls.get(subject)
        if url is None:
            return _result("PyPI attestations", "fail", f"missing PyPI file URL for {subject}")
        verify = runner(
            [
                "uvx",
                "--from",
                "pypi-attestations",
                "pypi-attestations",
                "verify",
                "pypi",
                "--repository",
                _PYPI_ATTESTATION_REPOSITORY,
                url,
            ]
        )
        if verify.returncode != 0:
            detail = (verify.stderr or verify.stdout).strip() or f"PyPI attestation verification failed for {subject}"
            return _result("PyPI attestations", "fail", detail)
    return _result("PyPI attestations", "pass", f"PyPI provenance verifies wheel and sdist for {version}")


def _check_github_release(root: Path, runner: Runner) -> CheckResult:
    try:
        version = _read_project_version(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return _result("GitHub release", "fail", str(exc))
    repo_result = _read_github_repo(runner, "GitHub release")
    if isinstance(repo_result, CheckResult):
        return repo_result
    repo = repo_result
    payload_result = _load_github_release_payload(runner, repo, version)
    if isinstance(payload_result, CheckResult):
        return payload_result
    problem = _github_release_problem(payload_result, version)
    if problem:
        return _result("GitHub release", "fail", problem)
    return _result("GitHub release", "pass", f"v{version} is published with wheel, sdist, SBOM, and attestation")


def _check_github_attestations(root: Path, runner: Runner) -> CheckResult:
    try:
        version = _read_project_version(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return _result("GitHub attestations", "fail", str(exc))
    repo_result = _read_github_repo(runner, "GitHub attestations")
    if isinstance(repo_result, CheckResult):
        return repo_result
    repo = repo_result
    subjects = (f"recon_tool-{version}-py3-none-any.whl", f"recon_tool-{version}.tar.gz")
    with tempfile.TemporaryDirectory(prefix="recon-attestation-") as temp_dir:
        directory = Path(temp_dir)
        for subject in subjects:
            download = runner(
                [
                    "gh",
                    "release",
                    "download",
                    f"v{version}",
                    "--repo",
                    repo,
                    "--pattern",
                    subject,
                    "--dir",
                    str(directory),
                ]
            )
            if download.returncode != 0:
                detail = (download.stderr or download.stdout).strip() or f"could not download {subject}"
                return _result("GitHub attestations", "fail", detail)
            artifact = directory / subject
            if not artifact.is_file():
                return _result("GitHub attestations", "fail", f"release download did not produce {subject}")
            verify = runner(["gh", "attestation", "verify", str(artifact), "--repo", repo])
            if verify.returncode != 0:
                detail = (verify.stderr or verify.stdout).strip() or f"attestation verification failed for {subject}"
                return _result("GitHub attestations", "fail", detail)
    return _result("GitHub attestations", "pass", f"GitHub provenance verifies wheel and sdist for v{version}")


def _load_github_release_payload(runner: Runner, repo: str, version: str) -> dict[str, object] | CheckResult:
    result = runner(
        [
            "gh",
            "release",
            "view",
            f"v{version}",
            "--repo",
            repo,
            "--json",
            "tagName,isDraft,isPrerelease,assets",
        ]
    )
    if result.returncode != 0:
        return _result("GitHub release", "fail", (result.stderr or result.stdout).strip() or "gh release view failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return _result("GitHub release", "fail", f"could not parse gh JSON: {exc}")
    if not isinstance(payload, dict):
        return _result("GitHub release", "fail", "gh JSON was not an object")
    return payload


def _github_release_problem(payload: dict[str, object], version: str) -> str | None:
    tag = payload.get("tagName")
    if tag != f"v{version}":
        return f"release tag is {tag!r}, expected v{version}"
    if payload.get("isDraft") is True:
        return f"v{version} is still a draft"
    if payload.get("isPrerelease") is True:
        return f"v{version} is marked prerelease"
    assets = payload.get("assets")
    if not isinstance(assets, list):
        return "release assets were not a list"
    asset_names = {
        asset.get("name")
        for asset in assets
        if isinstance(asset, dict) and isinstance(asset.get("name"), str)
    }
    expected_assets = {
        f"recon_tool-{version}-py3-none-any.whl",
        f"recon_tool-{version}.tar.gz",
        f"recon-tool-{version}.cdx.json",
        f"recon-tool-{version}.intoto.jsonl",
    }
    missing = sorted(expected_assets - asset_names)
    if missing:
        return "missing asset(s): " + ", ".join(missing)
    return None


def collect_checks(
    root: Path = ROOT,
    *,
    runner: Runner | None = None,
    allow_dirty: bool = False,
    allow_non_main: bool = False,
    remote: bool = False,
) -> list[CheckResult]:
    actual_runner = runner or _make_runner(root)
    checks = [
        _check_git_branch(actual_runner, allow_non_main),
        _check_worktree(actual_runner, allow_dirty),
        _check_upstream_state(actual_runner),
        _check_version_consistency(root),
        _check_uv_lock(actual_runner),
        _check_coverage_targets(root),
        _check_roadmap_version(root),
        _check_citation_metadata(root),
        _check_readme_usage(root),
        _check_homebrew_formula(root),
        _check_private_tracked_files(actual_runner, root),
        _check_latest_commit_message(actual_runner),
    ]
    if remote:
        checks.append(_check_remote_workflows(actual_runner))
        checks.append(_check_scorecard_api(actual_runner))
        checks.append(_check_pypi_release(root, actual_runner))
        checks.append(_check_pypi_attestations(root, actual_runner))
        checks.append(_check_github_release(root, actual_runner))
        checks.append(_check_github_attestations(root, actual_runner))
    else:
        checks.append(_result("remote CI", "skip", "not requested; pass --remote after pushing main"))
        checks.append(_result("Scorecard API", "skip", "not requested; pass --remote after pushing main"))
        checks.append(_result("PyPI release", "skip", "not requested; pass --remote after release publication"))
        checks.append(_result("PyPI attestations", "skip", "not requested; pass --remote after release publication"))
        checks.append(_result("GitHub release", "skip", "not requested; pass --remote after release publication"))
        checks.append(_result("GitHub attestations", "skip", "not requested; pass --remote after release publication"))
    return checks


def _has_failure(checks: list[CheckResult]) -> bool:
    return any(check.status == "fail" for check in checks)


def _render_text(checks: list[CheckResult]) -> str:
    width = max(len(check.name) for check in checks)
    lines: list[str] = []
    for check in checks:
        status = check.status.upper()
        line = f"{status:<4}  {check.name:<{width}}  {check.detail}"
        if check.action:
            line += f"  [{check.action}]"
        lines.append(line)
    if _has_failure(checks):
        lines.append("")
        lines.append("Release readiness failed.")
    else:
        lines.append("")
        lines.append("Release readiness passed.")
    return "\n".join(lines)


def _render_json(checks: list[CheckResult]) -> str:
    payload = {"ok": not _has_failure(checks), "checks": [asdict(check) for check in checks]}
    return json.dumps(payload, indent=2, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check recon maintainer release readiness.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--remote", action="store_true", help="Also inspect GitHub Actions runs for HEAD via gh.")
    parser.add_argument("--allow-dirty", action="store_true", help="Warn instead of failing on uncommitted changes.")
    parser.add_argument("--allow-non-main", action="store_true", help="Warn instead of failing off main.")
    args = parser.parse_args(argv)

    checks = collect_checks(
        allow_dirty=args.allow_dirty,
        allow_non_main=args.allow_non_main,
        remote=args.remote,
    )
    print(_render_json(checks) if args.json else _render_text(checks))
    return 1 if _has_failure(checks) else 0


if __name__ == "__main__":
    sys.exit(main())
