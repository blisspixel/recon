"""Structural checks for Scorecard-facing repository posture."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_PINNED_ACTION_RE = r"^[^@]+@[0-9a-f]{40}$"
_READ_ONLY_PERMISSIONS = {"contents": "read"}
_ALLOWED_ELEVATED_JOB_PERMISSIONS = {
    ".github/workflows/codeql.yml": {
        "analyze": {
            "actions": "read",
            "contents": "read",
            "security-events": "write",
        },
    },
    ".github/workflows/release.yml": {
        "attest": {
            "contents": "read",
            "id-token": "write",
            "attestations": "write",
        },
        "publish-pypi": {
            "id-token": "write",
        },
        "github-release": {
            "contents": "write",
        },
    },
    ".github/workflows/scorecard.yml": {
        "analysis": {
            "contents": "read",
            "security-events": "write",
            "id-token": "write",
        },
    },
}


def _workflow_paths() -> list[Path]:
    return sorted((_ROOT / ".github" / "workflows").glob("*.yml"))


def _load_yaml(relative: str) -> dict[Any, Any]:
    data = yaml.safe_load((_ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _workflow_on(workflow: dict[Any, Any]) -> dict[str, Any]:
    raw = workflow.get("on", workflow.get(True))
    assert isinstance(raw, dict)
    return raw


def test_all_workflows_default_to_read_only_tokens() -> None:
    for path in _workflow_paths():
        relative = path.relative_to(_ROOT).as_posix()
        workflow = _load_yaml(relative)
        assert workflow["permissions"] == _READ_ONLY_PERMISSIONS, relative


def test_elevated_job_permissions_are_allowlisted() -> None:
    for path in _workflow_paths():
        relative = path.relative_to(_ROOT).as_posix()
        workflow = _load_yaml(relative)
        jobs = workflow["jobs"]
        allowed = _ALLOWED_ELEVATED_JOB_PERMISSIONS.get(relative, {})
        seen_elevated: set[str] = set()

        for name, job in jobs.items():
            permissions = job.get("permissions")
            if permissions is None or permissions == _READ_ONLY_PERMISSIONS:
                continue

            seen_elevated.add(name)
            assert permissions == allowed.get(name), f"{relative}:{name}"

        assert seen_elevated == set(allowed), relative


def test_scorecard_workflow_uses_explicit_least_privilege_permissions() -> None:
    workflow = _load_yaml(".github/workflows/scorecard.yml")
    job = workflow["jobs"]["analysis"]

    assert workflow["permissions"] == _READ_ONLY_PERMISSIONS
    assert job["permissions"] == _ALLOWED_ELEVATED_JOB_PERMISSIONS[".github/workflows/scorecard.yml"]["analysis"]


def test_release_workflow_exports_scorecard_recognized_provenance() -> None:
    workflow = _load_yaml(".github/workflows/release.yml")
    jobs = workflow["jobs"]
    export_job = jobs["export-attestations"]
    github_release = jobs["github-release"]
    export_text = "\n".join(str(step.get("run", "")) for step in export_job["steps"])
    release_text = "\n".join(str(step.get("run", "")) for step in github_release["steps"])

    assert export_job["needs"] == ["build", "attest"]
    assert export_job["permissions"] == {"contents": "read"}
    assert ".intoto.jsonl" in export_text
    assert "gh attestation download" in export_text
    assert "export-attestations" in github_release["needs"]
    assert "provenance/*" in release_text


def test_codeql_workflow_is_scheduled_and_least_privilege() -> None:
    workflow = _load_yaml(".github/workflows/codeql.yml")
    triggers = _workflow_on(workflow)
    job = workflow["jobs"]["analyze"]
    step_text = "\n".join(str(step.get("uses", "")) for step in job["steps"])

    assert "schedule" in triggers
    assert "workflow_dispatch" in triggers
    assert "push" not in triggers
    assert workflow["permissions"] == _READ_ONLY_PERMISSIONS
    assert job["permissions"] == _ALLOWED_ELEVATED_JOB_PERMISSIONS[".github/workflows/codeql.yml"]["analyze"]
    assert "github/codeql-action/init@8aad20d150bbac5944a9f9d289da16a4b0d87c1e" in step_text
    assert "github/codeql-action/analyze@8aad20d150bbac5944a9f9d289da16a4b0d87c1e" in step_text


def test_workflow_actions_are_pinned_with_readable_version_comments() -> None:
    workflow_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((_ROOT / ".github" / "workflows").glob("*.yml"))
    )

    assert "uses: github/codeql-action/init@8aad20d150bbac5944a9f9d289da16a4b0d87c1e # v4" in workflow_text
    assert "uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6" in workflow_text
    for line in workflow_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("uses: ") and not stripped.startswith("uses: ./"):
            ref, _, comment = stripped.removeprefix("uses: ").partition(" # ")
            assert re.match(_PINNED_ACTION_RE, ref), line
            assert comment, line


def test_dependabot_is_configured_low_noise_for_scorecard_checks() -> None:
    config = _load_yaml(".github/dependabot.yml")
    updates = config["updates"]
    ecosystems = {entry["package-ecosystem"]: entry for entry in updates}

    assert set(ecosystems) == {"uv", "github-actions"}
    for entry in ecosystems.values():
        assert entry["schedule"] == {"interval": "monthly"}
        assert entry["open-pull-requests-limit"] <= 2
        assert entry["ignore"] == [
            {
                "dependency-name": "*",
                "update-types": ["version-update:semver-major"],
            }
        ]
