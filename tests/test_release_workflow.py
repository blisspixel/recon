"""Release workflow security regressions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def _load_release_workflow() -> dict[str, Any]:
    workflow_path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"
    data = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _step_text(step: dict[str, Any]) -> str:
    parts: list[str] = []
    if isinstance(step.get("run"), str):
        parts.append(step["run"])
    if isinstance(step.get("uses"), str):
        parts.append(step["uses"])
    return "\n".join(parts)


def test_release_workflow_does_not_grant_workflow_level_oidc() -> None:
    workflow = _load_release_workflow()
    permissions = workflow.get("permissions")

    assert permissions == {"contents": "read"}


def test_release_oidc_is_scoped_to_dependency_free_jobs() -> None:
    workflow = _load_release_workflow()
    jobs = workflow["jobs"]

    jobs_with_oidc = {name for name, job in jobs.items() if job.get("permissions", {}).get("id-token") == "write"}
    # Only jobs that run NO project dependency code may mint an OIDC token:
    # publish-pypi (downloads the sealed dist and publishes it) and attest
    # (downloads the sealed dist and signs a provenance attestation). Both
    # are verified dependency-free in test_release_workflow_contract.py, so
    # a compromised dependency cannot mint a token in either.
    assert jobs_with_oidc == {"publish-pypi", "attest"}
    assert jobs["publish-pypi"]["environment"] == "pypi"


def test_release_test_and_build_jobs_are_read_only() -> None:
    workflow = _load_release_workflow()
    jobs = workflow["jobs"]

    assert jobs["test"]["permissions"] == {"contents": "read"}
    assert jobs["build"]["permissions"] == {"contents": "read"}
    assert jobs["package-smoke"]["permissions"] == {"contents": "read"}
    assert jobs["verify-pypi-parity"]["permissions"] == {"contents": "read"}


def test_release_preflight_blocks_mismatched_or_non_main_tags() -> None:
    workflow = _load_release_workflow()
    jobs = workflow["jobs"]
    preflight = jobs["preflight"]
    text = "\n".join(_step_text(step) for step in preflight["steps"])

    assert jobs["test"]["needs"] == "preflight"
    assert preflight["permissions"] == {"contents": "read"}
    assert preflight["steps"][0]["with"]["fetch-depth"] == 0
    assert "refs/remotes/origin/main" in text
    assert "scripts/validate_release_tag.py" in text


def test_release_test_job_runs_complete_quality_gate() -> None:
    workflow = _load_release_workflow()
    steps = workflow["jobs"]["test"]["steps"]
    step_text = "\n".join(_step_text(step) for step in steps)
    checkout = steps[0]
    history_step = next(step for step in steps if step.get("name") == "Require full Git history")
    history_command = str(history_step["run"])

    assert checkout["with"]["persist-credentials"] is False
    assert checkout["with"]["fetch-depth"] == 0
    assert '"$(git rev-parse --is-shallow-repository)" != "false"' in history_command
    assert "exit 1" in history_command
    assert "actions/setup-node" in step_text
    assert "uv run python scripts/check.py" in step_text
    assert "--text-range" in step_text
    assert "git describe --tags" in step_text
    assert "scripts/check_mcp_compatibility.py" in step_text
    assert "pip-audit" in step_text


def test_pypi_publication_waits_for_valid_sbom() -> None:
    workflow = _load_release_workflow()
    assert "sbom" in workflow["jobs"]["publish-pypi"]["needs"]
    assert "package-smoke" in workflow["jobs"]["publish-pypi"]["needs"]


def test_github_publication_waits_for_pypi_byte_parity() -> None:
    workflow = _load_release_workflow()
    jobs = workflow["jobs"]

    assert set(jobs["verify-pypi-parity"]["needs"]) == {"build", "publish-pypi"}
    assert "verify-pypi-parity" in jobs["github-release"]["needs"]
