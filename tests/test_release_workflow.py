# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportUnknownVariableType=none
"""Release workflow security regressions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
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
    # publish-pypi (downloads the sealed dist and publishes it), attest
    # (downloads the sealed dist and signs a provenance attestation), and
    # publish-mcp-registry (publishes server.json with a verified
    # mcp-publisher binary and does not download dist/). All three are
    # verified dependency-free in test_release_workflow_contract.py, so a
    # compromised dependency cannot mint a token in any of them.
    assert jobs_with_oidc == {"publish-pypi", "attest", "publish-mcp-registry"}
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
    assert "scripts/run_dependency_audit.py" in step_text
    assert "uv run pip-audit" not in step_text


def test_pypi_publication_waits_for_valid_sbom() -> None:
    workflow = _load_release_workflow()
    assert "sbom" in workflow["jobs"]["publish-pypi"]["needs"]
    assert "package-smoke" in workflow["jobs"]["publish-pypi"]["needs"]


def test_github_publication_waits_for_pypi_byte_parity() -> None:
    workflow = _load_release_workflow()
    jobs = workflow["jobs"]

    assert set(jobs["verify-pypi-parity"]["needs"]) == {"build", "publish-pypi"}
    assert "verify-pypi-parity" in jobs["github-release"]["needs"]


@pytest.mark.parametrize("filename", ["ci.yml", "release.yml"])
def test_uv_uses_the_interpreter_installed_by_each_job(filename: str) -> None:
    path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / filename
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    for name, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            if not step.get("uses", "").startswith("actions/setup-python@"):
                continue
            env = {**workflow.get("env", {}), **job.get("env", {}), **step.get("env", {})}
            assert env.get("UV_PYTHON") == step["with"]["python-version"], name


def test_pypi_publisher_uses_the_reviewed_ca_remediation_release() -> None:
    workflow = _load_release_workflow()
    steps = workflow["jobs"]["publish-pypi"]["steps"]
    publisher = next(step for step in steps if step.get("name") == "Publish to PyPI")
    # v1.14.3's peeled tag commit, whose runtime locks sigstore 4.5.1 and
    # certifi 2026.10.19. Verify a replacement release before updating this pin.
    assert publisher["uses"] == "pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086"
    assert publisher["with"]["attestations"] is True
