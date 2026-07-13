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


def test_release_test_job_typechecks_source_and_tests() -> None:
    workflow = _load_release_workflow()
    steps = workflow["jobs"]["test"]["steps"]
    step_text = "\n".join(_step_text(step) for step in steps)

    assert "actions/setup-node" in step_text
    assert "uv run pyright src/recon_tool/ tests/" in step_text
    assert "uv run python scripts/generate_fingerprint_catalog.py --check" in step_text
