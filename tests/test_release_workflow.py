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


def test_release_workflow_does_not_grant_workflow_level_oidc() -> None:
    workflow = _load_release_workflow()
    permissions = workflow.get("permissions")

    assert permissions == {"contents": "read"}


def test_release_oidc_is_scoped_to_pypi_publish_job() -> None:
    workflow = _load_release_workflow()
    jobs = workflow["jobs"]

    jobs_with_oidc = {name for name, job in jobs.items() if job.get("permissions", {}).get("id-token") == "write"}
    assert jobs_with_oidc == {"publish-pypi"}
    assert jobs["publish-pypi"]["environment"] == "pypi"


def test_release_test_and_build_jobs_are_read_only() -> None:
    workflow = _load_release_workflow()
    jobs = workflow["jobs"]

    assert jobs["test"]["permissions"] == {"contents": "read"}
    assert jobs["build"]["permissions"] == {"contents": "read"}
