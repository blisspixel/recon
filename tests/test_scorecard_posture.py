"""Structural checks for Scorecard-facing repository posture."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_PINNED_ACTION_RE = r"^[^@]+@[0-9a-f]{40}$"


def _load_yaml(relative: str) -> dict[Any, Any]:
    data = yaml.safe_load((_ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _workflow_on(workflow: dict[Any, Any]) -> dict[str, Any]:
    raw = workflow.get("on", workflow.get(True))
    assert isinstance(raw, dict)
    return raw


def test_ci_and_mutation_workflows_default_to_read_only_tokens() -> None:
    for relative in (".github/workflows/ci.yml", ".github/workflows/mutation.yml"):
        workflow = _load_yaml(relative)
        assert workflow["permissions"] == {"contents": "read"}


def test_scorecard_workflow_uses_explicit_least_privilege_permissions() -> None:
    workflow = _load_yaml(".github/workflows/scorecard.yml")
    job = workflow["jobs"]["analysis"]

    assert workflow["permissions"] == {"contents": "read"}
    assert job["permissions"] == {
        "contents": "read",
        "security-events": "write",
        "id-token": "write",
    }


def test_codeql_workflow_is_scheduled_and_least_privilege() -> None:
    workflow = _load_yaml(".github/workflows/codeql.yml")
    triggers = _workflow_on(workflow)
    job = workflow["jobs"]["analyze"]
    step_text = "\n".join(str(step.get("uses", "")) for step in job["steps"])

    assert "schedule" in triggers
    assert "workflow_dispatch" in triggers
    assert "push" not in triggers
    assert workflow["permissions"] == {"contents": "read"}
    assert job["permissions"] == {
        "actions": "read",
        "contents": "read",
        "security-events": "write",
    }
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
