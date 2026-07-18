"""Executable contract for the release artifact build toolchain."""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_CONSTRAINTS = _REPO_ROOT / "build-constraints.txt"
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"
_EXPECTED_BUILD_PACKAGES = {
    "hatchling",
    "packaging",
    "pathspec",
    "pluggy",
    "trove-classifiers",
}
_EXACT_REQUIREMENT = re.compile(r"^([a-z0-9-]+)==([^\s\\]+) \\$", re.MULTILINE)


def _project_config() -> dict[str, object]:
    with _PYPROJECT.open("rb") as stream:
        return tomllib.load(stream)


def test_build_root_and_uv_are_exactly_selected() -> None:
    config = _project_config()
    build_system = config["build-system"]
    dependency_groups = config["dependency-groups"]
    uv_config = config["tool"]["uv"]

    assert build_system["requires"] == ["hatchling==1.31.0"]
    assert dependency_groups["build"] == build_system["requires"]
    assert uv_config["required-version"] == "==0.11.17"


def test_build_constraints_are_exact_complete_and_hashed() -> None:
    text = _CONSTRAINTS.read_text(encoding="utf-8")
    requirements = list(_EXACT_REQUIREMENT.finditer(text))

    assert {match.group(1) for match in requirements} == _EXPECTED_BUILD_PACKAGES
    assert " @ " not in text
    assert ">=" not in text
    assert "<=" not in text
    assert "~=" not in text

    for index, requirement in enumerate(requirements):
        end = requirements[index + 1].start() if index + 1 < len(requirements) else len(text)
        block = text[requirement.start() : end]
        assert "--hash=sha256:" in block, f"{requirement.group(1)} has no artifact hash"


def test_build_constraints_match_frozen_build_group(tmp_path: Path) -> None:
    uv_exe = shutil.which("uv")
    assert uv_exe is not None, "uv is required to verify build constraints"
    exported = tmp_path / "build-constraints.txt"
    result = subprocess.run(  # noqa: S603 - fixed dev-tool argv, no shell.
        [
            uv_exe,
            "export",
            "--frozen",
            "--only-group",
            "build",
            "--no-emit-project",
            "--format",
            "requirements.txt",
            "--no-header",
            "--output-file",
            str(exported),
        ],
        cwd=_REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert exported.read_bytes() == _CONSTRAINTS.read_bytes()


def test_artifact_workflows_select_required_uv_version() -> None:
    required_version = _project_config()["tool"]["uv"]["required-version"].removeprefix("==")

    uv_step_count = 0
    for path in sorted(_WORKFLOW_DIR.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        uv_steps = [
            step
            for job in workflow["jobs"].values()
            for step in job["steps"]
            if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
        ]
        uv_step_count += len(uv_steps)
        for step in uv_steps:
            assert step.get("with", {}).get("version") == required_version, (
                f"{path.name} job step {step.get('name')!r} does not select uv {required_version}"
            )
    assert uv_step_count > 0
