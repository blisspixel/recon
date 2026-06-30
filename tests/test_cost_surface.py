"""Cost-surface guard regressions."""

from __future__ import annotations

from pathlib import Path

from scripts import check_cost_surface


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_minimal_project(
    root: Path,
    *,
    dependencies: str = '"httpx>=0.27"',
    packages: str = '"src/recon_tool"',
) -> None:
    _write(
        root,
        "pyproject.toml",
        f"""
[project]
dependencies = [{dependencies}]

[tool.hatch.build.targets.wheel]
packages = [{packages}]
""",
    )
    _write(root, "src/recon_tool/__init__.py", "__version__ = '0.0.0'\n")
    _write(root, ".github/workflows/ci.yml", "name: CI\njobs: {{}}\n")


def test_clean_runtime_dependencies_and_workflows_pass(tmp_path: Path) -> None:
    _write_minimal_project(tmp_path)

    assert check_cost_surface.find_violations(tmp_path) == []


def test_paid_runtime_dependency_fails(tmp_path: Path) -> None:
    _write_minimal_project(tmp_path, dependencies='"httpx>=0.27", "openai>=1"')

    violations = check_cost_surface.find_violations(tmp_path)

    assert len(violations) == 1
    assert violations[0].path == "pyproject.toml"
    assert "openai" in violations[0].detail


def test_runtime_api_key_marker_fails(tmp_path: Path) -> None:
    _write_minimal_project(tmp_path)
    _write(tmp_path, "src/recon_tool/provider.py", "KEY = 'XAI_API_KEY'\n")

    violations = check_cost_surface.find_violations(tmp_path)

    assert len(violations) == 1
    assert violations[0].path == "src/recon_tool/provider.py"
    assert violations[0].line == 1
    assert "paid model provider key" in violations[0].detail


def test_workflow_paid_provider_secret_fails(tmp_path: Path) -> None:
    _write_minimal_project(tmp_path)
    _write(
        tmp_path,
        ".github/workflows/llm.yml",
        """
name: paid
jobs:
  run:
    steps:
      - run: python -m validation.agentic_ux.run --provider xai
        env:
          XAI_API_KEY: ${{ secrets.XAI_API_KEY }}
""",
    )

    violations = check_cost_surface.find_violations(tmp_path)

    details = [violation.detail for violation in violations]
    assert any("manual paid validation harness" in detail for detail in details)
    assert any("paid model provider key" in detail for detail in details)


def test_validation_only_paid_provider_harness_is_allowed_when_not_packaged(tmp_path: Path) -> None:
    _write_minimal_project(tmp_path)
    _write(
        tmp_path,
        "validation/agentic_ux/providers.py",
        "client = openai.OpenAI(api_key='test', base_url='https://api.x.ai/v1')\nKEY = 'XAI_API_KEY'\n",
    )

    assert check_cost_surface.find_violations(tmp_path) == []


def test_wheel_package_scope_must_not_include_validation(tmp_path: Path) -> None:
    _write_minimal_project(tmp_path, packages='"src/recon_tool", "validation"')

    violations = check_cost_surface.find_violations(tmp_path)

    assert len(violations) == 1
    assert violations[0].path == "pyproject.toml"
    assert "wheel packages" in violations[0].detail
