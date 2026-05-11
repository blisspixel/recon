"""Regression tests for the release workflow supply-chain isolation contract.

These tests parse ``.github/workflows/release.yml`` and assert the
structural properties that prevent the audit finding "Dev deps can
tamper release artifacts" (HIGH, v1.9.3.1) from regressing. The
contract is documented in the release.yml header comment; this
file is the executable enforcement.

The threat the contract addresses: if a transitive dev dependency
of pip-audit (or pip-audit itself) is compromised at the locked
version, executing it in the same workspace as a built ``dist/``
allows the malicious code to tamper with the wheel and sdist
between ``uv build`` and ``actions/upload-artifact``. The fix is
workspace isolation — dev tooling and dist/ never share a runner.

These tests are textual / structural inspection only. They do not
run the workflow. They run cheaply on every pytest invocation and
catch a regression that would only otherwise be caught by a
post-mortem after a tampered release.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_RELEASE_YML = _REPO_ROOT / ".github" / "workflows" / "release.yml"

# GitHub Actions permission value, not a credential. Hoisted so ruff
# doesn't flag the literal string as a hardcoded password (S105).
_PERM_WRITE = "write"


@pytest.fixture(scope="module")
def workflow() -> dict[str, Any]:
    raw = yaml.safe_load(_RELEASE_YML.read_text(encoding="utf-8"))
    assert isinstance(raw, dict), "release.yml must parse to a mapping at top level"
    return raw


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    raw = job.get("steps")
    assert isinstance(raw, list), "job must have a steps list"
    return raw


def _step_text(step: dict[str, Any]) -> str:
    """Flatten a step's run script + uses + with for substring search.

    Deliberately excludes ``step.name`` because the human-readable step
    name often contains *descriptions* of the contract (e.g. "Sync runtime
    deps (no --extra dev)") which would generate false positives when
    searching for forbidden substrings. Contract assertions care about
    what executes (``run``) and what's pulled in (``uses``), not about
    how a step is labelled for the GitHub Actions UI.
    """
    parts: list[str] = []
    if isinstance(step.get("run"), str):
        parts.append(step["run"])
    if isinstance(step.get("uses"), str):
        parts.append(step["uses"])
    with_block = step.get("with")
    if isinstance(with_block, dict):
        for k, v in with_block.items():
            parts.append(f"{k}={v}")
    return "\n".join(parts)


class TestBuildJobIsPure:
    """The build job must not install dev deps or execute dependency code
    after ``uv build`` and before artifact upload."""

    def test_build_job_exists(self, workflow):
        jobs = workflow.get("jobs", {})
        assert "build" in jobs, "release workflow must have a 'build' job"

    def test_build_job_does_not_install_dev_extra(self, workflow):
        """The fix for the audit finding: ``uv sync --extra dev`` does
        NOT appear in the build job. Dev tooling lives in test/sbom
        jobs only."""
        build = workflow["jobs"]["build"]
        for step in _steps(build):
            text = _step_text(step)
            assert "--extra dev" not in text, (
                f"build job step {step.get('name')!r} installs the dev extra; "
                "this regresses the v1.9.3.3 supply-chain isolation contract. "
                "Dev tooling must run in the test or sbom jobs, never in build."
            )

    def test_build_job_does_not_run_pip_audit(self, workflow):
        """pip-audit is dev tooling. Running it in the build job —
        where dist/ exists between build and upload — is the exact
        audit finding v1.9.3.3 closes."""
        build = workflow["jobs"]["build"]
        for step in _steps(build):
            text = _step_text(step)
            assert "pip-audit" not in text, (
                f"build job step {step.get('name')!r} runs pip-audit; "
                "this is exactly the v1.9.3.1 audit finding. Move pip-audit "
                "to the test or sbom job."
            )

    def test_build_job_does_not_generate_sbom(self, workflow):
        """SBOM generation lives in its own job. The build job must
        not produce SBOM output — that would require dev tooling in
        the build workspace."""
        build = workflow["jobs"]["build"]
        for step in _steps(build):
            text = _step_text(step).lower()
            assert "cyclonedx" not in text, (
                f"build job step {step.get('name')!r} mentions cyclonedx; "
                "SBOM generation belongs in the dedicated sbom job."
            )
            assert "sbom" not in text, (
                f"build job step {step.get('name')!r} touches SBOM output; "
                "SBOM belongs in the dedicated sbom job."
            )

    def test_build_job_uploads_dist_immediately_after_build(self, workflow):
        """Between the ``uv build`` step and the ``upload-artifact`` step,
        only steps that do not execute project dependency code are
        allowed. In practice the contract is: no ``run`` step between
        them. We verify this by finding both steps and asserting no
        ``run:`` step sits between them."""
        build = workflow["jobs"]["build"]
        steps = _steps(build)
        build_idx = next(
            (i for i, s in enumerate(steps) if isinstance(s.get("run"), str) and "uv build" in s["run"]),
            None,
        )
        upload_idx = next(
            (
                i
                for i, s in enumerate(steps)
                if isinstance(s.get("uses"), str)
                and s["uses"].startswith("actions/upload-artifact")
                and isinstance(s.get("with"), dict)
                and s["with"].get("name") == "dist"
            ),
            None,
        )
        assert build_idx is not None, "build job must contain a 'uv build' step"
        assert upload_idx is not None, "build job must upload dist/ as the 'dist' artifact"
        assert upload_idx > build_idx, "dist upload must come after uv build"
        between = steps[build_idx + 1 : upload_idx]
        for step in between:
            assert "run" not in step, (
                f"build job has a 'run' step {step.get('name')!r} between "
                "'uv build' and dist upload — this violates the isolation "
                "contract. Move any post-build code execution to a separate job."
            )


class TestSbomJobIsIsolated:
    """The sbom job must run in a separate workspace and must not
    have access to dist/."""

    def test_sbom_job_exists(self, workflow):
        jobs = workflow.get("jobs", {})
        assert "sbom" in jobs, (
            "release workflow must have a separate 'sbom' job — SBOM generation "
            "cannot live in the build job per the v1.9.3.3 isolation contract."
        )

    def test_sbom_job_does_not_depend_on_build(self, workflow):
        """The sbom job must not have build/ as a dependency — if it
        did, GitHub would block sbom from starting until build finishes,
        which is fine for ordering but signals confusion about the
        threat model. The point is that sbom runs on a separate runner
        with no dist/. It can run in parallel with build."""
        sbom = workflow["jobs"]["sbom"]
        needs = sbom.get("needs")
        if isinstance(needs, str):
            needs_list = [needs]
        elif isinstance(needs, list):
            needs_list = list(needs)
        else:
            needs_list = []
        assert "build" not in needs_list, (
            "sbom job must not depend on build; that ties them temporally "
            "and obscures the workspace-isolation property. sbom should "
            "depend on test only (or nothing) so the parallel-runner "
            "isolation is structurally obvious."
        )

    def test_sbom_job_does_not_download_dist_artifact(self, workflow):
        """The sbom job must not download the dist/ artifact. If it did,
        a compromised pip-audit running in the sbom workspace could
        tamper with dist/ before it gets re-uploaded — defeating the
        whole isolation contract."""
        sbom = workflow["jobs"]["sbom"]
        for step in _steps(sbom):
            text = _step_text(step)
            if "download-artifact" in text:
                with_block = step.get("with") or {}
                assert with_block.get("name") != "dist", (
                    "sbom job downloads the dist/ artifact — this defeats the "
                    "isolation contract. SBOM generation derives from the locked "
                    "requirements text, not from the built wheel."
                )

    def test_sbom_job_uploads_sbom_artifact(self, workflow):
        """The sbom job must produce the sbom artifact for downstream
        consumption (github-release)."""
        sbom = workflow["jobs"]["sbom"]
        uploads = [
            step
            for step in _steps(sbom)
            if isinstance(step.get("uses"), str)
            and step["uses"].startswith("actions/upload-artifact")
        ]
        assert uploads, "sbom job must upload at least one artifact"
        assert any(
            isinstance(s.get("with"), dict) and s["with"].get("name") == "sbom"
            for s in uploads
        ), "sbom job must upload an artifact named 'sbom'"


class TestPublishJobIsHardened:
    """The publish-pypi job is the only job with id-token: write.
    It must not install or execute project dev dependencies, and must
    not touch dist/ beyond downloading and publishing."""

    def test_publish_pypi_is_only_job_with_id_token_write(self, workflow):
        for name, job in workflow.get("jobs", {}).items():
            perms = job.get("permissions") or {}
            id_token = perms.get("id-token") if isinstance(perms, dict) else None
            if name == "publish-pypi":
                assert id_token == _PERM_WRITE, (
                    "publish-pypi must have id-token: write for OIDC trusted publishing"
                )
            else:
                assert id_token != _PERM_WRITE, (
                    f"job {name!r} has id-token: write — only publish-pypi may carry this "
                    "scope. A compromised dep in any other job could otherwise mint a "
                    "token and publish to PyPI under our trusted-publisher identity."
                )

    def test_publish_pypi_does_not_install_dev_deps(self, workflow):
        publish = workflow["jobs"]["publish-pypi"]
        for step in _steps(publish):
            text = _step_text(step)
            assert "--extra dev" not in text, (
                f"publish-pypi step {step.get('name')!r} installs dev deps; "
                "this job runs with id-token: write — keep the surface tiny."
            )
            assert "uv sync" not in text, (
                f"publish-pypi step {step.get('name')!r} runs uv sync; "
                "this job downloads the sealed dist/ artifact and publishes it. "
                "Any code execution in this job runs with id-token: write — "
                "keep the surface tiny."
            )


class TestGithubReleaseAttachesBothArtifacts:
    """The github-release job must surface both the wheel/sdist and
    the SBOM so consumers can audit the supply chain."""

    def test_github_release_depends_on_build_and_sbom(self, workflow):
        gh = workflow["jobs"]["github-release"]
        needs = gh.get("needs")
        if isinstance(needs, str):
            needs_list = [needs]
        elif isinstance(needs, list):
            needs_list = list(needs)
        else:
            needs_list = []
        assert "build" in needs_list, "github-release must wait for build (dist/)"
        assert "sbom" in needs_list, (
            "github-release must wait for sbom (SBOM artifact). Skipping the SBOM "
            "dependency means the release could ship without an SBOM if sbom fails."
        )

    def test_github_release_downloads_dist_and_sbom(self, workflow):
        gh = workflow["jobs"]["github-release"]
        names = []
        for step in _steps(gh):
            if isinstance(step.get("uses"), str) and step["uses"].startswith("actions/download-artifact"):
                with_block = step.get("with") or {}
                if isinstance(with_block, dict):
                    names.append(with_block.get("name"))
        assert "dist" in names, "github-release must download the dist artifact"
        assert "sbom" in names, "github-release must download the sbom artifact"
