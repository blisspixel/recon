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
_BUILD_CONSTRAINT_ARGS = "--build-constraints build-constraints.txt --require-hashes"

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
    """The build job creates no project environment and seals immediately."""

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

    def test_build_job_has_only_required_executable_steps(self, workflow):
        """Keep the artifact workspace free of a synced project environment.

        The setup actions install Git, uv, and Python. The only shell commands
        set the deterministic timestamp and invoke the isolated build backend.
        Artifact upload must be the next executable step after the build.
        """
        steps = _steps(workflow["jobs"]["build"])
        run_steps = [step["run"] for step in steps if isinstance(step.get("run"), str)]
        assert len(run_steps) == 2
        assert "SOURCE_DATE_EPOCH=" in run_steps[0]
        build_lines = [line.strip() for line in run_steps[1].splitlines() if line.strip()]
        assert build_lines == [
            f"uv build --sdist --out-dir dist {_BUILD_CONSTRAINT_ARGS}",
            f"uv build --wheel dist/recon_tool-*.tar.gz --out-dir dist {_BUILD_CONSTRAINT_ARGS}",
        ]

        action_steps = [step["uses"] for step in steps if isinstance(step.get("uses"), str)]
        assert len(action_steps) == 4
        for action, expected in zip(
            action_steps,
            (
                "actions/checkout@",
                "astral-sh/setup-uv@",
                "actions/setup-python@",
                "actions/upload-artifact@",
            ),
            strict=True,
        ):
            assert action.startswith(expected)

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
                f"build job step {step.get('name')!r} touches SBOM output; SBOM belongs in the dedicated sbom job."
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


class TestPackageSmokeJob:
    """A low-privilege job must execute the sealed wheel before publication."""

    def test_package_smoke_consumes_dist_and_runs_both_entry_points(self, workflow):
        job = workflow["jobs"]["package-smoke"]
        text = "\n".join(_step_text(step) for step in _steps(job))
        needs = job.get("needs")

        assert needs == "build"
        assert job["permissions"] == {"contents": "read"}
        assert "actions/download-artifact@" in text
        assert "name=dist" in text
        assert "artifacts=(dist/*)" in text
        assert "sdists=(dist/recon_tool-*.tar.gz)" in text
        assert 'version="${GITHUB_REF_NAME#v}"' in text
        assert 'expected_wheel="dist/recon_tool-${version}-py3-none-any.whl"' in text
        assert 'expected_sdist="dist/recon_tool-${version}.tar.gz"' in text
        assert '"${#artifacts[@]}" -ne 2' in text
        assert '"${#sdists[@]}" -ne 1' in text
        assert '"$wheel" != "$expected_wheel"' in text
        assert '"${sdists[0]}" != "$expected_sdist"' in text
        assert 'uv tool run --isolated --from "$wheel" recon --version' in text
        assert 'uv run --no-project --isolated --with "$wheel" python -m recon_tool --version' in text
        assert job.get("permissions", {}).get("id-token") != _PERM_WRITE

    def test_publication_waits_for_package_smoke(self, workflow):
        for name in ("publish-pypi", "github-release"):
            needs = workflow["jobs"][name]["needs"]
            assert "package-smoke" in needs, f"{name} must wait for the sealed-wheel smoke test"


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
            if isinstance(step.get("uses"), str) and step["uses"].startswith("actions/upload-artifact")
        ]
        assert uploads, "sbom job must upload at least one artifact"
        assert any(isinstance(s.get("with"), dict) and s["with"].get("name") == "sbom" for s in uploads), (
            "sbom job must upload an artifact named 'sbom'"
        )

    def test_sbom_job_validates_complete_project_bom(self, workflow):
        text = "\n".join(_step_text(step) for step in _steps(workflow["jobs"]["sbom"]))
        assert "scripts/finalize_sbom.py" in text
        assert "test -s" in text
        assert "audit_status" in text
        assert 'if [ "$audit_status" -ne 0 ]; then' in text
        assert '"$audit_status" -gt 1' not in text
        assert "|| true" not in text

    def test_sbom_job_seals_only_the_exact_expected_regular_file(self, workflow):
        text = "\n".join(_step_text(step) for step in _steps(workflow["jobs"]["sbom"]))

        assert "shopt -s nullglob dotglob" in text
        assert 'sbom_entries=(sbom/*)' in text
        assert '"${#sbom_entries[@]}" -ne 1' in text
        assert '"${sbom_entries[0]}" != "$expected_sbom"' in text
        assert '[ -L "$expected_sbom" ]' in text


class TestAttestationJob:
    """The signed subject set must cover every completed release artifact."""

    def test_attestation_waits_for_and_downloads_dist_and_sbom(self, workflow):
        job = workflow["jobs"]["attest"]
        assert set(job["needs"]) == {"build", "sbom"}
        downloads = [
            step.get("with", {}).get("name")
            for step in _steps(job)
            if str(step.get("uses", "")).startswith("actions/download-artifact@")
        ]
        assert downloads == ["dist", "sbom"]

    def test_attestation_subject_set_includes_completed_sbom(self, workflow):
        job = workflow["jobs"]["attest"]
        attest_step = next(
            step for step in _steps(job) if str(step.get("uses", "")).startswith("actions/attest-build-provenance@")
        )
        subjects = str(attest_step["with"]["subject-path"]).splitlines()

        assert subjects == ["dist/*", "sbom/*"]


class TestProvenanceExportJob:
    """The release workflow must surface a Scorecard-recognized provenance asset
    without executing project dependency code."""

    def test_export_attestations_job_exists_and_waits_for_attestation(self, workflow):
        jobs = workflow.get("jobs", {})
        assert "export-attestations" in jobs, "release workflow must export attestation bundles for release assets"
        job = jobs["export-attestations"]
        needs = job.get("needs")
        if isinstance(needs, str):
            needs_list = [needs]
        elif isinstance(needs, list):
            needs_list = list(needs)
        else:
            needs_list = []

        assert "build" in needs_list, "export-attestations must wait for build (dist/)"
        assert "sbom" in needs_list, "export-attestations must wait for the completed SBOM"
        assert "attest" in needs_list, "export-attestations must wait for signed build provenance"
        assert job["permissions"] == {"contents": "read"}

    def test_export_attestations_downloads_all_subjects_and_uploads_provenance(self, workflow):
        job = workflow["jobs"]["export-attestations"]
        text = "\n".join(_step_text(step) for step in _steps(job))

        assert "gh attestation download" in text
        assert ".intoto.jsonl" in text
        assert "uv sync" not in text
        assert "uv run" not in text

        downloads = [
            step
            for step in _steps(job)
            if isinstance(step.get("uses"), str) and step["uses"].startswith("actions/download-artifact")
        ]
        uploads = [
            step
            for step in _steps(job)
            if isinstance(step.get("uses"), str) and step["uses"].startswith("actions/upload-artifact")
        ]
        assert any(isinstance(s.get("with"), dict) and s["with"].get("name") == "dist" for s in downloads), (
            "export-attestations must download the dist artifact"
        )
        assert any(isinstance(s.get("with"), dict) and s["with"].get("name") == "sbom" for s in downloads), (
            "export-attestations must download the completed SBOM"
        )
        assert '"$GITHUB_WORKSPACE"/dist/* "$GITHUB_WORKSPACE"/sbom/*' in text
        assert any(isinstance(s.get("with"), dict) and s["with"].get("name") == "provenance" for s in uploads), (
            "export-attestations must upload a provenance artifact"
        )


# Jobs allowed to hold id-token: write. The rule is not "only
# publish-pypi" but "only jobs that run NO project dependency code", so a
# compromised dependency cannot mint a token. publish-pypi downloads the
# sealed dist and publishes it; attest downloads the sealed dist and signs
# a provenance attestation. Both are dependency-free, asserted below. Any
# new entry here must come with the same dependency-free guarantee.
_OIDC_ALLOWED_JOBS = {"publish-pypi", "attest"}


class TestPublishJobIsHardened:
    """Only dependency-free jobs (publish-pypi, attest) may hold
    id-token: write. They must not install or execute project
    dependencies, and must not touch dist/ beyond downloading it."""

    def test_only_dependency_free_jobs_have_id_token_write(self, workflow):
        for name, job in workflow.get("jobs", {}).items():
            perms = job.get("permissions") or {}
            id_token = perms.get("id-token") if isinstance(perms, dict) else None
            if name in _OIDC_ALLOWED_JOBS:
                continue
            assert id_token != _PERM_WRITE, (
                f"job {name!r} has id-token: write — only the dependency-free jobs "
                f"{sorted(_OIDC_ALLOWED_JOBS)} may carry this scope. A compromised dep "
                "in any other job could otherwise mint a token and publish to PyPI "
                "under our trusted-publisher identity."
            )
        # publish-pypi must always carry it (OIDC trusted publishing).
        publish_perms = workflow["jobs"]["publish-pypi"].get("permissions") or {}
        assert publish_perms.get("id-token") == _PERM_WRITE, (
            "publish-pypi must have id-token: write for OIDC trusted publishing"
        )

    def test_publish_pypi_waits_for_provenance_attestation(self, workflow):
        publish = workflow["jobs"]["publish-pypi"]
        needs = publish.get("needs")
        if isinstance(needs, str):
            needs_list = [needs]
        elif isinstance(needs, list):
            needs_list = list(needs)
        else:
            needs_list = []

        assert "build" in needs_list, "publish-pypi must wait for build (dist/)"
        assert "attest" in needs_list, (
            "publish-pypi must wait for provenance attestation so a release "
            "cannot publish to PyPI if artifact attestation fails."
        )

    def test_id_token_jobs_do_not_install_or_run_deps(self, workflow):
        # Every job that mints an OIDC token must run no project dependency
        # code, so a compromised dep cannot execute under id-token: write.
        for name in _OIDC_ALLOWED_JOBS:
            job = workflow["jobs"].get(name)
            if job is None:
                continue
            for step in _steps(job):
                text = _step_text(step)
                assert "--extra dev" not in text, (
                    f"{name} step {step.get('name')!r} installs dev deps; "
                    "this job runs with id-token: write — keep the surface tiny."
                )
                assert "uv sync" not in text, (
                    f"{name} step {step.get('name')!r} runs uv sync; "
                    "this job downloads the sealed dist/ artifact only. Any code "
                    "execution under id-token: write widens the surface."
                )
                assert "uv run" not in text, (
                    f"{name} step {step.get('name')!r} runs uv run; "
                    "this job must execute no project code under id-token: write."
                )


class TestGithubReleaseAttachesBothArtifacts:
    """The github-release job must surface both the wheel/sdist and
    the SBOM so consumers can audit the supply chain."""

    def test_github_release_depends_on_build_attestation_and_sbom(self, workflow):
        gh = workflow["jobs"]["github-release"]
        needs = gh.get("needs")
        if isinstance(needs, str):
            needs_list = [needs]
        elif isinstance(needs, list):
            needs_list = list(needs)
        else:
            needs_list = []
        assert "build" in needs_list, "github-release must wait for build (dist/)"
        assert "attest" in needs_list, (
            "github-release must wait for provenance attestation so a release "
            "cannot publish GitHub assets if artifact attestation fails."
        )
        assert "export-attestations" in needs_list, (
            "github-release must wait for exported attestation bundles so the "
            "release exposes a Scorecard-recognized provenance asset."
        )
        assert "sbom" in needs_list, (
            "github-release must wait for sbom (SBOM artifact). Skipping the SBOM "
            "dependency means the release could ship without an SBOM if sbom fails."
        )

    def test_github_release_downloads_dist_sbom_and_provenance(self, workflow):
        gh = workflow["jobs"]["github-release"]
        names = []
        run_text = ""
        for step in _steps(gh):
            if isinstance(step.get("uses"), str) and step["uses"].startswith("actions/download-artifact"):
                with_block = step.get("with") or {}
                if isinstance(with_block, dict):
                    names.append(with_block.get("name"))
            run_text += _step_text(step)
        assert "dist" in names, "github-release must download the dist artifact"
        assert "sbom" in names, "github-release must download the sbom artifact"
        assert "provenance" in names, "github-release must download the provenance artifact"
        assert "provenance/*" in run_text, "github-release must attach exported provenance to the release"

    def test_existing_release_is_validated_before_assets_can_be_replaced(self, workflow):
        job = workflow["jobs"]["github-release"]
        text = "\n".join(_step_text(step) for step in _steps(job))

        metadata = "--json tagName,name,isDraft,isPrerelease,isImmutable,assets"
        validator = "python3 scripts/check_release_recovery.py"
        clobber = "gh release upload"
        remote_tag = "git ls-remote --exit-code --refs origin"
        assert metadata in text
        assert validator in text
        assert clobber in text
        assert remote_tag in text
        assert text.index(remote_tag) < text.index(metadata) < text.index(validator) < text.index(clobber)
        assert '"$remote_tag_sha" != "$GITHUB_SHA"' in text
        assert ">/dev/null" not in text
        assert "--verify-tag" in text


class TestPublishedChannelParity:
    """GitHub publication must not diverge from immutable PyPI files."""

    def test_parity_job_is_read_only_and_waits_for_pypi(self, workflow):
        job = workflow["jobs"]["verify-pypi-parity"]
        assert set(job["needs"]) == {"build", "publish-pypi"}
        assert job["permissions"] == {"contents": "read"}
        assert job["timeout-minutes"] == 10

    def test_parity_job_checks_out_safely_and_downloads_sealed_dist(self, workflow):
        steps = _steps(workflow["jobs"]["verify-pypi-parity"])
        checkout = next(step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@"))
        downloads = [
            step
            for step in steps
            if str(step.get("uses", "")).startswith("actions/download-artifact@")
        ]

        assert checkout["with"]["persist-credentials"] is False
        assert len(downloads) == 1
        assert downloads[0]["with"] == {"name": "dist", "path": "dist/"}

    def test_parity_job_runs_bounded_exact_pair_checker(self, workflow):
        text = "\n".join(_step_text(step) for step in _steps(workflow["jobs"]["verify-pypi-parity"]))

        assert "set -euo pipefail" in text
        assert "scripts/check_release_channel_parity.py" in text
        assert '--version "${VERSION#v}"' in text
        assert "--dist-dir dist" in text
        assert "--attempts 12" in text
        assert "--delay-seconds 10" in text

    def test_github_release_waits_for_channel_parity(self, workflow):
        assert "verify-pypi-parity" in workflow["jobs"]["github-release"]["needs"]
