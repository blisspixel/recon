"""Canonical local-gate orchestration regressions."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from scripts import check

_CI_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


def test_text_range_is_forwarded_only_to_text_hygiene(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        check,
        "_STAGES",
        [
            (check._CORE, "ruff", ["python", "-m", "ruff"]),
            (check._CORE, "text-hygiene", ["python", "scripts/check_text_hygiene.py"]),
        ],
    )

    def fake_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(check.subprocess, "run", fake_run)
    assert check.main(["--text-range", "v2.5.8..HEAD"]) == 0
    assert commands == [
        ["python", "-m", "ruff"],
        ["python", "scripts/check_text_hygiene.py", "--range", "v2.5.8..HEAD"],
    ]


@pytest.mark.parametrize("return_code", [0, 1])
def test_captured_gate_output_is_plain(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    return_code: int,
) -> None:
    monkeypatch.setattr(check, "_STAGES", [(check._CORE, "sample", ["python", "sample.py"])])

    def fake_run(_cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["python", "sample.py"], return_code, "", "")

    monkeypatch.setattr(check.subprocess, "run", fake_run)

    assert check.main(["--fast"]) == return_code
    output = capsys.readouterr().out
    assert "\x1b[" not in output
    assert ("All gate stages passed" if return_code == 0 else "1 stage(s) failed") in output


def test_color_capable_gate_output_retains_status_style(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(check, "_STAGES", [(check._CORE, "sample", ["python", "sample.py"])])
    monkeypatch.setattr(check, "_supports_color", lambda: True)

    def fake_run(_cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["python", "sample.py"], 0, "", "")

    monkeypatch.setattr(check.subprocess, "run", fake_run)

    assert check.main(["--fast"]) == 0
    assert "\x1b[" in capsys.readouterr().out


def test_pyright_scope_comes_only_from_pyproject() -> None:
    local_stage = next(command for _group, name, command in check._STAGES if name == "pyright")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert local_stage == [check._PY, "-m", "pyright"]
    assert "run: uv run pyright\n" in workflow
    assert "pyright src/recon_tool/ tests/" not in workflow


def test_ruff_scope_and_cache_policy_match_ci() -> None:
    local_stage = next(command for _group, name, command in check._STAGES if name == "ruff")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert local_stage == [check._PY, "-m", "ruff", "check", "--no-cache", "."]
    assert "run: uv run ruff check --no-cache .\n" in workflow


def test_ruff_format_scope_matches_ci() -> None:
    local_stage = next(command for _group, name, command in check._STAGES if name == "ruff-format")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert local_stage == [check._PY, "-m", "ruff", "format", "--check", "."]
    assert "run: uv run ruff format --check .\n" in workflow


def test_live_mcp_doctor_is_serial_and_appends_to_parallel_coverage() -> None:
    stages = {name: command for _group, name, command in check._STAGES}
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    parallel = stages["pytest+cov-parallel"]
    doctor = stages["pytest+cov-mcp-doctor"]

    assert "--ignore=tests/test_mcp_doctor.py" in parallel
    assert parallel[parallel.index("-n") + 1] == "auto"
    assert "--cov-report=" in parallel
    assert "--cov-fail-under=0" in parallel
    assert "tests/test_mcp_doctor.py" in doctor
    assert doctor[doctor.index("-n") + 1] == "0"
    assert "--cov-append" in doctor
    assert "--cov-fail-under=90.2" in doctor
    assert "Test parallel suite with coverage" in workflow
    assert "uv run pytest tests/ --ignore=tests/test_mcp_doctor.py" in workflow
    assert "Test live MCP doctor serially and enforce coverage" in workflow
    assert "uv run pytest tests/test_mcp_doctor.py -n 0" in workflow
    assert "--cov=src/recon_tool --cov-branch --cov-append" in workflow


def test_ci_runs_the_interface_layout_guard() -> None:
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert "run: uv run python scripts/check_interface_layout.py" in workflow


def test_default_claim_audit_is_wired_into_local_and_ci_gates() -> None:
    local_stage = next(command for _group, name, command in check._STAGES if name == "default-claim-audit")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert local_stage == [check._PY, "scripts/check_default_claim_audit.py"]
    assert "run: uv run python scripts/check_default_claim_audit.py" in workflow


def test_terminal_demo_is_wired_into_local_and_ci_gates() -> None:
    local_stage = next(command for _group, name, command in check._STAGES if name == "terminal-demo")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert local_stage == [check._PY, "scripts/generate_terminal_demo.py", "--check"]
    assert "run: uv run python scripts/generate_terminal_demo.py --check" in workflow


def test_agent_portability_contract_is_wired_into_local_and_ci_gates() -> None:
    local_stage = next(command for _group, name, command in check._STAGES if name == "agent-portability-contract")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert local_stage == [check._PY, "-m", "validation.agent_portability_contract"]
    assert "run: uv run python -m validation.agent_portability_contract" in workflow


def test_agent_plugin_candidate_is_wired_into_local_and_ci_gates() -> None:
    generated = next(command for _group, name, command in check._STAGES if name == "agent-plugin-generated")
    validated = next(command for _group, name, command in check._STAGES if name == "agent-plugin-candidate")
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")

    assert generated == [check._PY, "scripts/generate_agent_plugin.py", "--check"]
    assert validated == [check._PY, "scripts/check_agent_plugin.py"]
    assert "run: uv run python scripts/generate_agent_plugin.py --check" in workflow
    assert "run: uv run python scripts/check_agent_plugin.py" in workflow


def test_ci_gate_requires_every_other_main_workflow_job() -> None:
    workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    gate = jobs["ci-gate"]

    assert set(gate["needs"]) == set(jobs) - {"ci-gate"}
    assert gate["if"] == "always()"
    assert gate["steps"][0]["env"]["BLOCKING_RESULTS"] == "${{ toJSON(needs) }}"
    assert 'detail.get("result") != "success"' in gate["steps"][0]["run"]


def test_reproducible_build_smokes_built_wheel_entry_points() -> None:
    workflow = _CI_WORKFLOW.read_text(encoding="utf-8")
    build_commands = [line.strip() for line in workflow.splitlines() if line.strip().startswith("uv build")]

    assert "Smoke-test built wheel entry points" in workflow
    assert len(build_commands) == 2
    assert all("--build-constraints build-constraints.txt --require-hashes" in line for line in build_commands)
    assert 'uv build --sdist --out-dir "$out_dir"' in workflow
    assert 'uv build --wheel "${sdists[0]}" --out-dir "$out_dir"' in workflow
    assert 'uv tool run --isolated --from "$wheel" recon --version' in workflow
    assert 'uv run --no-project --isolated --with "$wheel" python -m recon_tool --version' in workflow
