"""Fail-closed retry semantics for the dependency-audit runner."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest
import yaml

from scripts import run_dependency_audit

ROOT = Path(__file__).resolve().parents[1]


def _result(returncode: int, *, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["pip-audit"], returncode, stdout, stderr)


class _Results:
    def __init__(self, *results: subprocess.CompletedProcess[str]) -> None:
        self._results = list(results)
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(arguments))
        return self._results.pop(0)


def test_success_returns_without_retry(capsys: pytest.CaptureFixture[str]) -> None:
    runner = _Results(_result(0, stdout="No known vulnerabilities found\n"))
    sleeps: list[float] = []

    assert run_dependency_audit.run(["-r", "locked.txt"], runner=runner, sleeper=sleeps.append) == 0
    assert runner.calls == [("-r", "locked.txt")]
    assert sleeps == []
    assert capsys.readouterr().out == "No known vulnerabilities found\n"


def test_vulnerability_result_is_never_retried(capsys: pytest.CaptureFixture[str]) -> None:
    runner = _Results(
        _result(
            1,
            stdout="Found 1 known vulnerability in 1 package\n",
            stderr="requests.exceptions.ConnectionError appears in unrelated diagnostic context\n",
        )
    )
    sleeps: list[float] = []

    assert run_dependency_audit.run(["-r", "locked.txt"], runner=runner, sleeper=sleeps.append) == 1
    assert len(runner.calls) == 1
    assert sleeps == []
    assert "retrying" not in capsys.readouterr().err


def test_recognized_transport_failure_retries_once(capsys: pytest.CaptureFixture[str]) -> None:
    runner = _Results(
        _result(1, stderr="requests.exceptions.ConnectionError: connection reset\n"),
        _result(0, stdout="No known vulnerabilities found\n"),
    )
    sleeps: list[float] = []

    assert run_dependency_audit.run(["-r", "locked.txt"], runner=runner, sleeper=sleeps.append) == 0
    assert runner.calls == [("-r", "locked.txt"), ("-r", "locked.txt")]
    assert sleeps == [3.0]
    captured = capsys.readouterr()
    assert "recognized transport failure; retrying once in 3 seconds" in captured.err
    assert "No known vulnerabilities found" in captured.out


def test_transport_failure_exhaustion_preserves_failure(capsys: pytest.CaptureFixture[str]) -> None:
    runner = _Results(
        _result(1, stderr="urllib3.exceptions.ProtocolError: reset\n"),
        _result(2, stderr="ConnectionResetError: reset again\n"),
    )
    sleeps: list[float] = []

    assert run_dependency_audit.run([], runner=runner, sleeper=sleeps.append) == 2
    assert len(runner.calls) == 2
    assert sleeps == [3.0]
    assert "transport failure persisted after one retry; audit remains failed" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("final_result", "expected_status"),
    [
        (_result(1, stdout="Found 1 known vulnerability in 1 package\n"), 1),
        (_result(2, stderr="pip-audit: error: malformed response\n"), 2),
    ],
)
def test_transport_retry_preserves_later_non_transport_failure(
    final_result: subprocess.CompletedProcess[str],
    expected_status: int,
) -> None:
    runner = _Results(
        _result(1, stderr="ConnectionResetError: initial reset\n"),
        final_result,
    )
    sleeps: list[float] = []

    assert run_dependency_audit.run([], runner=runner, sleeper=sleeps.append) == expected_status
    assert len(runner.calls) == 2
    assert sleeps == [3.0]


def test_unrecognized_failure_is_not_retried(capsys: pytest.CaptureFixture[str]) -> None:
    runner = _Results(_result(2, stderr="pip-audit: error: malformed requirements file\n"))
    sleeps: list[float] = []

    assert run_dependency_audit.run([], runner=runner, sleeper=sleeps.append) == 2
    assert len(runner.calls) == 1
    assert sleeps == []
    assert "retrying" not in capsys.readouterr().err


@pytest.mark.parametrize("collision_shape", ["module", "package"])
def test_pip_audit_module_resolution_ignores_checkout_shadow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collision_shape: str,
) -> None:
    marker = "SHADOWED_PIP_AUDIT_MODULE"
    if collision_shape == "module":
        (tmp_path / "pip_audit.py").write_text(f'print("{marker}")\n', encoding="utf-8")
    else:
        package = tmp_path / "pip_audit"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "__main__.py").write_text(f'print("{marker}")\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = run_dependency_audit._run_once(["--version"])

    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0
    assert marker not in output
    assert "pip-audit" in output


def test_enforcing_workflows_use_bounded_audit_runner() -> None:
    expected = "uv run python scripts/run_dependency_audit.py -r .ci-audit-requirements.txt"
    for relative, job_name in (
        (".github/workflows/ci.yml", "audit"),
        (".github/workflows/release.yml", "test"),
    ):
        workflow = yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))
        steps = workflow["jobs"][job_name]["steps"]
        audit_step = next(step for step in steps if step.get("name") == "Audit dependencies")
        assert audit_step["run"] == expected
        assert "continue-on-error" not in audit_step
        assert "uv run pip-audit" not in "\n".join(str(step.get("run", "")) for step in steps)


def test_dependency_audit_guidance_matches_fail_closed_workflows() -> None:
    guidance = {
        relative: (ROOT / relative).read_text(encoding="utf-8")
        for relative in (
            "docs/release-process.md",
            "docs/security.md",
            "docs/supply-chain.md",
        )
    }

    normalized = {relative: " ".join(text.split()) for relative, text in guidance.items()}
    assert all("Python isolated mode" in text for text in normalized.values())
    assert all("every nonzero audit status" in text.casefold() for text in normalized.values())
    assert "Findings may coexist with this artifact" not in guidance["docs/release-process.md"]
    assert "may emit an artifact when findings exist" not in guidance["docs/supply-chain.md"]
