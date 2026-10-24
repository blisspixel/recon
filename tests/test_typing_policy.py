"""Exercise policy bypasses and actual pinned-checker boundary contracts."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from scripts import check_typing_policy as policy

_ROOT = Path(__file__).resolve().parents[1]


def _empty_root(root: Path) -> dict[str, object]:
    includes = [
        "src/recon_tool",
        "tests",
        "validation/corpus_aggregator.py",
        "validation/drift_check.py",
        "validation/quality_arm_identifiability.py",
        "scripts/check_typing_policy.py",
        "validation/catalog_result_input.py",
    ]
    for name in includes:
        path = root / name
        if path.suffix == ".py":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        else:
            path.mkdir(parents=True, exist_ok=True)
    config: dict[str, object] = {
        "typeCheckingMode": "strict",
        "include": includes,
        "pythonVersion": "3.11",
    }
    (root / "pyproject.toml").write_text(
        '[tool.pyright]\ntypeCheckingMode = "strict"\n'
        + "include = "
        + json.dumps(includes)
        + '\npythonVersion = "3.11"\n'
    )
    return config


def _ledger(config: dict[str, object]) -> dict[str, object]:
    return {"configuration": config, "file_controls": {}, "inline_controls": {}}


def test_unchanged_strict_policy_without_exceptions_passes(tmp_path: Path) -> None:
    config = _empty_root(tmp_path)
    assert policy.policy_problems(config, _ledger(config), tmp_path) == []


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"reportArgumentType": "none"}, "global diagnostic"),
        ({"executionEnvironments": [{"root": "tests"}]}, "execution-environment"),
        ({"include": ["src/recon_tool"]}, "scope must remain complete"),
        ({"ignore": ["tests"]}, "scope must remain complete"),
    ],
)
def test_global_or_environment_relaxations_fail_even_if_ledger_is_edited(
    tmp_path: Path, change: dict[str, object], expected: str
) -> None:
    config = {**_empty_root(tmp_path), **change}
    assert expected in " ".join(policy.policy_problems(config, _ledger(config), tmp_path))


@pytest.mark.parametrize(
    "directive",
    [
        "# pyright: reportUnknownMemberType=none",
        "#pyright: reportArgumentType=warning",
        "#pyright: basic",
        "#pyright: basic, reportUnknownMemberType=none",
    ],
)
def test_new_file_exception_and_new_inline_exception_are_unowned(tmp_path: Path, directive: str) -> None:
    config = _empty_root(tmp_path)
    source = tmp_path / "src/recon_tool/other.py"
    source.write_text(directive + "\nvalue = 1\n")
    assert "file-level" in " ".join(policy.policy_problems(config, _ledger(config), tmp_path))
    source.write_text("value = 1  # pyright: ignore[reportArgumentType]\n")
    assert "inline" in " ".join(policy.policy_problems(config, _ledger(config), tmp_path))


def test_repaired_boundary_cannot_regain_file_exceptions(tmp_path: Path) -> None:
    config = _empty_root(tmp_path)
    source = tmp_path / "src/recon_tool/json_limits.py"
    source.write_text("# pyright: reportUnknownArgumentType=none\n")
    files, inline = policy.controls(tmp_path)
    ledger = {"configuration": config, "file_controls": files, "inline_controls": inline}
    assert "repaired boundary" in " ".join(policy.policy_problems(config, ledger, tmp_path))


def test_same_count_different_diagnostic_identity_requires_review() -> None:
    before = {"diagnostics": {"tests/fixture.py": {"reportArgumentType": {"count": 1, "digest": "old"}}}}
    after = {"diagnostics": {"tests/fixture.py": {"reportArgumentType": {"count": 1, "digest": "new"}}}}
    assert policy.diagnostic_problems(before, {"audit": before}) == []
    assert policy.diagnostic_problems(after, {"audit": before})
    assert policy.diagnostic_problems({"diagnostics": {}}, {"audit": before})


def test_inline_exception_is_bound_to_tested_code(tmp_path: Path) -> None:
    _empty_root(tmp_path)
    source = tmp_path / "src/recon_tool/other.py"
    source.write_text("check(None)  # pyright: ignore[reportArgumentType]\n")
    first = policy.controls(tmp_path)
    source.write_text('check("changed")  # pyright: ignore[reportArgumentType]\n')
    assert policy.controls(tmp_path) != first


def test_audit_restores_file_rules_without_touching_code_or_inline_negative_tests() -> None:
    text = (
        "# pyright: reportPrivateUsage=false, reportUnknownArgumentType=none\n"
        "f(None)  # pyright: ignore[reportArgumentType]\n"
    )
    restored = policy._restore_diagnostics(text)  # pyright: ignore[reportPrivateUsage]
    assert (
        restored == "# pyright: reportPrivateUsage=error, reportUnknownArgumentType=error\n"
        "f(None)  # pyright: ignore[reportArgumentType]\n"
    )


def test_empty_checker_scope_is_never_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _empty_root(tmp_path)
    (tmp_path / "src/recon_tool/one.py").write_text("value: int = 1\n")
    result = subprocess.CompletedProcess(
        ["pyright"], returncode=0, stdout=json.dumps({"summary": {"filesAnalyzed": 0}, "generalDiagnostics": []})
    )

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return result

    monkeypatch.setattr(policy.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="wrong scope"):
        policy.audit(tmp_path)


def test_local_audit_diagnostics_identify_real_source_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _empty_root(tmp_path)
    (tmp_path / "src/recon_tool/one.py").write_text('value: int = "wrong"\n')
    expected_files = len(policy.checked_files(tmp_path))

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        copied = Path(command[-1])
        data = {
            "summary": {"filesAnalyzed": expected_files},
            "generalDiagnostics": [
                {
                    "file": str(copied / "src/recon_tool/one.py"),
                    "severity": "error",
                    "rule": "reportAssignmentType",
                    "range": {"start": {"line": 0}},
                    "message": f"wrong value in {copied}",
                }
            ],
        }
        return subprocess.CompletedProcess(command, returncode=1, stdout=json.dumps(data))

    monkeypatch.setattr(policy.subprocess, "run", fake_run)
    destination = tmp_path / "private-errors.json"
    measured = policy.audit(tmp_path, diagnostics_output=destination)
    assert measured["diagnostics"]["src/recon_tool/one.py"]["reportAssignmentType"]["count"] == 1
    assert json.loads(destination.read_text()) == [
        {
            "file": "src/recon_tool/one.py",
            "line": 1,
            "rule": "reportAssignmentType",
            "message": "wrong value in <checkout>",
        }
    ]


@pytest.mark.parametrize("fixture", ["valid", "invalid", "loader-boundary"])
def test_pinned_checker_accepts_checked_values_and_rejects_wrong_calls(tmp_path: Path, fixture: str) -> None:
    source = _ROOT / f"tests/fixtures/typing/{fixture}.py.txt"
    sample = tmp_path / "contract.py"
    sample.write_bytes(source.read_bytes())
    current = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pyright"]
    config = {
        **current,
        "include": ["contract.py"],
        "extraPaths": [str(_ROOT), str(_ROOT / "src")],
        "venvPath": str(_ROOT),
    }
    (tmp_path / "pyrightconfig.json").write_text(json.dumps(config))
    result = subprocess.run(  # noqa: S603 - pinned checker and repository-owned fixture, no fixture execution.
        [sys.executable, "-m", "pyright", "--outputjson", "--project", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode in (0, 1), result.stderr
    data = json.loads(result.stdout)
    assert data["summary"]["filesAnalyzed"] == 1
    actual = {
        item["range"]["start"]["line"] + 1: item["rule"]
        for item in data["generalDiagnostics"]
        if item["severity"] == "error"
    }
    expected = {
        number: line.split("# expected: ", 1)[1].strip()
        for number, line in enumerate(sample.read_text().splitlines(), 1)
        if "# expected: " in line
    }
    assert actual == expected, data
    assert result.returncode == (1 if expected else 0)
