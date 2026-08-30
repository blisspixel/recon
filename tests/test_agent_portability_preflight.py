"""Tests for the private v2.15 representative-client preflight."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts import check_agent_plugin
from validation import prepare_agent_portability_evaluation as preflight

STOP_MEMO = preflight.ROOT / "validation" / "2026-08-14-agent-portability-preflight.md"
READY_MEMO = preflight.ROOT / "validation" / "2026-08-20-agent-portability-preflight.md"


def _probe(command: str, *, version: str | None, status: str = "ready") -> dict[str, object]:
    return {
        "command": command,
        "resolved_path": f"/private/{command}",
        "version": version,
        "version_output_sha256": "a" * 64 if version is not None else None,
        "status": status,
        "detail": None if status == "ready" else f"{command} is {status}",
    }


def test_version_parser_accepts_client_and_runtime_forms() -> None:
    assert preflight._version_from_output(b"1.99.3\ncommit\nx64\n", label="client")[0] == "1.99.3"
    assert preflight._version_from_output(b"recon 2.14.0\n", label="runtime")[0] == "2.14.0"


def test_version_parser_rejects_unbounded_or_versionless_output() -> None:
    version, detail = preflight._version_from_output(b"x" * 4097, label="client")
    assert version is None
    assert "exceeded" in detail
    version, detail = preflight._version_from_output(b"no version here", label="client")
    assert version is None
    assert "semantic version" in detail


def test_probe_uses_resolved_executable_without_a_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "client.exe"
    executable.write_bytes(b"placeholder")
    observed: dict[str, Any] = {}

    def find_executable(_command: str) -> str:
        return str(executable)

    monkeypatch.setattr(preflight.shutil, "which", find_executable)

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=b"3.4.5\n", stderr=b"")

    monkeypatch.setattr(preflight.subprocess, "run", fake_run)
    result = preflight._probe_version("client", label="Client")

    assert result["status"] == "ready"
    assert result["version"] == "3.4.5"
    assert observed["command"] == [str(executable.resolve()), "--version"]
    assert observed["shell"] is False
    assert observed["timeout"] == preflight.COMMAND_TIMEOUT_SECONDS


def test_probe_reports_missing_and_timeout_without_paths_in_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_executable(_command: str) -> None:
        return None

    monkeypatch.setattr(preflight.shutil, "which", missing_executable)
    assert preflight._probe_version("missing", label="Client")["status"] == "missing"

    executable = tmp_path / "client.exe"
    executable.write_bytes(b"placeholder")

    def find_executable(_command: str) -> str:
        return str(executable)

    monkeypatch.setattr(preflight.shutil, "which", find_executable)

    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired("client", 10)

    monkeypatch.setattr(preflight.subprocess, "run", timeout)
    result = preflight._probe_version("client", label="Client")
    assert result["status"] == "error"
    assert result["detail"] == "Client version probe failed: TimeoutExpired"


def test_prepare_preflight_is_ready_only_when_every_frozen_gate_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The frozen gate is "the recon that launches the client must be the exact
    # candidate under evaluation", so the runtime version is derived from the
    # candidate rather than pinned to a literal. A literal would make every
    # ordinary version bump look like a contract breach.
    candidate_version, _digest = check_agent_plugin.validate_candidate()
    versions = {"recon": candidate_version, "code": "1.99.3", "cursor": "2.1.0", "kiro": "0.12.263"}

    def ready_probe(command: str, *, label: str) -> dict[str, object]:
        del label
        return _probe(command, version=versions[command])

    monkeypatch.setattr(preflight, "_probe_version", ready_probe)

    report = preflight.prepare_preflight(runtime_command="recon", recorded_at="2026-08-14T10:00:00Z")

    assert report["ready_for_collection"] is True
    assert report["stop_reasons"] == []
    assert report["sessions_started"] == 0
    assert report["network_requests"] == 0
    assert len(str(report["implementation_digest_sha256"])) == 64
    assert len(str(report["report_digest_sha256"])) == 64


def test_prepare_preflight_records_stop_reasons_without_starting_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_probe(command: str, *, label: str) -> dict[str, object]:
        del label
        if command == "recon":
            return _probe(command, version="2.6.3")
        if command == "cursor":
            return _probe(command, version=None, status="missing")
        return _probe(command, version="1.2.3")

    monkeypatch.setattr(preflight, "_probe_version", fake_probe)
    report = preflight.prepare_preflight(runtime_command="recon", recorded_at="2026-08-14T10:00:00Z")

    assert report["ready_for_collection"] is False
    assert report["stop_reasons"] == ["runtime-version-mismatch", "required-client-cursor-missing"]
    assert report["sessions_started"] == 0


def test_prepare_preflight_requires_exact_client_override_set() -> None:
    with pytest.raises(preflight.PreflightError, match="vscode, cursor, and kiro exactly"):
        preflight.prepare_preflight(runtime_command="recon", client_commands={"vscode": "code"})


def test_write_preflight_is_private_contained_and_exclusive(tmp_path: Path) -> None:
    output_root = tmp_path / "private"
    output = output_root / "run" / "preflight.json"
    report = {"private": True, "ready_for_collection": False}

    assert preflight.write_preflight(report, output, output_root=output_root) == output.resolve()
    assert json.loads(output.read_text(encoding="utf-8")) == report
    with pytest.raises(preflight.PreflightError, match="refusing to replace"):
        preflight.write_preflight(report, output, output_root=output_root)
    with pytest.raises(preflight.PreflightError, match="must stay under"):
        preflight.write_preflight(report, tmp_path / "outside.json", output_root=output_root)
    with pytest.raises(preflight.PreflightError, match=r"\.json suffix"):
        preflight.write_preflight(report, output_root / "report.txt", output_root=output_root)


def test_cli_reports_only_aggregate_state_and_returns_stop_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report: dict[str, object] = {
        "schema_version": 1,
        "round_id": "agent-portability-v2.15-20260814",
        "contract_digest_sha256": "a" * 64,
        "implementation_digest_sha256": "c" * 64,
        "candidate": {"version": "2.14.0", "package_digest_sha256": "b" * 64},
        "runtime": {"resolved_path": "C:/private/recon.exe", "version": "2.6.3", "status": "version-mismatch"},
        "clients": [
            {"id": "vscode", "version": "1.99.3", "status": "ready", "resolved_path": "C:/private/code.exe"},
            {"id": "cursor", "version": None, "status": "missing", "resolved_path": None},
            {"id": "kiro", "version": "0.12.263", "status": "ready", "resolved_path": "C:/private/kiro.exe"},
        ],
        "ready_for_collection": False,
        "stop_reasons": ["runtime-version-mismatch", "required-client-cursor-missing"],
    }

    def fake_prepare(**_kwargs: object) -> dict[str, object]:
        return report

    def fake_write(*_args: object, **_kwargs: object) -> Path:
        return tmp_path / "private.json"

    monkeypatch.setattr(preflight, "prepare_preflight", fake_prepare)
    monkeypatch.setattr(preflight, "write_preflight", fake_write)

    code = preflight.main(["--runtime-command", "C:/private/recon.exe", "--output", str(tmp_path / "private.json")])
    captured = capsys.readouterr()

    assert code == 3
    assert "C:/private" not in captured.out
    assert '"paths_printed": 0' in captured.out
    assert captured.err == ""


def test_cli_requires_explicit_runtime_command() -> None:
    with pytest.raises(SystemExit) as exc:
        preflight.main(["--output", "preflight.json"])
    assert exc.value.code == 2


def test_public_stop_memo_is_disclosure_safe_and_preserves_the_historical_result() -> None:
    text = STOP_MEMO.read_text(encoding="utf-8")

    assert "403a5860dc547ab0fd8961023d196e0b72ec6524ed2c1cb7da4253899628eafe" in text
    assert "e424ec0a9e27e2ee422b63c5fe983a556ee65e78f98cf50adf4e45b59daef1cf" in text
    assert "b0ab3db1932db421945eee6cee6428109d056c63fa1a4c86409d63dcf3d91eed" in text
    assert "`ready_for_collection` is `false`" in text
    assert "Sessions started: 0. Network requests: 0." in text
    assert "Cursor | not observed" in text
    assert "2.6.3" in text
    assert "2.14.0" in text
    assert "C:\\" not in text
    assert "/Users/" not in text
    assert "compatibility result" in text


def test_public_ready_memo_is_disclosure_safe_and_preserves_its_historical_preflight() -> None:
    text = READY_MEMO.read_text(encoding="utf-8")

    assert "403a5860dc547ab0fd8961023d196e0b72ec6524ed2c1cb7da4253899628eafe" in text
    assert "e81a7570478e95ee6d118e7d2fea3009d4956aa9e70f55a89b0a6a803df98b63" in text
    assert "d428a99fc1845eddbb3948297734d96174e4d81a75f7a9923a0eead8c40c21a2" in text
    assert "8ae8de2ad52d3d38cecfb38b549339b03ab55d45e110968a1065403325b15f44" in text
    assert "`ready_for_collection` is `true`" in text
    assert "Sessions started: 0. Network requests: 0." in text
    assert "Visual Studio Code | `1.132.0`" in text
    assert "Cursor | `3.16.29`" in text
    assert "Kiro | `1.0.309`" in text
    assert "C:\\" not in text
    assert "/Users/" not in text
    assert "compatibility result" in text
