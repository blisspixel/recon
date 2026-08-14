"""Prepare a private, fail-closed v2.15 representative-client evaluation.

The preflight is network-free. It validates the frozen public contract and the
schema-pinned candidate, records exact local client and recon versions, and
stops before any client session when a required executable is unavailable or
the runtime version does not match the candidate.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import yaml

from scripts.check_agent_plugin import CandidateError, validate_candidate
from scripts.generate_agent_plugin import GenerationError, rendered_files
from validation.agent_portability_contract import (
    DEFAULT_CONTRACT,
    ContractError,
    load_contract,
    validate_contract,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = ROOT / "validation" / "agent-portability-local"
MAX_COMMAND_LENGTH = 1024
MAX_VERSION_OUTPUT_BYTES = 4096
COMMAND_TIMEOUT_SECONDS = 10
SCHEMA_VERSION = 1

_CLIENT_COMMANDS = {
    "vscode": "code",
    "cursor": "cursor",
    "kiro": "kiro",
}
_IMPLEMENTATION_FILES = (
    Path(__file__),
    ROOT / "validation" / "agent_portability_contract.py",
    ROOT / "scripts" / "check_agent_plugin.py",
    ROOT / "scripts" / "generate_agent_plugin.py",
)
_VERSION_PATTERN = re.compile(r"(?<![0-9A-Za-z])v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?![0-9A-Za-z])")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class PreflightError(ValueError):
    """Raised when a safe, reproducible preflight cannot be prepared."""


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _report_digest(payload: Mapping[str, object]) -> str:
    canonical = dict(payload)
    canonical.pop("report_digest_sha256", None)
    return _digest(_canonical_bytes(canonical))


def _candidate_digest(files: Mapping[Path, bytes]) -> str:
    digest = hashlib.sha256()
    for path, content in sorted(files.items(), key=lambda item: item[0].as_posix()):
        relative = path.resolve().relative_to(ROOT.resolve()).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _implementation_digest(paths: Sequence[Path] = _IMPLEMENTATION_FILES) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.as_posix()):
        relative = path.resolve().relative_to(ROOT.resolve()).as_posix().encode("utf-8")
        content = path.read_text(encoding="utf-8").encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _safe_command(value: str, *, label: str) -> str:
    if not value or len(value) > MAX_COMMAND_LENGTH:
        raise PreflightError(f"{label} must be between 1 and {MAX_COMMAND_LENGTH} characters")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise PreflightError(f"{label} contains a control character")
    return value


def _version_from_output(raw: bytes, *, label: str) -> tuple[str | None, str]:
    if len(raw) > MAX_VERSION_OUTPUT_BYTES:
        return None, f"{label} --version output exceeded {MAX_VERSION_OUTPUT_BYTES} bytes"
    text = raw.decode("utf-8", errors="replace")
    text = _CONTROL_CHARACTERS.sub("", text).strip()
    match = _VERSION_PATTERN.search(text)
    if match is None:
        return None, f"{label} --version did not contain a semantic version"
    return match.group(1), _digest(text.encode("utf-8"))


def _probe_version(command: str, *, label: str) -> dict[str, object]:
    safe_command = _safe_command(command, label=f"{label} command")
    resolved = shutil.which(safe_command)
    if resolved is None:
        return {
            "command": safe_command,
            "resolved_path": None,
            "version": None,
            "version_output_sha256": None,
            "status": "missing",
            "detail": f"{label} executable was not found",
        }
    resolved_path = Path(resolved).resolve()
    if not resolved_path.is_file():
        return {
            "command": safe_command,
            "resolved_path": str(resolved_path),
            "version": None,
            "version_output_sha256": None,
            "status": "invalid",
            "detail": f"{label} command did not resolve to a regular file",
        }
    try:
        completed = subprocess.run(  # noqa: S603 - resolved executable, no shell
            [str(resolved_path), "--version"],
            capture_output=True,
            check=False,
            shell=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "command": safe_command,
            "resolved_path": str(resolved_path),
            "version": None,
            "version_output_sha256": None,
            "status": "error",
            "detail": f"{label} version probe failed: {type(exc).__name__}",
        }
    combined = completed.stdout + (b"\n" if completed.stdout and completed.stderr else b"") + completed.stderr
    version, output_digest = _version_from_output(combined, label=label)
    if completed.returncode != 0:
        return {
            "command": safe_command,
            "resolved_path": str(resolved_path),
            "version": version,
            "version_output_sha256": output_digest if version is not None else None,
            "status": "error",
            "detail": f"{label} --version exited with code {completed.returncode}",
        }
    if version is None:
        return {
            "command": safe_command,
            "resolved_path": str(resolved_path),
            "version": None,
            "version_output_sha256": None,
            "status": "invalid",
            "detail": output_digest,
        }
    return {
        "command": safe_command,
        "resolved_path": str(resolved_path),
        "version": version,
        "version_output_sha256": output_digest,
        "status": "ready",
        "detail": None,
    }


def _timestamp(value: str | None) -> str:
    timestamp = value or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PreflightError("recorded_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise PreflightError("recorded_at must carry the UTC timezone")
    return timestamp


def prepare_preflight(
    *,
    runtime_command: str,
    contract_path: Path = DEFAULT_CONTRACT,
    client_commands: Mapping[str, str] | None = None,
    recorded_at: str | None = None,
) -> dict[str, object]:
    """Return a private preflight report without starting any client session."""

    contract = load_contract(contract_path)
    contract_digest = validate_contract(contract)
    candidate_version, candidate_contract_digest = validate_candidate()
    if candidate_contract_digest != contract_digest:
        raise PreflightError("candidate and preflight contract digests differ")

    try:
        expected = rendered_files()
    except (GenerationError, OSError, UnicodeError, tomllib.TOMLDecodeError, yaml.YAMLError) as exc:
        raise PreflightError(f"could not regenerate the Agent Plugins candidate: {exc}") from exc
    stale = [path for path, content in expected.items() if not path.is_file() or path.read_bytes() != content]
    if stale:
        raise PreflightError("generated Agent Plugins candidate is stale")

    requested_commands = dict(_CLIENT_COMMANDS)
    if client_commands is not None:
        if set(client_commands) != set(_CLIENT_COMMANDS):
            raise PreflightError("client command overrides must name vscode, cursor, and kiro exactly")
        requested_commands.update(client_commands)

    runtime = _probe_version(runtime_command, label="recon runtime")
    stop_reasons: list[str] = []
    if runtime["status"] != "ready":
        stop_reasons.append(f"runtime-{runtime['status']}")
    elif runtime["version"] != candidate_version:
        runtime["status"] = "version-mismatch"
        runtime["detail"] = "runtime version does not match the candidate version"
        stop_reasons.append("runtime-version-mismatch")

    raw_clients = cast(list[object], contract["clients"])
    clients: list[dict[str, object]] = []
    for raw_client in raw_clients:
        client = cast(dict[str, object], raw_client)
        client_id = cast(str, client["id"])
        probe = _probe_version(requested_commands[client_id], label=cast(str, client["name"]))
        probe.update({"id": client_id, "name": client["name"], "required": client["required"]})
        clients.append(probe)
        if client["required"] is True and probe["status"] != "ready":
            stop_reasons.append(f"required-client-{client_id}-{probe['status']}")

    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "round_id": contract["round_id"],
        "recorded_at": _timestamp(recorded_at),
        "contract_digest_sha256": contract_digest,
        "implementation_digest_sha256": _implementation_digest(),
        "candidate": {
            "version": candidate_version,
            "package_digest_sha256": _candidate_digest(expected),
            "generated_current": True,
            "offline_validation_passed": True,
        },
        "runtime": runtime,
        "clients": clients,
        "ready_for_collection": not stop_reasons,
        "stop_reasons": stop_reasons,
        "sessions_started": 0,
        "network_requests": 0,
    }
    report["report_digest_sha256"] = _report_digest(report)
    return report


def _private_output(path: Path, *, output_root: Path = DEFAULT_OUTPUT_ROOT) -> Path:
    resolved_root = output_root.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise PreflightError("preflight output must stay under validation/agent-portability-local") from exc
    if resolved == resolved_root:
        raise PreflightError("preflight output must name a JSON file")
    if resolved.suffix.casefold() != ".json":
        raise PreflightError("preflight output must use a .json suffix")
    return resolved


def write_preflight(
    report: Mapping[str, object],
    output: Path,
    *,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
) -> Path:
    """Write one private report exclusively and never replace prior evidence."""

    resolved = _private_output(output, output_root=output_root)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor: int | None = None
    owned = False
    try:
        descriptor = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        owned = True
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
    except FileExistsError as exc:
        raise PreflightError("preflight output already exists; refusing to replace it") from exc
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        if owned:
            with contextlib.suppress(OSError):
                resolved.unlink()
        raise
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--runtime-command",
        required=True,
        help="Exact recon executable path that the evaluated desktop clients resolve.",
    )
    for client_id, command in _CLIENT_COMMANDS.items():
        parser.add_argument(f"--{client_id}-command", default=command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    commands = {client_id: getattr(args, f"{client_id}_command") for client_id in _CLIENT_COMMANDS}
    try:
        report = prepare_preflight(
            contract_path=args.contract,
            runtime_command=args.runtime_command,
            client_commands=commands,
        )
        write_preflight(report, args.output)
    except (CandidateError, ContractError, OSError, PreflightError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    candidate = cast(dict[str, object], report["candidate"])
    runtime = cast(dict[str, object], report["runtime"])
    clients = cast(list[dict[str, object]], report["clients"])
    summary = {
        "schema_version": report["schema_version"],
        "round_id": report["round_id"],
        "contract_digest_sha256": report["contract_digest_sha256"],
        "implementation_digest_sha256": report["implementation_digest_sha256"],
        "candidate_version": candidate["version"],
        "candidate_digest_sha256": candidate["package_digest_sha256"],
        "runtime": {"version": runtime["version"], "status": runtime["status"]},
        "clients": [
            {"id": client["id"], "version": client["version"], "status": client["status"]} for client in clients
        ],
        "ready_for_collection": report["ready_for_collection"],
        "stop_reasons": report["stop_reasons"],
        "sessions_started": 0,
        "paths_printed": 0,
        "network_requests": 0,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if report["ready_for_collection"] is True else 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
