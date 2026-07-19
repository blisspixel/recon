#!/usr/bin/env python3
"""Run pip-audit with one fail-closed retry for known transport faults."""

from __future__ import annotations

import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence

_MAX_ATTEMPTS = 2
_RETRY_DELAY_SECONDS = 3.0
_VULNERABILITY_SUMMARY = re.compile(r"\bFound \d+ known vulnerabilit(?:y|ies)\b")
_TRANSPORT_FAILURE_MARKERS = (
    "requests.exceptions.ConnectionError",
    "requests.exceptions.ConnectTimeout",
    "requests.exceptions.ReadTimeout",
    "urllib3.exceptions.ProtocolError",
    "ConnectionAbortedError",
    "ConnectionResetError",
    "Could not connect to PyPI's vulnerability feed",
    "PyPI is not redirecting properly",
)

AuditResult = subprocess.CompletedProcess[str]
AuditRunner = Callable[[Sequence[str]], AuditResult]
Sleeper = Callable[[float], None]


def _run_once(arguments: Sequence[str]) -> AuditResult:
    return subprocess.run(  # noqa: S603 - fixed interpreter/module, argv list, no shell.
        [sys.executable, "-I", "-m", "pip_audit", *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _replay(result: AuditResult) -> None:
    if result.stdout:
        sys.stdout.write(result.stdout)
        sys.stdout.flush()
    if result.stderr:
        sys.stderr.write(result.stderr)
        sys.stderr.flush()


def _is_retryable_transport_failure(result: AuditResult) -> bool:
    if result.returncode == 0:
        return False
    output = f"{result.stdout}\n{result.stderr}"
    if _VULNERABILITY_SUMMARY.search(output):
        return False
    return any(marker in output for marker in _TRANSPORT_FAILURE_MARKERS)


def run(
    arguments: Sequence[str],
    *,
    runner: AuditRunner = _run_once,
    sleeper: Sleeper = time.sleep,
) -> int:
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        result = runner(arguments)
        _replay(result)
        retryable = _is_retryable_transport_failure(result)
        if result.returncode == 0:
            return 0
        if retryable and attempt < _MAX_ATTEMPTS:
            print(
                "dependency audit: recognized transport failure; retrying once in "
                f"{_RETRY_DELAY_SECONDS:g} seconds",
                file=sys.stderr,
                flush=True,
            )
            sleeper(_RETRY_DELAY_SECONDS)
            continue
        if retryable:
            print(
                "dependency audit: transport failure persisted after one retry; audit remains failed",
                file=sys.stderr,
                flush=True,
            )
        return result.returncode
    raise AssertionError("bounded dependency-audit attempts were exhausted")


def main(argv: Sequence[str] | None = None) -> int:
    return run(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(main())
