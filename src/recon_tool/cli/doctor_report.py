"""Doctor report data: check rows, the closing summary, and the JSON document.

Every doctor mode collects its checks as ``DoctorCheck`` rows first. The human
renderer and the ``--json`` renderer both read those rows and the one
``DoctorSummary`` derived from them, so the two views cannot disagree on a
status, a count, or the exit code.
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, NamedTuple, TypeAlias

import typer

from recon_tool.cli.shared import DIAGNOSTIC_STATUS_STYLES, DiagnosticStatus, safe_diagnostic_markup
from recon_tool.exit_codes import EXIT_ERROR, EXIT_NO_DATA

DoctorStatus: TypeAlias = DiagnosticStatus


class DoctorCheck(NamedTuple):
    """One doctor row: the data both the human and the JSON renderers read.

    ``next`` is the operator's next step for a failed or warning row, or None
    when the row needs no action or its detail already names the action.
    """

    name: str
    status: DoctorStatus
    detail: str
    next: str | None = None


DoctorMode: TypeAlias = Literal["doctor", "mcp", "client"]

# Bump only for a breaking change to the `recon doctor --json` shape. Adding a
# field is additive and keeps this value.
DOCTOR_JSON_SCHEMA_VERSION = 1

NEXT_RERUN = "then rerun `recon doctor`"
NEXT_MCP_REINSTALL = "pip install -U recon-tool, then rerun `recon doctor --mcp`"
CT_CHECK_NAME = "crt.sh (cert transparency)"


@dataclass(frozen=True)
class DoctorSummary:
    """Counts, closing message, next step, and exit code for one check list."""

    status: DoctorStatus
    counts: dict[str, int]
    message: str
    next: str | None
    exit_code: int


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def summarize_checks(
    checks: Sequence[DoctorCheck],
    *,
    mode: DoctorMode,
    client: str | None = None,
) -> DoctorSummary:
    """Derive the closing summary from the same rows every renderer reads.

    Failures exit non-zero (``recon doctor`` and ``--mcp`` exit 1, ``--client``
    keeps its historical no-data exit). Warnings and info rows never change
    the exit code.
    """
    counts = {status: sum(1 for check in checks if check.status == status) for status in DIAGNOSTIC_STATUS_STYLES}
    counts["total"] = len(checks)
    failures = [check for check in checks if check.status == "fail"]
    warnings = [check for check in checks if check.status == "warn"]

    if failures:
        next_step = next((check.next for check in failures if check.next), None)
        failed = f"{_plural(len(failures), 'check')} failed."
        if mode == "client":
            consequence = "recon is not registered in this client's config, or a config file is broken."
            next_step = next_step or f"recon mcp install --client={client}"
            exit_code = EXIT_NO_DATA
        elif mode == "mcp":
            consequence = "MCP clients may not load recon."
            next_step = next_step or NEXT_MCP_REINSTALL
            exit_code = EXIT_ERROR
        else:
            consequence = "Lookups may be incomplete."
            next_step = next_step or f"review the failed rows above, {NEXT_RERUN}"
            exit_code = EXIT_ERROR
        return DoctorSummary("fail", counts, f"{failed} {consequence} Next: {next_step}", next_step, exit_code)

    if warnings:
        next_step = next((check.next for check in warnings if check.next), None)
        noun = _plural(len(warnings), "warning")
        if mode == "client":
            message = f"recon is registered in this client's config, with {noun}. Review the rows above."
        elif mode == "doctor" and all(check.name == CT_CHECK_NAME for check in warnings):
            message = f"Core checks passed. Optional enrichment sources are degraded ({noun})."
        else:
            message = f"Core checks passed with {noun}. Review the rows above."
        return DoctorSummary("warn", counts, message, next_step, 0)

    message = "recon is registered in this client's config." if mode == "client" else "All checks passed."
    return DoctorSummary("ok", counts, message, None, 0)


def render_summary(console: Any, summary: DoctorSummary) -> None:
    """Print the closing line in the color of its worst status."""
    style = DIAGNOSTIC_STATUS_STYLES[summary.status]
    # Wrap once at the console width, keeping continuation lines under the
    # first word and never splitting a command or path.
    lines = textwrap.wrap(
        summary.message,
        width=max(20, console.width - 2),
        break_long_words=False,
        break_on_hyphens=False,
    )
    for line in lines:
        console.print(f"  [{style}]{safe_diagnostic_markup(line)}[/{style}]", soft_wrap=True, highlight=False)


def doctor_json_payload(
    checks: Sequence[DoctorCheck],
    summary: DoctorSummary,
    *,
    mode: DoctorMode,
    client: str | None = None,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """Build the `recon doctor --json` document from the rendered check list."""
    from recon_tool import __version__

    payload: dict[str, Any] = {
        "schema_version": DOCTOR_JSON_SCHEMA_VERSION,
        "mode": mode,
        "recon_version": __version__,
        "checks": [
            {"name": check.name, "status": check.status, "detail": check.detail, "next": check.next} for check in checks
        ],
        "summary": {
            "status": summary.status,
            **summary.counts,
            "message": summary.message,
            "next": summary.next,
            "exit_code": summary.exit_code,
        },
        "notes": list(notes),
    }
    if client is not None:
        payload["client"] = client
    return payload


def emit_doctor_json(
    checks: Sequence[DoctorCheck],
    summary: DoctorSummary,
    *,
    mode: DoctorMode,
    client: str | None = None,
    notes: Sequence[str] = (),
) -> None:
    """Write the doctor JSON document, and nothing else, to stdout."""
    payload = doctor_json_payload(checks, summary, mode=mode, client=client, notes=notes)
    typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
