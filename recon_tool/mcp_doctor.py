"""End-to-end MCP self-check.

`recon doctor --mcp` (existing) confirms the *static* shape of an MCP
install: the package imports, the server module loads, FastMCP has
instructions, the tool manager enumerates tools. It never actually
exercises the JSON-RPC loop.

This module adds the dynamic complement: spawn the server as a
subprocess the way a real MCP client would, perform the standard
``initialize`` + ``notifications/initialized`` + ``tools/list``
handshake, and report what came back.

If this passes, an MCP client *will* be able to talk to recon. If it
fails, the failure points at exactly which step broke — server crash
on launch, framing error, missing tools, or hung I/O.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Literal, TextIO

# Tools we expect any healthy build to surface. Picked from the banner
# (server.py:2456-2468) — these are the public-facing primary tools,
# not internal debug helpers. If any of these go missing, something
# real is broken at the registration layer.
_REQUIRED_TOOLS: frozenset[str] = frozenset(
    {
        "lookup_tenant",
        "analyze_posture",
        "assess_exposure",
        "find_hardening_gaps",
        "chain_lookup",
    }
)

# Hard wall on how long the handshake may take. Spawning a Python
# subprocess and importing recon_tool dependencies on a cold cache is
# the slowest realistic case; 30s is generous but not unbounded so a
# stuck server fails the doctor instead of hanging it.
_HANDSHAKE_TIMEOUT_S: float = 30.0


CheckStatus = Literal["ok", "fail"]


@dataclass(frozen=True)
class DoctorCheck:
    """One line in the doctor report: human-readable name + result."""

    name: str
    status: CheckStatus
    detail: str


@dataclass(frozen=True)
class DoctorReport:
    """Aggregate result for the whole run.

    ``server_stderr_tail`` is empty when the handshake succeeded — a
    healthy server's startup banner isn't useful diagnostic output.
    On failure, it carries the trailing N lines of the spawned
    server's stderr so the CLI can surface the actual import error,
    traceback, or missing-dependency message that caused the crash.
    """

    checks: tuple[DoctorCheck, ...]
    elapsed_seconds: float
    server_stderr_tail: str = ""

    @property
    def ok(self) -> bool:
        return all(c.status == "ok" for c in self.checks)


def _indent(text: str, prefix: str) -> str:
    """Indent every line of ``text`` with ``prefix`` (no textwrap import)."""
    return "\n".join(prefix + line for line in text.splitlines())


async def _run_handshake(errlog: TextIO) -> tuple[list[str], list[DoctorCheck]]:
    """Spawn the server and walk the MCP handshake.

    Returns (tool_names, checks). Each phase that succeeds becomes an
    "ok" check; the first failure short-circuits and is appended as
    "fail" before raising back up.

    Server stderr is captured into ``errlog`` rather than forwarded
    to the doctor's own stderr. That way, if the handshake fails,
    the caller can attach the captured tail to the failure detail —
    a server crash during ``initialize`` would otherwise show as a
    bare ``BrokenPipeError`` with no hint at the underlying import
    error, traceback, or missing-dependency message that produced it.
    """
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    checks: list[DoctorCheck] = []

    # Run the server through the same Python interpreter that's running
    # the doctor — that way `recon mcp doctor` validates THIS install,
    # not whatever happens to be on PATH.
    env = dict(os.environ)
    env["RECON_MCP_FORCE_STDIO"] = "1"  # bypass the TTY guard added in v1.9.x
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "recon_tool.server"],
        env=env,
    )

    async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
        checks.append(DoctorCheck("server spawn", "ok", "stdio transport opened"))

        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            server_name = getattr(init_result.serverInfo, "name", "?")
            checks.append(
                DoctorCheck(
                    "initialize handshake",
                    "ok",
                    f"server={server_name} protocol={init_result.protocolVersion}",
                )
            )

            tools_result = await session.list_tools()
            tool_names = [t.name for t in tools_result.tools]
            checks.append(
                DoctorCheck(
                    "tools/list",
                    "ok",
                    f"{len(tool_names)} tools registered",
                )
            )

    return tool_names, checks


def _stderr_tail(buffer: TextIO, max_lines: int = 12) -> str:
    """Return the last ``max_lines`` lines of captured server stderr.

    The server's startup banner is large (>20 lines) and uninteresting
    when the handshake succeeded; truncating to a tail means a real
    crash trace lands at the bottom and we surface that, while a clean
    startup banner just falls off the top.

    Accepts both ``io.StringIO`` (in-memory; used by tests) and a real
    on-disk text file (used by ``_run_with_timeout``, since the MCP
    SDK's ``stdio_client`` passes errlog to ``asyncio.create_subprocess``
    which requires a real file descriptor).
    """
    if isinstance(buffer, io.StringIO):
        raw = buffer.getvalue()
    else:
        with contextlib.suppress(ValueError, OSError):
            buffer.flush()
        try:
            buffer.seek(0)
            raw = buffer.read()
        except (ValueError, OSError):
            return ""
    if not raw.strip():
        return ""
    lines = raw.splitlines()
    if len(lines) <= max_lines:
        return raw
    return "\n".join(lines[-max_lines:])


async def _run_with_timeout() -> DoctorReport:
    """Wrap the handshake in a wall-clock budget.

    Uses a real on-disk tempfile (not ``io.StringIO``) for stderr
    capture because the MCP SDK's ``stdio_client`` hands the errlog
    object to ``asyncio.create_subprocess_exec``, which calls
    ``.fileno()`` on it. ``StringIO`` doesn't have a fileno; a
    text-mode tempfile does and gets cleaned up automatically when
    closed.
    """
    start = time.monotonic()
    # delete=False on Windows because tempfile auto-delete-on-close
    # conflicts with the subprocess holding the handle. We close+remove
    # explicitly in the finally below.
    fd, errlog_path = tempfile.mkstemp(prefix="recon-mcp-doctor-", suffix=".log", text=True)
    errlog: TextIO = os.fdopen(fd, "w+", encoding="utf-8")

    try:
        try:
            tool_names, checks = await asyncio.wait_for(_run_handshake(errlog), timeout=_HANDSHAKE_TIMEOUT_S)
        except asyncio.TimeoutError:
            return DoctorReport(
                checks=(
                    DoctorCheck(
                        "handshake",
                        "fail",
                        f"timed out after {_HANDSHAKE_TIMEOUT_S:.0f}s — server hung or didn't start",
                    ),
                ),
                elapsed_seconds=time.monotonic() - start,
                server_stderr_tail=_stderr_tail(errlog),
            )
        except Exception as exc:
            # Server crashes during initialize surface as opaque pipe errors
            # on the client side. Glue the captured stderr tail to the
            # check detail so the user sees the actual ImportError /
            # traceback that caused the spawn to die.
            tail = _stderr_tail(errlog)
            detail = f"{type(exc).__name__}: {exc}".rstrip(": ")
            if tail:
                detail = f"{detail}\n        server stderr (tail):\n{_indent(tail, '          ')}"
            return DoctorReport(
                checks=(
                    DoctorCheck(
                        "handshake",
                        "fail",
                        detail,
                    ),
                ),
                elapsed_seconds=time.monotonic() - start,
                server_stderr_tail=tail,
            )
    finally:
        with contextlib.suppress(OSError):
            errlog.close()
        # Best effort — on Windows the subprocess may still hold the
        # handle if cleanup races. The OS will sweep the tempdir
        # eventually; we don't gate doctor results on the unlink.
        with contextlib.suppress(OSError):
            os.unlink(errlog_path)

    missing = sorted(_REQUIRED_TOOLS - set(tool_names))
    if missing:
        checks.append(
            DoctorCheck(
                "required tools present",
                "fail",
                f"missing: {', '.join(missing)}",
            )
        )
    else:
        checks.append(
            DoctorCheck(
                "required tools present",
                "ok",
                f"{len(_REQUIRED_TOOLS)} of {len(_REQUIRED_TOOLS)} canonical tools found",
            )
        )

    return DoctorReport(
        checks=tuple(checks),
        elapsed_seconds=time.monotonic() - start,
    )


def run_doctor() -> DoctorReport:
    """Public entry point — runs the async handshake from sync code."""
    return asyncio.run(_run_with_timeout())
