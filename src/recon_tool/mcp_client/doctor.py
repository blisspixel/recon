"""End-to-end MCP self-check.

`recon doctor --mcp` (existing) confirms the *static* shape of an MCP
install: the package imports, the server module loads, the application has
instructions, and the public registry API enumerates canonical tools and
resources. It never actually exercises the JSON-RPC loop.

This module adds the dynamic complement: spawn the server as a subprocess the
way a real MCP client would, perform the SDK-supported discovery flow, list
tools and resources, and read each canonical local JSON resource.

A pass validates this install's local stdio protocol surface. It does not read
any MCP client's configuration. A failure identifies the protocol phase that
broke, including startup, framing, registration, resource content, or hung I/O.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable, Generator
from dataclasses import dataclass
from typing import Any, Literal, TextIO, cast

from recon_tool.mcp_client.sdk_compat import SDK_FAMILY, SDK_VERSION, model_wire_dict

# Tools we expect any healthy build to surface. These are the public-facing
# primary tools, not internal debug helpers. If any of these go missing,
# something real is broken at the registration layer.
REQUIRED_TOOLS: frozenset[str] = frozenset(
    {
        "lookup_tenant",
        "analyze_posture",
        "assess_exposure",
        "find_hardening_gaps",
        "chain_lookup",
    }
)

# Local discovery resources that every healthy recon MCP server publishes.
# Keeping this list explicit makes both static and live diagnostics detect a
# registration regression without requiring an external inventory or network
# request.
REQUIRED_RESOURCES: tuple[str, ...] = (
    "recon://fingerprints",
    "recon://signals",
    "recon://profiles",
    "recon://schema",
    "recon://surface-inventory",
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


class _HandshakePhaseError(RuntimeError):
    """Carry completed checks when a specific protocol phase fails."""

    def __init__(
        self,
        phase: str,
        completed_checks: tuple[DoctorCheck, ...],
        cause: Exception,
    ) -> None:
        super().__init__(str(cause))
        self.phase = phase
        self.completed_checks = completed_checks
        self.cause = cause


@dataclass
class _HandshakeProgress:
    """Mutable phase state retained even when transport cleanup replaces errors."""

    phase: str = "server spawn"
    completed_checks: tuple[DoctorCheck, ...] = ()

    def start(self, phase: str, checks: list[DoctorCheck]) -> None:
        self.phase = phase
        self.completed_checks = tuple(checks)


@contextlib.contextmanager
def _protocol_phase(
    name: str,
    checks: list[DoctorCheck],
    progress: _HandshakeProgress | None = None,
) -> Generator[None]:
    """Convert one protocol failure into a phase-aware diagnostic."""
    if progress is not None:
        progress.start(name, checks)
    try:
        yield
    except _HandshakePhaseError:
        raise
    except Exception as exc:
        raise _HandshakePhaseError(name, tuple(checks), exc) from exc


def _indent(text: str, prefix: str) -> str:
    """Indent every line of ``text`` with ``prefix`` (no textwrap import)."""
    return "\n".join(prefix + line for line in text.splitlines())


async def _discover_session(
    session: Any,
    checks: list[DoctorCheck],
    progress: _HandshakeProgress,
) -> None:
    """Run the generation-specific discovery phase."""
    discover = getattr(session, "discover", None)
    if callable(discover):
        with _protocol_phase("server/discover", checks, progress):
            discovery_result = await cast(Callable[[], Awaitable[Any]], discover)()
            discovery_wire = model_wire_dict(discovery_result)
            server_info = discovery_wire.get("serverInfo", {})
            server_name = server_info.get("name", "?") if isinstance(server_info, dict) else "?"
            supported = discovery_wire.get("supportedVersions", [])
            protocol = ",".join(str(item) for item in supported) if isinstance(supported, list) else "?"
            checks.append(
                DoctorCheck(
                    "server/discover",
                    "ok",
                    f"server={server_name} protocol={protocol} sdk={SDK_VERSION}",
                )
            )
        with _protocol_phase("server/discover metadata", checks, progress):
            _append_cache_metadata_check(checks, "server/discover metadata", discovery_wire)
        return

    with _protocol_phase("initialize handshake", checks, progress):
        init_result = await session.initialize()
        init_wire = model_wire_dict(init_result)
        server_info = init_wire.get("serverInfo", {})
        server_name = server_info.get("name", "?") if isinstance(server_info, dict) else "?"
        protocol = init_wire.get("protocolVersion", "?")
        checks.append(
            DoctorCheck(
                "initialize handshake",
                "ok",
                f"server={server_name} protocol={protocol} sdk={SDK_VERSION}",
            )
        )


async def _list_session_tools(
    session: Any,
    checks: list[DoctorCheck],
    progress: _HandshakeProgress,
) -> list[str]:
    """List tools and validate their protocol envelope."""
    with _protocol_phase("tools/list", checks, progress):
        tools_result = await session.list_tools()
        tools_wire = model_wire_dict(tools_result)
        raw_tools = tools_wire.get("tools", [])
        if not isinstance(raw_tools, list):
            raise TypeError("tools/list did not return a tool list")
        tool_names = [str(tool.get("name", "")) for tool in raw_tools if isinstance(tool, dict)]
        checks.append(DoctorCheck("tools/list", "ok", f"{len(tool_names)} tools registered"))
    if SDK_FAMILY == "v2":
        with _protocol_phase("tools/list metadata", checks, progress):
            _append_cache_metadata_check(checks, "tools/list metadata", tools_wire)
    return tool_names


async def _list_session_resources(
    session: Any,
    checks: list[DoctorCheck],
    progress: _HandshakeProgress,
) -> dict[str, dict[str, Any]]:
    """List resources and validate canonical media types."""
    with _protocol_phase("resources/list", checks, progress):
        resources_result = await session.list_resources()
        resources_wire = model_wire_dict(resources_result)
        raw_resources = resources_wire.get("resources", [])
        if not isinstance(raw_resources, list):
            raise TypeError("resources/list did not return a resource list")
        resource_entries = {
            str(resource.get("uri", "")): resource for resource in raw_resources if isinstance(resource, dict)
        }
        for uri in REQUIRED_RESOURCES:
            entry = resource_entries.get(uri)
            if entry is not None and entry.get("mimeType") != "application/json":
                raise ValueError(f"{uri} is not advertised as application/json")
        checks.append(
            DoctorCheck(
                "resources/list",
                "ok",
                f"{len(resource_entries)} resources registered",
            )
        )
    if SDK_FAMILY == "v2":
        with _protocol_phase("resources/list metadata", checks, progress):
            _append_cache_metadata_check(checks, "resources/list metadata", resources_wire)
    return resource_entries


async def _read_session_resources(
    session: Any,
    resource_entries: dict[str, dict[str, Any]],
    checks: list[DoctorCheck],
    progress: _HandshakeProgress,
) -> None:
    """Read and validate every registered canonical local resource."""
    read_count = 0
    for uri in REQUIRED_RESOURCES:
        if uri not in resource_entries:
            continue
        with _protocol_phase(f"resources/read {uri}", checks, progress):
            read_result = await session.read_resource(uri)
            read_wire = model_wire_dict(read_result)
            _validate_resource_read(uri, read_wire)
            if SDK_FAMILY == "v2":
                _cache_metadata_detail(read_wire)
            read_count += 1
    checks.append(DoctorCheck("resources/read", "ok", f"{read_count} JSON resources read"))
    if SDK_FAMILY == "v2":
        checks.append(
            DoctorCheck(
                "resources/read metadata",
                "ok",
                f"{read_count} complete results validated",
            )
        )


async def _run_handshake(
    errlog: TextIO,
    progress: _HandshakeProgress | None = None,
) -> tuple[list[str], list[str], list[DoctorCheck]]:
    """Spawn the server and walk the MCP handshake.

    Returns (tool_names, resource_uris, checks). Each successful phase
    becomes an "ok" check. A protocol failure carries the completed
    checks and exact failed phase back to the report builder.

    Server stderr is captured into ``errlog`` rather than forwarded
    to the doctor's own stderr. That way, if the handshake fails,
    the caller can attach the captured tail to the failure detail —
    a server crash during ``initialize`` would otherwise show as a
    bare ``BrokenPipeError`` with no hint at the underlying import
    error, traceback, or missing-dependency message that produced it.

    Supply-chain hardening (v1.9.3.4): the subprocess is spawned with
    ``cwd`` pointing at an empty temporary directory and the
    ``PYTHONSAFEPATH=1`` env var set. Both protect against the
    cwd-shadow attack pattern audited in v1.9.3.4 — Python's ``-m``
    flag prepends cwd to ``sys.path`` on Python 3.10 (and absent
    ``PYTHONSAFEPATH``), so a malicious workspace containing a
    ``recon_tool/`` directory could otherwise shadow the installed
    package and execute attacker code. The empty-cwd defense works
    on all supported Python versions; the env-var defense reinforces
    it on Python 3.11+. The runtime guard in
    ``recon_tool.server._detect_cwd_shadow_install`` is the third
    layer.
    """
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    checks: list[DoctorCheck] = []
    phase_progress = progress if progress is not None else _HandshakeProgress()

    # Run the server through the same Python interpreter that's running
    # the doctor — that way `recon mcp doctor` validates THIS install,
    # not whatever happens to be on PATH.
    env = dict(os.environ)
    env["RECON_MCP_FORCE_STDIO"] = "1"  # bypass the TTY guard added in v1.9.x
    env["PYTHONSAFEPATH"] = "1"  # v1.9.3.4: disable cwd prepend on Py3.11+

    # v1.9.3.4: empty cwd for the child so ``-m recon_tool.server``
    # can never find a shadow ``recon_tool/`` next to it. We use a
    # tempdir created on entry to ``stdio_client`` rather than a fixed
    # location (e.g. the installed package's parent) because:
    #   * an empty tempdir guarantees no Python files exist there,
    #   * it isolates the child filesystem footprint from the doctor's,
    #   * cleanup is automatic via the context manager.
    with tempfile.TemporaryDirectory(prefix="recon-mcp-doctor-cwd-") as safe_cwd:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "recon_tool.server"],
            env=env,
            cwd=safe_cwd,
        )

        async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
            checks.append(DoctorCheck("server spawn", "ok", "stdio transport opened"))

            phase_progress.start("client session", checks)
            async with ClientSession(read_stream, write_stream) as session:
                await _discover_session(cast(Any, session), checks, phase_progress)
                tool_names = await _list_session_tools(cast(Any, session), checks, phase_progress)
                resource_entries = await _list_session_resources(cast(Any, session), checks, phase_progress)
                await _read_session_resources(cast(Any, session), resource_entries, checks, phase_progress)
                phase_progress.start("session cleanup", checks)

    return tool_names, list(resource_entries), checks


def _validate_resource_read(uri: str, wire: dict[str, object]) -> None:
    """Validate one local JSON resource response without exposing its payload."""
    contents = wire.get("contents")
    if not isinstance(contents, list) or len(contents) != 1 or not isinstance(contents[0], dict):
        raise TypeError(f"{uri} did not return exactly one content object")
    content = contents[0]
    if str(content.get("uri", "")) != uri:
        raise ValueError(f"{uri} returned a mismatched content URI")
    if content.get("mimeType") != "application/json":
        raise ValueError(f"{uri} did not return application/json")
    text = content.get("text")
    if not isinstance(text, str):
        raise TypeError(f"{uri} did not return text content")
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{uri} did not return valid JSON") from exc
    if not isinstance(payload, dict):
        raise TypeError(f"{uri} JSON payload is not an object")
    _validate_resource_payload(uri, payload)


_CATALOG_RESOURCE_KEYS: dict[str, tuple[str, str]] = {
    "recon://fingerprints": ("fingerprints", "slug"),
    "recon://signals": ("signals", "name"),
    "recon://profiles": ("profiles", "name"),
}


def _validate_resource_payload(uri: str, payload: dict[str, object]) -> None:
    """Require the stable identifying shape of each canonical resource."""
    catalog_shape = _CATALOG_RESOURCE_KEYS.get(uri)
    if catalog_shape is not None:
        list_key, identity_key = catalog_shape
        count = payload.get("count")
        entries = payload.get(list_key)
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            or not isinstance(entries, list)
            or len(entries) != count
            or any(
                not isinstance(entry, dict) or not isinstance(entry.get(identity_key), str) or not entry[identity_key]
                for entry in entries
            )
        ):
            raise ValueError(f"{uri} JSON payload has an invalid catalog envelope")
        if uri == "recon://fingerprints" and any(
            not isinstance(entry.get("detection_count"), int)
            or isinstance(entry.get("detection_count"), bool)
            or entry["detection_count"] < 1
            or not isinstance(entry.get("detection_types"), list)
            or not entry["detection_types"]
            for entry in entries
        ):
            raise ValueError(f"{uri} JSON payload has an invalid detection summary")
        return

    if uri == "recon://schema":
        if (
            payload.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
            or payload.get("type") != "object"
            or not isinstance(payload.get("title"), str)
            or not payload["title"]
            or not isinstance(payload.get("$defs"), dict)
            or not isinstance(payload.get("properties"), dict)
            or not isinstance(payload.get("required"), list)
        ):
            raise ValueError(f"{uri} JSON payload has an invalid schema envelope")
        return

    if uri == "recon://surface-inventory":
        mcp_inventory = payload.get("mcp")
        if not isinstance(mcp_inventory, dict):
            raise ValueError(f"{uri} JSON payload has an invalid MCP inventory")
        schema_version = payload.get("schema_version")
        tools = mcp_inventory.get("tools")
        resources = mcp_inventory.get("resources")
        tool_names = (
            {str(entry.get("name", "")) for entry in tools if isinstance(entry, dict)}
            if isinstance(tools, list)
            else set()
        )
        resource_uris = (
            {str(entry.get("uri", "")) for entry in resources if isinstance(entry, dict)}
            if isinstance(resources, list)
            else set()
        )
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version < 1
            or not isinstance(tools, list)
            or not isinstance(resources, list)
            or mcp_inventory.get("tool_count") != len(tools)
            or mcp_inventory.get("resource_count") != len(resources)
            or not REQUIRED_TOOLS.issubset(tool_names)
            or not set(REQUIRED_RESOURCES).issubset(resource_uris)
        ):
            raise ValueError(f"{uri} JSON payload has an invalid MCP inventory")
        return

    raise ValueError(f"{uri} is not a canonical MCP resource")


def _append_cache_metadata_check(checks: list[DoctorCheck], name: str, wire: dict[str, object]) -> None:
    """Require complete-result cache metadata on the 2026 protocol path."""
    detail = _cache_metadata_detail(wire)
    checks.append(DoctorCheck(name, "ok", detail))


def _cache_metadata_detail(wire: dict[str, object]) -> str:
    """Return validated complete-result cache metadata detail."""
    ttl_ms = wire.get("ttlMs")
    cache_scope = wire.get("cacheScope")
    result_type = wire.get("resultType")
    if (
        isinstance(ttl_ms, int)
        and not isinstance(ttl_ms, bool)
        and ttl_ms >= 0
        and cache_scope in {"public", "private"}
        and result_type == "complete"
    ):
        return f"ttlMs={ttl_ms} cacheScope={cache_scope} resultType={result_type}"
    raise ValueError(
        f"invalid complete-result metadata: ttlMs={ttl_ms!r} cacheScope={cache_scope!r} resultType={result_type!r}"
    )


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


def _find_phase_error(exc: BaseException) -> _HandshakePhaseError | None:
    """Return one phase error nested by transport cleanup, if unambiguous."""
    if isinstance(exc, _HandshakePhaseError):
        return exc
    if not isinstance(exc, BaseExceptionGroup):
        return None
    matches = [match for nested in exc.exceptions if (match := _find_phase_error(nested)) is not None]
    return matches[0] if len(matches) == 1 else None


def _single_exception_leaf(exc: Exception) -> Exception:
    """Unwrap single-cause task-group wrappers for a useful diagnostic."""
    current = exc
    while isinstance(current, BaseExceptionGroup) and len(current.exceptions) == 1:
        nested = current.exceptions[0]
        if not isinstance(nested, Exception):
            break
        current = nested
    return current


def _phase_failure_report(
    exc: _HandshakePhaseError,
    *,
    errlog: TextIO,
    start: float,
) -> DoctorReport:
    """Build one phase-aware failure report with bounded terminal context."""
    tail = _stderr_tail(errlog)
    detail = f"{type(exc.cause).__name__}: {exc.cause}".rstrip(": ")
    if tail:
        detail = f"{detail}\n        server stderr (tail):\n{_indent(tail, '          ')}"
    return DoctorReport(
        checks=(
            *exc.completed_checks,
            DoctorCheck(
                exc.phase,
                "fail",
                detail,
            ),
        ),
        elapsed_seconds=time.monotonic() - start,
        server_stderr_tail=tail,
    )


def _timeout_failure_report(
    progress: _HandshakeProgress,
    *,
    errlog: TextIO,
    start: float,
) -> DoctorReport:
    """Build a phase-aware timeout report from shared progress state."""
    failure = _HandshakePhaseError(
        progress.phase,
        progress.completed_checks,
        TimeoutError(f"timed out after {_HANDSHAKE_TIMEOUT_S:.0f}s"),
    )
    return _phase_failure_report(failure, errlog=errlog, start=start)


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
    progress = _HandshakeProgress()

    try:
        try:
            handshake_task = asyncio.create_task(_run_handshake(errlog, progress))
            try:
                done, _pending = await asyncio.wait(
                    {handshake_task},
                    timeout=_HANDSHAKE_TIMEOUT_S,
                )
            except asyncio.CancelledError:
                handshake_task.cancel()
                await asyncio.gather(handshake_task, return_exceptions=True)
                raise
            if not done:
                handshake_task.cancel()
                await asyncio.gather(handshake_task, return_exceptions=True)
                return _timeout_failure_report(progress, errlog=errlog, start=start)
            tool_names, resource_uris, checks = handshake_task.result()
        except _HandshakePhaseError as exc:
            return _phase_failure_report(exc, errlog=errlog, start=start)
        except Exception as exc:
            phase_error = _find_phase_error(exc)
            if phase_error is not None:
                return _phase_failure_report(phase_error, errlog=errlog, start=start)
            return _phase_failure_report(
                _HandshakePhaseError(
                    progress.phase,
                    progress.completed_checks,
                    _single_exception_leaf(exc),
                ),
                errlog=errlog,
                start=start,
            )
    finally:
        with contextlib.suppress(OSError):
            errlog.close()
        # Best effort — on Windows the subprocess may still hold the
        # handle if cleanup races. The OS will sweep the tempdir
        # eventually; we don't gate doctor results on the unlink.
        with contextlib.suppress(OSError):
            os.unlink(errlog_path)

    missing_tools = sorted(REQUIRED_TOOLS - set(tool_names))
    if missing_tools:
        checks.append(
            DoctorCheck(
                "required tools present",
                "fail",
                f"missing: {', '.join(missing_tools)}",
            )
        )
    else:
        checks.append(
            DoctorCheck(
                "required tools present",
                "ok",
                f"{len(REQUIRED_TOOLS)} of {len(REQUIRED_TOOLS)} canonical tools found",
            )
        )

    missing_resources = [uri for uri in REQUIRED_RESOURCES if uri not in set(resource_uris)]
    if missing_resources:
        checks.append(
            DoctorCheck(
                "required resources present",
                "fail",
                f"missing: {', '.join(missing_resources)}",
            )
        )
    else:
        checks.append(
            DoctorCheck(
                "required resources present",
                "ok",
                f"{len(REQUIRED_RESOURCES)} of {len(REQUIRED_RESOURCES)} canonical resources found",
            )
        )

    return DoctorReport(
        checks=tuple(checks),
        elapsed_seconds=time.monotonic() - start,
    )


def run_doctor() -> DoctorReport:
    """Public entry point — runs the async handshake from sync code."""
    return asyncio.run(_run_with_timeout())
