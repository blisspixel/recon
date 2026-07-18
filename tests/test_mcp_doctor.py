"""Tests for the live `recon mcp doctor` JSON-RPC self-check.

The handshake actually spawns a subprocess and exercises the MCP
stdio transport end-to-end. That makes the happy-path test slower
than the rest of the suite (~2-4s on a warm cache, more on cold) but
the whole point of the doctor is that it exercises this install's local stdio
surface. Client configuration remains a separate check.

The error-path tests inject failures via a stub handshake function
to keep them fast and OS-independent.
"""

from __future__ import annotations

import asyncio
import io
import json

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.mcp_doctor import (
    REQUIRED_RESOURCES,
    REQUIRED_TOOLS,
    DoctorCheck,
    DoctorReport,
    _HandshakePhaseError,
    _HandshakeProgress,
    _protocol_phase,
    _run_with_timeout,
    _validate_resource_read,
    run_doctor,
)

pytest.importorskip("mcp")

runner = CliRunner()


class TestLiveHandshake:
    """End-to-end: actually spawn the server and walk the protocol.

    Slower than the rest of the suite (~2-4s on a warm cache) but
    deliberately real — if subprocess spawning is broken on this
    platform, that's exactly what the doctor needs to catch.
    """

    def test_doctor_passes_against_live_server(self) -> None:
        report = run_doctor()
        assert report.ok, f"doctor failed: {[c for c in report.checks if c.status == 'fail']}"
        # Sanity-check the shape of the report so silent regressions in
        # the report contract get caught here too.
        assert report.elapsed_seconds > 0
        names = {c.name for c in report.checks}
        assert "server spawn" in names
        assert "initialize handshake" in names
        assert "tools/list" in names
        assert "required tools present" in names
        assert "resources/list" in names
        assert "required resources present" in names
        assert "resources/read" in names


class TestTimeoutPath:
    def test_timeout_reports_failure_without_raising(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _hang(
            _errlog: io.StringIO,
            _progress: _HandshakeProgress,
        ) -> tuple[list[str], list[str], list[DoctorCheck]]:
            await asyncio.sleep(60)
            return [], [], []

        # Shrink the timeout so the test resolves fast.
        monkeypatch.setattr("recon_tool.mcp_doctor._HANDSHAKE_TIMEOUT_S", 0.05)
        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _hang)

        report = asyncio.run(_run_with_timeout())
        assert not report.ok
        assert any(c.status == "fail" and "timed out" in c.detail for c in report.checks)

    def test_real_timeout_during_resources_list_preserves_phase_and_completed_checks(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mcp import ClientSession

        entered = asyncio.Event()
        real_wait = asyncio.wait

        async def _hang_resources(_session: ClientSession) -> object:
            entered.set()
            await asyncio.sleep(60)
            raise AssertionError("unreachable")

        async def _timeout_after_resource_entry(
            tasks: set[asyncio.Task[object]],
            *,
            timeout: float | None = None,
        ) -> tuple[set[asyncio.Task[object]], set[asyncio.Task[object]]]:
            del timeout
            marker = asyncio.create_task(entered.wait())
            done, _pending = await real_wait({marker}, timeout=10)
            assert done, "live handshake never reached resources/list"
            return set(), tasks

        monkeypatch.setattr(ClientSession, "list_resources", _hang_resources)
        monkeypatch.setattr("recon_tool.mcp_doctor.asyncio.wait", _timeout_after_resource_entry)

        report = asyncio.run(_run_with_timeout())

        assert [check.name for check in report.checks] == [
            "server spawn",
            "initialize handshake",
            "tools/list",
            "resources/list",
        ]
        assert report.checks[-1].status == "fail"
        assert "timed out" in report.checks[-1].detail

    def test_external_cancellation_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        started = asyncio.Event()

        async def _hang(
            _errlog: io.StringIO,
            _progress: _HandshakeProgress,
        ) -> tuple[list[str], list[str], list[DoctorCheck]]:
            started.set()
            await asyncio.sleep(60)
            return [], [], []

        async def _cancel() -> BaseException:
            task = asyncio.create_task(_run_with_timeout())
            await started.wait()
            task.cancel()
            outcome = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcome[0], BaseException)
            return outcome[0]

        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _hang)

        assert isinstance(asyncio.run(_cancel()), asyncio.CancelledError)


class TestExceptionPath:
    def test_handshake_exception_reports_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _boom(
            _errlog: io.StringIO,
            _progress: _HandshakeProgress,
        ) -> tuple[list[str], list[str], list[DoctorCheck]]:
            raise RuntimeError("synthetic spawn failure")

        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _boom)

        report = asyncio.run(_run_with_timeout())
        assert not report.ok
        fail_check = next(c for c in report.checks if c.status == "fail")
        assert "synthetic spawn failure" in fail_check.detail
        assert "RuntimeError" in fail_check.detail

    def test_handshake_exception_includes_captured_server_stderr(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the spawned server crashes with an ImportError, the
        client side sees an opaque BrokenPipe-style error. The doctor
        should glue the captured server stderr tail to the failure
        detail so the user sees the actual cause."""

        async def _crash(
            errlog: io.StringIO,
            _progress: _HandshakeProgress,
        ) -> tuple[list[str], list[str], list[DoctorCheck]]:
            errlog.write(
                "Traceback (most recent call last):\n"
                '  File "server.py", line 1, in <module>\n'
                "    import recon_tool\n"
                "ModuleNotFoundError: No module named 'recon_tool'\n"
            )
            raise BrokenPipeError("connection closed")

        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _crash)

        report = asyncio.run(_run_with_timeout())
        assert not report.ok
        fail_check = next(c for c in report.checks if c.status == "fail")
        assert "BrokenPipeError" in fail_check.detail
        # The crash cause should be visible in the failure detail.
        assert "ModuleNotFoundError" in fail_check.detail
        assert "No module named 'recon_tool'" in fail_check.detail
        assert "ModuleNotFoundError" in report.server_stderr_tail

    def test_protocol_phase_failure_preserves_completed_checks(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        completed = (
            DoctorCheck("server spawn", "ok", "stub"),
            DoctorCheck("initialize handshake", "ok", "stub"),
            DoctorCheck("tools/list", "ok", "22 tools registered"),
        )

        async def _fail_resources(
            errlog: io.StringIO,
            _progress: _HandshakeProgress,
        ) -> tuple[list[str], list[str], list[DoctorCheck]]:
            errlog.write("synthetic phase stderr\n")
            raise _HandshakePhaseError(
                "resources/list",
                completed,
                RuntimeError("synthetic resource listing failure"),
            )

        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _fail_resources)

        report = asyncio.run(_run_with_timeout())

        assert [check.name for check in report.checks] == [
            "server spawn",
            "initialize handshake",
            "tools/list",
            "resources/list",
        ]
        assert report.checks[-1].status == "fail"
        assert "synthetic resource listing failure" in report.checks[-1].detail
        assert "synthetic phase stderr" in report.checks[-1].detail
        assert "synthetic phase stderr" in report.server_stderr_tail

    @pytest.mark.parametrize(
        "phase",
        [
            "initialize handshake",
            "server/discover",
            "tools/list",
            "resources/list",
            "resources/read recon://schema",
        ],
    )
    def test_each_protocol_phase_keeps_its_name(
        self,
        monkeypatch: pytest.MonkeyPatch,
        phase: str,
    ) -> None:
        async def _fail_phase(
            _errlog: io.StringIO,
            _progress: _HandshakeProgress,
        ) -> tuple[list[str], list[str], list[DoctorCheck]]:
            checks = [DoctorCheck("server spawn", "ok", "stub")]
            with _protocol_phase(phase, checks):
                raise RuntimeError("synthetic phase failure")
            return [], [], checks

        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _fail_phase)

        report = asyncio.run(_run_with_timeout())

        assert [check.name for check in report.checks] == ["server spawn", phase]
        assert report.checks[-1].status == "fail"

    def test_grouped_protocol_failure_preserves_phase_and_completed_checks(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        completed = (DoctorCheck("server spawn", "ok", "stub"),)

        async def _fail_during_cleanup(
            _errlog: io.StringIO,
            _progress: _HandshakeProgress,
        ) -> tuple[list[str], list[str], list[DoctorCheck]]:
            phase_error = _HandshakePhaseError(
                "tools/list",
                completed,
                RuntimeError("synthetic grouped failure"),
            )
            raise ExceptionGroup("transport cleanup", [phase_error])

        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _fail_during_cleanup)

        report = asyncio.run(_run_with_timeout())

        assert [check.name for check in report.checks] == ["server spawn", "tools/list"]
        assert report.checks[-1].status == "fail"
        assert "synthetic grouped failure" in report.checks[-1].detail

    def test_real_client_phase_failure_survives_transport_cleanup(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mcp import ClientSession

        async def _fail_tools(_session: ClientSession) -> object:
            raise RuntimeError("synthetic live tools failure")

        monkeypatch.setattr(ClientSession, "list_tools", _fail_tools)

        report = run_doctor()

        assert [check.name for check in report.checks][-1] == "tools/list"
        assert "initialize handshake" in {check.name for check in report.checks}
        assert report.checks[-1].status == "fail"
        assert "synthetic live tools failure" in report.checks[-1].detail

    def test_real_client_session_entry_failure_preserves_spawn(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mcp import ClientSession

        async def _fail_entry(_session: ClientSession) -> ClientSession:
            raise RuntimeError("synthetic client session entry failure")

        monkeypatch.setattr(ClientSession, "__aenter__", _fail_entry)

        report = run_doctor()

        assert [check.name for check in report.checks] == ["server spawn", "client session"]
        assert report.checks[-1].status == "fail"
        assert "synthetic client session entry failure" in report.checks[-1].detail

    def test_real_client_session_cleanup_failure_preserves_protocol_checks(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from types import TracebackType

        from mcp import ClientSession

        original_exit = ClientSession.__aexit__

        async def _fail_cleanup(
            session: ClientSession,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: TracebackType | None,
        ) -> bool | None:
            await original_exit(session, exc_type, exc_value, traceback)
            raise RuntimeError("synthetic client session cleanup failure")

        monkeypatch.setattr(ClientSession, "__aexit__", _fail_cleanup)

        report = run_doctor()

        assert report.checks[0].name == "server spawn"
        assert "resources/read" in {check.name for check in report.checks}
        assert report.checks[-1].name == "session cleanup"
        assert report.checks[-1].status == "fail"
        assert "synthetic client session cleanup failure" in report.checks[-1].detail


class TestRequiredToolsGate:
    def test_missing_canonical_tools_fails_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Pretend the handshake succeeded but only returned an unrelated tool.
        async def _stub(
            _errlog: io.StringIO,
            _progress: _HandshakeProgress,
        ) -> tuple[list[str], list[str], list[DoctorCheck]]:
            return (
                ["unrelated_tool"],
                list(REQUIRED_RESOURCES),
                [
                    DoctorCheck("server spawn", "ok", "stub"),
                    DoctorCheck("initialize handshake", "ok", "stub"),
                    DoctorCheck("tools/list", "ok", "1 tools registered"),
                    DoctorCheck("resources/list", "ok", "5 resources registered"),
                    DoctorCheck("resources/read", "ok", "5 JSON resources read"),
                ],
            )

        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _stub)

        report = asyncio.run(_run_with_timeout())
        assert not report.ok
        gate = next(c for c in report.checks if c.name == "required tools present")
        assert gate.status == "fail"
        assert "missing" in gate.detail
        assert "lookup_tenant" in gate.detail


class TestRequiredResourcesGate:
    def test_missing_canonical_resource_fails_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        missing_uri = REQUIRED_RESOURCES[-1]

        async def _stub(
            _errlog: io.StringIO,
            _progress: _HandshakeProgress,
        ) -> tuple[list[str], list[str], list[DoctorCheck]]:
            return (
                list(REQUIRED_TOOLS),
                [uri for uri in REQUIRED_RESOURCES if uri != missing_uri],
                [
                    DoctorCheck("server spawn", "ok", "stub"),
                    DoctorCheck("initialize handshake", "ok", "stub"),
                    DoctorCheck("tools/list", "ok", "5 tools registered"),
                    DoctorCheck("resources/list", "ok", "4 resources registered"),
                    DoctorCheck("resources/read", "ok", "4 JSON resources read"),
                ],
            )

        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _stub)

        report = asyncio.run(_run_with_timeout())

        assert not report.ok
        gate = next(c for c in report.checks if c.name == "required resources present")
        assert gate.status == "fail"
        assert gate.detail == f"missing: {missing_uri}"


class TestResourceReadValidation:
    def test_accepts_one_matching_json_object(self) -> None:
        uri = "recon://fingerprints"
        _validate_resource_read(
            uri,
            {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(
                            {
                                "count": 1,
                                "fingerprints": [
                                    {
                                        "slug": "synthetic-service",
                                        "detection_count": 1,
                                        "detection_types": ["txt"],
                                    }
                                ],
                            }
                        ),
                    }
                ]
            },
        )

    @pytest.mark.parametrize("uri", REQUIRED_RESOURCES)
    def test_rejects_empty_object_for_every_canonical_resource(self, uri: str) -> None:
        with pytest.raises((TypeError, ValueError)):
            _validate_resource_read(
                uri,
                {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": "{}",
                        }
                    ]
                },
            )

    @pytest.mark.parametrize(
        "wire",
        [
            {},
            {"contents": []},
            {"contents": [{"uri": "recon://other", "mimeType": "application/json", "text": "{}"}]},
            {"contents": [{"uri": "recon://fingerprints", "mimeType": "text/plain", "text": "{}"}]},
            {"contents": [{"uri": "recon://fingerprints", "mimeType": "application/json", "text": 7}]},
            {
                "contents": [
                    {
                        "uri": "recon://fingerprints",
                        "mimeType": "application/json",
                        "text": '{"secret":"never echo this",',
                    }
                ]
            },
            {
                "contents": [
                    {
                        "uri": "recon://fingerprints",
                        "mimeType": "application/json",
                        "text": "[]",
                    }
                ]
            },
        ],
    )
    def test_rejects_malformed_or_mismatched_content_without_echoing_payload(
        self,
        wire: dict[str, object],
    ) -> None:
        with pytest.raises((TypeError, ValueError)) as caught:
            _validate_resource_read("recon://fingerprints", wire)

        assert "never echo this" not in str(caught.value)


class TestDoctorReport:
    def test_ok_property_true_when_all_ok(self) -> None:
        report = DoctorReport(
            checks=(DoctorCheck("a", "ok", "x"), DoctorCheck("b", "ok", "y")),
            elapsed_seconds=1.0,
        )
        assert report.ok is True

    def test_ok_property_false_when_any_fail(self) -> None:
        report = DoctorReport(
            checks=(DoctorCheck("a", "ok", "x"), DoctorCheck("b", "fail", "y")),
            elapsed_seconds=1.0,
        )
        assert report.ok is False


class TestCLI:
    def test_doctor_subcommand_help(self) -> None:
        result = runner.invoke(app, ["mcp", "doctor", "--help"])
        assert result.exit_code == 0
        assert "discovery" in result.output.lower()
        assert "resources" in result.output.lower()

    def test_doctor_renders_failed_report_with_nonzero_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _stub_run() -> DoctorReport:
            return DoctorReport(
                checks=(DoctorCheck("server spawn", "fail", "subprocess refused to start"),),
                elapsed_seconds=0.1,
            )

        monkeypatch.setattr("recon_tool.mcp_doctor.run_doctor", _stub_run)

        result = runner.invoke(app, ["mcp", "doctor"])
        assert result.exit_code != 0
        assert "FAIL" in result.output
        assert "server spawn" in result.output
        assert "subprocess refused to start" in result.output

    def test_doctor_renders_hostile_report_fields_as_one_bounded_literal_row(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        hostile = "[red]forged[/red]\n  ok  forged-row\x1b]52;c;cGF5bG9hZA==\x07" + "x" * 2500

        def _stub_run() -> DoctorReport:
            return DoctorReport(
                checks=(DoctorCheck("spawn [name]", "fail", hostile),),
                elapsed_seconds=0.1,
            )

        monkeypatch.setattr("recon_tool.mcp_doctor.run_doctor", _stub_run)
        result = runner.invoke(app, ["mcp", "doctor"])

        assert result.exit_code != 0
        assert "spawn [name]" in result.output
        assert "[red]forged[/red]" in result.output
        assert "\n  ok  forged-row" not in result.output
        assert "\x1b]52" not in result.output
        assert "[truncated]" in result.output

    def test_doctor_renders_ok_report_with_zero_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _stub_run() -> DoctorReport:
            return DoctorReport(
                checks=(
                    DoctorCheck("server spawn", "ok", "stdio transport opened"),
                    DoctorCheck("initialize handshake", "ok", "server=recon-tool"),
                    DoctorCheck("tools/list", "ok", "22 tools registered"),
                    DoctorCheck("required tools present", "ok", "5 of 5"),
                    DoctorCheck("resources/list", "ok", "5 resources registered"),
                    DoctorCheck("required resources present", "ok", "5 of 5"),
                    DoctorCheck("resources/read", "ok", "5 JSON resources read"),
                ),
                elapsed_seconds=2.34,
            )

        monkeypatch.setattr("recon_tool.mcp_doctor.run_doctor", _stub_run)

        result = runner.invoke(app, ["mcp", "doctor"])
        assert result.exit_code == 0
        assert "ok" in result.output
        assert "22 tools registered" in result.output
        assert "All checks passed" in result.output
        assert "canonical tool registrations and five local JSON resource reads" in result.output
        assert "client config was not checked" in result.output.lower()
