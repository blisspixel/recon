"""Tests for `recon mcp doctor` — the live JSON-RPC self-check.

The handshake actually spawns a subprocess and exercises the MCP
stdio transport end-to-end. That makes the happy-path test slower
than the rest of the suite (~2-4s on a warm cache, more on cold) but
the whole point of the doctor is that it's *real*: a passing test
here means an MCP client can talk to this install. A unit test that
mocked the handshake wouldn't catch that.

The error-path tests inject failures via a stub handshake function
to keep them fast and OS-independent.
"""

from __future__ import annotations

import asyncio
import io

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.mcp_doctor import (
    DoctorCheck,
    DoctorReport,
    _run_with_timeout,
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


class TestTimeoutPath:
    def test_timeout_reports_failure_without_raising(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _hang(_errlog: io.StringIO) -> tuple[list[str], list[DoctorCheck]]:
            await asyncio.sleep(60)
            return [], []

        # Shrink the timeout so the test resolves fast.
        monkeypatch.setattr("recon_tool.mcp_doctor._HANDSHAKE_TIMEOUT_S", 0.05)
        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _hang)

        report = asyncio.run(_run_with_timeout())
        assert not report.ok
        assert any(c.status == "fail" and "timed out" in c.detail for c in report.checks)


class TestExceptionPath:
    def test_handshake_exception_reports_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _boom(_errlog: io.StringIO) -> tuple[list[str], list[DoctorCheck]]:
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

        async def _crash(errlog: io.StringIO) -> tuple[list[str], list[DoctorCheck]]:
            errlog.write(
                "Traceback (most recent call last):\n"
                "  File \"server.py\", line 1, in <module>\n"
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


class TestRequiredToolsGate:
    def test_missing_canonical_tools_fails_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Pretend the handshake succeeded but only returned an unrelated tool.
        async def _stub(_errlog: io.StringIO) -> tuple[list[str], list[DoctorCheck]]:
            return (
                ["unrelated_tool"],
                [
                    DoctorCheck("server spawn", "ok", "stub"),
                    DoctorCheck("initialize handshake", "ok", "stub"),
                    DoctorCheck("tools/list", "ok", "1 tools registered"),
                ],
            )

        monkeypatch.setattr("recon_tool.mcp_doctor._run_handshake", _stub)

        report = asyncio.run(_run_with_timeout())
        assert not report.ok
        gate = next(c for c in report.checks if c.name == "required tools present")
        assert gate.status == "fail"
        assert "missing" in gate.detail
        assert "lookup_tenant" in gate.detail


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
        assert "self-check" in result.output.lower()

    def test_doctor_renders_failed_report_with_nonzero_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _stub_run() -> DoctorReport:
            return DoctorReport(
                checks=(
                    DoctorCheck("server spawn", "fail", "subprocess refused to start"),
                ),
                elapsed_seconds=0.1,
            )

        monkeypatch.setattr("recon_tool.mcp_doctor.run_doctor", _stub_run)

        result = runner.invoke(app, ["mcp", "doctor"])
        assert result.exit_code != 0
        assert "FAIL" in result.output
        assert "server spawn" in result.output
        assert "subprocess refused to start" in result.output

    def test_doctor_renders_ok_report_with_zero_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _stub_run() -> DoctorReport:
            return DoctorReport(
                checks=(
                    DoctorCheck("server spawn", "ok", "stdio transport opened"),
                    DoctorCheck("initialize handshake", "ok", "server=recon-tool"),
                    DoctorCheck("tools/list", "ok", "22 tools registered"),
                    DoctorCheck("required tools present", "ok", "5 of 5"),
                ),
                elapsed_seconds=2.34,
            )

        monkeypatch.setattr("recon_tool.mcp_doctor.run_doctor", _stub_run)

        result = runner.invoke(app, ["mcp", "doctor"])
        assert result.exit_code == 0
        assert "ok" in result.output
        assert "22 tools registered" in result.output
        assert "All checks passed" in result.output
