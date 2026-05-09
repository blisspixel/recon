"""Integration tests for MCP server."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("mcp")

from recon_tool.models import (
    ConfidenceLevel,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)
from recon_tool.server import _cache_clear, _print_mcp_banner, _rate_limit, lookup_tenant

RESOLVE_PATH = "recon_tool.server.resolve_tenant"

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Contoso Ltd",
    default_domain="contoso.onmicrosoft.com",
    queried_domain="contoso.com",
    confidence=ConfidenceLevel.HIGH,
    region="NA",
    sources=("oidc_discovery", "azure_ad_metadata"),
    services=("Exchange Online", "Microsoft 365"),
    slugs=("microsoft365",),
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
    SourceResult(source_name="azure_ad_metadata", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
]


@pytest.fixture(autouse=True)
def _clear_server_caches():
    """Clear server caches and rate limits between tests."""
    _cache_clear()
    _rate_limit.clear()
    yield
    _cache_clear()
    _rate_limit.clear()


class TestLookupText:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_text_contains_company(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com")
        assert "Company: Contoso Ltd" in result
        assert "Provider: Microsoft 365" in result
        assert "Tenant ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in result
        assert "Region: NA" in result

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_text_not_json(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com")
        with pytest.raises(json.JSONDecodeError):
            json.loads(result)

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_omits_region_when_none(self, mock_resolve: AsyncMock) -> None:
        info = TenantInfo(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            display_name="Contoso Ltd",
            default_domain="contoso.onmicrosoft.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.MEDIUM,
            region=None,
            sources=("oidc_discovery",),
        )
        mock_resolve.return_value = (info, SAMPLE_RESULTS[:1])
        result = await lookup_tenant("contoso.com")
        assert "Region:" not in result


class TestLookupJson:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_json_format(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json")
        data = json.loads(result)
        assert data["display_name"] == "Contoso Ltd"
        # v0.9.3 (revised): slug-only fallback uses
        # "(account detected, no MX)" because the fallback runs
        # only when no MX evidence exists, so the slug match came
        # from a non-MX identity source. See
        # test_backward_compat.TestBackwardCompatDetectProvider
        # for the full rationale.
        assert data["provider"] == "Microsoft 365 (account detected, no MX)"
        assert data["tenant_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert data["confidence"] == "high"


class TestLookupMarkdown:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_markdown_format(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="markdown")
        assert "# " in result
        assert "Contoso Ltd" in result


class TestErrors:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_not_found(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com",
            message="No data",
            error_type="all_sources_failed",
        )
        result = await lookup_tenant("unknown.com")
        assert "No information found for unknown.com" in result

    @pytest.mark.asyncio
    async def test_empty_domain(self) -> None:
        result = await lookup_tenant("   ")
        assert "error" in result.lower()

    @pytest.mark.asyncio
    async def test_invalid_domain(self) -> None:
        result = await lookup_tenant("not a domain")
        assert "error" in result.lower()

    @pytest.mark.asyncio
    async def test_invalid_format(self) -> None:
        result = await lookup_tenant("example.com", format="xml")
        assert "invalid format" in result.lower()

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_unexpected_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = RuntimeError("timeout")
        result = await lookup_tenant("example.com")
        assert "Error looking up example.com" in result
        assert "internal error" in result

    @pytest.mark.asyncio
    async def test_concurrent_miss_only_one_lookup_reaches_upstream(self) -> None:
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def fake_resolve(_domain: str):
            nonlocal calls
            calls += 1
            started.set()
            await release.wait()
            return SAMPLE_INFO, SAMPLE_RESULTS

        with patch(RESOLVE_PATH, side_effect=fake_resolve):
            first = asyncio.create_task(lookup_tenant("contoso.com"))
            await started.wait()
            second = await lookup_tenant("contoso.com")
            release.set()
            first_result = await first

        assert calls == 1
        assert "Company: Contoso Ltd" in first_result
        assert "Rate limited:" in second

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_failed_lookup_releases_inflight_rate_limit(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com",
            message="No data",
            error_type="all_sources_failed",
        )

        first = await lookup_tenant("unknown.com")
        second = await lookup_tenant("unknown.com")

        assert "No information found for unknown.com" in first
        assert "No information found for unknown.com" in second
        assert mock_resolve.await_count == 2


class TestMCPMetadata:
    def test_server_name(self) -> None:
        from recon_tool.server import mcp

        assert mcp.name == "recon-tool"

    def test_tool_description(self) -> None:
        assert lookup_tenant.__doc__ is not None
        doc = lookup_tenant.__doc__.lower()
        assert "domain" in doc

    def test_prompt_exists(self) -> None:
        from recon_tool.server import domain_report

        result = domain_report("contoso.com")
        assert "contoso.com" in result
        assert "lookup_tenant" in result

    def test_startup_banner_warns_and_uses_stderr(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_mcp_banner()
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "WARNING" in captured.err
        assert "privileges of the calling user" in captured.err
        assert "auto-approval" in captured.err


class TestTTYStartupGuard:
    """A human running `python -m recon_tool.server` directly should see a
    helpful 'this is not a REPL' panel instead of being dropped into the
    JSON-RPC loop where their stray newlines surface as Pydantic errors."""

    def test_tty_prints_misuse_panel_and_exits_without_running(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from recon_tool import server

        monkeypatch.setattr(server, "_stdin_is_tty", lambda: True)
        monkeypatch.delenv("RECON_MCP_FORCE_STDIO", raising=False)

        ran = {"called": False}

        def _fail_run() -> None:
            ran["called"] = True
            raise AssertionError("mcp.run() must not be reached when stdin is a TTY")

        monkeypatch.setattr(server.mcp, "run", _fail_run)

        server.main()

        captured = capsys.readouterr()
        assert captured.out == ""
        assert "NOT an interactive REPL" in captured.err
        assert "JSON-RPC over stdio" in captured.err
        assert "RECON_MCP_FORCE_STDIO" in captured.err
        assert ran["called"] is False

    def test_tty_skip_does_not_emit_normal_banner(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from recon_tool import server

        monkeypatch.setattr(server, "_stdin_is_tty", lambda: True)
        monkeypatch.delenv("RECON_MCP_FORCE_STDIO", raising=False)
        monkeypatch.setattr(server.mcp, "run", lambda: None)

        server.main()

        captured = capsys.readouterr()
        # The startup banner's WARNING block belongs only to the JSON-RPC
        # path. The misuse panel is the only thing humans should see.
        assert "Listening on stdio transport." not in captured.err

    @pytest.mark.parametrize("override_value", ["1", "true", "yes"])
    def test_force_stdio_env_var_bypasses_tty_guard(
        self,
        override_value: str,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from recon_tool import server

        monkeypatch.setattr(server, "_stdin_is_tty", lambda: True)
        monkeypatch.setenv("RECON_MCP_FORCE_STDIO", override_value)

        ran = {"called": False}

        def _ok_run() -> None:
            ran["called"] = True

        monkeypatch.setattr(server.mcp, "run", _ok_run)

        server.main()

        captured = capsys.readouterr()
        assert ran["called"] is True
        assert "NOT an interactive REPL" not in captured.err
        assert "Listening on stdio transport." in captured.err

    def test_non_tty_path_runs_server_normally(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from recon_tool import server

        monkeypatch.setattr(server, "_stdin_is_tty", lambda: False)
        monkeypatch.delenv("RECON_MCP_FORCE_STDIO", raising=False)

        ran = {"called": False}

        def _ok_run() -> None:
            ran["called"] = True

        monkeypatch.setattr(server.mcp, "run", _ok_run)

        server.main()

        captured = capsys.readouterr()
        assert ran["called"] is True
        assert "NOT an interactive REPL" not in captured.err
        assert "Listening on stdio transport." in captured.err

    def test_stdin_is_tty_helper_handles_missing_isatty(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from recon_tool import server

        class _StubStdin:
            pass  # no isatty attribute at all

        monkeypatch.setattr("sys.stdin", _StubStdin())

        # Must not raise; absence of a real terminal looks like a client
        # spawn from the server's perspective.
        assert server._stdin_is_tty() is False

    @pytest.mark.parametrize("exc", [ValueError("closed"), OSError("bad handle")])
    def test_stdin_is_tty_helper_handles_isatty_raising(
        self,
        exc: BaseException,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from recon_tool import server

        class _RaisingStdin:
            def isatty(self) -> bool:
                raise exc

        monkeypatch.setattr("sys.stdin", _RaisingStdin())

        # Closed stdin (ValueError) and weird-handle states (OSError on
        # Windows when the underlying file descriptor is in a bad state)
        # both mean "no human at the keyboard" — we should not crash
        # the server before mcp.run() ever gets a chance.
        assert server._stdin_is_tty() is False

    @pytest.mark.parametrize("override_value", ["true", "TRUE", "TruE", " 1 ", "ON"])
    def test_force_stdio_override_is_case_insensitive_and_trimmed(
        self,
        override_value: str,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from recon_tool import server

        monkeypatch.setattr(server, "_stdin_is_tty", lambda: True)
        monkeypatch.setenv("RECON_MCP_FORCE_STDIO", override_value)

        ran = {"called": False}

        def _ok_run() -> None:
            ran["called"] = True

        monkeypatch.setattr(server.mcp, "run", _ok_run)

        server.main()

        captured = capsys.readouterr()
        assert ran["called"] is True
        assert "NOT an interactive REPL" not in captured.err
