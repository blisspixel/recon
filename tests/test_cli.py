"""Unit tests for CLI application."""

from __future__ import annotations

import json
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import typer
import typer.rich_utils as typer_rich_utils
from typer.main import get_command
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.models import (
    ConfidenceLevel,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)

runner = CliRunner()


def _strip_ansi(value: str) -> str:
    """Return Rich-rendered help text without terminal color sequences."""
    return re.sub(r"\x1b\[[0-9;]*m", "", value)


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
    SourceResult(source_name="dns_records", error="no indicators"),
]

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"


class TestHelp:
    def test_help_shows_usage(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        collapsed = " ".join(_strip_ansi(result.output).replace("│", " ").split())
        assert "recon" in collapsed.lower()
        assert "Start with recon DOMAIN" in collapsed
        assert "run recon with no arguments for examples" in collapsed

    def test_lookup_help(self) -> None:
        result = runner.invoke(app, ["lookup", "--help"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "--json" in plain
        assert "--md" in plain
        assert "--full" in plain
        assert "--strict" in plain
        collapsed = " ".join(plain.replace("│", " ").split())
        assert "Services are shown by default; retained for compatibility" in collapsed
        assert "Expanded evidence, all domains, and posture" in collapsed
        assert "configured recursive resolver" in collapsed
        assert "authoritative DNS may observe the resulting traffic" in collapsed
        assert "MTA-STS policy fetch is the only default target-owned HTTP/application request" in collapsed
        assert "High confidence with at least three sources" in collapsed
        assert "underlying evidence, validation, and confidence are unchanged" in collapsed

    def test_doctor_help_distinguishes_online_connectivity(self) -> None:
        result = runner.invoke(app, ["doctor", "--help"])

        assert result.exit_code == 0
        collapsed = " ".join(_strip_ansi(result.output).replace("│", " ").split())
        assert "installation health" in collapsed
        assert "online source connectivity" in collapsed
        assert "emit an mcpServers reference config" in collapsed
        assert "copy-pasteable client config" not in collapsed

    def test_lookup_help_groups_options_by_user_task(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(typer_rich_utils, "MAX_WIDTH", 80)
        result = runner.invoke(app, ["lookup", "--help"])

        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        collapsed = " ".join(plain.replace("│", " ").split())
        assert (
            "Start with recon DOMAIN. Add --full for detail, --explain for evidence, "
            "or --json for automation. Google CSE and BIMI probes require --direct-probes; "
            "MTA-STS is the only default target-owned HTTP request." in collapsed
        )

        headings = (
            "Output",
            "Report detail and wording",
            "Collection, cache, and scope",
            "Analysis modes",
            "Evidence model",
        )
        positions = tuple(plain.index(heading) for heading in headings)
        assert positions == tuple(sorted(positions))
        output, detail, collection, analysis, evidence = positions
        assert output < plain.index("--plain") < detail
        assert detail < plain.index("--services") < collection
        assert detail < plain.index("--confidence-mode") < collection
        assert collection < plain.index("--no-cache") < analysis
        assert analysis < plain.index("--compare") < evidence
        assert evidence < plain.index("--fusion")

        root_command = get_command(app)
        assert isinstance(root_command, typer.core.TyperGroup)
        lookup_command = root_command.commands["lookup"]
        options = tuple(param for param in lookup_command.params if isinstance(param, typer.core.TyperOption))
        assert len(options) == 28
        primary_tokens = tuple(next(token for token in option.opts if token.startswith("--")) for option in options)
        assert all(token in plain for token in primary_tokens)

    @pytest.mark.parametrize(
        "args",
        [
            ["--fix", "--mcp"],
            ["--fix", "--client", "cursor"],
            ["--mcp", "--client", "cursor"],
        ],
    )
    def test_doctor_modes_are_mutually_exclusive(self, args: list[str]) -> None:
        result = runner.invoke(app, ["doctor", *args])

        assert result.exit_code == 2
        assert "choose exactly one" in result.output.lower()

    def test_welcome_prioritizes_primary_accessible_and_automation_paths(self) -> None:
        result = runner.invoke(app, [])

        assert result.exit_code == 0
        collapsed = " ".join(_strip_ansi(result.output).split())
        assert "--plain" in collapsed
        assert "screen readers and grep" in collapsed
        assert "--json" in collapsed
        assert "structured automation" in collapsed
        assert "mcp install --help" in collapsed
        assert "connect an MCP client" in collapsed
        assert "recon mcp → start" not in collapsed
        assert "→ everything" not in collapsed
        assert "offline install check" in collapsed
        assert "python -m recon_tool --version" in collapsed
        assert "public-suffix domain" in collapsed
        assert "DNS queries" in collapsed
        assert "MTA-STS" in collapsed
        assert "Google CSE and BIMI direct probes run only with --direct-probes" in collapsed

    def test_version_flag(self) -> None:
        from recon_tool.cli import version_callback

        with pytest.raises(typer.Exit):
            version_callback(True)


class TestDirectDomainLookup:
    """``recon contoso.com`` (no ``lookup`` subcommand) routes to the lookup
    command via ``_DomainGroup``. This is exercised through CliRunner: the
    routing runs inside Click's command resolution, which CliRunner drives."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_bare_domain_routes_to_lookup(self, mock_resolve) -> None:
        # Regression guard for the shorthand routing. Typer >=0.25 vendors its
        # own Click, so the group's domain-to-lookup routing must not depend on
        # catching the top-level ``click.UsageError`` (it does not see the
        # vendored one). A bare domain must reach the lookup command, not error
        # with "No such command".
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["contoso.com", "--no-cache"])
        assert result.exit_code == 0, result.output
        assert "No such command" not in result.output
        assert "Contoso Ltd" in result.output

    def test_undotted_domain_attempt_uses_domain_validation(self) -> None:
        # Hostnames without a dot (or other invalid tokens) must not fall through
        # as Click "No such command". Route them to lookup so the user gets a
        # domain-format rejection.
        result = runner.invoke(app, ["contoso"])
        assert result.exit_code == 2
        assert "No such command" not in result.output
        assert "Invalid domain format" in result.output
        collapsed = " ".join(result.output.split())
        assert "Expected a domain with a public suffix, such as contoso.com." in collapsed
        assert "Run recon with no arguments for examples." in collapsed

    def test_malformed_undotted_token_is_not_unknown_command(self) -> None:
        result = runner.invoke(app, ["not-a-valid-domain!!!"])
        assert result.exit_code == 2
        assert "No such command" not in result.output
        assert "Invalid domain format" in result.output
        collapsed = " ".join(result.output.split())
        assert collapsed.count("Run recon with no arguments for examples.") == 1

    def test_root_help_uses_passive_public_sources_summary(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Passive domain intelligence from public sources" in result.output
        assert "Start with recon DOMAIN" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_default(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        # ``--no-cache`` ensures the mocked resolver is actually called
        # rather than the test reading whatever is in the developer's
        # ``~/.recon/cache/`` from prior real runs.
        result = runner.invoke(app, ["lookup", "contoso.com", "--no-cache"])
        assert result.exit_code == 0
        assert "Contoso Ltd" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_json(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--json", "--no-cache"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["display_name"] == "Contoso Ltd"

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_md(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--md", "--no-cache"])
        assert result.exit_code == 0
        assert "# " in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_plain(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--plain", "--no-cache"])
        assert result.exit_code == 0
        assert "queried_domain: contoso.com" in result.output
        # Linear text — no box-drawing characters.
        assert "─" not in result.output
        assert "│" not in result.output

    def test_lookup_json_plain_mutually_exclusive(self) -> None:
        result = runner.invoke(app, ["lookup", "contoso.com", "--json", "--plain"])
        assert result.exit_code == 2

    def test_lookup_plain_rejected_with_alternate_modes(self) -> None:
        # --plain only governs the standard render; combining it with a mode
        # that has its own output is rejected, not silently ignored.
        for mode in ("--exposure", "--gaps", "--chain"):
            result = runner.invoke(app, ["lookup", "contoso.com", "--plain", mode])
            assert result.exit_code == 2, f"--plain {mode} should be rejected"


class TestLookupSubcommand:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_subcommand(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--no-cache"])
        assert result.exit_code == 0
        assert "Contoso Ltd" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_verbose_flag(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--verbose", "--no-cache"])
        assert result.exit_code == 0
        assert "oidc_discovery" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_sources_flag(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--sources"])
        assert result.exit_code == 0
        assert "Source Details" in result.output

    def test_strict_alias_sets_confidence_mode(self, monkeypatch) -> None:
        seen = {}

        async def fake_lookup(_domain, options) -> None:
            seen["confidence_mode"] = options.confidence_mode

        monkeypatch.setattr("recon_tool.cli._lookup", fake_lookup)
        result = runner.invoke(app, ["lookup", "contoso.com", "--strict"])
        assert result.exit_code == 0
        assert seen["confidence_mode"] == "strict"

    def test_confidence_mode_rejects_typo(self) -> None:
        result = runner.invoke(app, ["lookup", "contoso.com", "--confidence-mode", "scrict"])
        assert result.exit_code == 2
        assert "hedged" in result.output
        assert "strict" in result.output


class TestErrors:
    def test_invalid_domain(self) -> None:
        result = runner.invoke(app, ["lookup", "not a domain"])
        assert result.exit_code == 2

    def test_empty_domain(self) -> None:
        result = runner.invoke(app, ["lookup", "   "])
        assert result.exit_code == 2

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_all_sources_failed(self, mock_resolve) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com",
            message="No tenant found",
            error_type="all_sources_failed",
        )
        result = runner.invoke(app, ["lookup", "unknown.com"])
        assert result.exit_code == 4
        assert "No tenant found" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_unexpected_error(self, mock_resolve) -> None:
        mock_resolve.side_effect = RuntimeError("connection failed")
        result = runner.invoke(app, ["lookup", "example.com", "--no-cache"])
        assert result.exit_code == 4
        assert "connection failed" in result.output


class TestDoctor:
    @patch("dns.resolver.resolve")
    @patch("httpx.AsyncClient")
    def test_doctor_all_pass(self, mock_http_cls, mock_dns) -> None:
        mock_dns.return_value = [MagicMock()]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_http_cls.return_value = mock_client

        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "All checks passed" in result.output
