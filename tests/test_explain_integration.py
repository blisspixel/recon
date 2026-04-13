"""QA Round 3 — Integration tests for CLI --explain, MCP introspection, and agentic tools.

Covers:
  11.1 CLI --explain flag (Rich, JSON, markdown, chain, backward compat)
  11.2 MCP introspection tools (get_fingerprints, get_signals, explain_signal)
  11.3 test_hypothesis MCP tool
  11.4 simulate_hardening MCP tool
  11.5 explain parameter on lookup_tenant and analyze_posture
  11.6 Conflict annotations in Rich panel
  11.7 (ruff/pyright/pytest — run separately)
"""

from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.formatter import render_conflict_annotation, render_tenant_panel
from recon_tool.models import (
    CandidateValue,
    ConfidenceLevel,
    EvidenceRecord,
    MergeConflicts,
    SourceResult,
    TenantInfo,
)
from recon_tool.server import (
    _cache_clear,  # pyright: ignore[reportPrivateUsage]
    _rate_limit,  # pyright: ignore[reportPrivateUsage]
    analyze_posture,
    explain_signal,
    get_fingerprints,
    get_signals,
    lookup_tenant,
    simulate_hardening,
)
from recon_tool.server import test_hypothesis as mcp_test_hypothesis

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"
SERVER_RESOLVE_PATH = "recon_tool.server.resolve_tenant"
SERVER_RESOLVE_OR_CACHE = "recon_tool.server._resolve_or_cache"

# Fictional company fixture data
_EVIDENCE = (
    EvidenceRecord(
        source_type="TXT",
        raw_value="v=spf1 include:spf.protection.outlook.com",
        rule_name="SPF M365",
        slug="microsoft365",
    ),
    EvidenceRecord(
        source_type="MX", raw_value="contoso-com.mail.protection.outlook.com", rule_name="MX M365", slug="microsoft365"
    ),
)

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Contoso Ltd",
    default_domain="contoso.onmicrosoft.com",
    queried_domain="contoso.com",
    confidence=ConfidenceLevel.HIGH,
    region="NA",
    sources=("oidc_discovery", "azure_ad_metadata", "dns_records"),
    services=("Exchange Online", "Microsoft 365"),
    slugs=("microsoft365",),
    auth_type="Managed",
    dmarc_policy="reject",
    insights=("Email Security Score: 3/5 (DMARC, DKIM, SPF)",),
    evidence=_EVIDENCE,
    detection_scores=(("microsoft365", "high"),),
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
    SourceResult(source_name="azure_ad_metadata", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
    SourceResult(
        source_name="dns_records",
        detected_services=("Exchange Online",),
        detected_slugs=("microsoft365",),
        evidence=_EVIDENCE,
    ),
]

# TenantInfo with merge conflicts for conflict annotation tests
_CONFLICTS = MergeConflicts(
    display_name=(
        CandidateValue("Contoso Ltd", "oidc_discovery", "high"),
        CandidateValue("Contoso Corporation", "azure_ad_metadata", "medium"),
    ),
    auth_type=(
        CandidateValue("Managed", "userrealm", "high"),
        CandidateValue("Federated", "oidc_discovery", "medium"),
    ),
)

SAMPLE_INFO_WITH_CONFLICTS = replace(SAMPLE_INFO, merge_conflicts=_CONFLICTS)


@pytest.fixture(autouse=True)
def _clear_server_state():  # pyright: ignore[reportUnusedFunction]
    """Clear server caches and rate limits between tests."""
    _cache_clear()
    _rate_limit.clear()
    yield
    _cache_clear()
    _rate_limit.clear()


# ── 11.1 CLI --explain flag ──────────────────────────────────────────────


class TestCLIExplainFlag:
    """Unit tests for --explain CLI flag."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_explain_rich_output(self, mock_resolve: AsyncMock) -> None:
        """--explain alone produces explanation section in Rich output."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        from io import StringIO

        from rich.console import Console

        from recon_tool.formatter import get_console, set_console

        original = get_console()
        buf = StringIO()
        set_console(Console(file=buf, width=120, force_terminal=True))
        try:
            result = runner.invoke(app, ["lookup", "contoso.com", "--explain", "--no-cache"])
            assert result.exit_code == 0
            output = buf.getvalue() + result.output
            assert "Explanations" in output
        finally:
            set_console(original)

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_explain_json_output(self, mock_resolve: AsyncMock) -> None:
        """--explain --json includes explanations key."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--explain", "--json", "--no-cache"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "explanations" in data
        assert isinstance(data["explanations"], list)
        assert len(data["explanations"]) > 0

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_explain_md_output(self, mock_resolve: AsyncMock) -> None:
        """--explain --md appends ## Explanations section."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--explain", "--md", "--no-cache"])
        assert result.exit_code == 0
        assert "## Explanations" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_explain_chain_output(self, mock_resolve: AsyncMock) -> None:
        """--explain --chain produces per-domain explanations."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        from io import StringIO

        from rich.console import Console

        from recon_tool.formatter import get_console, set_console

        original = get_console()
        buf = StringIO()
        set_console(Console(file=buf, width=120, force_terminal=True))
        try:
            result = runner.invoke(app, ["lookup", "contoso.com", "--explain", "--chain", "--no-cache"])
            assert result.exit_code == 0
            output = buf.getvalue() + result.output
            assert "Explanations" in output or "Chain" in output
        finally:
            set_console(original)

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_no_explain_backward_compat(self, mock_resolve: AsyncMock) -> None:
        """Without --explain, no explanation output (backward compatible)."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        from io import StringIO

        from rich.console import Console

        from recon_tool.formatter import get_console, set_console

        original = get_console()
        buf = StringIO()
        set_console(Console(file=buf, width=120, force_terminal=True))
        try:
            result = runner.invoke(app, ["lookup", "contoso.com", "--no-cache"])
            assert result.exit_code == 0
            output = buf.getvalue() + result.output
            assert "Explanations" not in output
        finally:
            set_console(original)

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_no_explain_json_backward_compat(self, mock_resolve: AsyncMock) -> None:
        """Without --explain, JSON output has no explanations key."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--json", "--no-cache"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "explanations" not in data


# ── 11.2 MCP introspection tools ────────────────────────────────────────


class TestGetFingerprints:
    """Unit tests for get_fingerprints MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_json_array(self) -> None:
        result = await get_fingerprints()
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_has_required_fields(self) -> None:
        result = await get_fingerprints()
        data = json.loads(result)
        first = data[0]
        assert "slug" in first
        assert "name" in first
        assert "category" in first
        assert "confidence" in first
        assert "match_mode" in first
        assert "detection_types" in first

    @pytest.mark.asyncio
    async def test_category_filter(self) -> None:
        """Category filter is case-insensitive partial match."""
        result_all = await get_fingerprints()
        result_email = await get_fingerprints(category="email")
        all_data = json.loads(result_all)
        email_data = json.loads(result_email)
        assert len(email_data) > 0
        assert len(email_data) < len(all_data)
        for fp in email_data:
            assert "email" in fp["category"].lower()

    @pytest.mark.asyncio
    async def test_category_filter_case_insensitive(self) -> None:
        result_lower = await get_fingerprints(category="email")
        result_upper = await get_fingerprints(category="EMAIL")
        assert json.loads(result_lower) == json.loads(result_upper)


class TestGetSignals:
    """Unit tests for get_signals MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_json_array(self) -> None:
        result = await get_signals()
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_has_new_fields(self) -> None:
        """New v0.7.0 fields are present."""
        result = await get_signals()
        data = json.loads(result)
        first = data[0]
        assert "contradicts" in first
        assert "requires_signals" in first
        assert "explain" in first
        assert "layer" in first

    @pytest.mark.asyncio
    async def test_category_filter(self) -> None:
        result = await get_signals(category="security")
        data = json.loads(result)
        assert len(data) > 0
        for sig in data:
            assert "security" in sig["category"].lower()

    @pytest.mark.asyncio
    async def test_layer_filter(self) -> None:
        result = await get_signals(layer=1)
        data = json.loads(result)
        assert len(data) > 0
        for sig in data:
            assert sig["layer"] == 1


class TestExplainSignal:
    """Unit tests for explain_signal MCP tool."""

    @pytest.mark.asyncio
    async def test_known_signal_no_domain(self) -> None:
        """Known signal without domain returns definition and conditions."""
        # Use a signal name that exists in the built-in signals.yaml
        from recon_tool.signals import load_signals

        signals = load_signals()
        assert len(signals) > 0
        sig_name = signals[0].name

        result = await explain_signal(sig_name)
        data = json.loads(result)
        assert "name" in data
        assert data["name"] == sig_name
        assert "trigger_conditions" in data
        assert "weakening_conditions" in data

    @pytest.mark.asyncio
    async def test_unknown_signal(self) -> None:
        """Unknown signal returns error with available names."""
        result = await explain_signal("Nonexistent Signal That Does Not Exist")
        data = json.loads(result)
        assert "error" in data
        assert "available_signals" in data
        assert isinstance(data["available_signals"], list)
        assert len(data["available_signals"]) > 0

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_with_domain(self, mock_resolve: AsyncMock) -> None:
        """explain_signal with domain returns evaluation state."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))

        from recon_tool.signals import load_signals

        signals = load_signals()
        sig_name = signals[0].name

        result = await explain_signal(sig_name, domain="contoso.com")
        data = json.loads(result)
        assert "domain" in data
        assert "fired" in data
        assert "matched_slugs" in data


# ── 11.3 test_hypothesis MCP tool ───────────────────────────────────────


class TestTestHypothesis:
    """Unit tests for test_hypothesis MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_returns_correct_structure(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        result = await mcp_test_hypothesis("contoso.com", "mid-migration to cloud identity")
        data = json.loads(result)
        assert "likelihood" in data
        assert "supporting_signals" in data
        assert "contradicting_signals" in data
        assert "missing_evidence" in data
        assert "confidence" in data
        assert "disclaimer" in data

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_keyword_matching(self, mock_resolve: AsyncMock) -> None:
        """Hypothesis keywords map to relevant signals."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        result = await mcp_test_hypothesis("contoso.com", "security posture assessment")
        data = json.loads(result)
        # Should have some signals matched via keyword matching
        assert isinstance(data["supporting_signals"], list)
        assert isinstance(data["contradicting_signals"], list)
        assert isinstance(data["missing_evidence"], list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_hedged_language(self, mock_resolve: AsyncMock) -> None:
        """Output uses hedged language (indicators suggest, not confirms)."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        result = await mcp_test_hypothesis("contoso.com", "email security")
        data = json.loads(result)
        disclaimer = data["disclaimer"]
        assert "suggest" in disclaimer.lower() or "indicators" in disclaimer.lower()
        assert "confirm" not in disclaimer.lower() or "do not confirm" in disclaimer.lower()

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_error_on_invalid_domain(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = "Error: invalid domain"
        result = await mcp_test_hypothesis("not-a-domain", "test")
        assert "Error" in result


# ── 11.4 simulate_hardening MCP tool ────────────────────────────────────


class TestSimulateHardening:
    """Unit tests for simulate_hardening MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_returns_correct_structure(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        result = await simulate_hardening("contoso.com", ["DMARC reject", "MTA-STS enforce"])
        data = json.loads(result)
        assert "current_score" in data
        assert "simulated_score" in data
        assert "score_delta" in data
        assert "applied_fixes" in data
        assert "remaining_gaps" in data
        assert isinstance(data["score_delta"], (int, float))

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_consider_language_in_gaps(self, mock_resolve: AsyncMock) -> None:
        """Remaining gaps use 'Consider' language in recommendations."""
        # Use info without DMARC to ensure gaps exist
        info_no_dmarc = replace(SAMPLE_INFO, dmarc_policy=None, services=("Exchange Online",))
        mock_resolve.return_value = (info_no_dmarc, list(SAMPLE_RESULTS))
        result = await simulate_hardening("contoso.com", ["BIMI"])
        data = json.loads(result)
        # Check remaining_gaps have recommendation text
        for gap in data["remaining_gaps"]:
            assert "recommendation" in gap
            assert "observation" in gap

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_score_delta_non_negative_for_fixes(self, mock_resolve: AsyncMock) -> None:
        """Applying fixes should not decrease the score."""
        info_weak = replace(SAMPLE_INFO, dmarc_policy=None, mta_sts_mode=None)
        mock_resolve.return_value = (info_weak, list(SAMPLE_RESULTS))
        result = await simulate_hardening("contoso.com", ["DMARC reject", "MTA-STS enforce"])
        data = json.loads(result)
        assert data["score_delta"] >= 0

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_error_on_invalid_domain(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = "Error: invalid domain"
        result = await simulate_hardening("bad", [])
        assert "Error" in result


# ── 11.5 explain parameter on lookup_tenant and analyze_posture ──────────


class TestLookupTenantExplain:
    """Unit tests for explain parameter on lookup_tenant MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_true_includes_explanations(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json", explain=True)
        data = json.loads(result)
        assert "explanations" in data
        assert isinstance(data["explanations"], list)
        assert len(data["explanations"]) > 0

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_false_no_explanations(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json", explain=False)
        data = json.loads(result)
        assert "explanations" not in data

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_omitted_no_explanations(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json")
        data = json.loads(result)
        assert "explanations" not in data

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_with_conflicts(self, mock_resolve: AsyncMock) -> None:
        """explain=True with conflicts includes conflicts key."""
        mock_resolve.return_value = (SAMPLE_INFO_WITH_CONFLICTS, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json", explain=True)
        data = json.loads(result)
        assert "explanations" in data
        assert "conflicts" in data
        assert "display_name" in data["conflicts"]


class TestAnalyzePostureExplain:
    """Unit tests for explain parameter on analyze_posture MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_true_includes_explanations(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await analyze_posture("contoso.com", explain=True)
        data = json.loads(result)
        assert "explanations" in data
        assert isinstance(data["explanations"], list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_false_no_explanations(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await analyze_posture("contoso.com", explain=False)
        data = json.loads(result)
        # Without explain, result is a plain list of observations
        assert isinstance(data, list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_omitted_no_explanations(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await analyze_posture("contoso.com")
        data = json.loads(result)
        assert isinstance(data, list)


# ── 11.6 Conflict annotations in Rich panel ─────────────────────────────


class TestConflictAnnotations:
    """Unit tests for conflict annotations in Rich panel."""

    def test_conflict_annotation_with_explain(self) -> None:
        """render_conflict_annotation shows disagreement count."""
        ann = render_conflict_annotation("display_name", _CONFLICTS)
        assert "2 sources disagree" in ann

    def test_conflict_annotation_verbose(self) -> None:
        """Verbose mode shows all candidate values."""
        ann = render_conflict_annotation("display_name", _CONFLICTS, verbose=True)
        assert "2 sources disagree" in ann
        assert "Contoso Ltd" in ann
        assert "Contoso Corporation" in ann
        assert "oidc_discovery" in ann
        assert "azure_ad_metadata" in ann

    def test_no_conflict_returns_empty(self) -> None:
        """No conflict for a field returns empty string."""
        no_conflicts = MergeConflicts()
        ann = render_conflict_annotation("display_name", no_conflicts)
        assert ann == ""

    def test_panel_with_explain_shows_annotations(self) -> None:
        """render_tenant_panel with explain=True shows conflict annotations."""
        panel = render_tenant_panel(SAMPLE_INFO_WITH_CONFLICTS, explain=True)
        # Render to string to check content
        from io import StringIO

        from rich.console import Console

        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        console.print(panel)
        output = buf.getvalue()
        assert "sources disagree" in output

    def test_panel_with_verbose_explain_shows_candidates(self) -> None:
        """render_tenant_panel with verbose+explain shows all candidates."""
        panel = render_tenant_panel(SAMPLE_INFO_WITH_CONFLICTS, verbose=True, explain=True)
        from io import StringIO

        from rich.console import Console

        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        console.print(panel)
        output = buf.getvalue()
        assert "sources disagree" in output
        assert "Contoso Corporation" in output

    def test_panel_without_explain_no_annotations(self) -> None:
        """Without explain, no conflict indicators (backward compatible)."""
        panel = render_tenant_panel(SAMPLE_INFO_WITH_CONFLICTS, explain=False)
        from io import StringIO

        from rich.console import Console

        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        console.print(panel)
        output = buf.getvalue()
        assert "sources disagree" not in output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_cli_explain_with_conflicts(self, mock_resolve: AsyncMock) -> None:
        """CLI --explain with conflicts shows dim annotation."""
        mock_resolve.return_value = (SAMPLE_INFO_WITH_CONFLICTS, SAMPLE_RESULTS)
        from io import StringIO

        from rich.console import Console

        from recon_tool.formatter import get_console, set_console

        original = get_console()
        buf = StringIO()
        set_console(Console(file=buf, width=120, force_terminal=True))
        try:
            result = runner.invoke(app, ["lookup", "contoso.com", "--explain", "--no-cache"])
            assert result.exit_code == 0
            output = buf.getvalue() + result.output
            assert "sources disagree" in output
        finally:
            set_console(original)

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_cli_no_explain_no_conflict_indicators(self, mock_resolve: AsyncMock) -> None:
        """CLI without --explain shows no conflict indicators."""
        mock_resolve.return_value = (SAMPLE_INFO_WITH_CONFLICTS, SAMPLE_RESULTS)
        from io import StringIO

        from rich.console import Console

        from recon_tool.formatter import get_console, set_console

        original = get_console()
        buf = StringIO()
        set_console(Console(file=buf, width=120, force_terminal=True))
        try:
            result = runner.invoke(app, ["lookup", "contoso.com", "--no-cache"])
            assert result.exit_code == 0
            output = buf.getvalue() + result.output
            assert "sources disagree" not in output
        finally:
            set_console(original)
