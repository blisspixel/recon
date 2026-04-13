"""QA Round 3 — CLI --explain flag tests (11.1, 11.6).

Unit tests for:
- 11.1: --explain CLI flag (Rich, JSON, markdown, backward compat)
- 11.6: Conflict annotations in Rich panel with --explain

All examples use fictional companies (Contoso, Northwind, Fabrikam).
"""

from __future__ import annotations

import json
from dataclasses import replace
from io import StringIO
from unittest.mock import AsyncMock, patch

from rich.console import Console
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.formatter import (
    get_console,
    render_conflict_annotation,
    render_tenant_panel,
    set_console,
)
from recon_tool.models import (
    CandidateValue,
    ConfidenceLevel,
    EvidenceRecord,
    MergeConflicts,
    SourceResult,
    TenantInfo,
)

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"

# ── Fixture data ─────────────────────────────────────────────────────────

_EVIDENCE = (
    EvidenceRecord(
        source_type="TXT",
        raw_value="v=spf1 include:spf.protection.outlook.com",
        rule_name="SPF M365",
        slug="microsoft365",
    ),
    EvidenceRecord(
        source_type="MX",
        raw_value="contoso-com.mail.protection.outlook.com",
        rule_name="MX M365",
        slug="microsoft365",
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

SAMPLE_RESULTS: list[SourceResult] = [
    SourceResult(
        source_name="oidc_discovery",
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        region="NA",
    ),
    SourceResult(
        source_name="azure_ad_metadata",
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        region="NA",
    ),
    SourceResult(
        source_name="dns_records",
        detected_services=("Exchange Online",),
        detected_slugs=("microsoft365",),
        evidence=_EVIDENCE,
    ),
]

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


# ── Helpers ──────────────────────────────────────────────────────────────


def _capture_rich_cli(args: list[str], mock_resolve: AsyncMock) -> tuple[object, str]:
    """Invoke CLI with a captured Rich console and return (result, combined_output)."""
    original = get_console()
    buf = StringIO()
    set_console(Console(file=buf, width=120, force_terminal=True))
    try:
        result = runner.invoke(app, args)
        output = buf.getvalue() + result.output
    finally:
        set_console(original)
    return result, output


# ── 11.1 CLI --explain flag ──────────────────────────────────────────────


class TestCLIExplainRichOutput:
    """--explain produces explanation section in Rich output."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_explain_produces_explanations_section(self, mock_resolve: AsyncMock) -> None:
        """--explain alone produces 'Explanations' in Rich output."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result, output = _capture_rich_cli(["lookup", "contoso.com", "--explain", "--no-cache"], mock_resolve)
        assert result.exit_code == 0  # pyright: ignore[reportAttributeAccessIssue]
        assert "Explanations" in output


class TestCLIExplainJSON:
    """--explain --json includes explanations key."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_explain_json_has_explanations_key(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--explain", "--json", "--no-cache"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "explanations" in data
        assert isinstance(data["explanations"], list)
        assert len(data["explanations"]) > 0


class TestCLIExplainMarkdown:
    """--explain --md appends ## Explanations section."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_explain_md_has_explanations_heading(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--explain", "--md", "--no-cache"])
        assert result.exit_code == 0
        assert "## Explanations" in result.output


class TestCLINoExplainBackwardCompat:
    """Without --explain, no explanation output (backward compatible)."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_no_explain_rich_no_explanations(self, mock_resolve: AsyncMock) -> None:
        """Rich output without --explain has no Explanations section."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result, output = _capture_rich_cli(["lookup", "contoso.com", "--no-cache"], mock_resolve)
        assert result.exit_code == 0  # pyright: ignore[reportAttributeAccessIssue]
        assert "Explanations" not in output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_no_explain_json_no_explanations_key(self, mock_resolve: AsyncMock) -> None:
        """JSON output without --explain has no explanations key."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--json", "--no-cache"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "explanations" not in data


# ── 11.6 Conflict annotations in Rich panel ─────────────────────────────


class TestConflictAnnotationUnit:
    """Unit tests for render_conflict_annotation."""

    def test_conflict_shows_disagreement_count(self) -> None:
        """render_conflict_annotation shows '[2 sources disagree]'."""
        ann = render_conflict_annotation("display_name", _CONFLICTS)
        assert "2 sources disagree" in ann

    def test_verbose_shows_all_candidates(self) -> None:
        """Verbose mode lists all candidate values and sources."""
        ann = render_conflict_annotation("display_name", _CONFLICTS, verbose=True)
        assert "2 sources disagree" in ann
        assert "Contoso Ltd" in ann
        assert "Contoso Corporation" in ann
        assert "oidc_discovery" in ann
        assert "azure_ad_metadata" in ann

    def test_no_conflict_returns_empty(self) -> None:
        """No conflict for a field returns empty string."""
        empty = MergeConflicts()
        ann = render_conflict_annotation("display_name", empty)
        assert ann == ""


class TestConflictAnnotationPanel:
    """Conflict annotations in render_tenant_panel."""

    def test_panel_with_explain_shows_annotations(self) -> None:
        """render_tenant_panel with explain=True shows conflict annotations."""
        panel = render_tenant_panel(SAMPLE_INFO_WITH_CONFLICTS, explain=True)
        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        console.print(panel)
        output = buf.getvalue()
        assert "sources disagree" in output

    def test_panel_verbose_explain_shows_candidates(self) -> None:
        """render_tenant_panel with verbose+explain shows all candidates."""
        panel = render_tenant_panel(SAMPLE_INFO_WITH_CONFLICTS, verbose=True, explain=True)
        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        console.print(panel)
        output = buf.getvalue()
        assert "sources disagree" in output
        assert "Contoso Corporation" in output

    def test_panel_without_explain_no_annotations(self) -> None:
        """Without explain, no conflict indicators (backward compatible)."""
        panel = render_tenant_panel(SAMPLE_INFO_WITH_CONFLICTS, explain=False)
        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        console.print(panel)
        output = buf.getvalue()
        assert "sources disagree" not in output


class TestConflictAnnotationCLI:
    """CLI integration: conflict annotations with --explain."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_cli_explain_with_conflicts(self, mock_resolve: AsyncMock) -> None:
        """CLI --explain with conflicts shows dim annotation."""
        mock_resolve.return_value = (SAMPLE_INFO_WITH_CONFLICTS, SAMPLE_RESULTS)
        result, output = _capture_rich_cli(["lookup", "contoso.com", "--explain", "--no-cache"], mock_resolve)
        assert result.exit_code == 0  # pyright: ignore[reportAttributeAccessIssue]
        assert "sources disagree" in output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_cli_no_explain_no_conflict_indicators(self, mock_resolve: AsyncMock) -> None:
        """CLI without --explain shows no conflict indicators."""
        mock_resolve.return_value = (SAMPLE_INFO_WITH_CONFLICTS, SAMPLE_RESULTS)
        result, output = _capture_rich_cli(["lookup", "contoso.com", "--no-cache"], mock_resolve)
        assert result.exit_code == 0  # pyright: ignore[reportAttributeAccessIssue]
        assert "sources disagree" not in output
