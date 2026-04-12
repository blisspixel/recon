"""Unit tests for CLI --exposure and --gaps flags.

Tests use typer.testing.CliRunner with mocked resolution to verify
output, JSON mode, mutual exclusion, and error handling.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.models import (
    ConfidenceLevel,
    EvidenceRecord,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Northwind Traders",
    default_domain="northwindtraders.onmicrosoft.com",
    queried_domain="northwindtraders.com",
    confidence=ConfidenceLevel.HIGH,
    region="NA",
    sources=("oidc_discovery", "dns_records"),
    services=("Exchange Online", "Microsoft 365", "DMARC", "DKIM (Exchange Online)"),
    slugs=("microsoft365", "dmarc", "dkim-exchange"),
    dmarc_policy="reject",
    auth_type="Federated",
    mta_sts_mode="enforce",
    evidence=(
        EvidenceRecord(source_type="TXT", raw_value="v=DMARC1; p=reject", rule_name="dmarc-detect", slug="dmarc"),
    ),
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
]


# ── --exposure flag tests ──────────────────────────────────────────────


class TestExposureFlag:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_exposure_produces_output(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "northwindtraders.com", "--exposure", "--no-cache"])
        assert result.exit_code == 0

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_exposure_json_produces_valid_json(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "northwindtraders.com", "--exposure", "--json", "--no-cache"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "domain" in data
        assert "email_posture" in data
        assert "posture_score" in data
        assert "disclaimer" in data


# ── --gaps flag tests ──────────────────────────────────────────────────


class TestGapsFlag:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_gaps_produces_output(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "northwindtraders.com", "--gaps", "--no-cache"])
        assert result.exit_code == 0

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_gaps_json_produces_valid_json(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "northwindtraders.com", "--gaps", "--json", "--no-cache"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "domain" in data
        assert "gaps" in data
        assert "disclaimer" in data


# ── Mutual exclusion tests ─────────────────────────────────────────────


class TestMutualExclusion:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_exposure_chain_mutually_exclusive(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "northwindtraders.com", "--exposure", "--chain"])
        assert result.exit_code == 2

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_gaps_compare_mutually_exclusive(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "northwindtraders.com", "--gaps", "--compare", "old.json"])
        assert result.exit_code == 2


# ── Error handling tests ───────────────────────────────────────────────


class TestErrorHandling:
    def test_exposure_invalid_domain(self) -> None:
        result = runner.invoke(app, ["lookup", "not a domain", "--exposure"])
        assert result.exit_code == 2

    def test_gaps_invalid_domain(self) -> None:
        result = runner.invoke(app, ["lookup", "not a domain", "--gaps"])
        assert result.exit_code == 2

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_exposure_resolution_failure(self, mock_resolve) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com",
            message="No data",
            error_type="all_sources_failed",
        )
        result = runner.invoke(app, ["lookup", "unknown.com", "--exposure", "--no-cache"])
        assert result.exit_code == 3

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_gaps_resolution_failure(self, mock_resolve) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com",
            message="No data",
            error_type="all_sources_failed",
        )
        result = runner.invoke(app, ["lookup", "unknown.com", "--gaps", "--no-cache"])
        assert result.exit_code == 3
