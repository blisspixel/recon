"""Unit tests for MCP tool integration — assess_exposure, find_hardening_gaps, compare_postures.

Tests mock resolve_tenant and verify JSON output structure, error handling,
ToolAnnotations values, and tool docstrings.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from recon_tool.models import (
    ConfidenceLevel,
    EvidenceRecord,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)
from recon_tool.server import (
    _cache_clear,
    _rate_limit,
    assess_exposure,
    compare_postures,
    find_hardening_gaps,
)

RESOLVE_PATH = "recon_tool.server.resolve_tenant"

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Northwind Traders",
    default_domain="northwindtraders.onmicrosoft.com",
    queried_domain="northwindtraders.com",
    confidence=ConfidenceLevel.HIGH,
    region="NA",
    sources=("oidc_discovery", "dns_records"),
    services=("Exchange Online", "Microsoft 365", "DMARC", "DKIM (Exchange Online)"),
    slugs=("microsoft365", "dmarc", "dkim-exchange", "proofpoint"),
    dmarc_policy="reject",
    auth_type="Federated",
    mta_sts_mode="enforce",
    evidence=(
        EvidenceRecord(source_type="TXT", raw_value="v=DMARC1; p=reject", rule_name="dmarc-detect", slug="dmarc"),
        EvidenceRecord(source_type="MX", raw_value="pphosted.com", rule_name="proofpoint-mx", slug="proofpoint"),
    ),
)

SAMPLE_INFO_B = TenantInfo(
    tenant_id="bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
    display_name="Contoso Ltd",
    default_domain="contoso.onmicrosoft.com",
    queried_domain="contoso.com",
    confidence=ConfidenceLevel.MEDIUM,
    sources=("oidc_discovery",),
    services=("Exchange Online",),
    slugs=("microsoft365",),
    dmarc_policy="none",
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
]

SAMPLE_RESULTS_B = [
    SourceResult(source_name="oidc_discovery", tenant_id="bbbbbbbb-cccc-dddd-eeee-ffffffffffff"),
]


@pytest.fixture(autouse=True)
def _clear_server_caches():
    """Clear server caches and rate limits between tests."""
    _cache_clear()
    _rate_limit.clear()
    yield
    _cache_clear()
    _rate_limit.clear()


# ── assess_exposure tests ──────────────────────────────────────────────


class TestAssessExposure:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_returns_valid_json(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await assess_exposure("northwindtraders.com")
        data = json.loads(result)
        assert "domain" in data
        assert "email_posture" in data
        assert "identity_posture" in data
        assert "infrastructure_footprint" in data
        assert "posture_score" in data
        assert "disclaimer" in data
        assert data["domain"] == "northwindtraders.com"

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_posture_score_in_range(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await assess_exposure("northwindtraders.com")
        data = json.loads(result)
        assert 0 <= data["posture_score"] <= 100

    @pytest.mark.asyncio
    async def test_validation_failure(self) -> None:
        result = await assess_exposure("not a domain")
        assert result.startswith("Error:")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_recon_lookup_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com", message="No data", error_type="all_sources_failed",
        )
        result = await assess_exposure("unknown.com")
        assert "No information found for unknown.com" in result

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_unexpected_exception(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = RuntimeError("connection timeout")
        result = await assess_exposure("example.com")
        assert "Error looking up example.com" in result
        assert "internal error" in result

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_rate_limiting(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        # First call succeeds
        await assess_exposure("northwindtraders.com")
        # Clear cache but keep rate limit
        _cache_clear()
        # Second call should be rate limited
        result = await assess_exposure("northwindtraders.com")
        assert "Rate limited" in result


# ── find_hardening_gaps tests ──────────────────────────────────────────


class TestFindHardeningGaps:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_returns_valid_json(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await find_hardening_gaps("northwindtraders.com")
        data = json.loads(result)
        assert "domain" in data
        assert "gaps" in data
        assert "disclaimer" in data
        assert isinstance(data["gaps"], list)

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_gaps_have_valid_structure(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await find_hardening_gaps("northwindtraders.com")
        data = json.loads(result)
        for gap in data["gaps"]:
            assert "category" in gap
            assert "severity" in gap
            assert "observation" in gap
            assert "recommendation" in gap

    @pytest.mark.asyncio
    async def test_validation_failure(self) -> None:
        result = await find_hardening_gaps("not a domain")
        assert result.startswith("Error:")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_recon_lookup_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com", message="No data", error_type="all_sources_failed",
        )
        result = await find_hardening_gaps("unknown.com")
        assert "No information found for unknown.com" in result

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_unexpected_exception(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = RuntimeError("timeout")
        result = await find_hardening_gaps("example.com")
        assert "Error looking up example.com" in result
        assert "internal error" in result

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_rate_limiting(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        await find_hardening_gaps("northwindtraders.com")
        _cache_clear()
        result = await find_hardening_gaps("northwindtraders.com")
        assert "Rate limited" in result


# ── compare_postures tests ─────────────────────────────────────────────


class TestComparePostures:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_returns_valid_json(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = [
            (SAMPLE_INFO, SAMPLE_RESULTS),
            (SAMPLE_INFO_B, SAMPLE_RESULTS_B),
        ]
        result = await compare_postures("northwindtraders.com", "contoso.com")
        data = json.loads(result)
        assert "domain_a" in data
        assert "domain_b" in data
        assert "metrics" in data
        assert "differences" in data
        assert "relative_assessment" in data
        assert "disclaimer" in data

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_domain_a_fails(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="bad.com", message="No data", error_type="all_sources_failed",
        )
        result = await compare_postures("bad.com", "contoso.com")
        assert "Could not resolve domain_a" in result

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_domain_b_fails(self, mock_resolve: AsyncMock) -> None:
        # domain_a succeeds, domain_b fails
        mock_resolve.side_effect = [
            (SAMPLE_INFO, SAMPLE_RESULTS),
            ReconLookupError(domain="bad.com", message="No data", error_type="all_sources_failed"),
        ]
        result = await compare_postures("northwindtraders.com", "bad.com")
        assert "Could not resolve domain_b" in result

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_both_domains_fail(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="bad.com", message="No data", error_type="all_sources_failed",
        )
        result = await compare_postures("bad.com", "worse.com")
        # domain_a fails first (fail-fast)
        assert "Could not resolve domain_a" in result

    @pytest.mark.asyncio
    async def test_validation_failure_domain_a(self) -> None:
        result = await compare_postures("not a domain", "contoso.com")
        assert result.startswith("Error:")

    @pytest.mark.asyncio
    async def test_validation_failure_domain_b(self) -> None:
        result = await compare_postures("contoso.com", "not a domain")
        assert result.startswith("Error:")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_rate_limiting_domain_a(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        # Resolve domain_a once to set rate limit
        await assess_exposure("northwindtraders.com")
        _cache_clear()
        result = await compare_postures("northwindtraders.com", "contoso.com")
        assert "Rate limited" in result


# ── ToolAnnotations tests ──────────────────────────────────────────────


class TestToolAnnotations:
    def _get_tool(self, name: str):
        from recon_tool.server import mcp as server_mcp
        return server_mcp._tool_manager.get_tool(name)  # noqa: SLF001

    def test_assess_exposure_annotations(self) -> None:
        tool = self._get_tool("assess_exposure")
        assert tool is not None
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.openWorldHint is True

    def test_find_hardening_gaps_annotations(self) -> None:
        tool = self._get_tool("find_hardening_gaps")
        assert tool is not None
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.openWorldHint is True

    def test_compare_postures_annotations(self) -> None:
        tool = self._get_tool("compare_postures")
        assert tool is not None
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.openWorldHint is True


# ── Tool docstring tests ──────────────────────────────────────────────


class TestToolDocstrings:
    def test_assess_exposure_docstring_has_disclaimer(self) -> None:
        doc = assess_exposure.__doc__
        assert doc is not None
        assert "defensive security posture assessment only" in doc.lower()

    def test_find_hardening_gaps_docstring_has_disclaimer(self) -> None:
        doc = find_hardening_gaps.__doc__
        assert doc is not None
        assert "defensive security posture assessment only" in doc.lower()

    def test_compare_postures_docstring_has_disclaimer(self) -> None:
        doc = compare_postures.__doc__
        assert doc is not None
        assert "defensive security posture assessment only" in doc.lower()
