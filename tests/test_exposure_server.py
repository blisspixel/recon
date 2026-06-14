"""Unit tests for MCP tool integration — assess_exposure, find_hardening_gaps, compare_postures.

Tests mock resolve_tenant and verify JSON output structure, error handling,
ToolAnnotations values, and tool docstrings.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("mcp")

from mcp.server.fastmcp.exceptions import ToolError

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

RESOLVE_PATH = "recon_tool.server_app.resolve_tenant"

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
        data = await assess_exposure("northwindtraders.com")
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
        data = await assess_exposure("northwindtraders.com")
        assert 0 <= data["posture_score"] <= 100

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_observability_envelope_present(self, mock_resolve: AsyncMock) -> None:
        # The score is a lower bound; the envelope tells a consuming agent how
        # much it could understate the true posture, so "quiet" isn't read as
        # "weak". (SAMPLE_INFO has no email gateway, so the floor is non-trivial.)
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        data = await assess_exposure("northwindtraders.com")
        obs = data["observability"]
        assert {"score_is_lower_bound", "unconfirmable_absent_points", "score_ceiling", "note"} <= set(obs)
        assert obs["unconfirmable_absent_points"] >= 0
        assert data["posture_score"] <= obs["score_ceiling"] <= 100
        assert obs["score_is_lower_bound"] == (obs["unconfirmable_absent_points"] > 0)

    @pytest.mark.asyncio
    async def test_validation_failure(self) -> None:
        with pytest.raises(ToolError):
            await assess_exposure("not a domain")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_recon_lookup_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com",
            message="No data",
            error_type="all_sources_failed",
        )
        with pytest.raises(ToolError, match=r"No information found for unknown\.com"):
            await assess_exposure("unknown.com")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_unexpected_exception(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = RuntimeError("connection timeout")
        with pytest.raises(ToolError, match=r"Error looking up example\.com"):
            await assess_exposure("example.com")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_rate_limiting(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        # First call succeeds
        await assess_exposure("northwindtraders.com")
        # Clear cache but keep rate limit
        _cache_clear()
        # Second call should be rate limited
        with pytest.raises(ToolError, match="Rate limited"):
            await assess_exposure("northwindtraders.com")


# ── find_hardening_gaps tests ──────────────────────────────────────────


class TestFindHardeningGaps:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_returns_valid_json(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        data = await find_hardening_gaps("northwindtraders.com")
        assert "domain" in data
        assert "gaps" in data
        assert "disclaimer" in data
        assert isinstance(data["gaps"], list)
        # Every gap carries the confirmability flag so an agent can tell a real
        # public-records fact from a "could not observe" (possibly false) gap.
        for gap in data["gaps"]:
            assert isinstance(gap["absence_confirmable"], bool)

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_gaps_have_valid_structure(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        data = await find_hardening_gaps("northwindtraders.com")
        for gap in data["gaps"]:
            assert "category" in gap
            assert "severity" in gap
            assert "observation" in gap
            assert "recommendation" in gap

    @pytest.mark.asyncio
    async def test_validation_failure(self) -> None:
        with pytest.raises(ToolError):
            await find_hardening_gaps("not a domain")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_recon_lookup_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com",
            message="No data",
            error_type="all_sources_failed",
        )
        with pytest.raises(ToolError, match=r"No information found for unknown\.com"):
            await find_hardening_gaps("unknown.com")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_unexpected_exception(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = RuntimeError("timeout")
        with pytest.raises(ToolError, match=r"Error looking up example\.com"):
            await find_hardening_gaps("example.com")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_rate_limiting(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        await find_hardening_gaps("northwindtraders.com")
        _cache_clear()
        with pytest.raises(ToolError, match="Rate limited"):
            await find_hardening_gaps("northwindtraders.com")


# ── compare_postures tests ─────────────────────────────────────────────


class TestComparePostures:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_returns_valid_json(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = [
            (SAMPLE_INFO, SAMPLE_RESULTS),
            (SAMPLE_INFO_B, SAMPLE_RESULTS_B),
        ]
        data = await compare_postures("northwindtraders.com", "contoso.com")
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
            domain="bad.com",
            message="No data",
            error_type="all_sources_failed",
        )
        with pytest.raises(ToolError, match=r"No information found for bad\.com"):
            await compare_postures("bad.com", "contoso.com")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_domain_b_fails(self, mock_resolve: AsyncMock) -> None:
        # domain_a succeeds, domain_b fails
        mock_resolve.side_effect = [
            (SAMPLE_INFO, SAMPLE_RESULTS),
            ReconLookupError(domain="bad.com", message="No data", error_type="all_sources_failed"),
        ]
        with pytest.raises(ToolError, match=r"No information found for bad\.com"):
            await compare_postures("northwindtraders.com", "bad.com")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_both_domains_fail(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="bad.com",
            message="No data",
            error_type="all_sources_failed",
        )
        # domain_a fails first (fail-fast)
        with pytest.raises(ToolError, match=r"No information found for bad\.com"):
            await compare_postures("bad.com", "worse.com")

    @pytest.mark.asyncio
    async def test_validation_failure_domain_a(self) -> None:
        with pytest.raises(ToolError):
            await compare_postures("not a domain", "contoso.com")

    @pytest.mark.asyncio
    async def test_validation_failure_domain_b(self) -> None:
        with pytest.raises(ToolError):
            await compare_postures("contoso.com", "not a domain")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_rate_limiting_domain_a(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        # Resolve domain_a once to set rate limit
        await assess_exposure("northwindtraders.com")
        _cache_clear()
        with pytest.raises(ToolError, match="Rate limited"):
            await compare_postures("northwindtraders.com", "contoso.com")


# ── ToolAnnotations tests ──────────────────────────────────────────────


class TestToolAnnotations:
    def _get_tool(self, name: str):
        from recon_tool.server import mcp as server_mcp

        return server_mcp._tool_manager.get_tool(name)

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


class TestExposureReadingGuidance:
    """The "Reading the exposure score" guidance must stay in the instructions.

    An LLM consumer reads a 0-100 score as a grade unless told it is a lower
    bound; the injected server instructions tell it to report the score as a
    floor (with its ceiling) and to treat an `absence_confirmable=false` gap as
    "not observed", not a definite weakness. This guards that guidance, the same
    discipline as the posterior-reading and data-not-instructions sections.
    """

    def test_instructions_carry_the_exposure_guidance(self) -> None:
        from recon_tool.server import _SERVER_INSTRUCTIONS  # pyright: ignore[reportPrivateUsage]

        collapsed = " ".join(_SERVER_INSTRUCTIONS.lower().split())
        assert "reading the exposure score" in collapsed
        assert "lower bound" in collapsed
        assert "score_ceiling" in collapsed
        assert "absence_confirmable" in collapsed
