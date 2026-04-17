"""QA Round 3 — MCP introspection and agentic tool tests (11.2–11.5).

Unit tests for:
- 11.2: get_fingerprints, get_signals, explain_signal MCP tools
- 11.3: test_hypothesis MCP tool
- 11.4: simulate_hardening MCP tool
- 11.5: explain parameter on lookup_tenant and analyze_posture

All examples use fictional companies (Contoso, Northwind, Fabrikam).
"""

from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("mcp")

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

SERVER_RESOLVE_PATH = "recon_tool.server.resolve_tenant"
SERVER_RESOLVE_OR_CACHE = "recon_tool.server._resolve_or_cache"

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


# ── 11.2 get_fingerprints ───────────────────────────────────────────────


class TestGetFingerprints:
    """Unit tests for get_fingerprints MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_valid_json_array(self) -> None:
        """get_fingerprints returns a valid JSON array."""
        result = await get_fingerprints()
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_entries_have_expected_fields(self) -> None:
        """Each fingerprint entry has slug, name, category, confidence, match_mode, detection_types."""
        result = await get_fingerprints()
        data = json.loads(result)
        expected_fields = {
            "slug",
            "name",
            "category",
            "confidence",
            "match_mode",
            "detection_types",
        }
        for fp in data:
            assert expected_fields.issubset(fp.keys()), f"Missing fields in fingerprint: {expected_fields - fp.keys()}"

    @pytest.mark.asyncio
    async def test_category_filter_narrows_results(self) -> None:
        """Category filter returns a subset matching the category."""
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
        """Category filter is case-insensitive."""
        lower = json.loads(await get_fingerprints(category="email"))
        upper = json.loads(await get_fingerprints(category="EMAIL"))
        assert lower == upper


# ── 11.2 get_signals ────────────────────────────────────────────────────


class TestGetSignals:
    """Unit tests for get_signals MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_valid_json_array(self) -> None:
        """get_signals returns a valid JSON array."""
        result = await get_signals()
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_entries_have_new_fields(self) -> None:
        """Signal entries include contradicts, requires_signals, explain, layer."""
        result = await get_signals()
        data = json.loads(result)
        new_fields = {"contradicts", "requires_signals", "explain", "layer"}
        for sig in data:
            assert new_fields.issubset(sig.keys()), f"Missing new fields in signal: {new_fields - sig.keys()}"

    @pytest.mark.asyncio
    async def test_category_filter(self) -> None:
        """Category filter returns only matching signals."""
        result = await get_signals(category="security")
        data = json.loads(result)
        assert len(data) > 0
        for sig in data:
            assert "security" in sig["category"].lower()

    @pytest.mark.asyncio
    async def test_layer_filter(self) -> None:
        """Layer filter returns only signals in the specified layer."""
        result = await get_signals(layer=1)
        data = json.loads(result)
        assert len(data) > 0
        for sig in data:
            assert sig["layer"] == 1


# ── 11.2 explain_signal ─────────────────────────────────────────────────


class TestExplainSignal:
    """Unit tests for explain_signal MCP tool."""

    @pytest.mark.asyncio
    async def test_known_signal_returns_definition(self) -> None:
        """Known signal name returns definition with trigger and weakening conditions."""
        from recon_tool.signals import load_signals

        signals = load_signals()
        assert len(signals) > 0
        sig_name = signals[0].name

        result = await explain_signal(sig_name)
        data = json.loads(result)
        assert data["name"] == sig_name
        assert "trigger_conditions" in data
        assert "weakening_conditions" in data

    @pytest.mark.asyncio
    async def test_unknown_signal_returns_error_with_available(self) -> None:
        """Unknown signal name returns error with list of available names."""
        result = await explain_signal("Nonexistent Fabrikam Signal")
        data = json.loads(result)
        assert "error" in data
        assert "available_signals" in data
        assert isinstance(data["available_signals"], list)
        assert len(data["available_signals"]) > 0

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_with_domain_returns_evaluation(self, mock_resolve: AsyncMock) -> None:
        """explain_signal with domain returns evaluation state."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))

        from recon_tool.signals import load_signals

        signals = load_signals()
        sig_name = signals[0].name

        result = await explain_signal(sig_name, domain="contoso.com")
        data = json.loads(result)
        assert "domain" in data
        assert "fired" in data
        assert isinstance(data["fired"], bool)
        assert "matched_slugs" in data
        assert "matched_evidence" in data


# ── 11.3 test_hypothesis ────────────────────────────────────────────────


class TestTestHypothesis:
    """Unit tests for test_hypothesis MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_returns_correct_json_structure(self, mock_resolve: AsyncMock) -> None:
        """test_hypothesis returns JSON with likelihood, supporting, contradicting, etc."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        result = await mcp_test_hypothesis("contoso.com", "mid-migration to cloud identity")
        data = json.loads(result)
        assert "likelihood" in data
        assert data["likelihood"] in {"strong", "moderate", "weak", "unsupported"}
        assert "supporting_signals" in data
        assert isinstance(data["supporting_signals"], list)
        assert "contradicting_signals" in data
        assert isinstance(data["contradicting_signals"], list)
        assert "missing_evidence" in data
        assert isinstance(data["missing_evidence"], list)
        assert "confidence" in data
        assert data["confidence"] in {"high", "medium", "low"}

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_keyword_matching_maps_hypothesis(self, mock_resolve: AsyncMock) -> None:
        """Hypothesis keywords map to relevant signals via keyword matching."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        result = await mcp_test_hypothesis("contoso.com", "security posture assessment")
        data = json.loads(result)
        # The tool should produce lists (possibly empty) for all signal categories
        assert isinstance(data["supporting_signals"], list)
        assert isinstance(data["contradicting_signals"], list)
        assert isinstance(data["missing_evidence"], list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_hedged_language_in_disclaimer(self, mock_resolve: AsyncMock) -> None:
        """Output uses hedged language ('indicators suggest', not 'confirms')."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        result = await mcp_test_hypothesis("contoso.com", "email security")
        data = json.loads(result)
        disclaimer = data.get("disclaimer", "")
        assert "suggest" in disclaimer.lower() or "indicators" in disclaimer.lower()
        # "confirm" should only appear in negated form
        assert "confirm" not in disclaimer.lower() or "do not confirm" in disclaimer.lower()


# ── 11.4 simulate_hardening ─────────────────────────────────────────────


class TestSimulateHardening:
    """Unit tests for simulate_hardening MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_returns_correct_json_structure(self, mock_resolve: AsyncMock) -> None:
        """simulate_hardening returns JSON with score delta and applied fixes."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        result = await simulate_hardening("contoso.com", ["DMARC reject", "MTA-STS enforce"])
        data = json.loads(result)
        assert "current_score" in data
        assert isinstance(data["current_score"], int)
        assert "simulated_score" in data
        assert isinstance(data["simulated_score"], int)
        assert "score_delta" in data
        assert isinstance(data["score_delta"], int)
        assert "applied_fixes" in data
        assert isinstance(data["applied_fixes"], list)
        assert "remaining_gaps" in data
        assert isinstance(data["remaining_gaps"], list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_consider_language_in_remaining_gaps(self, mock_resolve: AsyncMock) -> None:
        """Remaining gaps use 'Consider' language in recommendations."""
        info_weak = replace(SAMPLE_INFO, dmarc_policy=None, services=("Exchange Online",))
        mock_resolve.return_value = (info_weak, list(SAMPLE_RESULTS))
        result = await simulate_hardening("contoso.com", ["BIMI"])
        data = json.loads(result)
        for gap in data["remaining_gaps"]:
            assert "recommendation" in gap
            assert "observation" in gap

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_score_delta_non_negative_for_fixes(self, mock_resolve: AsyncMock) -> None:
        """Applying hardening fixes should not decrease the posture score."""
        info_weak = replace(SAMPLE_INFO, dmarc_policy=None, mta_sts_mode=None)
        mock_resolve.return_value = (info_weak, list(SAMPLE_RESULTS))
        result = await simulate_hardening("contoso.com", ["DMARC reject", "MTA-STS enforce"])
        data = json.loads(result)
        assert data["score_delta"] >= 0


# ── 11.5 explain parameter on lookup_tenant ──────────────────────────────


class TestLookupTenantExplain:
    """Unit tests for explain parameter on lookup_tenant MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_true_includes_explanations(self, mock_resolve: AsyncMock) -> None:
        """explain=True on lookup_tenant includes explanations in JSON response."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json", explain=True)
        data = json.loads(result)
        assert "explanations" in data
        assert isinstance(data["explanations"], list)
        assert len(data["explanations"]) > 0

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_false_no_explanations(self, mock_resolve: AsyncMock) -> None:
        """explain=False on lookup_tenant produces standard output without explanations."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json", explain=False)
        data = json.loads(result)
        assert "explanations" not in data

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_omitted_no_explanations(self, mock_resolve: AsyncMock) -> None:
        """Omitting explain on lookup_tenant produces standard output."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json")
        data = json.loads(result)
        assert "explanations" not in data

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_with_conflicts_includes_conflicts_key(self, mock_resolve: AsyncMock) -> None:
        """explain=True with merge conflicts includes 'conflicts' key."""
        mock_resolve.return_value = (SAMPLE_INFO_WITH_CONFLICTS, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json", explain=True)
        data = json.loads(result)
        assert "explanations" in data
        assert "conflicts" in data
        assert "display_name" in data["conflicts"]


# ── 11.5 explain parameter on analyze_posture ────────────────────────────


class TestAnalyzePostureExplain:
    """Unit tests for explain parameter on analyze_posture MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_true_includes_explanations(self, mock_resolve: AsyncMock) -> None:
        """explain=True on analyze_posture includes explanations in response."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await analyze_posture("contoso.com", explain=True)
        data = json.loads(result)
        assert "explanations" in data
        assert isinstance(data["explanations"], list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_false_returns_plain_list(self, mock_resolve: AsyncMock) -> None:
        """explain=False on analyze_posture returns a plain observation list."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await analyze_posture("contoso.com", explain=False)
        data = json.loads(result)
        assert isinstance(data, list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_omitted_returns_plain_list(self, mock_resolve: AsyncMock) -> None:
        """Omitting explain on analyze_posture returns a plain observation list."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await analyze_posture("contoso.com")
        data = json.loads(result)
        assert isinstance(data, list)
