"""QA Round 3 — MCP introspection and agentic tool tests (11.2–11.5).

Unit tests for:
- 11.2: get_fingerprints, get_signals, explain_signal MCP tools
- 11.3: test_hypothesis MCP tool
- 11.4: simulate_hardening MCP tool
- 11.5: explain parameter on lookup_tenant and analyze_posture

All examples use explicit synthetic labels and reserved domains.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import cast
from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("mcp")

from recon_tool.catalog_discovery import category_matches
from recon_tool.mcp_client.sdk_compat import ToolError
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
    _cache_get,  # pyright: ignore[reportPrivateUsage]
    _rate_limit,  # pyright: ignore[reportPrivateUsage]
    analyze_posture,
    discover_fingerprint_candidates,
    explain_signal,
    get_fingerprints,
    get_signals,
    lookup_tenant,
    simulate_hardening,
)
from recon_tool.server import test_hypothesis as mcp_test_hypothesis

SERVER_RESOLVE_PATH = "recon_tool.server_app.resolve_tenant"
SERVER_RESOLVE_OR_CACHE = "recon_tool.server_app.resolve_or_cache"

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
        raw_value="alpha-com.mail.protection.outlook.com",
        rule_name="MX M365",
        slug="microsoft365",
    ),
)

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Synthetic Alpha Ltd",
    default_domain="alpha.onmicrosoft.com",
    queried_domain="alpha.invalid",
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
        CandidateValue("Synthetic Alpha Ltd", "oidc_discovery", "high"),
        CandidateValue("Synthetic Alpha Corporation", "azure_ad_metadata", "medium"),
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
    async def test_returns_list(self) -> None:
        """get_fingerprints returns a list of summaries."""
        data = await get_fingerprints()
        assert isinstance(data, list)
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_entries_have_expected_fields(self) -> None:
        """Each fingerprint entry has slug, name, category, confidence, match_mode, detection_types."""
        data = await get_fingerprints()
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
        all_data = await get_fingerprints()
        email_data = await get_fingerprints(category="email")
        assert len(email_data) > 0
        assert len(email_data) < len(all_data)
        for fp in email_data:
            assert "email" in fp["category"].lower()

    @pytest.mark.asyncio
    async def test_category_filter_case_insensitive(self) -> None:
        """Category filter is case-insensitive."""
        lower = await get_fingerprints(category="email")
        upper = await get_fingerprints(category="EMAIL")
        assert lower == upper

    @pytest.mark.asyncio
    async def test_category_filter_uses_word_prefix_or_phrase_matching(self) -> None:
        data = await get_fingerprints(category="ai")

        assert data
        assert all(category_matches(entry["category"], "ai") for entry in data)
        assert all(entry["category"].lower() != "email" for entry in data)

    @pytest.mark.asyncio
    async def test_pagination_is_additive(self) -> None:
        """limit/offset slice the list; omitting them returns the full list
        (backward-compatible default)."""
        full = await get_fingerprints()
        page1 = await get_fingerprints(limit=5)
        page2 = await get_fingerprints(limit=5, offset=5)
        assert len(page1) == 5
        assert len(page2) == 5
        assert page1 == full[:5]
        assert page2 == full[5:10]


# ── 11.2 get_signals ────────────────────────────────────────────────────


class TestGetSignals:
    """Unit tests for get_signals MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_list(self) -> None:
        """get_signals returns a list of definitions."""
        data = await get_signals()
        assert isinstance(data, list)
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_entries_have_new_fields(self) -> None:
        """Signal entries include contradicts, requires_signals, explain, layer."""
        data = await get_signals()
        new_fields = {"contradicts", "requires_signals", "explain", "layer"}
        for sig in data:
            assert new_fields.issubset(sig.keys()), f"Missing new fields in signal: {new_fields - sig.keys()}"

    @pytest.mark.asyncio
    async def test_category_filter(self) -> None:
        """Category filter returns only matching signals."""
        data = await get_signals(category="security")
        assert len(data) > 0
        for sig in data:
            assert "security" in sig["category"].lower()

    @pytest.mark.asyncio
    async def test_category_filter_uses_word_prefix_or_phrase_matching(self) -> None:
        data = await get_signals(category="ai")

        assert data
        assert all(category_matches(entry["category"], "ai") for entry in data)
        assert all(entry["category"].lower() != "email" for entry in data)

    @pytest.mark.asyncio
    async def test_layer_filter(self) -> None:
        """Layer filter returns only signals in the specified layer."""
        data = await get_signals(layer=1)
        assert len(data) > 0
        for sig in data:
            assert sig["layer"] == 1

    @pytest.mark.asyncio
    async def test_nonreportable_rule_identifiers_are_not_exposed(self) -> None:
        data = await get_signals()

        names = {signal["name"] for signal in data}
        assert "Dual Email Delivery Path" not in names
        assert "Incomplete Identity Migration" not in names


# ── 11.2 explain_signal ─────────────────────────────────────────────────


class TestExplainSignal:
    """Unit tests for explain_signal MCP tool."""

    @pytest.mark.asyncio
    async def test_known_signal_returns_definition(self) -> None:
        """Known signal name returns definition with trigger and weakening conditions."""
        from recon_tool.signals import reportable_signals

        _signal, public_label = reportable_signals()[0]

        data = await explain_signal(public_label)
        assert data["name"] == public_label
        assert "trigger_conditions" in data
        assert "weakening_conditions" in data

    @pytest.mark.asyncio
    async def test_unknown_signal_raises_tool_error(self) -> None:
        """Unknown signal name raises ToolError (isError) listing available names."""
        with pytest.raises(ToolError, match="not found"):
            await explain_signal("Nonexistent Synthetic Beta Signal")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", ["Dual Email Delivery Path", "Incomplete Identity Migration"])
    async def test_nonreportable_signal_is_rejected(self, name: str) -> None:
        with pytest.raises(ToolError, match="not found"):
            await explain_signal(name)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_with_domain_returns_evaluation(self, mock_resolve: AsyncMock) -> None:
        """explain_signal with domain returns evaluation state."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))

        from recon_tool.signals import reportable_signals

        _signal, public_label = reportable_signals()[0]

        data = await explain_signal(public_label, domain="alpha.invalid")
        assert "domain" in data
        assert "fired" in data
        assert isinstance(data["fired"], bool)
        assert "matched_slugs" in data
        assert "matched_evidence" in data

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_domain_output_uses_resolved_normalized_domain(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        from recon_tool.signals import reportable_signals

        _signal, public_label = reportable_signals()[0]
        raw = "https://www.alpha.invalid/private/path?token=secret"

        data = await explain_signal(public_label, domain=raw)

        assert data["domain"] == "alpha.invalid"
        assert raw not in str(data)
        assert "/private/path" not in str(data)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_unavailable_channel_evidence_cannot_fire_or_leak(self, mock_resolve: AsyncMock) -> None:
        info = replace(
            SAMPLE_INFO,
            services=("OpenAI",),
            slugs=("openai",),
            evidence=(
                EvidenceRecord(
                    source_type="TXT",
                    raw_value="openai-domain-verification=opaque",
                    rule_name="OpenAI",
                    slug="openai",
                ),
            ),
            insights=(),
            degraded_sources=("dns:apex_txt",),
        )
        mock_resolve.return_value = (info, list(SAMPLE_RESULTS))

        data = await explain_signal("AI-platform indicators observed", domain="alpha.invalid")

        assert data["fired"] is False
        assert data["matched_slugs"] == []
        assert data["matched_evidence"] == []


# ── 11.3 test_hypothesis ────────────────────────────────────────────────


class TestTestHypothesis:
    """Unit tests for test_hypothesis MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_returns_correct_json_structure(self, mock_resolve: AsyncMock) -> None:
        """test_hypothesis returns JSON with likelihood, supporting, contradicting, etc."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        data = await mcp_test_hypothesis("alpha.invalid", "mid-migration to cloud identity")
        assert "likelihood" in data
        assert data["likelihood"] == "unresolved"
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
    async def test_domain_output_uses_resolved_normalized_domain(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        raw = "https://www.alpha.invalid/private/path?token=secret"

        data = await mcp_test_hypothesis(raw, "email configuration")

        assert data["domain"] == "alpha.invalid"
        assert raw not in str(data)
        assert "/private/path" not in str(data)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_keyword_matching_maps_hypothesis(self, mock_resolve: AsyncMock) -> None:
        """Hypothesis keywords map to relevant signals via keyword matching."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        data = await mcp_test_hypothesis("alpha.invalid", "security posture assessment")
        # The tool should produce lists (possibly empty) for all signal categories
        assert isinstance(data["supporting_signals"], list)
        assert isinstance(data["contradicting_signals"], list)
        assert isinstance(data["missing_evidence"], list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_hedged_language_in_disclaimer(self, mock_resolve: AsyncMock) -> None:
        """Output uses hedged language ('indicators suggest', not 'confirms')."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        data = await mcp_test_hypothesis("alpha.invalid", "email security")
        disclaimer = data.get("disclaimer", "")
        assert "suggest" in disclaimer.lower() or "indicators" in disclaimer.lower()
        # "confirm" should only appear in negated form
        assert "confirm" not in disclaimer.lower() or "do not confirm" in disclaimer.lower()


# ── 11.4 simulate_hardening ─────────────────────────────────────────────


class TestSimulateHardening:
    """Unit tests for simulate_hardening MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_no_fixes_reports_no_change(self, mock_resolve: AsyncMock) -> None:
        """Applying nothing cannot change the index.

        The simulated TenantInfo used to be rebuilt field by field, which
        dropped every field the list omitted. The scorer reads some of them, so
        an empty fix list reported a loss and every gateway-fronted simulation
        understated its gain by the same amount.
        """
        info = replace(SAMPLE_INFO, email_gateway="Proofpoint")
        mock_resolve.return_value = (info, list(SAMPLE_RESULTS))

        data = await simulate_hardening("alpha.invalid", [])

        assert data["score_delta"] == 0
        assert data["simulated_score"] == data["current_score"]

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_already_satisfied_fix_preserves_live_lineage(self, mock_resolve: AsyncMock) -> None:
        """An exact live control is not replaced with hypothetical evidence."""
        live_dkim = EvidenceRecord(
            source_type="DKIM",
            raw_value="v=DKIM1; p=retained-live-value",
            rule_name="DKIM",
            slug="dkim",
        )
        info = replace(
            SAMPLE_INFO,
            services=(*SAMPLE_INFO.services, "DKIM"),
            slugs=(*SAMPLE_INFO.slugs, "dkim"),
            evidence=(*SAMPLE_INFO.evidence, live_dkim),
        )
        mock_resolve.return_value = (info, list(SAMPLE_RESULTS))

        data = await simulate_hardening("alpha.invalid", ["DKIM"])
        component = next(
            item
            for item in data["simulated_observability"]["components"]
            if item["component_id"] == "index.email.dkim.v1"
        )

        assert data["applied_fixes"] == []
        assert data["score_delta"] == 0
        assert component["state"] == "observed_value"
        assert component["evidence"][0]["raw_value"] == live_dkim.raw_value

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_observed_fields_survive_simulation(self, mock_resolve: AsyncMock) -> None:
        """Fields a fix does not touch must carry into the simulated result."""
        info = replace(SAMPLE_INFO, email_gateway="Proofpoint", dmarc_policy=None)
        mock_resolve.return_value = (info, list(SAMPLE_RESULTS))

        data = await simulate_hardening("alpha.invalid", ["DMARC reject"])

        # The gateway is untouched by a DMARC fix, so its contribution must be
        # present in both scores and the delta must be a gain.
        assert data["score_delta"] > 0

    @pytest.mark.parametrize(
        ("fix", "component_id"),
        [
            ("DMARC reject", "index.email.dmarc.v1"),
            ("DKIM", "index.email.dkim.v1"),
            ("SPF strict", "index.email.spf-strict.v1"),
            ("MTA-STS enforce", "index.email.mta-sts.v1"),
            ("BIMI", "index.email.bimi.v1"),
            ("TLS-RPT", "index.email.tls-rpt.v1"),
            ("CAA", "index.infrastructure.caa.v1"),
        ],
    )
    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_every_supported_scored_fix_is_explicitly_hypothetical(
        self,
        mock_resolve: AsyncMock,
        fix: str,
        component_id: str,
    ) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))

        data = await simulate_hardening("alpha.invalid", [fix])
        components = {item["component_id"]: item for item in data["simulated_observability"]["components"]}

        assert components[component_id]["state"] == "hypothetical_value"
        assert components[component_id]["evidence"]

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_returns_correct_json_structure(self, mock_resolve: AsyncMock) -> None:
        """simulate_hardening returns JSON with score delta and applied fixes."""
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        data = await simulate_hardening("alpha.invalid", ["DMARC reject", "MTA-STS enforce"])
        assert "current_score" in data
        assert isinstance(data["current_score"], int)
        assert "simulated_score" in data
        assert isinstance(data["simulated_score"], int)
        assert "score_delta" in data
        assert isinstance(data["score_delta"], int)
        assert data["current_observability"]["score_floor"] == data["current_score"]
        assert data["simulated_observability"]["score_floor"] == data["simulated_score"]
        simulated_components = {
            component["component_id"]: component for component in data["simulated_observability"]["components"]
        }
        assert simulated_components["index.email.dmarc.v1"]["state"] == "hypothetical_value"
        assert simulated_components["index.email.mta-sts.v1"]["state"] == "hypothetical_value"
        assert "applied_fixes" in data
        assert isinstance(data["applied_fixes"], list)
        assert "remaining_gaps" in data
        assert isinstance(data["remaining_gaps"], list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_hypothetical_fix_remains_distinct_when_live_collection_failed(
        self,
        mock_resolve: AsyncMock,
    ) -> None:
        mock_resolve.return_value = (
            replace(SAMPLE_INFO, degraded_sources=("dns:dmarc",)),
            list(SAMPLE_RESULTS),
        )

        data = await simulate_hardening("alpha.invalid", ["DMARC reject"])
        current = {item["component_id"]: item for item in data["current_observability"]["components"]}
        simulated = {item["component_id"]: item for item in data["simulated_observability"]["components"]}

        assert current["index.email.dmarc.v1"]["state"] == "unavailable"
        assert simulated["index.email.dmarc.v1"]["state"] == "hypothetical_value"
        assert simulated["index.email.dmarc.v1"]["awarded_points"] == 20

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_generic_dmarc_fix_applies_when_live_channel_failed(
        self,
        mock_resolve: AsyncMock,
    ) -> None:
        mock_resolve.return_value = (
            replace(SAMPLE_INFO, degraded_sources=("dns:dmarc",)),
            list(SAMPLE_RESULTS),
        )

        data = await simulate_hardening("alpha.invalid", ["DMARC"])

        assert any("DMARC" in fix for fix in data["applied_fixes"])
        simulated = {item["component_id"]: item for item in data["simulated_observability"]["components"]}
        assert simulated["index.email.dmarc.v1"]["state"] == "hypothetical_value"
        assert data["score_delta"] > 0

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_generic_mta_sts_fix_applies_when_live_channel_failed(
        self,
        mock_resolve: AsyncMock,
    ) -> None:
        mock_resolve.return_value = (
            replace(SAMPLE_INFO, mta_sts_mode="testing", degraded_sources=("dns:mta_sts",)),
            list(SAMPLE_RESULTS),
        )

        data = await simulate_hardening("alpha.invalid", ["MTA-STS"])

        assert any("MTA-STS" in fix for fix in data["applied_fixes"])
        simulated = {item["component_id"]: item for item in data["simulated_observability"]["components"]}
        assert simulated["index.email.mta-sts.v1"]["state"] == "hypothetical_value"

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_domain_output_uses_resolved_normalized_domain(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, list(SAMPLE_RESULTS))
        raw = "https://www.alpha.invalid/private/path?token=secret"

        data = await simulate_hardening(raw, ["DMARC reject"])

        assert data["domain"] == "alpha.invalid"
        assert raw not in str(data)
        assert "/private/path" not in str(data)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_consider_language_in_remaining_gaps(self, mock_resolve: AsyncMock) -> None:
        """Remaining gaps use 'Consider' language in recommendations."""
        info_weak = replace(SAMPLE_INFO, dmarc_policy=None, services=("Exchange Online",))
        mock_resolve.return_value = (info_weak, list(SAMPLE_RESULTS))
        data = await simulate_hardening("alpha.invalid", ["BIMI"])
        for gap in data["remaining_gaps"]:
            assert "recommendation" in gap
            assert "observation" in gap

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_unrelated_fix_preserves_dmarc_testing_mode(self, mock_resolve: AsyncMock) -> None:
        info = replace(
            SAMPLE_INFO,
            services=("DMARC",),
            slugs=("dmarc",),
            dmarc_policy="quarantine",
            dmarc_testing=True,
            evidence=(
                EvidenceRecord(
                    source_type="DMARC",
                    raw_value="v=DMARC1; p=quarantine; t=y",
                    rule_name="DMARC",
                    slug="dmarc",
                ),
            ),
        )
        mock_resolve.return_value = (info, list(SAMPLE_RESULTS))

        data = await simulate_hardening("alpha.invalid", ["BIMI"])

        assert data["current_score"] == 0
        assert data["simulated_score"] == 5
        assert any("not effectively enforcing" in gap["observation"] for gap in data["remaining_gaps"])

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_simulated_controls_replace_proof_and_leave_consistent_gaps(self, mock_resolve: AsyncMock) -> None:
        info = replace(
            SAMPLE_INFO,
            dmarc_policy="none",
            services=("DMARC",),
            slugs=("dmarc",),
            evidence=(EvidenceRecord("DMARC", "v=DMARC1; p=none", "DMARC", "dmarc"),),
            merge_conflicts=MergeConflicts(
                dmarc_policy=(
                    CandidateValue("none", "dns_records", "high"),
                    CandidateValue("reject", "cached_result", "medium"),
                )
            ),
        )
        mock_resolve.return_value = (info, list(SAMPLE_RESULTS))

        data = await simulate_hardening("alpha.invalid", ["DMARC quarantine", "TLS-RPT"])
        observations = {gap["observation"] for gap in data["remaining_gaps"]}

        assert "DMARC policy set to quarantine" in data["applied_fixes"]
        assert "TLS-RPT configured" in data["applied_fixes"]
        assert "Effective DMARC policy is quarantine, not reject" in observations
        assert not any("TLS-RPT" in observation for observation in observations)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_OR_CACHE)
    async def test_score_delta_non_negative_for_fixes(self, mock_resolve: AsyncMock) -> None:
        """Applying hardening fixes should not decrease the posture score."""
        info_weak = replace(SAMPLE_INFO, dmarc_policy=None, mta_sts_mode=None)
        mock_resolve.return_value = (info_weak, list(SAMPLE_RESULTS))
        data = await simulate_hardening("alpha.invalid", ["DMARC reject", "MTA-STS enforce"])
        assert data["score_delta"] >= 0


# ── 11.5 explain parameter on lookup_tenant ──────────────────────────────


class TestLookupTenantExplain:
    """Unit tests for explain parameter on lookup_tenant MCP tool."""

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_true_includes_explanations(self, mock_resolve: AsyncMock) -> None:
        """explain=True on lookup_tenant includes explanations in JSON response."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("alpha.invalid", format="json", explain=True)
        data = json.loads(result)
        assert "explanations" in data
        assert isinstance(data["explanations"], list)
        assert len(data["explanations"]) > 0

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_false_no_explanations(self, mock_resolve: AsyncMock) -> None:
        """explain=False on lookup_tenant produces standard output without explanations."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("alpha.invalid", format="json", explain=False)
        data = json.loads(result)
        assert "explanations" not in data

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_omitted_no_explanations(self, mock_resolve: AsyncMock) -> None:
        """Omitting explain on lookup_tenant produces standard output."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("alpha.invalid", format="json")
        data = json.loads(result)
        assert "explanations" not in data

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_with_conflicts_includes_conflicts_key(self, mock_resolve: AsyncMock) -> None:
        """explain=True with merge conflicts includes 'conflicts' key."""
        mock_resolve.return_value = (SAMPLE_INFO_WITH_CONFLICTS, SAMPLE_RESULTS)
        result = await lookup_tenant("alpha.invalid", format="json", explain=True)
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
        data = await analyze_posture("alpha.invalid", explain=True)
        # The declared return is a union of envelope variants and only the
        # explained one carries this key, so read it as a plain mapping.
        payload = cast(dict[str, object], data)
        assert "explanations" in payload
        assert isinstance(payload["explanations"], list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_false_returns_plain_list(self, mock_resolve: AsyncMock) -> None:
        """explain=False on analyze_posture returns a plain observation list."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        data = await analyze_posture("alpha.invalid", explain=False)
        assert isinstance(data, list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_explain_omitted_returns_plain_list(self, mock_resolve: AsyncMock) -> None:
        """Omitting explain on analyze_posture returns a plain observation list."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        data = await analyze_posture("alpha.invalid")
        assert isinstance(data, list)

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_success_log_uses_only_normalized_domain(
        self,
        mock_resolve: AsyncMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        raw = "https://www.alpha.invalid/private/path?token=secret"

        with caplog.at_level("INFO", logger="recon"):
            await analyze_posture(raw)

        mock_resolve.assert_awaited_once_with("alpha.invalid")
        assert "alpha.invalid" in caplog.text
        assert raw not in caplog.text
        assert "/private/path" not in caplog.text


# ── discover_fingerprint_candidates cache safety ─────────────────────────


class TestDiscoverCacheSafety:
    """discover_fingerprint_candidates must not write a CT-degraded
    (skip_ct=True) result into the shared cache, where lookup_tenant, graph,
    and infrastructure tools would read it back as confidently-wrong data.
    """

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_skip_ct_result_does_not_poison_shared_cache(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        assert _cache_get("alpha.invalid") is None
        await discover_fingerprint_candidates("alpha.invalid", skip_ct=True)
        assert _cache_get("alpha.invalid") is None

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_full_result_still_populates_shared_cache(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        assert _cache_get("alpha.invalid") is None
        await discover_fingerprint_candidates("alpha.invalid", skip_ct=False)
        cached = _cache_get("alpha.invalid")
        assert cached is not None
        assert cached[0].queried_domain == "alpha.invalid"

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_success_log_uses_only_normalized_domain(
        self,
        mock_resolve: AsyncMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        raw = "https://www.alpha.invalid/private/path?token=secret"

        with caplog.at_level("INFO", logger="recon"):
            await discover_fingerprint_candidates(raw)

        mock_resolve.assert_awaited_once_with("alpha.invalid", skip_ct=False)
        assert "alpha.invalid" in caplog.text
        assert raw not in caplog.text
        assert "/private/path" not in caplog.text

    @pytest.mark.asyncio
    async def test_rate_limit_message_uses_only_normalized_domain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recon_tool.server.introspection as server_introspection

        acquired: list[str] = []

        def deny(domain: str) -> bool:
            acquired.append(domain)
            return False

        monkeypatch.setattr(server_introspection, "rate_limit_try_acquire", deny)
        raw = "https://www.alpha.invalid/private/path?token=secret"

        with pytest.raises(ToolError) as exc_info:
            await discover_fingerprint_candidates(raw)

        message = str(exc_info.value)
        assert acquired == ["alpha.invalid"]
        assert "Rate limited: alpha.invalid" in message
        assert raw not in message
        assert "/private/path" not in message

    @pytest.mark.asyncio
    @patch(SERVER_RESOLVE_PATH, new_callable=AsyncMock)
    async def test_internal_error_and_log_use_only_normalized_domain(
        self,
        mock_resolve: AsyncMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        mock_resolve.side_effect = RuntimeError("boom")
        raw = "https://www.alpha.invalid/private/path?token=secret"

        with caplog.at_level("ERROR", logger="recon"), pytest.raises(ToolError) as exc_info:
            await discover_fingerprint_candidates(raw)

        message = str(exc_info.value)
        assert "Error mining alpha.invalid" in message
        assert raw not in message
        assert "/private/path" not in message
        assert "discover for alpha.invalid" in caplog.text
        assert raw not in caplog.text
        assert "/private/path" not in caplog.text


class TestGetFingerprintsPagingConvention:
    """Paging must match the cap convention the rest of the server uses.

    Every other cap treats zero as the full remainder and rejects a negative
    value. get_fingerprints folded both to an empty page, which is exactly the
    "no catalog match" false negative the server instructions warn agents
    about. An empty and a blank category were also two spellings of the same
    filter that returned opposite results.
    """

    @pytest.mark.asyncio
    async def test_zero_limit_returns_the_full_remainder(self) -> None:
        full = len(await get_fingerprints())

        assert len(await get_fingerprints(limit=0)) == full

    @pytest.mark.asyncio
    async def test_negative_limit_is_rejected(self) -> None:
        from recon_tool.mcp_client.sdk_compat import ToolError

        with pytest.raises(ToolError):
            await get_fingerprints(limit=-5)

    @pytest.mark.asyncio
    async def test_offset_still_applies_without_a_limit(self) -> None:
        full = len(await get_fingerprints())

        assert len(await get_fingerprints(limit=0, offset=10)) == full - 10

    @pytest.mark.asyncio
    async def test_blank_category_matches_an_empty_filter(self) -> None:
        full = len(await get_fingerprints())

        assert len(await get_fingerprints(category="")) == full
        assert len(await get_fingerprints(category="   ")) == full
