"""Primary email provider detection and topology classification tests.

Validates:
- _compute_email_topology() classification (11.1)
- Enhanced detect_provider() formatting — all 5 topology cases + backward compat (11.2)
- MX-backed gateway insight semantics (11.3)
- "Email Gateway Topology" signal (11.4)
- "Secondary Email Provider Observed" signal (11.5)
- Property 1: Primary Email Provider Classification from EvidenceRecords (11.6)
- Requirements: 1.1–1.5, 2.1–2.5, 3.1–3.3, 4.1–4.4, 21.6, 21.12
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recon_tool.formatter import detect_provider, format_tenant_csv_row, format_tenant_dict
from recon_tool.insights import InsightContext, _gateway_insights
from recon_tool.merger import (
    _EMAIL_PROVIDER_SLUG_NAMES,
    _GATEWAY_SLUG_NAMES,
    _GATEWAY_SLUGS,
    _compute_email_topology,
)
from recon_tool.models import ConfidenceLevel, EvidenceRecord, SignalContext, TenantInfo
from recon_tool.signals import evaluate_signals, reload_signals

# ── Helpers ───────────────────────────────────────────────────────────


def _ev(source_type: str, slug: str) -> EvidenceRecord:
    """Create a minimal EvidenceRecord for testing."""
    return EvidenceRecord(
        source_type=source_type,
        raw_value=f"test-{slug}",
        rule_name=f"Test {slug}",
        slug=slug,
    )


def _ctx(
    slugs: set[str],
    *,
    primary_email_provider: str | None = None,
) -> SignalContext:
    return SignalContext(
        detected_slugs=frozenset(slugs),
        primary_email_provider=primary_email_provider,
    )


# ── 11.1: _compute_email_topology() ──────────────────────────────────


class TestComputeEmailTopology:
    """Verify _compute_email_topology() classifies MX evidence correctly."""

    def test_mx_only_provider(self) -> None:
        """MX-only provider slug → primary_email_provider populated, no gateway."""
        evidence = (_ev("MX", "microsoft365"),)
        primary, gateway, _likely = _compute_email_topology(evidence)
        assert primary == "Microsoft 365"
        assert gateway is None

    def test_mx_gateway_slug(self) -> None:
        """MX gateway slug → email_gateway populated, no primary."""
        evidence = (_ev("MX", "proofpoint"),)
        primary, gateway, _likely = _compute_email_topology(evidence)
        assert primary is None
        assert gateway == "Proofpoint"

    def test_mixed_provider_and_gateway(self) -> None:
        """MX provider + MX gateway → both populated."""
        evidence = (
            _ev("MX", "microsoft365"),
            _ev("MX", "proofpoint"),
        )
        primary, gateway, _likely = _compute_email_topology(evidence)
        assert primary == "Microsoft 365"
        assert gateway == "Proofpoint"

    def test_txt_spf_only_slugs_not_classified(self) -> None:
        """TXT/SPF-only slugs → neither primary nor gateway populated."""
        evidence = (
            _ev("TXT", "microsoft365"),
            _ev("SPF", "google-workspace"),
        )
        primary, gateway, _likely = _compute_email_topology(evidence)
        assert primary is None
        assert gateway is None

    def test_multiple_mx_providers_joined(self) -> None:
        """Multiple MX providers → joined by ' + ' (sorted)."""
        evidence = (
            _ev("MX", "microsoft365"),
            _ev("MX", "google-workspace"),
        )
        primary, _gateway, _likely = _compute_email_topology(evidence)
        assert primary is not None
        assert "Google Workspace" in primary
        assert "Microsoft 365" in primary
        assert " + " in primary

    def test_no_mx_evidence(self) -> None:
        """No MX evidence at all → both None."""
        evidence = (
            _ev("TXT", "microsoft365"),
            _ev("CNAME", "proofpoint"),
        )
        primary, gateway, _likely = _compute_email_topology(evidence)
        assert primary is None
        assert gateway is None

    def test_empty_evidence(self) -> None:
        """Empty evidence tuple → both None."""
        primary, gateway, _likely = _compute_email_topology(())
        assert primary is None
        assert gateway is None

    def test_multiple_gateways_joined(self) -> None:
        """Multiple MX gateways → joined by ' + ' (sorted)."""
        evidence = (
            _ev("MX", "proofpoint"),
            _ev("MX", "mimecast"),
        )
        primary, gateway, _likely = _compute_email_topology(evidence)
        assert primary is None
        assert gateway is not None
        assert "Mimecast" in gateway
        assert "Proofpoint" in gateway
        assert " + " in gateway

    def test_unknown_mx_slug_ignored(self) -> None:
        """MX slug not in provider or gateway maps → ignored."""
        evidence = (_ev("MX", "unknown-provider"),)
        primary, gateway, _likely = _compute_email_topology(evidence)
        assert primary is None
        assert gateway is None

    def test_mixed_mx_and_non_mx(self) -> None:
        """MX provider + TXT provider → only MX classified."""
        evidence = (
            _ev("MX", "microsoft365"),
            _ev("TXT", "google-workspace"),
        )
        primary, gateway, _likely = _compute_email_topology(evidence)
        assert primary == "Microsoft 365"
        assert gateway is None


# ── 11.2: Enhanced detect_provider() formatting ──────────────────────


class TestDetectProviderFormatting:
    """Verify detect_provider() topology-aware formatting for all 5 cases."""

    def test_primary_plus_gateway(self) -> None:
        """Provider and gateway MX records remain separate observed paths."""
        result = detect_provider(
            services=(),
            slugs=("microsoft365",),
            primary_email_provider="Microsoft 365",
            email_gateway="Proofpoint",
        )
        assert result == "Microsoft 365 (MX delivery path) + Proofpoint gateway (MX delivery path)"

    def test_gateway_only(self) -> None:
        """A gateway-only MX path does not invent a downstream."""
        result = detect_provider(
            services=(),
            slugs=(),
            primary_email_provider=None,
            email_gateway="Mimecast",
        )
        assert result == "Mimecast gateway (MX delivery path; downstream unobserved)"

    def test_direct_mx_path_does_not_assign_an_untyped_slug_a_secondary_role(self) -> None:
        result = detect_provider(
            services=(),
            slugs=("microsoft365", "google-workspace"),
            primary_email_provider="Microsoft 365",
            email_gateway=None,
        )
        assert result == "Microsoft 365 (MX delivery path)"

    def test_secondary_only_no_primary(self) -> None:
        """Secondary only (no MX-based primary) → '(no MX-based primary detected)'."""
        result = detect_provider(
            services=(),
            slugs=("microsoft365",),
            primary_email_provider=None,
            email_gateway=None,
        )
        # No topology fields set → falls back to slug-based detection
        # But if we explicitly pass None for both, and slugs are present,
        # the fallback path handles it
        assert "Microsoft 365" in result

    def test_gateway_does_not_promote_an_untyped_account_slug(self) -> None:
        result = detect_provider(
            services=(),
            slugs=("microsoft365",),
            primary_email_provider=None,
            email_gateway="Proofpoint",
        )
        assert result == "Proofpoint gateway (MX delivery path; downstream unobserved)"

    def test_backward_compat_no_topology_fields(self) -> None:
        """Slug-only fallback separates account and unclassified-MX roles."""
        result = detect_provider(
            services=(),
            slugs=("microsoft365",),
        )
        assert result == ("Microsoft 365 (account indicator) + Custom or unclassified MX (MX delivery path)")

    def test_backward_compat_google_workspace(self) -> None:
        """Same rationale as above."""
        result = detect_provider(
            services=(),
            slugs=("google-workspace",),
        )
        assert result == ("Google Workspace (account indicator) + Custom or unclassified MX (MX delivery path)")

    def test_backward_compat_dual_provider(self) -> None:
        """Backward compat: Both M365 + GWS slugs → 'Microsoft 365 + Google Workspace'."""
        result = detect_provider(
            services=(),
            slugs=("microsoft365", "google-workspace"),
        )
        assert "Microsoft 365" in result
        assert "Google Workspace" in result

    def test_no_slugs_returns_explicit_unknown(self) -> None:
        """With no slugs and no topology data, return an explicit "unknown"
        message that tells the user nothing matched. The bare "Unknown"
        fallback explains WHY, so users know the tool looked and came up
        empty, rather than silently rendering a generic label that could
        be confused with "not queried"."""
        result = detect_provider(services=(), slugs=())
        assert result.startswith("Unknown")
        assert "no known provider pattern matched" in result

    def test_primary_only_no_gateway_no_secondary(self) -> None:
        """A single named MX provider is one observed delivery path."""
        result = detect_provider(
            services=(),
            slugs=("microsoft365",),
            primary_email_provider="Microsoft 365",
            email_gateway=None,
        )
        assert result == "Microsoft 365 (MX delivery path)"

    def test_primary_does_not_duplicate_in_secondary(self) -> None:
        """Primary provider slug should not appear in secondary list."""
        result = detect_provider(
            services=(),
            slugs=("microsoft365",),
            primary_email_provider="Microsoft 365",
            email_gateway="Proofpoint",
        )
        assert "(secondary)" not in result

    # Multiple possible downstream indicators ─────────────────────────

    def test_multi_likely_candidates_preserve_equal_possible_downstream_roles(self) -> None:
        result = detect_provider(
            services=(),
            slugs=("microsoft365", "google-workspace"),
            primary_email_provider=None,
            email_gateway="Trend Micro",
            likely_primary_email_provider="Google Workspace + Microsoft 365",
        )
        assert result == (
            "Trend Micro gateway (MX delivery path) + "
            "Google Workspace (possible downstream indicator) + "
            "Microsoft 365 (possible downstream indicator)"
        )
        assert "primary" not in result
        assert "secondary" not in result

    def test_multi_likely_candidates_preserve_input_order_without_precedence(self) -> None:
        result = detect_provider(
            services=(),
            slugs=(),
            primary_email_provider=None,
            email_gateway=None,
            likely_primary_email_provider="Zoho Mail + ProtonMail",
        )
        assert result == ("Zoho Mail (possible downstream indicator) + ProtonMail (possible downstream indicator)")

    def test_direct_provider_and_gateway_paths_do_not_invent_a_secondary(self) -> None:
        result = detect_provider(
            services=(),
            slugs=("microsoft365", "google-workspace"),
            primary_email_provider="Microsoft 365",
            email_gateway="Trend Micro",
        )
        assert result == "Microsoft 365 (MX delivery path) + Trend Micro gateway (MX delivery path)"

    @pytest.mark.parametrize("secondary_slug", ["aws-ses", "self-hosted-mail"])
    def test_legacy_direct_call_does_not_promote_new_secondary_types(
        self,
        secondary_slug: str,
    ) -> None:
        result = detect_provider(
            services=(),
            slugs=("microsoft365", secondary_slug),
            primary_email_provider="Microsoft 365",
        )

        assert result == "Microsoft 365 (MX delivery path)"


class TestProviderSurfaceConsistency:
    @pytest.mark.parametrize(
        ("secondary_slug", "secondary_name"),
        [
            ("aws-ses", "AWS SES"),
            ("self-hosted-mail", "Custom or unclassified MX"),
        ],
    )
    def test_mx_confirmed_secondary_provider_is_preserved(
        self,
        secondary_slug: str,
        secondary_name: str,
    ) -> None:
        info = TenantInfo(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            display_name="Contoso Ltd",
            default_domain="contoso.onmicrosoft.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.HIGH,
            services=("Microsoft 365", secondary_name),
            slugs=("microsoft365", secondary_slug),
            evidence=(
                _ev("MX", "microsoft365"),
                _ev("MX", secondary_slug),
            ),
            primary_email_provider=f"{secondary_name} + Microsoft 365",
        )

        expected = f"{secondary_name} (MX delivery path) + Microsoft 365 (MX delivery path)"
        assert format_tenant_dict(info)["provider"] == expected
        assert format_tenant_csv_row(info)["provider"] == expected

    def test_txt_only_secondary_is_omitted_from_json_and_csv_provider_lines(self) -> None:
        info = TenantInfo(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            display_name="Contoso Ltd",
            default_domain="contoso.onmicrosoft.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.HIGH,
            services=("Microsoft 365", "Google Workspace"),
            slugs=("microsoft365", "google-workspace"),
            evidence=(
                _ev("MX", "microsoft365"),
                _ev("TXT", "google-workspace"),
            ),
            primary_email_provider="Microsoft 365",
        )

        expected = "Microsoft 365 (MX delivery path)"
        assert format_tenant_dict(info)["provider"] == expected
        assert format_tenant_csv_row(info)["provider"] == expected

    def test_gateway_does_not_promote_second_account_signal_to_secondary(self) -> None:
        info = TenantInfo(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            display_name="Contoso Ltd",
            default_domain="contoso.onmicrosoft.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.MEDIUM,
            services=("Proofpoint", "Microsoft 365", "Google Workspace"),
            slugs=("proofpoint", "microsoft365", "google-workspace"),
            evidence=(
                _ev("MX", "proofpoint"),
                _ev("HTTP", "microsoft365"),
                _ev("TXT", "google-workspace"),
            ),
            email_gateway="Proofpoint",
            likely_primary_email_provider="Google Workspace + Microsoft 365",
        )

        expected = (
            "Proofpoint gateway (MX delivery path) + "
            "Google Workspace (possible downstream indicator) + "
            "Microsoft 365 (possible downstream indicator)"
        )
        assert format_tenant_dict(info)["provider"] == expected
        assert format_tenant_csv_row(info)["provider"] == expected

    def test_structured_topology_fields_require_observable_lineage(self) -> None:
        """Legacy cache fields cannot survive without supporting evidence."""
        info = TenantInfo(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            display_name="Contoso Ltd",
            default_domain="contoso.onmicrosoft.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.MEDIUM,
            services=("Microsoft 365",),
            slugs=("microsoft365",),
            evidence=(_ev("TXT", "microsoft365"),),
            primary_email_provider="Google Workspace",
            email_gateway="Proofpoint",
            likely_primary_email_provider="Microsoft 365",
        )

        data = format_tenant_dict(info)

        assert data["provider"] == "Microsoft 365 (account indicator; no MX observed)"
        assert data["primary_email_provider"] is None
        assert data["email_gateway"] is None
        assert data["likely_primary_email_provider"] is None


# ── 11.3: MX-backed gateway insights ─────────────────────────────────


class TestGatewayInsights:
    """Gateway prose must be anchored to functional MX evidence."""

    def test_generic_vendor_and_provider_slugs_do_not_establish_routing(self) -> None:
        ctx = InsightContext.from_sets(
            services=set(),
            slugs={"proofpoint", "microsoft365"},
            auth_type=None,
            dmarc_policy=None,
            domain_count=0,
        )
        assert _gateway_insights(ctx) == []

    def test_mx_backed_gateway_is_reported_without_downstream_claim(self) -> None:
        ctx = InsightContext.from_sets(
            services=set(),
            slugs={"proofpoint", "microsoft365"},
            auth_type=None,
            dmarc_policy=None,
            domain_count=0,
            email_gateway="Proofpoint",
        )
        insights = _gateway_insights(ctx)

        assert insights == ["MX gateway observed: Proofpoint"]
        assert "Microsoft 365" not in insights[0]
        assert "path" not in insights[0].lower()
        assert "in front of" not in insights[0].lower()

    def test_multiple_mx_gateways_are_reported_as_observed(self) -> None:
        ctx = InsightContext.from_sets(
            services=set(),
            slugs={"proofpoint", "mimecast"},
            auth_type=None,
            dmarc_policy=None,
            domain_count=0,
            email_gateway="Mimecast + Proofpoint",
        )
        assert _gateway_insights(ctx) == ["MX gateway observed: Mimecast + Proofpoint"]


# ── 11.4: "Email Gateway Topology" signal ────────────────────────────


class TestEmailGatewayTopologySignal:
    """Verify the Email Gateway Topology signal fires correctly."""

    def setup_method(self) -> None:
        reload_signals()

    def test_fires_when_gateway_and_primary_set(self) -> None:
        """Signal fires when gateway slug detected and primary_email_provider is set."""
        result = evaluate_signals(
            _ctx(
                {"proofpoint", "microsoft365"},
                primary_email_provider="Microsoft 365",
            )
        )
        topology = [s for s in result if s.name == "Email Gateway Topology"]
        assert len(topology) == 1
        assert topology[0].confidence == "high"
        assert topology[0].category == "Email"

    def test_fires_with_mimecast_gateway(self) -> None:
        """Signal fires with Mimecast as gateway."""
        result = evaluate_signals(
            _ctx(
                {"mimecast"},
                primary_email_provider="Google Workspace",
            )
        )
        topology = [s for s in result if s.name == "Email Gateway Topology"]
        assert len(topology) == 1

    def test_does_not_treat_unknown_primary_as_inequality(self) -> None:
        """Unknown provider state cannot satisfy the topology neq condition."""
        result = evaluate_signals(_ctx({"proofpoint"}, primary_email_provider=None))
        topology = [s for s in result if s.name == "Email Gateway Topology"]
        assert len(topology) == 0

    def test_does_not_fire_when_primary_is_empty(self) -> None:
        """Signal does not fire when primary_email_provider is empty string."""
        result = evaluate_signals(_ctx({"proofpoint"}, primary_email_provider=""))
        topology = [s for s in result if s.name == "Email Gateway Topology"]
        assert len(topology) == 0

    def test_does_not_fire_without_gateway_slug(self) -> None:
        """Signal does not fire when no gateway slug is detected."""
        result = evaluate_signals(_ctx({"microsoft365"}, primary_email_provider="Microsoft 365"))
        topology = [s for s in result if s.name == "Email Gateway Topology"]
        assert len(topology) == 0


# ── 11.5: "Secondary Email Provider Observed" signal ───────────────────────────


class TestLegacyProviderResidueSignal:
    """Verify the Secondary Email Provider Observed signal fires correctly."""

    def setup_method(self) -> None:
        reload_signals()

    def test_fires_when_provider_slug_and_primary_set(self) -> None:
        """Signal fires when provider slug detected and primary_email_provider is set."""
        # Contoso has M365 slug detected (via TXT/DKIM) but a different primary
        result = evaluate_signals(
            _ctx(
                {"microsoft365"},
                primary_email_provider="Google Workspace",
            )
        )
        residue = [s for s in result if s.name == "Secondary Email Provider Observed"]
        assert len(residue) == 1
        assert residue[0].confidence == "medium"
        assert residue[0].category == "Consistency"

    def test_fires_with_google_workspace_slug(self) -> None:
        """Signal fires when google-workspace slug detected with different primary."""
        result = evaluate_signals(
            _ctx(
                {"google-workspace"},
                primary_email_provider="Microsoft 365",
            )
        )
        residue = [s for s in result if s.name == "Secondary Email Provider Observed"]
        assert len(residue) == 1

    def test_does_not_fire_when_primary_is_none(self) -> None:
        """Signal does not fire when primary_email_provider is None.

        Regression guard for the A4 follow-up: with exclude_matches_in_primary
        set, the residue signal now refuses to fire at all when the primary
        provider is unknown. A "residue" claim is meaningless without a
        known primary to be residue against — the signal was firing on
        hardened enterprise domains where MX routes through a gateway and
        no primary provider slug appears in MX evidence, producing a
        false-positive residue report on the secondary-via-TXT detections.
        """
        result = evaluate_signals(_ctx({"microsoft365"}, primary_email_provider=None))
        residue = [s for s in result if s.name == "Secondary Email Provider Observed"]
        assert len(residue) == 0

    def test_does_not_fire_when_primary_is_empty(self) -> None:
        """Signal does not fire when primary_email_provider is empty string."""
        result = evaluate_signals(_ctx({"microsoft365"}, primary_email_provider=""))
        residue = [s for s in result if s.name == "Secondary Email Provider Observed"]
        assert len(residue) == 0

    def test_does_not_fire_without_provider_slug(self) -> None:
        """Signal does not fire when no provider slug (m365/gws) is detected."""
        result = evaluate_signals(_ctx({"proofpoint"}, primary_email_provider="Microsoft 365"))
        residue = [s for s in result if s.name == "Secondary Email Provider Observed"]
        assert len(residue) == 0


# ── 11.6: Property 1 — Primary Email Provider Classification (PBT) ──
# Feature: intelligence-amplification, Property 1: Primary Email Provider Classification from EvidenceRecords
# **Validates: Requirements 1.1, 1.2, 1.3, 1.5, 2.1, 2.2**

# Strategy building blocks
_PROVIDER_SLUGS = list(_EMAIL_PROVIDER_SLUG_NAMES.keys())
_GATEWAY_SLUG_LIST = list(_GATEWAY_SLUGS)
_RANDOM_SLUGS = ["sendgrid", "mailgun", "cloudflare", "datadog", "slack", "okta"]
_ALL_SLUGS = _PROVIDER_SLUGS + _GATEWAY_SLUG_LIST + _RANDOM_SLUGS
_SOURCE_TYPES = ["MX", "TXT", "SPF", "DMARC_RUA"]


@st.composite
def evidence_records_strategy(draw: st.DrawFn) -> tuple[EvidenceRecord, ...]:
    """Generate a random set of EvidenceRecords with mixed source_type and slug values."""
    n = draw(st.integers(min_value=0, max_value=10))
    records: list[EvidenceRecord] = []
    for _ in range(n):
        source_type = draw(st.sampled_from(_SOURCE_TYPES))
        slug = draw(st.sampled_from(_ALL_SLUGS))
        records.append(_ev(source_type, slug))
    return tuple(records)


class TestProperty1PrimaryEmailProviderClassification:
    """Hypothesis PBT for primary email provider classification from EvidenceRecords."""

    @given(evidence=evidence_records_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_mx_provider_slugs_become_primary(self, evidence: tuple[EvidenceRecord, ...]) -> None:
        """MX provider slugs → primary_email_provider, MX gateway slugs → email_gateway, non-MX → neither."""
        primary, gateway, _likely = _compute_email_topology(evidence)

        mx_evidence = [e for e in evidence if e.source_type == "MX"]
        mx_slugs = {e.slug for e in mx_evidence}

        # Expected provider slugs from MX
        expected_provider_slugs = mx_slugs - _GATEWAY_SLUGS
        expected_provider_names = sorted(
            _EMAIL_PROVIDER_SLUG_NAMES[s] for s in expected_provider_slugs if s in _EMAIL_PROVIDER_SLUG_NAMES
        )

        # Expected gateway slugs from MX
        expected_gateway_slugs = mx_slugs & _GATEWAY_SLUGS
        expected_gateway_names = sorted(
            _GATEWAY_SLUG_NAMES[s] for s in expected_gateway_slugs if s in _GATEWAY_SLUG_NAMES
        )

        # Verify primary_email_provider
        if expected_provider_names:
            assert primary == " + ".join(expected_provider_names), (
                f"Expected primary='{' + '.join(expected_provider_names)}', got '{primary}'"
            )
        else:
            assert primary is None, f"Expected primary=None, got '{primary}'"

        # Verify email_gateway
        if expected_gateway_names:
            assert gateway == " + ".join(expected_gateway_names), (
                f"Expected gateway='{' + '.join(expected_gateway_names)}', got '{gateway}'"
            )
        else:
            assert gateway is None, f"Expected gateway=None, got '{gateway}'"

    @given(evidence=evidence_records_strategy())
    @settings(max_examples=100)
    def test_non_mx_slugs_never_classified(self, evidence: tuple[EvidenceRecord, ...]) -> None:
        """Non-MX evidence never contributes to primary or gateway classification."""
        primary, gateway, _likely = _compute_email_topology(evidence)

        # Collect slugs that appear ONLY in non-MX evidence
        mx_slugs = {e.slug for e in evidence if e.source_type == "MX"}
        non_mx_only_slugs = {e.slug for e in evidence if e.source_type != "MX"} - mx_slugs

        # These slugs should never appear in primary or gateway
        for slug in non_mx_only_slugs:
            if slug in _EMAIL_PROVIDER_SLUG_NAMES:
                name = _EMAIL_PROVIDER_SLUG_NAMES[slug]
                if primary is not None:
                    assert name not in primary, (
                        f"Non-MX slug '{slug}' ({name}) should not appear in primary='{primary}'"
                    )
            if slug in _GATEWAY_SLUG_NAMES:
                name = _GATEWAY_SLUG_NAMES[slug]
                if gateway is not None:
                    assert name not in gateway, (
                        f"Non-MX slug '{slug}' ({name}) should not appear in gateway='{gateway}'"
                    )
