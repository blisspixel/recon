"""Backward-compatibility and cross-pillar integration tests.

Validates:
- All existing fingerprints load without warnings (20.1)
- All existing signals load and evaluate without modification (20.2)
- Posture rules with dmarc_pct=None → condition not satisfied (20.3)
- New TenantInfo, SignalContext, Signal, SourceResult fields default correctly (20.4)
- detect_provider() without topology fields produces existing output (20.5)
- Property 6: Backward Compatibility (20.6)
- Requirements: 2.5, 3.3, 19.1–19.5, 21.13
"""

from __future__ import annotations

import logging

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recon_tool.fingerprints import load_fingerprints, reload_fingerprints
from recon_tool.formatter import detect_provider
from recon_tool.models import (
    ConfidenceLevel,
    SignalContext,
    SourceResult,
    TenantInfo,
)
from recon_tool.posture import analyze_posture, load_posture_rules, reload_posture
from recon_tool.signals import (
    Signal,
    evaluate_signals,
    load_signals,
    reload_signals,
)

# ── Helpers ───────────────────────────────────────────────────────────


def _make_tenant_info(**overrides: object) -> TenantInfo:
    defaults: dict[str, object] = {
        "tenant_id": "contoso-tenant-id",
        "display_name": "Contoso Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": ConfidenceLevel.MEDIUM,
    }
    defaults.update(overrides)
    return TenantInfo(**defaults)  # type: ignore[arg-type]


# ── 20.1: Backward compatibility — existing fingerprints ─────────────


class TestBackwardCompatFingerprints:
    """Verify all existing fingerprints load without warnings after v0.9.0 changes."""

    def setup_method(self) -> None:
        reload_fingerprints()

    def test_all_fingerprints_load_without_warnings(self, caplog: pytest.LogCaptureFixture) -> None:
        """All 208+ fingerprints should load without any warnings."""
        with caplog.at_level(logging.WARNING, logger="recon"):
            fps = load_fingerprints()
        # No warnings during loading
        fp_warnings = [r for r in caplog.records if r.name == "recon"]
        assert len(fp_warnings) == 0, f"Unexpected warnings: {[r.message for r in fp_warnings]}"
        # Should have 208+ fingerprints (206 original + 6 DMARC vendors - 4 moved = 208)
        assert len(fps) >= 208, f"Expected 208+ fingerprints, got {len(fps)}"

    def test_fingerprints_without_dmarc_rua_still_work(self) -> None:
        """Fingerprints without dmarc_rua detection type continue to work."""
        fps = load_fingerprints()
        non_rua = [fp for fp in fps if not any(d.type == "dmarc_rua" for d in fp.detections)]
        # The vast majority of fingerprints don't use dmarc_rua
        assert len(non_rua) >= 200
        for fp in non_rua:
            assert fp.name
            assert fp.slug
            assert fp.detections

    def test_all_fingerprints_have_valid_structure(self) -> None:
        """Every fingerprint has required fields populated."""
        fps = load_fingerprints()
        for fp in fps:
            assert fp.name, "Fingerprint missing name"
            assert fp.slug, "Fingerprint missing slug"
            assert fp.category, "Fingerprint missing category"
            assert fp.confidence in {"high", "medium", "low"}
            assert fp.detections, f"Fingerprint {fp.name} has no detections"
            assert fp.match_mode in {"any", "all"}


# ── 20.2: Backward compatibility — existing signals ──────────────────


class TestBackwardCompatSignals:
    """Verify all existing signals load and evaluate without modification."""

    def setup_method(self) -> None:
        reload_signals()

    def test_all_signals_load_without_warnings(self, caplog: pytest.LogCaptureFixture) -> None:
        """All signals should load without any warnings."""
        with caplog.at_level(logging.WARNING, logger="recon"):
            sigs = load_signals()
        sig_warnings = [r for r in caplog.records if r.name == "recon"]
        assert len(sig_warnings) == 0, f"Unexpected warnings: {[r.message for r in sig_warnings]}"
        # Signal count is not a stability surface — individual signals can
        # be added or retired as validation reveals noise or missing
        # coverage. This test only guards that the YAML loads cleanly.
        assert len(sigs) > 0

    def test_signals_without_expected_counterparts_default_empty(self) -> None:
        """Signals without expected_counterparts default to empty tuple."""
        sigs = load_signals()
        for sig in sigs:
            assert isinstance(sig.expected_counterparts, tuple)
            # Signals that don't define expected_counterparts should have empty tuple
            # (some signals DO have expected_counterparts now, that's fine)

    def test_signals_without_new_metadata_evaluate_correctly(self) -> None:
        """Signals without new metadata fields evaluate with existing logic."""
        # Create a context with only traditional fields
        ctx = SignalContext(
            detected_slugs=frozenset({"openai", "anthropic", "mistral"}),
            dmarc_policy="reject",
        )
        results = evaluate_signals(ctx)
        # AI Adoption should fire (requires openai, anthropic, etc.)
        names = {r.name for r in results}
        assert "AI Adoption" in names

    def test_evaluate_signals_with_empty_context(self) -> None:
        """evaluate_signals with empty context should return empty or minimal results."""
        ctx = SignalContext(detected_slugs=frozenset())
        results = evaluate_signals(ctx)
        # No slugs → no slug-based signals should fire
        # Only metadata-only signals with neq conditions might fire
        for r in results:
            assert r.name  # All results should have names
            assert r.category  # All results should have categories


# ── 20.3: Backward compatibility — posture rules with dmarc_pct=None ─


class TestBackwardCompatPosture:
    """Verify posture rules with dmarc_pct=None → condition not satisfied."""

    def setup_method(self) -> None:
        reload_posture()

    def test_dmarc_pct_none_does_not_trigger_phased_rollout(self) -> None:
        """When dmarc_pct is None, dmarc_phased_rollout should NOT fire."""
        info = _make_tenant_info(
            dmarc_policy="reject",
            dmarc_pct=None,
            services=("DMARC",),
            slugs=(),
        )
        observations = analyze_posture(info)
        statements = [o.statement for o in observations]
        assert not any("phased rollout" in s.lower() for s in statements)

    def test_all_existing_posture_rules_evaluate_correctly(self) -> None:
        """All posture rules should load and evaluate without errors."""
        rules = load_posture_rules()
        assert len(rules) >= 1
        # Evaluate against a minimal TenantInfo — should not crash
        info = _make_tenant_info(services=(), slugs=())
        observations = analyze_posture(info)
        # Should return a tuple (possibly empty)
        assert isinstance(observations, tuple)

    def test_posture_rules_with_dmarc_pct_lte_condition_and_none_value(self) -> None:
        """Posture rules using dmarc_pct lte condition should not fire when dmarc_pct is None."""
        # Find rules that reference dmarc_pct
        rules = load_posture_rules()
        dmarc_pct_rules = [r for r in rules if any(m.field == "dmarc_pct" for m in r.metadata)]
        # There should be at least the dmarc_phased_rollout rule
        assert len(dmarc_pct_rules) >= 1

        # None dmarc_pct should not satisfy any dmarc_pct conditions (except neq)
        info = _make_tenant_info(
            dmarc_policy="quarantine",
            dmarc_pct=None,
            services=("DMARC",),
            slugs=(),
        )
        observations = analyze_posture(info)
        # No phased rollout observation should appear
        for obs in observations:
            assert "pct=" not in obs.statement.lower() or "phased" not in obs.statement.lower()


# ── 20.4: Backward compatibility — new field defaults ─────────────────


class TestBackwardCompatDefaults:
    """Verify new fields on TenantInfo, SignalContext, Signal, SourceResult default correctly."""

    def test_tenant_info_new_fields_default_none(self) -> None:
        info = _make_tenant_info()
        assert info.primary_email_provider is None
        assert info.email_gateway is None
        assert info.dmarc_pct is None

    def test_signal_context_new_fields_default_none(self) -> None:
        ctx = SignalContext(detected_slugs=frozenset())
        assert ctx.dmarc_pct is None
        assert ctx.primary_email_provider is None

    def test_signal_expected_counterparts_defaults_empty(self) -> None:
        sig = Signal(
            name="Test",
            category="Test",
            confidence="medium",
            description="",
            candidates=(),
            min_matches=0,
        )
        assert sig.expected_counterparts == ()

    def test_source_result_new_fields_default(self) -> None:
        result = SourceResult(source_name="DNS")
        assert result.dmarc_pct is None
        assert result.raw_dns_records == ()

    def test_all_defaults_preserve_existing_behavior(self) -> None:
        """Creating objects without new fields should behave identically to pre-v0.9.0."""
        # TenantInfo without new fields
        info = TenantInfo(
            tenant_id="test-id",
            display_name="Fabrikam Inc",
            default_domain="fabrikam.com",
            queried_domain="fabrikam.com",
        )
        assert info.tenant_id == "test-id"
        assert info.display_name == "Fabrikam Inc"
        # New fields should be None/empty without affecting existing fields
        assert info.primary_email_provider is None
        assert info.email_gateway is None
        assert info.dmarc_pct is None


# ── 20.5: Backward compatibility — detect_provider() without topology ─


class TestBackwardCompatDetectProvider:
    """Verify detect_provider() slug-only fallback output.

    v0.9.3 (second refinement): the fallback path now distinguishes
    two distinct scenarios when primary_email_provider is None:

    (a) ``has_mx_records=False`` — the domain has literally no MX
        records. The provider slug came from a non-MX identity
        endpoint. Label: "(account detected, no MX)".

    (b) ``has_mx_records=True`` (the default) — MX records exist
        but point to a host recon doesn't recognize (custom
        self-hosted, niche provider, Apache's own servers).
        Label: "(account detected, custom MX)".

    Previously, both cases produced the same label, which meant
    domains with custom self-hosted email (apache.org, debian.org,
    python.org) were falsely reported as having "no MX".
    """

    def test_microsoft365_slug_only_no_mx(self) -> None:
        """No MX records — honest "(account detected, no MX)" label."""
        result = detect_provider(services=(), slugs=("microsoft365",), has_mx_records=False)
        assert result == "Microsoft 365 (account detected, no MX)"

    def test_microsoft365_slug_only_custom_mx(self) -> None:
        """MX records exist but aren't recognized — custom MX label."""
        result = detect_provider(services=(), slugs=("microsoft365",), has_mx_records=True)
        assert result == "Microsoft 365 (account detected, custom MX)"

    def test_microsoft365_slug_only_default(self) -> None:
        """Default has_mx_records=True — most common real-world case."""
        result = detect_provider(services=(), slugs=("microsoft365",))
        assert result == "Microsoft 365 (account detected, custom MX)"

    def test_google_workspace_slug_only(self) -> None:
        result = detect_provider(services=(), slugs=("google-workspace",), has_mx_records=False)
        assert result == "Google Workspace (account detected, no MX)"

    def test_dual_provider_slugs_no_mx(self) -> None:
        result = detect_provider(
            services=(),
            slugs=("microsoft365", "google-workspace"),
            has_mx_records=False,
        )
        assert result == ("Microsoft 365 (account detected, no MX) + Google Workspace (account detected, no MX)")

    def test_zoho_slug_only(self) -> None:
        result = detect_provider(services=(), slugs=("zoho",), has_mx_records=False)
        assert result == "Zoho Mail (account detected, no MX)"

    def test_protonmail_slug_only(self) -> None:
        result = detect_provider(services=(), slugs=("protonmail",), has_mx_records=False)
        assert result == "ProtonMail (account detected, no MX)"

    def test_aws_ses_slug_only(self) -> None:
        result = detect_provider(services=(), slugs=("aws-ses",), has_mx_records=False)
        assert result == "AWS SES (account detected, no MX)"

    def test_no_slugs_returns_unknown(self) -> None:
        """v0.9.2 extended the bare "Unknown" fallback to include a short
        explanation of why nothing matched. Still starts with "Unknown" so
        existing string-contains checks keep working."""
        result = detect_provider(services=(), slugs=())
        assert result.startswith("Unknown")
        assert "no known provider pattern matched" in result

    def test_no_topology_fields_uses_slug_fallback(self) -> None:
        """When primary_email_provider / email_gateway /
        likely_primary_email_provider are all None, the slug-only
        fallback fires with an honest qualifier that distinguishes
        "no MX" from "custom MX"."""
        result = detect_provider(
            services=(),
            slugs=("microsoft365",),
            primary_email_provider=None,
            email_gateway=None,
            has_mx_records=False,
        )
        assert result == "Microsoft 365 (account detected, no MX)"

    def test_aws_ses_only_when_no_other_providers(self) -> None:
        """AWS SES should only appear when no other provider slugs are present."""
        result = detect_provider(services=(), slugs=("aws-ses", "microsoft365"))
        assert "AWS SES" not in result
        assert "Microsoft 365" in result


# ── 20.6: Property 6 — Backward Compatibility PBT ────────────────────


# Strategy: generate random SignalContext with arbitrary slugs and metadata
_KNOWN_SLUGS = [
    "openai",
    "anthropic",
    "mistral",
    "perplexity",
    "okta",
    "auth0",
    "crowdstrike",
    "sentinelone",
    "proofpoint",
    "mimecast",
    "microsoft365",
    "google-workspace",
    "salesforce-mc",
    "hubspot",
    "datadog",
    "newrelic",
    "aws-cloudfront",
    "aws-elb",
    "azure-fd",
    "gcp-app",
    "slack",
    "zoom",
    "jira",
    "confluence",
    "notion",
    "1password",
    "lastpass",
    "imperva",
    "cloudflare",
    "fastly",
    "vercel",
    "netlify",
    "flyio",
    "railway",
    "snyk",
    "sonatype",
    "github-advanced-security",
    "cosign-attestation",
    "crewai-aid",
    "langsmith",
    "mcp-discovery",
    "lakera",
    "beyond-identity",
    "cyberark",
    "ping-identity",
    "onelogin",
    "jamf",
    "kandji",
]

_slug_strategy = st.frozensets(st.sampled_from(_KNOWN_SLUGS), min_size=0, max_size=15)
_dmarc_policy_strategy = st.one_of(st.none(), st.sampled_from(["reject", "quarantine", "none"]))


@st.composite
def signal_context_strategy(draw: st.DrawFn) -> SignalContext:
    """Generate a SignalContext with random slugs and traditional metadata only."""
    slugs = draw(_slug_strategy)
    dmarc_policy = draw(_dmarc_policy_strategy)
    auth_type = draw(st.one_of(st.none(), st.sampled_from(["Federated", "Managed"])))
    email_security_score = draw(st.one_of(st.none(), st.integers(min_value=0, max_value=5)))
    spf_include_count = draw(st.one_of(st.none(), st.integers(min_value=0, max_value=20)))
    issuance_velocity = draw(st.one_of(st.none(), st.integers(min_value=0, max_value=100)))
    return SignalContext(
        detected_slugs=slugs,
        dmarc_policy=dmarc_policy,
        auth_type=auth_type,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
        # New fields left at defaults (None) to test backward compat
        dmarc_pct=None,
        primary_email_provider=None,
    )


class TestProperty6BackwardCompatibility:
    """Property 6: Backward Compatibility — Existing Signals and Fingerprints Unchanged.

    **Validates: Requirements 19.1, 19.2, 19.3, 19.5**

    For any SignalContext, evaluate_signals() produces valid results.
    All new dataclass fields have defaults preserving existing behavior.
    """

    @given(ctx=signal_context_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_evaluate_signals_produces_valid_results(self, ctx: SignalContext) -> None:
        """For any SignalContext, evaluate_signals returns valid SignalMatch instances.

        **Validates: Requirements 19.1, 19.2**
        """
        results = evaluate_signals(ctx)
        assert isinstance(results, list)
        for match in results:
            assert match.name, "SignalMatch must have a name"
            assert match.category, "SignalMatch must have a category"
            assert match.confidence in {"high", "medium", "low"}
            assert isinstance(match.matched, tuple)

    @given(ctx=signal_context_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_signals_without_counterparts_produce_no_absence(self, ctx: SignalContext) -> None:
        """Signals without expected_counterparts should not produce absence signals
        from the standard evaluate_signals path.

        **Validates: Requirements 19.1, 19.2**
        """
        results = evaluate_signals(ctx)
        # evaluate_signals does NOT run absence evaluation — that's done in merger
        # So no results should have category "Absence"
        for match in results:
            assert match.category != "Absence", f"evaluate_signals should not produce Absence signals; got {match.name}"

    @given(data=st.data())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_new_dataclass_fields_have_safe_defaults(self, data: st.DataObject) -> None:
        """All new v0.9.0 fields default to None or empty tuple.

        **Validates: Requirements 19.5**
        """
        # TenantInfo
        info = TenantInfo(
            tenant_id=data.draw(st.one_of(st.none(), st.text(min_size=1, max_size=20))),
            display_name=data.draw(st.text(min_size=1, max_size=30)),
            default_domain="contoso.com",
            queried_domain="contoso.com",
        )
        assert info.primary_email_provider is None
        assert info.email_gateway is None
        assert info.dmarc_pct is None

        # SignalContext
        ctx = SignalContext(detected_slugs=frozenset())
        assert ctx.dmarc_pct is None
        assert ctx.primary_email_provider is None

        # SourceResult
        sr = SourceResult(source_name="DNS")
        assert sr.dmarc_pct is None
        assert sr.raw_dns_records == ()

        # Signal
        sig = Signal(
            name="Test",
            category="Test",
            confidence="medium",
            description="",
            candidates=(),
            min_matches=0,
        )
        assert sig.expected_counterparts == ()
