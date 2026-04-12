"""Property-based tests for recon_tool/exposure.py core functions.

Uses Hypothesis to generate random TenantInfo instances and verify
correctness properties across all valid inputs.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import hypothesis.strategies as st
from hypothesis import HealthCheck, given, settings

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.exposure import (
    EXPOSURE_BANNED_TERMS,
    ExposureAssessment,
    _compute_email_security_score,
    assess_exposure_from_info,
    compare_postures_from_infos,
    find_gaps_from_info,
)
from recon_tool.models import ConfidenceLevel, EvidenceRecord, TenantInfo

# ── Custom Hypothesis strategy for TenantInfo ──────────────────────────

_KNOWN_SLUGS = (
    "microsoft365",
    "google-workspace",
    "proofpoint",
    "mimecast",
    "okta",
    "duo",
    "cloudflare",
    "aws-route53",
    "azure-dns",
    "akamai",
    "letsencrypt",
    "digicert",
    "crowdstrike",
    "zscaler",
    "dmarc",
    "bimi",
    "mta-sts",
    "mta-sts-enforce",
    "tls-rpt",
    "spf-strict",
    "spf-softfail",
    "dkim",
    "dkim-exchange",
    "canva",
    "dropbox",
    "zoom",
    "sentinelone",
    "netskope",
    "aws-cloudfront",
    "gcp-dns",
    "fastly",
    "sectigo",
    "aws-acm",
)

_KNOWN_SERVICES = (
    "Exchange Online",
    "Microsoft 365",
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_SPF_STRICT,
    SVC_SPF_SOFTFAIL,
    SVC_DMARC,
    SVC_BIMI,
    SVC_MTA_STS,
    "Google Workspace: Gmail",
    "Proofpoint",
    "Cloudflare CDN",
)

_DMARC_POLICIES = st.sampled_from([None, "none", "quarantine", "reject"])
_AUTH_TYPES = st.sampled_from([None, "Federated", "Managed"])
_MTA_STS_MODES = st.sampled_from([None, "enforce", "testing", "none"])
_CONFIDENCE_LEVELS = st.sampled_from(list(ConfidenceLevel))


def _evidence_for_slug(slug: str) -> st.SearchStrategy[EvidenceRecord]:
    """Generate an EvidenceRecord for a given slug."""
    return st.builds(
        EvidenceRecord,
        source_type=st.sampled_from(["TXT", "MX", "CNAME", "NS", "CAA"]),
        raw_value=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N", "P"))),
        rule_name=st.just(f"rule-{slug}"),
        slug=st.just(slug),
    )


@st.composite
def tenant_info_strategy(draw: st.DrawFn) -> TenantInfo:
    """Generate a random but valid TenantInfo instance."""
    slugs = draw(st.lists(st.sampled_from(_KNOWN_SLUGS), min_size=0, max_size=10, unique=True))
    services = draw(st.lists(st.sampled_from(_KNOWN_SERVICES), min_size=0, max_size=8, unique=True))
    dmarc_policy = draw(_DMARC_POLICIES)
    auth_type = draw(_AUTH_TYPES)
    mta_sts_mode = draw(_MTA_STS_MODES)
    google_auth_type = draw(st.sampled_from([None, "Federated", "Managed"]))
    google_idp_name = draw(st.sampled_from([None, "Okta", "Ping Identity"]))

    # Generate evidence records for a subset of slugs (only if slugs non-empty)
    evidence: list[EvidenceRecord] = []
    if slugs:
        evidence_slugs = draw(st.lists(st.sampled_from(slugs), max_size=5))
        for s in evidence_slugs:
            evidence.append(draw(_evidence_for_slug(s)))

    return TenantInfo(
        tenant_id=draw(st.sampled_from([None, "tid-12345"])),
        display_name="Test Corp",
        default_domain="test.onmicrosoft.com",
        queried_domain="test.com",
        confidence=draw(_CONFIDENCE_LEVELS),
        sources=("test_source",),
        services=tuple(services),
        slugs=tuple(slugs),
        dmarc_policy=dmarc_policy,
        auth_type=auth_type,
        mta_sts_mode=mta_sts_mode,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
        evidence=tuple(evidence),
    )


# Common settings for all property tests
_PBT_SETTINGS = settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
)


# ── Property 1: Structural completeness ────────────────────────────────
# Feature: defensive-security-tools, Property 1: Structural completeness


class TestProperty1StructuralCompleteness:
    """**Validates: Requirements 1.1, 1.7**"""

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_assess_exposure_returns_all_sections(self, info: TenantInfo) -> None:
        """For any valid TenantInfo, assess_exposure_from_info returns an
        ExposureAssessment with all required sections and score in [0, 100]."""
        result = assess_exposure_from_info(info)

        assert isinstance(result, ExposureAssessment)
        assert result.email_posture is not None
        assert result.identity_posture is not None
        assert result.infrastructure_footprint is not None
        assert result.consistency_observations is not None
        assert result.hardening_status is not None
        assert isinstance(result.posture_score, int)
        assert 0 <= result.posture_score <= 100
        assert result.domain == info.queried_domain


# ── Property 2: Subsection faithfulness ────────────────────────────────
# Feature: defensive-security-tools, Property 2: Subsection faithfulness


class TestProperty2SubsectionFaithfulness:
    """**Validates: Requirements 1.2, 1.3, 1.4, 1.5, 1.6**"""

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_email_posture_reflects_input(self, info: TenantInfo) -> None:
        """Email posture fields faithfully reflect TenantInfo input."""
        result = assess_exposure_from_info(info)
        ep = result.email_posture

        assert ep.dmarc_policy == info.dmarc_policy
        assert ep.mta_sts_mode == info.mta_sts_mode

        services_set = set(info.services)
        expected_dkim = SVC_DKIM in services_set or SVC_DKIM_EXCHANGE in services_set
        assert ep.dkim_configured == expected_dkim

        expected_spf = SVC_SPF_STRICT in services_set
        assert ep.spf_strict == expected_spf

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_identity_posture_reflects_input(self, info: TenantInfo) -> None:
        """Identity posture fields faithfully reflect TenantInfo input."""
        result = assess_exposure_from_info(info)
        ip = result.identity_posture

        assert ip.auth_type == info.auth_type
        assert ip.google_auth_type == info.google_auth_type

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_infrastructure_cloud_providers_subset_of_slugs(self, info: TenantInfo) -> None:
        """Infrastructure cloud providers are derived from slug classifications."""
        from recon_tool.exposure import _CLOUD_PROVIDER_SLUGS

        result = assess_exposure_from_info(info)
        infra = result.infrastructure_footprint

        # Every cloud provider in the output must come from a slug in the input
        expected_providers = {
            _CLOUD_PROVIDER_SLUGS[s] for s in info.slugs if s in _CLOUD_PROVIDER_SLUGS
        }
        assert set(infra.cloud_providers) == expected_providers


# ── Property 3: Score bounds ───────────────────────────────────────────
# Feature: defensive-security-tools, Property 3: Score bounds


class TestProperty3ScoreBounds:
    """**Validates: Requirements 1.7**"""

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_posture_score_in_range(self, info: TenantInfo) -> None:
        """Posture score is always in [0, 100]."""
        result = assess_exposure_from_info(info)
        assert 0 <= result.posture_score <= 100


# ── Property 4: Disclaimers ───────────────────────────────────────────
# Feature: defensive-security-tools, Property 4: Disclaimers


class TestProperty4Disclaimers:
    """**Validates: Requirements 1.8, 2.8, 3.5**"""

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_exposure_assessment_has_disclaimer(self, info: TenantInfo) -> None:
        """ExposureAssessment includes a non-empty disclaimer."""
        result = assess_exposure_from_info(info)
        assert result.disclaimer
        assert "defensive review" in result.disclaimer.lower() or "publicly observable" in result.disclaimer.lower()

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_gap_report_has_disclaimer(self, info: TenantInfo) -> None:
        """GapReport includes a non-empty disclaimer."""
        result = find_gaps_from_info(info)
        assert result.disclaimer
        assert "configuration gaps" in result.disclaimer.lower() or "best practices" in result.disclaimer.lower()

    @given(info_a=tenant_info_strategy(), info_b=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_comparison_has_disclaimer(self, info_a: TenantInfo, info_b: TenantInfo) -> None:
        """PostureComparison includes a non-empty disclaimer."""
        result = compare_postures_from_infos(info_a, info_b)
        assert result.disclaimer
        assert "publicly observable" in result.disclaimer.lower() or "comparison" in result.disclaimer.lower()


# ── Property 5: Evidence references ───────────────────────────────────
# Feature: defensive-security-tools, Property 5: Evidence references


class TestProperty5EvidenceReferences:
    """**Validates: Requirements 1.9, 2.7**"""

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_exposure_evidence_refs_link_to_input(self, info: TenantInfo) -> None:
        """All EvidenceReference slugs in ExposureAssessment appear in input evidence."""
        result = assess_exposure_from_info(info)
        input_slugs = {ev.slug for ev in info.evidence}

        for ref in result.evidence:
            assert ref.slug in input_slugs, f"Fabricated evidence slug: {ref.slug}"

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_gap_evidence_refs_link_to_input(self, info: TenantInfo) -> None:
        """All EvidenceReference slugs in GapReport appear in input evidence."""
        result = find_gaps_from_info(info)
        input_slugs = {ev.slug for ev in info.evidence}

        for gap in result.gaps:
            for ref in gap.evidence:
                assert ref.slug in input_slugs, f"Fabricated evidence slug: {ref.slug}"


# ── Property 6: Gap detection correctness ─────────────────────────────
# Feature: defensive-security-tools, Property 6: Gap detection correctness


class TestProperty6GapDetectionCorrectness:
    """**Validates: Requirements 2.2, 2.3, 2.4, 2.5**"""

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_missing_dmarc_produces_gap(self, info: TenantInfo) -> None:
        """If dmarc_policy is None or 'none', a DMARC-related gap is present."""
        result = find_gaps_from_info(info)
        gap_observations = " ".join(g.observation.lower() for g in result.gaps)

        if info.dmarc_policy is None:
            assert "dmarc" in gap_observations, "Missing DMARC should produce a gap"
        elif info.dmarc_policy == "none":
            assert "dmarc" in gap_observations, "DMARC 'none' should produce a gap"

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_missing_dkim_produces_gap(self, info: TenantInfo) -> None:
        """If no DKIM service is detected, a DKIM gap is present."""
        services_set = set(info.services)
        has_dkim = SVC_DKIM in services_set or SVC_DKIM_EXCHANGE in services_set
        result = find_gaps_from_info(info)
        gap_observations = " ".join(g.observation.lower() for g in result.gaps)

        if not has_dkim:
            assert "dkim" in gap_observations, "Missing DKIM should produce a gap"

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_missing_mta_sts_produces_gap(self, info: TenantInfo) -> None:
        """If mta_sts_mode is None, an MTA-STS gap is present."""
        result = find_gaps_from_info(info)
        gap_observations = " ".join(g.observation.lower() for g in result.gaps)

        if info.mta_sts_mode is None:
            assert "mta-sts" in gap_observations, "Missing MTA-STS should produce a gap"

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_spf_softfail_produces_gap(self, info: TenantInfo) -> None:
        """If SPF softfail is detected without strict, an SPF gap is present."""
        services_set = set(info.services)
        has_softfail = SVC_SPF_SOFTFAIL in services_set
        has_strict = SVC_SPF_STRICT in services_set
        result = find_gaps_from_info(info)
        gap_observations = " ".join(g.observation.lower() for g in result.gaps)

        if has_softfail and not has_strict:
            assert "spf" in gap_observations, "SPF softfail without strict should produce a gap"

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_gateway_without_dmarc_reject_produces_gap(self, info: TenantInfo) -> None:
        """If an email gateway slug is present but DMARC is not 'reject', an inconsistency gap is present."""
        from recon_tool.exposure import _EMAIL_GATEWAY_SLUGS

        slugs_set = set(info.slugs)
        gateway_present = bool(slugs_set & set(_EMAIL_GATEWAY_SLUGS.keys()))
        result = find_gaps_from_info(info)
        gap_observations = " ".join(g.observation.lower() for g in result.gaps)

        if gateway_present and info.dmarc_policy != "reject":
            assert "gateway" in gap_observations, "Gateway without DMARC reject should produce a gap"


# ── Property 7: Gap structure validity ────────────────────────────────
# Feature: defensive-security-tools, Property 7: Gap structure validity


class TestProperty7GapStructureValidity:
    """**Validates: Requirements 2.1, 2.6**"""

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_all_gaps_have_valid_structure(self, info: TenantInfo) -> None:
        """Every HardeningGap has valid category, severity, and non-empty fields."""
        result = find_gaps_from_info(info)
        valid_categories = {"email", "identity", "infrastructure", "consistency"}
        valid_severities = {"high", "medium", "low"}

        for gap in result.gaps:
            assert gap.category in valid_categories, f"Invalid category: {gap.category}"
            assert gap.severity in valid_severities, f"Invalid severity: {gap.severity}"
            assert gap.observation, "Observation must be non-empty"
            assert gap.recommendation, "Recommendation must be non-empty"


# ── Property 8: No banned terms ──────────────────────────────────────
# Feature: defensive-security-tools, Property 8: No banned terms


def _collect_string_fields(obj: object) -> list[str]:
    """Recursively collect all string fields from a dataclass."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, (tuple, list)):
        for item in obj:
            strings.extend(_collect_string_fields(item))
    elif hasattr(obj, "__dataclass_fields__"):
        for field_name in obj.__dataclass_fields__:
            strings.extend(_collect_string_fields(getattr(obj, field_name)))
    return strings


class TestProperty8NoBannedTerms:
    """**Validates: Requirements 7.1, 7.2, 7.5, 2.12, 3.9**"""

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_no_banned_terms_in_exposure_assessment(self, info: TenantInfo) -> None:
        """No banned term appears in any string field of ExposureAssessment."""
        result = assess_exposure_from_info(info)
        all_strings = _collect_string_fields(result)
        for s in all_strings:
            lower = s.lower()
            for term in EXPOSURE_BANNED_TERMS:
                assert term not in lower, f"Banned term '{term}' found in: {s!r}"

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_no_banned_terms_in_gap_report(self, info: TenantInfo) -> None:
        """No banned term appears in any string field of GapReport."""
        result = find_gaps_from_info(info)
        all_strings = _collect_string_fields(result)
        for s in all_strings:
            lower = s.lower()
            for term in EXPOSURE_BANNED_TERMS:
                assert term not in lower, f"Banned term '{term}' found in: {s!r}"

    @given(info_a=tenant_info_strategy(), info_b=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_no_banned_terms_in_comparison(self, info_a: TenantInfo, info_b: TenantInfo) -> None:
        """No banned term appears in any string field of PostureComparison."""
        result = compare_postures_from_infos(info_a, info_b)
        all_strings = _collect_string_fields(result)
        for s in all_strings:
            lower = s.lower()
            for term in EXPOSURE_BANNED_TERMS:
                assert term not in lower, f"Banned term '{term}' found in: {s!r}"


# ── Property 9: "Consider" language ──────────────────────────────────
# Feature: defensive-security-tools, Property 9: Consider language


class TestProperty9ConsiderLanguage:
    """**Validates: Requirements 7.3**"""

    @given(info=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_all_recommendations_start_with_consider(self, info: TenantInfo) -> None:
        """Every HardeningGap.recommendation starts with 'Consider'."""
        result = find_gaps_from_info(info)
        for gap in result.gaps:
            assert gap.recommendation.startswith("Consider"), (
                f"Recommendation does not start with 'Consider': {gap.recommendation!r}"
            )


# ── Property 10: Comparison metrics match inputs ─────────────────────
# Feature: defensive-security-tools, Property 10: Comparison metrics


class TestProperty10ComparisonMetrics:
    """**Validates: Requirements 3.2**"""

    @given(info_a=tenant_info_strategy(), info_b=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_comparison_metrics_match_inputs(self, info_a: TenantInfo, info_b: TenantInfo) -> None:
        """Comparison metrics accurately reflect both inputs."""
        result = compare_postures_from_infos(info_a, info_b)
        metrics = {m.metric_name: m for m in result.metrics}

        # Email security score
        score_a = _compute_email_security_score(info_a)
        score_b = _compute_email_security_score(info_b)
        assert metrics["email_security_score"].domain_a_value == str(score_a)
        assert metrics["email_security_score"].domain_b_value == str(score_b)

        # DMARC policy
        assert metrics["dmarc_policy"].domain_a_value == (info_a.dmarc_policy or "")
        assert metrics["dmarc_policy"].domain_b_value == (info_b.dmarc_policy or "")

        # Service count
        assert metrics["service_count"].domain_a_value == str(len(info_a.services))
        assert metrics["service_count"].domain_b_value == str(len(info_b.services))


# ── Property 11: Comparison differences ──────────────────────────────
# Feature: defensive-security-tools, Property 11: Comparison differences


class TestProperty11ComparisonDifferences:
    """**Validates: Requirements 3.3**"""

    @given(info_a=tenant_info_strategy(), info_b=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_differences_are_correct_set_operations(self, info_a: TenantInfo, info_b: TenantInfo) -> None:
        """Differences correctly represent the symmetric difference of controls."""
        result = compare_postures_from_infos(info_a, info_b)

        for diff in result.differences:
            # If domain_a_has is True and domain_b_has is False, the control
            # is present in a but absent in b (and vice versa)
            assert diff.domain_a_has != diff.domain_b_has, (
                f"Difference should be asymmetric: {diff.description}"
            )


# ── Property 12: Relative assessment consistency ─────────────────────
# Feature: defensive-security-tools, Property 12: Relative assessment consistency


class TestProperty12RelativeAssessmentConsistency:
    """**Validates: Requirements 3.4**"""

    @given(info_a=tenant_info_strategy(), info_b=tenant_info_strategy())
    @_PBT_SETTINGS
    def test_email_security_assessment_consistent(self, info_a: TenantInfo, info_b: TenantInfo) -> None:
        """If domain_a has higher email score, assessment indicates domain_a is stronger."""
        result = compare_postures_from_infos(info_a, info_b)
        score_a = _compute_email_security_score(info_a)
        score_b = _compute_email_security_score(info_b)

        email_assessment = next(
            (a for a in result.relative_assessment if a.dimension == "email_security"),
            None,
        )
        assert email_assessment is not None

        if score_a > score_b:
            assert info_a.queried_domain in email_assessment.summary
            assert "stronger" in email_assessment.summary.lower()
        elif score_b > score_a:
            assert info_b.queried_domain in email_assessment.summary
            assert "stronger" in email_assessment.summary.lower()
        else:
            assert "comparable" in email_assessment.summary.lower()



# ── Task 6.1: Import safety test ─────────────────────────────────────


class TestImportSafety:
    """**Validates: Requirements 8.1, 8.2, 8.3**"""

    def test_exposure_module_has_no_network_imports(self) -> None:
        """Verify exposure.py doesn't import network-facing modules."""
        source = Path("recon_tool/exposure.py").read_text()
        tree = ast.parse(source)

        # Collect all import names
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)

        banned_imports = {"httpx", "dns", "dns.resolver", "recon_tool.sources"}
        violations = imports & banned_imports
        assert not violations, f"Banned imports found in exposure.py: {violations}"


# ── Task 6.2: Banned-terms integration test ──────────────────────────


class TestBannedTermsIntegration:
    """**Validates: Requirements 7.1, 7.2, 7.4, 7.5**"""

    def _make_info(self, **overrides) -> TenantInfo:
        """Create a TenantInfo with sensible defaults, allowing overrides."""
        defaults = dict(
            tenant_id="tid-test",
            display_name="Test Corp",
            default_domain="test.onmicrosoft.com",
            queried_domain="test.com",
            confidence=ConfidenceLevel.HIGH,
            sources=("test_source",),
            services=(),
            slugs=(),
            dmarc_policy=None,
            auth_type=None,
            mta_sts_mode=None,
        )
        defaults.update(overrides)
        return TenantInfo(**defaults)

    def _scan_for_banned_terms(self, strings: list[str]) -> list[tuple[str, str]]:
        """Return list of (banned_term, containing_string) violations."""
        violations = []
        for s in strings:
            lower = s.lower()
            for term in EXPOSURE_BANNED_TERMS:
                if term in lower:
                    violations.append((term, s))
        return violations

    def test_no_banned_terms_in_exposure_output_variants(self) -> None:
        """Generate multiple TenantInfo variants, run assess_exposure, scan for banned terms."""
        infos = [
            self._make_info(),  # empty
            self._make_info(
                services=(SVC_DKIM, SVC_SPF_STRICT, SVC_DMARC, SVC_BIMI, SVC_MTA_STS),
                slugs=("microsoft365", "dmarc", "dkim", "proofpoint", "okta", "crowdstrike", "zscaler"),
                dmarc_policy="reject",
                auth_type="Federated",
                mta_sts_mode="enforce",
            ),
            self._make_info(
                slugs=("canva", "dropbox", "zoom"),
                dmarc_policy="none",
            ),
            self._make_info(
                services=(SVC_SPF_SOFTFAIL,),
                slugs=("proofpoint",),
                dmarc_policy="quarantine",
                mta_sts_mode="testing",
            ),
        ]

        for info in infos:
            result = assess_exposure_from_info(info)
            all_strings = _collect_string_fields(result)
            violations = self._scan_for_banned_terms(all_strings)
            assert not violations, f"Banned terms in exposure output: {violations}"

    def test_no_banned_terms_in_gaps_output_variants(self) -> None:
        """Generate multiple TenantInfo variants, run find_gaps, scan for banned terms."""
        infos = [
            self._make_info(),
            self._make_info(
                services=(SVC_SPF_SOFTFAIL,),
                slugs=("proofpoint", "mimecast"),
                dmarc_policy="quarantine",
                mta_sts_mode="testing",
            ),
            self._make_info(
                slugs=("canva", "dropbox"),
            ),
        ]

        for info in infos:
            result = find_gaps_from_info(info)
            all_strings = _collect_string_fields(result)
            violations = self._scan_for_banned_terms(all_strings)
            assert not violations, f"Banned terms in gaps output: {violations}"

    def test_no_banned_terms_in_comparison_output(self) -> None:
        """Run compare_postures, scan for banned terms."""
        info_a = self._make_info(
            queried_domain="a.com",
            dmarc_policy="reject",
            auth_type="Federated",
            slugs=("okta", "crowdstrike", "zscaler"),
        )
        info_b = self._make_info(
            queried_domain="b.com",
            dmarc_policy="none",
        )
        result = compare_postures_from_infos(info_a, info_b)
        all_strings = _collect_string_fields(result)
        violations = self._scan_for_banned_terms(all_strings)
        assert not violations, f"Banned terms in comparison output: {violations}"

    def test_no_banned_terms_in_tool_docstrings(self) -> None:
        """Verify no banned terms in the MCP tool docstrings.

        Uses word-boundary matching to avoid false positives like
        'hardening' matching 'harden' — 'hardening' is the approved
        replacement vocabulary per the design doc.
        """
        from recon_tool.server import assess_exposure as ae
        from recon_tool.server import compare_postures as cp
        from recon_tool.server import find_hardening_gaps as fhg

        for func in (ae, fhg, cp):
            doc = func.__doc__ or ""
            lower = doc.lower()
            for term in EXPOSURE_BANNED_TERMS:
                # Use word boundary to avoid false positives (e.g. "hardening" vs "harden")
                pattern = rf"\b{re.escape(term)}\b"
                assert not re.search(pattern, lower), (
                    f"Banned term '{term}' in docstring of {func.__name__}"
                )
