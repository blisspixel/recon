"""Property-based tests for M365 tenant lookup result merger and confidence scoring.

Tests Properties 12-15 from the design document:
- Property 12: Merge preserves highest-priority tenant_id
- Property 13: Merge fills missing fields from lower-priority sources
- Property 14: Confidence level reflects source agreement
- Property 15: Sources field tracks contributing sources
"""

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from recon_tool.constants import SVC_DMARC, email_security_score
from recon_tool.merger import _PLACEHOLDER_DISPLAY_NAMES, compute_confidence, merge_results
from recon_tool.models import ConfidenceLevel, SourceResult

# Strategies
uuid_str = st.uuids().map(str)
non_empty_str = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=20,
)
display_name_str = non_empty_str.filter(lambda s: s.strip().lower() not in _PLACEHOLDER_DISPLAY_NAMES)
source_name_str = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=15,
)


class TestMergePreservesHighestPriorityTenantId:
    """Property 12: Merge preserves highest-priority tenant_id.

    For any list of SourceResult objects where multiple results contain
    different tenant_id values, merge_results should use the tenant_id
    from the first (highest-priority) result that has one.

    **Validates: Requirements 10.2**
    """

    @given(
        uuid1=uuid_str,
        uuid2=uuid_str,
        name1=source_name_str,
        name2=source_name_str,
        domain=non_empty_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_first_tenant_id_wins(self, uuid1, uuid2, name1, name2, domain):
        """The merged result should use the tenant_id from the first
        SourceResult that has one, regardless of what later results contain."""
        assume(uuid1 != uuid2)
        assume(name1 != name2)

        results = [
            SourceResult(source_name=name1, tenant_id=uuid1),
            SourceResult(source_name=name2, tenant_id=uuid2),
        ]
        merged = merge_results(results, queried_domain=domain)
        assert merged.tenant_id == uuid1

    @given(
        uuid1=uuid_str,
        uuid2=uuid_str,
        name1=source_name_str,
        name2=source_name_str,
        name3=source_name_str,
        domain=non_empty_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_skips_none_tenant_id_uses_first_non_none(self, uuid1, uuid2, name1, name2, name3, domain):
        """When the first result has no tenant_id, merge should use the
        tenant_id from the next result that has one."""
        assume(len({name1, name2, name3}) == 3)

        results = [
            SourceResult(source_name=name1, tenant_id=None),
            SourceResult(source_name=name2, tenant_id=uuid1),
            SourceResult(source_name=name3, tenant_id=uuid2),
        ]
        merged = merge_results(results, queried_domain=domain)
        assert merged.tenant_id == uuid1


class TestMergeFillsMissingFields:
    """Property 13: Merge fills missing fields from lower-priority sources.

    For any two SourceResult objects where the first has a tenant_id but
    no display_name, and the second has a display_name, merge_results
    should produce a TenantInfo with both the first result's tenant_id
    and the second result's display_name.

    **Validates: Requirements 6.4**
    """

    @given(
        uuid1=uuid_str,
        display=display_name_str,
        name1=source_name_str,
        name2=source_name_str,
        domain=non_empty_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_display_name_filled_from_lower_priority(self, uuid1, display, name1, name2, domain):
        """First result has tenant_id but no display_name; second result
        has display_name. Merged result should have both."""
        assume(name1 != name2)

        results = [
            SourceResult(source_name=name1, tenant_id=uuid1, display_name=None),
            SourceResult(source_name=name2, display_name=display),
        ]
        merged = merge_results(results, queried_domain=domain)
        assert merged.tenant_id == uuid1
        assert merged.display_name == display

    @given(
        uuid1=uuid_str,
        default_dom=non_empty_str,
        region=non_empty_str,
        name1=source_name_str,
        name2=source_name_str,
        domain=non_empty_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_default_domain_and_region_filled_from_lower_priority(
        self, uuid1, default_dom, region, name1, name2, domain
    ):
        """First result has tenant_id only; second result has default_domain
        and region. Merged result should incorporate all fields."""
        assume(name1 != name2)

        results = [
            SourceResult(source_name=name1, tenant_id=uuid1),
            SourceResult(source_name=name2, default_domain=default_dom, region=region),
        ]
        merged = merge_results(results, queried_domain=domain)
        assert merged.tenant_id == uuid1
        assert merged.default_domain == default_dom
        assert merged.region == region


class TestMergeKeepsDmarcTagsSourceBound:
    def test_later_result_rollout_tags_do_not_modify_selected_policy(self):
        primary = SourceResult(
            source_name="primary_dns",
            dmarc_policy="reject",
            detected_services=(SVC_DMARC,),
            detected_slugs=("dmarc",),
            tenant_domains=("alpha.invalid",),
        )
        related = SourceResult(
            source_name="related_dns",
            dmarc_policy="quarantine",
            dmarc_pct=0,
            dmarc_testing=True,
            detected_services=(SVC_DMARC,),
            detected_slugs=("dmarc",),
        )

        merged = merge_results([primary, related], queried_domain="alpha.invalid")

        assert merged.dmarc_policy == "reject"
        assert merged.dmarc_pct is None
        assert merged.dmarc_testing is False
        assert email_security_score(merged.services, merged.dmarc_policy, merged.dmarc_pct, merged.dmarc_testing) == 1


class TestConfidenceReflectsSourceAgreement:
    """Property 14: Confidence level reflects source agreement.

    - If exactly one source has a tenant ID, compute_confidence should return MEDIUM
    - If two or more independent sources agree on a tenant ID, should return HIGH
    - If results have conflicting tenant_id values, should return LOW

    **Validates: Requirements 10.1, 10.2, 10.3, 10.4**
    """

    @given(
        uuid1=uuid_str,
        name1=source_name_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_single_source_returns_medium(self, uuid1, name1):
        """When exactly one result has a tenant_id, confidence is MEDIUM."""
        results = [SourceResult(source_name=name1, tenant_id=uuid1)]
        confidence, conflict = compute_confidence(results)
        assert confidence == ConfidenceLevel.MEDIUM
        assert not conflict

    @given(
        uuid1=uuid_str,
        name1=source_name_str,
        name2=source_name_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_two_agreeing_sources_returns_high(self, uuid1, name1, name2):
        """When two or more results have the same tenant_id, confidence is HIGH."""
        assume(name1 != name2)

        results = [
            SourceResult(source_name=name1, tenant_id=uuid1),
            SourceResult(source_name=name2, tenant_id=uuid1),
        ]
        assert compute_confidence(results) == (ConfidenceLevel.HIGH, False)

    def test_duplicate_results_from_one_source_are_not_independent(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
        ]

        assert compute_confidence(results) == (ConfidenceLevel.MEDIUM, False)

    @given(
        uuid1=uuid_str,
        uuid2=uuid_str,
        name1=source_name_str,
        name2=source_name_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_conflicting_sources_returns_low(self, uuid1, uuid2, name1, name2):
        """When results have conflicting tenant_ids, confidence is LOW."""
        assume(uuid1 != uuid2)
        assume(name1 != name2)

        results = [
            SourceResult(source_name=name1, tenant_id=uuid1),
            SourceResult(source_name=name2, tenant_id=uuid2),
        ]
        confidence, conflict = compute_confidence(results)
        assert confidence == ConfidenceLevel.LOW
        assert conflict

    @given(
        name1=source_name_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_no_tenant_ids_returns_low(self, name1):
        """When no results have a tenant_id, confidence is LOW."""
        results = [SourceResult(source_name=name1, tenant_id=None)]
        confidence, conflict = compute_confidence(results)
        assert confidence == ConfidenceLevel.LOW
        assert not conflict

    def test_unrelated_display_name_does_not_corroborate_m365_tenant(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(
                source_name="other",
                display_name="Unrelated service",
                detected_services=("Cloudflare",),
                detected_slugs=("cloudflare",),
            ),
        ]

        assert compute_confidence(results) == (ConfidenceLevel.MEDIUM, False)

    def test_failed_m365_result_does_not_corroborate_tenant(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(
                source_name="user_realm",
                m365_detected=True,
                detected_services=("Microsoft 365",),
                detected_slugs=("microsoft365",),
                error="upstream response was invalid",
            ),
        ]

        assert compute_confidence(results) == (ConfidenceLevel.MEDIUM, False)

    def test_failed_service_results_do_not_raise_non_tenant_confidence(self):
        results = [
            SourceResult(
                source_name=source_name,
                detected_services=("Service A", "Service B", "Service C", "Service D"),
                error="source failed",
            )
            for source_name in ("dns_records", "certificate_transparency")
        ]

        assert compute_confidence(results) == (ConfidenceLevel.LOW, False)

    def test_duplicate_service_results_from_one_source_count_once(self):
        result = SourceResult(source_name="dns_records", detected_services=("Cloudflare",))

        assert compute_confidence([result, result]) == (ConfidenceLevel.LOW, False)

    def test_two_sources_with_eight_distinct_services_are_high_confidence(self):
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Service A", "Service B", "Service C", "Service D"),
            ),
            SourceResult(
                source_name="certificate_transparency",
                detected_services=("Service E", "Service F", "Service G", "Service H"),
            ),
        ]

        assert compute_confidence(results) == (ConfidenceLevel.HIGH, False)


class TestSourcesFieldTracksContributors:
    """Property 15: Sources field tracks contributing sources.

    For any list of SourceResult objects passed to merge_results, the
    resulting TenantInfo.sources tuple should contain exactly the
    distinct source_name values from error-free results where is_success is
    true.

    **Validates: Requirements 6.5**
    """

    @given(
        uuid1=uuid_str,
        name1=source_name_str,
        name2=source_name_str,
        domain=non_empty_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_sources_contains_only_successful_results(self, uuid1, name1, name2, domain):
        """sources contains names from error-free results with useful data."""
        assume(name1 != name2)

        results = [
            SourceResult(source_name=name1, tenant_id=uuid1),  # is_success=True
            SourceResult(source_name=name2, tenant_id=None, m365_detected=False),  # is_success=False
        ]
        merged = merge_results(results, queried_domain=domain)
        assert merged.sources == (name1,)

    @given(
        uuid1=uuid_str,
        uuid2=uuid_str,
        name1=source_name_str,
        name2=source_name_str,
        domain=non_empty_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_sources_contains_all_successful_results(self, uuid1, uuid2, name1, name2, domain):
        """When multiple results are successful, all their source_names
        should appear in the sources tuple."""
        assume(name1 != name2)

        results = [
            SourceResult(source_name=name1, tenant_id=uuid1),
            SourceResult(source_name=name2, tenant_id=uuid2),
        ]
        merged = merge_results(results, queried_domain=domain)
        assert set(merged.sources) == {name1, name2}

    @given(
        uuid1=uuid_str,
        name1=source_name_str,
        name2=source_name_str,
        domain=non_empty_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_m365_detected_counts_as_success(self, uuid1, name1, name2, domain):
        """An error-free M365 detection without a tenant ID still contributes."""
        assume(name1 != name2)

        results = [
            SourceResult(source_name=name1, tenant_id=uuid1),
            SourceResult(source_name=name2, tenant_id=None, m365_detected=True),
        ]
        merged = merge_results(results, queried_domain=domain)
        assert set(merged.sources) == {name1, name2}
