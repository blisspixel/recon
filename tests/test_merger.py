"""Property-based tests for M365 tenant lookup result merger and confidence scoring.

Tests Properties 12-15 from the design document:
- Property 12: Merge preserves highest-priority tenant_id
- Property 13: Merge fills missing fields from lower-priority sources
- Property 14: Confidence level reflects source agreement
- Property 15: Sources field tracks contributing sources
"""

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from recon_tool.merger import compute_confidence, merge_results
from recon_tool.models import ConfidenceLevel, SourceResult

# Strategies
uuid_str = st.uuids().map(str)
non_empty_str = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=20,
)
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
        display=non_empty_str,
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


class TestConfidenceReflectsSourceAgreement:
    """Property 14: Confidence level reflects source agreement.

    - If exactly one result has data, compute_confidence should return MEDIUM
    - If two or more results have consistent tenant_id values, should return HIGH
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


class TestSourcesFieldTracksContributors:
    """Property 15: Sources field tracks contributing sources.

    For any list of SourceResult objects passed to merge_results, the
    resulting TenantInfo.sources tuple should contain exactly the
    source_name values from results where is_success == True.

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
        """sources tuple should contain source_names only from results
        where is_success is True."""
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
        """A result with m365_detected=True but no tenant_id should still
        appear in sources since is_success is True."""
        assume(name1 != name2)

        results = [
            SourceResult(source_name=name1, tenant_id=uuid1),
            SourceResult(source_name=name2, tenant_id=None, m365_detected=True),
        ]
        merged = merge_results(results, queried_domain=domain)
        assert set(merged.sources) == {name1, name2}
