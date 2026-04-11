"""Property-based tests for M365 tenant lookup data models.

Tests Property 18: SourceResult completeness invariant
Also tests is_success property behavior.

Validates: Requirements 6.2
"""

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recon_tool.models import SourceResult

# Strategy for optional non-empty strings (or None)
optional_str = st.one_of(
    st.none(),
    st.text(alphabet=st.characters(whitelist_categories=('L', 'N')), min_size=1, max_size=20),
)

# Strategy for non-None, non-empty strings
non_empty_str = st.text(alphabet=st.characters(whitelist_categories=('L', 'N')), min_size=1, max_size=20)


class TestSourceResultCompleteness:
    """Property 18: SourceResult completeness invariant.

    **Validates: Requirements 6.2**
    """

    @given(
        source_name=non_empty_str,
        tenant_id=non_empty_str,
        display_name=non_empty_str,
        default_domain=non_empty_str,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_is_complete_when_all_fields_present(
        self, source_name, tenant_id, display_name, default_domain
    ):
        """For any SourceResult where tenant_id, display_name, and default_domain
        are all non-None, is_complete should return True."""
        result = SourceResult(
            source_name=source_name,
            tenant_id=tenant_id,
            display_name=display_name,
            default_domain=default_domain,
        )
        assert result.is_complete is True

    @given(
        source_name=non_empty_str,
        tenant_id=optional_str,
        display_name=optional_str,
        default_domain=optional_str,
    )
    @settings(max_examples=100)
    def test_is_not_complete_when_any_field_none(
        self, source_name, tenant_id, display_name, default_domain
    ):
        """For any SourceResult where any of tenant_id, display_name, or
        default_domain is None, is_complete should return False."""
        from hypothesis import assume

        # At least one of the three fields must be None
        assume(tenant_id is None or display_name is None or default_domain is None)

        result = SourceResult(
            source_name=source_name,
            tenant_id=tenant_id,
            display_name=display_name,
            default_domain=default_domain,
        )
        assert result.is_complete is False


class TestSourceResultIsSuccess:
    """Test is_success property: True when tenant_id is not None OR m365_detected is True.

    **Validates: Requirements 6.2**
    """

    @given(
        source_name=non_empty_str,
        tenant_id=non_empty_str,
        m365_detected=st.booleans(),
    )
    @settings(max_examples=100)
    def test_is_success_when_tenant_id_present(
        self, source_name, tenant_id, m365_detected
    ):
        """is_success should be True when tenant_id is not None,
        regardless of m365_detected."""
        result = SourceResult(
            source_name=source_name,
            tenant_id=tenant_id,
            m365_detected=m365_detected,
        )
        assert result.is_success is True

    @given(source_name=non_empty_str)
    @settings(max_examples=100)
    def test_is_success_when_m365_detected(self, source_name):
        """is_success should be True when m365_detected is True,
        even if tenant_id is None."""
        result = SourceResult(
            source_name=source_name,
            tenant_id=None,
            m365_detected=True,
        )
        assert result.is_success is True

    @given(source_name=non_empty_str)
    @settings(max_examples=100)
    def test_is_not_success_when_no_tenant_id_and_no_m365(self, source_name):
        """is_success should be False when tenant_id is None and
        m365_detected is False."""
        result = SourceResult(
            source_name=source_name,
            tenant_id=None,
            m365_detected=False,
        )
        assert result.is_success is False
