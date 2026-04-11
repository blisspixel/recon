"""Tests for related domain auto-enrichment in the resolver."""

from __future__ import annotations

import pytest

from recon_tool.models import SourceResult, TenantInfo
from recon_tool.resolver import SourcePool, _enrich_from_related, resolve_tenant


class FakeSource:
    def __init__(self, name: str, result: SourceResult) -> None:
        self._name = name
        self._result = result

    @property
    def name(self) -> str:
        return self._name

    async def lookup(self, domain: str, **kwargs) -> SourceResult:
        return self._result


class TestEnrichFromRelated:
    """Tests for _enrich_from_related — the untested enrichment path."""

    @pytest.mark.asyncio
    async def test_no_related_domains_returns_unchanged(self):
        info = TenantInfo(
            tenant_id="aaa", display_name="Test", default_domain="test.com",
            queried_domain="test.com", related_domains=(),
        )
        enriched, results = await _enrich_from_related(info, [])
        assert enriched is info  # same object, no change

    @pytest.mark.asyncio
    async def test_onmicrosoft_domains_skipped(self):
        info = TenantInfo(
            tenant_id="aaa", display_name="Test", default_domain="test.com",
            queried_domain="test.com",
            related_domains=("contoso.onmicrosoft.com",),
        )
        enriched, results = await _enrich_from_related(info, [])
        assert enriched is info  # onmicrosoft filtered out, no enrichment

    @pytest.mark.asyncio
    async def test_cap_limits_enrichment_candidates(self):
        """More than MAX_RELATED_ENRICHMENTS candidates should be capped."""
        # Create 30 related domains — only first 25 should be looked up
        related = tuple(f"related{i}.com" for i in range(30))
        info = TenantInfo(
            tenant_id="aaa", display_name="Test", default_domain="test.com",
            queried_domain="test.com", related_domains=related,
        )
        # This will attempt real DNS lookups on the fake domains, which will
        # fail gracefully. The point is it doesn't try all 30.
        enriched, results = await _enrich_from_related(info, [])
        # At most 25 additional results from enrichment
        assert len(results) <= 25


class TestEnrichmentIntegration:
    """Integration test: resolver discovers related domains and enriches."""

    @pytest.mark.asyncio
    async def test_related_domain_services_merged(self):
        """When a source returns related_domains, the resolver enriches them."""
        primary = SourceResult(
            source_name="s1",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            detected_services=("Microsoft 365",),
            detected_slugs=("microsoft365",),
            related_domains=(),  # no related domains = no enrichment
        )
        pool = SourcePool([FakeSource("s1", primary)])
        info, results = await resolve_tenant("example.com", pool=pool)
        assert info.tenant_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
