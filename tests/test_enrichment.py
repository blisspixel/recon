"""Tests for related domain auto-enrichment in the resolver."""

from __future__ import annotations

import pytest

from recon_tool.models import EvidenceRecord, SourceResult, TenantInfo
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
            tenant_id="aaa",
            display_name="Test",
            default_domain="test.invalid",
            queried_domain="test.invalid",
            related_domains=(),
        )
        enriched, _results = await _enrich_from_related(info, [])
        assert enriched is info  # same object, no change

    @pytest.mark.asyncio
    async def test_onmicrosoft_domains_skipped(self):
        info = TenantInfo(
            tenant_id="aaa",
            display_name="Test",
            default_domain="test.invalid",
            queried_domain="test.invalid",
            related_domains=("alpha.onmicrosoft.com",),
        )
        enriched, _results = await _enrich_from_related(info, [])
        assert enriched is info  # onmicrosoft filtered out, no enrichment

    @pytest.mark.asyncio
    async def test_cap_limits_enrichment_candidates(self):
        """More than MAX_RELATED_ENRICHMENTS candidates should be capped."""
        # MAX_RELATED_ENRICHMENTS is 15 (tightened from 25 in v1.0.1). Submit
        # 30 candidates and assert the cap holds.
        related = tuple(f"related{i}.invalid" for i in range(30))
        info = TenantInfo(
            tenant_id="aaa",
            display_name="Test",
            default_domain="test.invalid",
            queried_domain="test.invalid",
            related_domains=related,
        )
        # Real DNS lookups on the fake domains fail gracefully — the point
        # is we don't try all 30.
        _enriched, results = await _enrich_from_related(info, [])
        assert len(results) <= 15

    @pytest.mark.asyncio
    async def test_related_subdomain_inventory_does_not_become_apex_evidence(self, monkeypatch):
        """Unscoped related evidence cannot support apex role claims."""

        async def fake_lightweight_lookup(_domain: str) -> SourceResult:
            return SourceResult(
                source_name="dns_records",
                detected_services=("Kartra",),
                detected_slugs=("kartra",),
                evidence=(
                    EvidenceRecord(
                        source_type="CNAME",
                        raw_value="example.kartra.com",
                        rule_name="Kartra",
                        slug="kartra",
                    ),
                ),
            )

        monkeypatch.setattr("recon_tool.sources.dns.lightweight_subdomain_lookup", fake_lightweight_lookup)
        info = TenantInfo(
            tenant_id="aaa",
            display_name="Test",
            default_domain="example.com",
            queried_domain="example.com",
            related_domains=("learn.example.com",),
        )
        enriched, _results = await _enrich_from_related(info, [])
        assert "Kartra" in enriched.services
        assert "kartra" in enriched.slugs
        assert all(e.slug != "kartra" for e in enriched.evidence)
        assert all(slug != "kartra" for slug, _score in enriched.detection_scores)

    @pytest.mark.asyncio
    async def test_failed_related_channel_cannot_contribute_partial_inventory(self, monkeypatch):
        async def fake_lightweight_lookup(_domain: str) -> SourceResult:
            return SourceResult(
                source_name="dns_records",
                detected_services=("Kartra",),
                detected_slugs=("kartra",),
                evidence=(EvidenceRecord("CNAME", "example.kartra.com", "Kartra", "kartra"),),
                degraded_sources=("dns:cname",),
            )

        monkeypatch.setattr("recon_tool.sources.dns.lightweight_subdomain_lookup", fake_lightweight_lookup)
        info = TenantInfo(
            tenant_id=None,
            display_name="Example",
            default_domain="example.com",
            queried_domain="example.com",
            related_domains=("learn.example.com",),
        )

        enriched, _results = await _enrich_from_related(info, [])

        assert enriched is info

    @pytest.mark.asyncio
    async def test_separate_related_domain_email_records_do_not_change_apex_posture(self, monkeypatch):
        """MX and DKIM from a breadcrumb domain stay outside the queried apex."""

        async def fake_dns_lookup(_self, _domain: str, **_kwargs) -> SourceResult:
            return SourceResult(
                source_name="dns_records",
                detected_services=("Google Workspace", "DKIM (Google Workspace)"),
                detected_slugs=("google-workspace",),
                evidence=(
                    EvidenceRecord("MX", "1 aspmx.l.google.com", "Google Workspace", "google-workspace"),
                    EvidenceRecord(
                        "DKIM",
                        "google._domainkey.brand2.invalid",
                        "DKIM (Google Workspace)",
                        "google-workspace",
                    ),
                ),
            )

        monkeypatch.setattr("recon_tool.sources.dns.DNSSource.lookup", fake_dns_lookup)
        info = TenantInfo(
            tenant_id=None,
            display_name="Brand 1",
            default_domain="brand1.invalid",
            queried_domain="brand1.invalid",
            related_domains=("brand2.invalid",),
        )

        enriched, _results = await _enrich_from_related(info, [])

        from recon_tool.exposure import assess_exposure_from_info

        posture = assess_exposure_from_info(enriched).email_posture
        assert enriched.primary_email_provider is None
        assert enriched.email_gateway is None
        assert enriched.evidence == ()
        assert posture.email_security_score == 0
        assert posture.dkim_configured is False


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
        info, _results = await resolve_tenant("example.com", pool=pool)
        assert info.tenant_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class TestRelatedEnrichmentDoesNotBorrowEmailControls:
    """A related namespace's records must not become this namespace's claims.

    Enrichment unions a related domain's detections into the queried one. An
    email-control label asserts that this namespace publishes that record, so
    storing the raw union let a neighbouring domain's DMARC, DKIM, SPF, MTA-STS
    and BIMI appear as the queried domain's own while its own dmarc_policy
    stayed null and its control score stayed zero. The claim-safe projection
    was already computed for the insight arguments; the stored tuples bypassed
    it.
    """

    @staticmethod
    def _apex():
        from recon_tool.models import ConfidenceLevel, EvidenceRecord, TenantInfo

        return TenantInfo(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            display_name="Synthetic Alpha",
            default_domain="alpha.onmicrosoft.com",
            queried_domain="alpha.invalid",
            confidence=ConfidenceLevel.HIGH,
            services=("Microsoft 365",),
            slugs=("microsoft365",),
            evidence=(
                EvidenceRecord(
                    source_type="CNAME",
                    raw_value="autodiscover.outlook.com",
                    rule_name="m365-cname",
                    slug="microsoft365",
                ),
            ),
            related_domains=("beta-internal.invalid",),
        )

    @staticmethod
    def _stub(monkeypatch, services, slugs):
        from recon_tool import resolver
        from recon_tool.models import SourceResult

        async def _lookup(_source, _domain, **_kwargs):
            return SourceResult(
                source_name="dns_records",
                detected_services=tuple(services),
                detected_slugs=tuple(slugs),
            )

        monkeypatch.setattr(resolver, "_safe_lookup", _lookup)

    @pytest.mark.asyncio
    async def test_control_slugs_are_not_borrowed(self, monkeypatch) -> None:
        from recon_tool import resolver

        self._stub(
            monkeypatch,
            ("DMARC", "DKIM", "SPF: strict (-all)", "MTA-STS", "BIMI"),
            ("dmarc", "dkim", "spf-strict", "mta-sts", "mta-sts-enforce", "bimi"),
        )

        enriched, _results = await resolver._enrich_from_related(self._apex(), [], skip_ct=True)

        borrowed = {"dmarc", "dkim", "spf-strict", "mta-sts", "mta-sts-enforce", "bimi"}
        assert borrowed.isdisjoint(enriched.slugs)
        assert not borrowed.intersection({s.lower() for s in enriched.services})
        # The apex keeps what its own evidence proves.
        assert "microsoft365" in enriched.slugs

    @pytest.mark.asyncio
    async def test_inventory_labels_still_merge(self, monkeypatch) -> None:
        from recon_tool import resolver

        # A non-control detection is an inventory label, not a record claim, so
        # enrichment must still surface it.
        self._stub(monkeypatch, ("Snowflake", "DMARC"), ("snowflake", "dmarc"))

        enriched, _results = await resolver._enrich_from_related(self._apex(), [], skip_ct=True)

        assert "snowflake" in enriched.slugs
        assert "dmarc" not in enriched.slugs
