"""Historical shape compatibility and the current disk-cache boundary.

The permissive dataclass decoder continues to accept older serialized field
shapes for fixture and import compatibility. Disk reads are intentionally
stricter: cache version 4 adds exact generated-insight lineage, so ``cache_get``
must miss every pre-v4 entry rather than serve an insight without its
generation-time association. Current-version disk round trips must preserve
that lineage exactly.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace

import pytest
from rich.console import Console

from recon_tool.cache import (
    _CACHE_VERSION,
    cache_dir,
    cache_get,
    cache_put,
    tenant_info_from_dict,
    tenant_info_to_dict,
)
from recon_tool.formatter import render_tenant_panel
from recon_tool.merger import merge_results
from recon_tool.models import ConfidenceLevel, EvidenceRecord, InsightClaim, SourceResult, TenantInfo


def _render(info, **kwargs) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info, **kwargs)
    console.print(rendered)
    return console.export_text()


def _v198_shape_multi_cloud_cache() -> dict:
    """A cache JSON that v1.9.8 could have written for a multi-cloud
    apex. The schema is identical to v1.9.9; the test point is that
    no v1.9.9-only fields are present in this cache and the v1.9.9
    panel still derives the new surfaces correctly."""
    return {
        "cache_version": _CACHE_VERSION,
        "tenant_id": "tid-198-multi",
        "display_name": "Synthetic Alpha, Ltd",
        "default_domain": "alpha.invalid",
        "queried_domain": "alpha.invalid",
        "confidence": "high",
        "domain_count": 8,
        "tenant_domains": ["alpha.invalid", "alpha.invalid", "alpha.invalid"],
        "services": ["AWS CloudFront", "Cloudflare", "GCP Compute Engine"],
        "slugs": ["aws-cloudfront", "cloudflare", "gcp-compute"],
        "sources": [],
        "surface_attributions": [
            {
                "subdomain": "api.alpha.invalid",
                "primary_slug": "fastly",
                "primary_name": "Fastly",
                "primary_tier": "infrastructure",
            },
        ],
    }


def _v198_shape_sparse_cache() -> dict:
    """A cache JSON that v1.9.8 could have written for a hardened-
    target sparse apex. Multi-domain (so the ceiling trigger fires)
    with one apex service and no surface attributions."""
    return {
        "cache_version": _CACHE_VERSION,
        "tenant_id": "tid-198-sparse",
        "display_name": "Synthetic Gamma",
        "default_domain": "gamma.invalid",
        "queried_domain": "gamma.invalid",
        "confidence": "low",
        "domain_count": 5,
        "tenant_domains": [
            "gamma.invalid",
            "gamma.test",
            "gamma.example",
            "gamma-corp.invalid",
            "gamma-internal.invalid",
        ],
        "services": ["Cloudflare"],
        "slugs": ["cloudflare"],
        "sources": [],
    }


class TestCacheLoadsAcrossVersions:
    """A v1.9.8 cache JSON, deserialized through the v1.9.9 reader,
    produces a usable TenantInfo. The test is non-trivial because the
    reader path is shared between versions and any silent schema
    rejection would surface here."""

    def test_multi_cloud_cache_loads(self):
        info = tenant_info_from_dict(_v198_shape_multi_cloud_cache())
        assert info.display_name == "Synthetic Alpha, Ltd"
        assert "aws-cloudfront" in info.slugs

    def test_sparse_cache_loads(self):
        info = tenant_info_from_dict(_v198_shape_sparse_cache())
        assert info.display_name == "Synthetic Gamma"
        assert info.domain_count == 5

    def test_json_round_trip_stable_to_load(self):
        """Even after a JSON serialize/deserialize cycle (mimicking
        on-disk persistence), the cache loads cleanly."""
        cache_dict = _v198_shape_multi_cloud_cache()
        json_text = json.dumps(cache_dict)
        round_tripped_dict = json.loads(json_text)
        info = tenant_info_from_dict(round_tripped_dict)
        assert info.display_name == "Synthetic Alpha, Ltd"


class TestV199SurfacesDeriveFromOlderCache:
    """The renderer-side v1.9.9 surfaces work on cached data that
    pre-dates v1.9.9. No re-collection or data migration is needed."""

    def test_v198_cache_without_lineage_does_not_claim_multi_cloud(self):
        info = tenant_info_from_dict(_v198_shape_multi_cloud_cache())
        out = _render(info)
        assert "Multi-cloud" not in out
        assert "role unavailable" in out

    def test_ceiling_footer_fires_on_v198_sparse_cache(self):
        info = tenant_info_from_dict(_v198_shape_sparse_cache())
        out = _render(info)
        assert "Passive-DNS ceiling" in out, (
            "v1.9.9 panel must derive the ceiling footer from v1.9.8-shape cache data without re-collection"
        )

    def test_cache_with_no_cloud_slugs_does_not_fire_multi_cloud(self):
        """A pure-SaaS cache must not produce a Multi-cloud row even
        though the apex has many distinct slugs. The rollup contract
        is canonicalized-cloud-vendors, not total slugs."""
        cache = _v198_shape_sparse_cache()
        cache["slugs"] = ["slack", "okta", "auth0", "atlassian"]
        cache["services"] = ["Slack", "Okta", "Auth0", "Atlassian"]
        info = tenant_info_from_dict(cache)
        out = _render(info)
        assert "Multi-cloud" not in out


class TestCacheVersionConstantPinning:
    """A change to ``_CACHE_VERSION`` is a deliberate schema-version
    bump that requires migration guidance, a CHANGELOG entry, and a
    forward-compat test update. This test pins the current version
    so a silent bump (e.g. accidental literal edit) is visible at
    commit time. To intentionally bump, update both this constant
    and the synthesized fixtures above."""

    _EXPECTED_CACHE_VERSION_AFTER_INSIGHT_LINEAGE = 4

    def test_cache_version_constant_matches_pinned_value(self):
        # The actual constant in cache.py may evolve. This test
        # exists to prevent silent bumps; if you intentionally
        # changed _CACHE_VERSION, update _EXPECTED_CACHE_VERSION_AFTER_INSIGHT_LINEAGE
        # and document the change in the CHANGELOG.
        assert _CACHE_VERSION == self._EXPECTED_CACHE_VERSION_AFTER_INSIGHT_LINEAGE, (
            f"_CACHE_VERSION changed from {self._EXPECTED_CACHE_VERSION_AFTER_INSIGHT_LINEAGE} to {_CACHE_VERSION}. "
            f"If this was intentional: update _EXPECTED_CACHE_VERSION_AFTER_INSIGHT_LINEAGE above, document the bump "
            f"in CHANGELOG.md, and ensure the v1.9.9 compat fixtures above reflect the new schema."
        )

    def test_pre_v4_disk_entry_is_a_cache_miss(self) -> None:
        info = TenantInfo(
            tenant_id=None,
            display_name="Example",
            default_domain="example.invalid",
            queried_domain="example.invalid",
            confidence=ConfidenceLevel.LOW,
        )
        payload = tenant_info_to_dict(info)
        payload["_cache_version"] = 3
        cache_dir().mkdir(parents=True, exist_ok=True)
        (cache_dir() / "example.invalid.json").write_text(json.dumps(payload), encoding="utf-8")

        assert cache_get("example.invalid") is None

    def test_v4_disk_round_trip_preserves_exact_insight_lineage(self) -> None:
        evidence = EvidenceRecord("MX", "10 mx.proofpoint.invalid", "Proofpoint", "proofpoint")
        claim = InsightClaim(
            text="MX gateway observed: Proofpoint",
            generator_rule_id="_gateway_insights",
            supporting_evidence=(evidence,),
            observation_scope=("dns:mx",),
            evidence_required=False,
        )
        info = TenantInfo(
            tenant_id=None,
            display_name="Example",
            default_domain="example.invalid",
            queried_domain="example.invalid",
            confidence=ConfidenceLevel.MEDIUM,
            services=("Proofpoint",),
            slugs=("proofpoint",),
            insights=(claim.text,),
            insight_claims=(claim,),
            evidence=(evidence,),
            email_gateway="Proofpoint",
        )

        cache_put("example.invalid", info)
        restored = cache_get("example.invalid")

        assert restored is not None
        assert restored.insight_claims == (claim,)

    @pytest.mark.parametrize("corruption", ["missing", "empty", "duplicate", "mismatched"])
    def test_v4_disk_entry_rejects_incomplete_or_inconsistent_lineage(self, corruption: str) -> None:
        evidence = EvidenceRecord("MX", "10 mx.proofpoint.invalid", "Proofpoint", "proofpoint")
        claim = InsightClaim(
            text="MX gateway observed: Proofpoint",
            generator_rule_id="_gateway_insights",
            supporting_evidence=(evidence,),
            observation_scope=("dns:mx",),
            evidence_required=False,
        )
        domain = f"lineage-{corruption}.invalid"
        payload = tenant_info_to_dict(
            TenantInfo(
                tenant_id=None,
                display_name="Example",
                default_domain=domain,
                queried_domain=domain,
                confidence=ConfidenceLevel.MEDIUM,
                services=("Proofpoint",),
                slugs=("proofpoint",),
                insights=(claim.text,),
                insight_claims=(claim,),
                evidence=(evidence,),
                email_gateway="Proofpoint",
            )
        )
        corrupted = deepcopy(payload)
        if corruption == "missing":
            corrupted.pop("insight_claims")
        elif corruption == "empty":
            corrupted["insight_claims"] = []
        elif corruption == "duplicate":
            corrupted["insight_claims"].append(deepcopy(corrupted["insight_claims"][0]))
        else:
            corrupted["insight_claims"][0]["generator_rule_id"] = "_security_vendor_insights"
        cache_dir().mkdir(parents=True, exist_ok=True)
        (cache_dir() / f"{domain}.json").write_text(json.dumps(corrupted), encoding="utf-8")

        assert cache_get(domain) is None

    def test_v4_cache_write_rejects_missing_generated_lineage(self) -> None:
        evidence = EvidenceRecord("MX", "10 mx.proofpoint.invalid", "Proofpoint", "proofpoint")
        domain = "invalid-write-lineage.invalid"
        info = TenantInfo(
            tenant_id=None,
            display_name="Example",
            default_domain=domain,
            queried_domain=domain,
            confidence=ConfidenceLevel.MEDIUM,
            services=("Proofpoint",),
            slugs=("proofpoint",),
            insights=("MX gateway observed: Proofpoint",),
            evidence=(evidence,),
            email_gateway="Proofpoint",
        )

        cache_put(domain, info)

        assert not (cache_dir() / f"{domain}.json").exists()

    @pytest.mark.parametrize("marker", ["crt.sh", "dns:mx"])
    def test_v4_round_trip_preserves_valid_degraded_resolution(self, marker: str) -> None:
        domain = f"degraded-{marker.replace(':', '-')}.invalid"
        info = merge_results(
            [
                SourceResult(
                    source_name="dns_records",
                    display_name="Example",
                    default_domain=domain,
                    evidence=(EvidenceRecord("A", "192.0.2.1", "Apex address", "apex-address"),),
                    degraded_sources=(marker,),
                )
            ],
            queried_domain=domain,
        )

        cache_put(domain, info)
        restored = cache_get(domain)

        assert restored is not None
        assert restored.degraded_sources == (marker,)
        assert restored.insight_claims == info.insight_claims

    def test_cache_boundaries_isolate_claim_regeneration_errors(self, monkeypatch) -> None:
        domain = "claim-regeneration.invalid"
        info = TenantInfo(
            tenant_id=None,
            display_name="Example",
            default_domain=domain,
            queried_domain=domain,
            confidence=ConfidenceLevel.LOW,
        )
        cache_put(domain, info)

        def fail_projection(_info: TenantInfo) -> TenantInfo:
            raise IndexError("synthetic generator failure")

        monkeypatch.setattr("recon_tool.collection_view.collection_observable_info", fail_projection)

        assert cache_get(domain) is None
        second_domain = "claim-write-regeneration.invalid"
        cache_put(second_domain, replace(info, default_domain=second_domain, queried_domain=second_domain))
        assert not (cache_dir() / f"{second_domain}.json").exists()

    def test_v4_round_trip_ignores_malformed_role_label(self) -> None:
        domain = "malformed-role.invalid"
        info = TenantInfo(
            tenant_id=None,
            display_name="Example",
            default_domain=domain,
            queried_domain=domain,
            confidence=ConfidenceLevel.LOW,
            services=("DNS:",),
            slugs=("malformed-dns",),
            evidence=(EvidenceRecord("NS", "ns.example.invalid", "DNS:", "malformed-dns"),),
        )

        cache_put(domain, info)

        assert cache_get(domain) is not None
