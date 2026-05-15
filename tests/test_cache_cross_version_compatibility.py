"""v1.9.9 — cache compatibility with pre-v1.9.9 serialized data.

The v1.9.9 release adds two renderer-side panel surfaces (Multi-cloud
rollup, Passive-DNS ceiling) but **introduces no new fields** in the
``TenantInfo`` dataclass or its serialized cache form. The cache
schema version (``_CACHE_VERSION`` in ``recon_tool/cache.py``) is
unchanged between v1.9.8 and v1.9.9.

The implication for operators: a cache written by v1.9.8 must (a)
load without error under v1.9.9, and (b) render through the v1.9.9
panel with the same operator-facing data plus the new v1.9.9
surfaces, derived from the existing cache fields. No data migration
is required; the new surfaces are pure functions of existing fields.

These tests pin both halves of that contract:

  * A synthesized v1.9.8-shape cache loads into v1.9.9 without error.
  * The same cache rendered through v1.9.9 surfaces the new Multi-
    cloud row when the cached data indicates multiple cloud vendors,
    and the new ceiling footer when the cached data is sparse on a
    multi-domain apex.

A future patch that introduces a real cache-schema change would need
to bump ``_CACHE_VERSION`` and update this test deliberately.
"""

from __future__ import annotations

import json

from rich.console import Console

from recon_tool.cache import _CACHE_VERSION, tenant_info_from_dict
from recon_tool.formatter import render_tenant_panel


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
        "display_name": "Contoso, Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": "high",
        "domain_count": 8,
        "tenant_domains": ["contoso.com", "contoso.net", "contoso.co.uk"],
        "services": ["AWS CloudFront", "Cloudflare", "GCP Compute Engine"],
        "slugs": ["aws-cloudfront", "cloudflare", "gcp-compute"],
        "sources": [],
        "surface_attributions": [
            {
                "subdomain": "api.contoso.com",
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
        "display_name": "Northwind Traders",
        "default_domain": "northwind.com",
        "queried_domain": "northwind.com",
        "confidence": "low",
        "domain_count": 5,
        "tenant_domains": ["northwind.com", "nw.net", "nw.co.uk", "nw-corp.com", "nw-internal.com"],
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
        assert info.display_name == "Contoso, Ltd"
        assert "aws-cloudfront" in info.slugs

    def test_sparse_cache_loads(self):
        info = tenant_info_from_dict(_v198_shape_sparse_cache())
        assert info.display_name == "Northwind Traders"
        assert info.domain_count == 5

    def test_json_round_trip_stable_to_load(self):
        """Even after a JSON serialize/deserialize cycle (mimicking
        on-disk persistence), the cache loads cleanly."""
        cache_dict = _v198_shape_multi_cloud_cache()
        json_text = json.dumps(cache_dict)
        round_tripped_dict = json.loads(json_text)
        info = tenant_info_from_dict(round_tripped_dict)
        assert info.display_name == "Contoso, Ltd"


class TestV199SurfacesDeriveFromOlderCache:
    """The renderer-side v1.9.9 surfaces work on cached data that
    pre-dates v1.9.9. No re-collection or data migration is needed."""

    def test_multi_cloud_rollup_fires_on_v198_cache(self):
        info = tenant_info_from_dict(_v198_shape_multi_cloud_cache())
        out = _render(info)
        assert "Multi-cloud" in out, (
            "v1.9.9 panel must derive the Multi-cloud rollup from v1.9.8-shape cache data without re-collection"
        )

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

    _EXPECTED_CACHE_VERSION_AT_V199 = 1  # tracks the version constant as of v1.9.9 ship

    def test_cache_version_constant_matches_pinned_value(self):
        # The actual constant in cache.py may evolve. This test
        # exists to prevent silent bumps; if you intentionally
        # changed _CACHE_VERSION, update _EXPECTED_CACHE_VERSION_AT_V199
        # and document the change in the CHANGELOG.
        assert _CACHE_VERSION == self._EXPECTED_CACHE_VERSION_AT_V199, (
            f"_CACHE_VERSION changed from {self._EXPECTED_CACHE_VERSION_AT_V199} to {_CACHE_VERSION}. "
            f"If this was intentional: update _EXPECTED_CACHE_VERSION_AT_V199 above, document the bump "
            f"in CHANGELOG.md, and ensure the v1.9.9 compat fixtures above reflect the new schema."
        )
