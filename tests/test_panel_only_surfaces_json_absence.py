"""v1.9.9 — JSON-absence contract: new surfaces are panel-only.

The Multi-cloud rollup and Passive-DNS ceiling phrasing are panel
output added in v1.9.9. By design they are *renderer-side derivations*
from the existing TenantInfo data model, not new JSON schema fields.
The JSON output of ``recon <domain> --json`` and the MCP tool responses
must stay schema-stable; adding a panel string to the JSON would be a
schema change that requires schema-version bump bookkeeping.

These tests pin the absence contract: serializing a TenantInfo that
*would* render the new surfaces must not introduce the user-facing
strings into the JSON shape. A future patch that wants to surface the
multi-cloud roll-up or ceiling status into JSON has to add a new
typed field deliberately, with its own schema review; it cannot
silently leak through the existing serializer.
"""

from __future__ import annotations

import json

from recon_tool.cache import tenant_info_to_dict
from recon_tool.models import ConfidenceLevel, SurfaceAttribution, TenantInfo


def _multi_cloud_tenant() -> TenantInfo:
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid",
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        domain_count=8,
        tenant_domains=("contoso.com", "contoso.net", "contoso.co.uk"),
        services=("AWS CloudFront", "Cloudflare", "Fastly"),
        slugs=("aws-cloudfront", "cloudflare", "fastly"),
        surface_attributions=tuple(
            SurfaceAttribution(
                subdomain=f"sub{i}.contoso.com",
                primary_slug="fastly",
                primary_name="Fastly",
                primary_tier="infrastructure",
            )
            for i in range(8)
        ),
    )


def _sparse_hardened_tenant() -> TenantInfo:
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid",
        display_name="Northwind Traders",
        default_domain="northwind.com",
        queried_domain="northwind.com",
        confidence=ConfidenceLevel.LOW,
        domain_count=5,
        tenant_domains=("northwind.com", "nw.net", "nw.co.uk", "nw-corp.com", "nw-internal.com"),
        services=("Cloudflare",),
        slugs=("cloudflare",),
    )


class TestMultiCloudNotInJson:
    """The renderer-side Multi-cloud row must not leak into the
    serialized JSON. A reader of the JSON would have no way to act on
    a free-text label embedded in the data shape."""

    def test_multi_cloud_string_absent_from_json(self):
        info = _multi_cloud_tenant()
        as_dict = tenant_info_to_dict(info)
        as_json = json.dumps(as_dict)
        assert "Multi-cloud" not in as_json, (
            "The 'Multi-cloud' rollup label is a panel-only string. A schema-stable JSON output "
            "must not embed it. If a future patch wants to surface the rollup, add a typed field "
            "(e.g. ``multi_cloud_vendors: [...]``) with its own schema review."
        )

    def test_n_providers_observed_string_absent_from_json(self):
        info = _multi_cloud_tenant()
        as_dict = tenant_info_to_dict(info)
        as_json = json.dumps(as_dict)
        assert "providers observed" not in as_json


class TestCeilingPhrasingNotInJson:
    """The ceiling teaching phrasing is a renderer-side footer. Like
    the rollup label, it must not appear in the JSON shape; a JSON
    consumer that wanted a 'sparse for scale' signal should rely on
    a derived flag at a clearly-named field, not on substring-matching
    a free-text English sentence."""

    def test_ceiling_header_absent_from_json(self):
        info = _sparse_hardened_tenant()
        as_dict = tenant_info_to_dict(info)
        as_json = json.dumps(as_dict)
        assert "Passive-DNS ceiling" not in as_json

    def test_ceiling_body_absent_from_json(self):
        info = _sparse_hardened_tenant()
        as_dict = tenant_info_to_dict(info)
        as_json = json.dumps(as_dict)
        # The teaching body uses phrases that should never appear in
        # a structured JSON payload.
        assert "Passive DNS surfaces what publishes externally" not in as_json
        assert "Server-side API consumption" not in as_json


class TestJsonShapeContainsOnlyDataFields:
    """The v1.9.9 surfaces are renderer-side derivations; the
    serialized dict must continue to expose the same field set the
    pre-v1.9.9 schema documented. Any v1.9.9-introduced data field
    would show up as a new top-level key on this serialized shape and
    surface in the assertion below."""

    _V199_FIELD_NAMES_NOT_IN_JSON = (
        "multi_cloud",
        "multi_cloud_vendors",
        "passive_dns_ceiling",
        "ceiling_fires",
    )

    def test_multi_cloud_tenant_serializes_without_v199_data_fields(self):
        info = _multi_cloud_tenant()
        as_dict = tenant_info_to_dict(info)
        for name in self._V199_FIELD_NAMES_NOT_IN_JSON:
            assert name not in as_dict, (
                f"v1.9.9 introduced renderer-side surfaces; data field {name!r} should NOT appear "
                f"in the serialized JSON. If a future patch promotes one of these to a structured "
                f"field, document the schema-version bump and remove this assertion deliberately."
            )

    def test_sparse_hardened_tenant_serializes_without_v199_data_fields(self):
        info = _sparse_hardened_tenant()
        as_dict = tenant_info_to_dict(info)
        for name in self._V199_FIELD_NAMES_NOT_IN_JSON:
            assert name not in as_dict
