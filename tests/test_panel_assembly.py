"""Evidence-semantic contracts for the default panel assembly."""

from __future__ import annotations

import io

from rich.console import Console

from recon_tool.cache import tenant_info_from_dict, tenant_info_to_dict
from recon_tool.collection_view import collection_observable_info, collection_observable_result
from recon_tool.formatter import (
    format_tenant_dict,
    format_tenant_markdown,
    render_tenant_panel,
)
from recon_tool.formatter.key_facts import key_facts_auth_line, key_facts_multicloud_line
from recon_tool.models import ConfidenceLevel, EvidenceRecord, SourceResult, SurfaceAttribution, TenantInfo
from recon_tool.server.lookup import _format_lookup_tenant


def _render(info: TenantInfo) -> str:
    output = io.StringIO()
    Console(file=output, width=100, force_terminal=False).print(render_tenant_panel(info))
    return output.getvalue()


def test_header_uses_the_queried_namespace_not_a_tenant_default_domain() -> None:
    info = TenantInfo(
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        display_name="Synthetic Alpha",
        default_domain="synthetic-alpha.onmicrosoft.com",
        queried_domain="alpha.invalid",
        confidence=ConfidenceLevel.HIGH,
        sources=("oidc",),
    )

    rendered = _render(info)
    structured = format_tenant_dict(info)

    assert rendered.splitlines()[:2] == [structured["display_name"], structured["queried_domain"]]
    assert f"Tenant domain {structured['default_domain']}" in " ".join(rendered.split())


def test_key_facts_retain_the_canonical_structured_values() -> None:
    info = TenantInfo(
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        display_name="Synthetic Alpha",
        default_domain="synthetic-alpha.onmicrosoft.com",
        queried_domain="alpha.invalid",
        confidence=ConfidenceLevel.HIGH,
        region="NA",
        sources=("oidc", "userrealm", "dns"),
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        auth_type="Managed",
        cloud_instance="microsoftonline.us",
        tenant_region_sub_scope="GCC",
        evidence=(
            EvidenceRecord(
                "MX",
                "10 alpha-invalid.mail.protection.outlook.com",
                "Microsoft 365",
                "microsoft365",
            ),
        ),
    )

    rendered = _render(info)
    structured = format_tenant_dict(info)

    assert f"Provider     {structured['provider']}" in rendered
    assert f"Tenant       {structured['tenant_id']} • {structured['region']}" in rendered
    assert f"Auth         {structured['auth_type']}" in rendered
    assert (
        f"Cloud        {structured['cloud_instance']} ({structured['tenant_region_sub_scope']})" in rendered
    )
    assert f"Confidence   ●●● {structured['confidence'].capitalize()} (3 sources)" in rendered


def test_multicloud_summary_excludes_evidence_from_an_unavailable_channel() -> None:
    info = TenantInfo(
        tenant_id=None,
        display_name="Synthetic Alpha",
        default_domain="alpha.invalid",
        queried_domain="alpha.invalid",
        services=("Cloudflare", "GCP Compute Engine"),
        slugs=("cloudflare", "gcp-compute"),
        degraded_sources=("dns:cname",),
        evidence=(
            EvidenceRecord("TXT", "cloudflare-verify=opaque", "Cloudflare", "cloudflare"),
            EvidenceRecord(
                "CNAME",
                "www.alpha.invalid -> edge.cloudflare.example",
                "Cloudflare",
                "cloudflare",
            ),
            EvidenceRecord(
                "A",
                "192.0.2.1 -> googleusercontent.com",
                "GCP Compute Engine",
                "gcp-compute",
            ),
        ),
    )

    rendered = _render(info)

    assert "Multi-cloud" not in rendered
    assert "Cloudflare (public TXT account indicator)" in rendered


def test_key_fact_producers_project_unavailable_channels_at_their_boundary() -> None:
    info = TenantInfo(
        tenant_id=None,
        display_name="Synthetic Alpha",
        default_domain="alpha.invalid",
        queried_domain="alpha.invalid",
        slugs=("gcp-compute",),
        auth_type="Federated",
        degraded_sources=("dns:cname", "identity:user_realm"),
        surface_attributions=(
            SurfaceAttribution(
                subdomain="www.alpha.invalid",
                primary_slug="fastly",
                primary_name="Fastly",
                primary_tier="infrastructure",
            ),
        ),
        evidence=(
            EvidenceRecord(
                "A",
                "192.0.2.1 -> googleusercontent.com",
                "GCP Compute Engine",
                "gcp-compute",
            ),
        ),
    )

    assert key_facts_auth_line(info) is None
    assert key_facts_multicloud_line(info) is None


def test_cached_autodiscover_failure_masks_a_stale_default_domain_everywhere() -> None:
    raw = TenantInfo(
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        display_name="Synthetic Alpha",
        default_domain="stale.onmicrosoft.com",
        queried_domain="alpha.invalid",
        confidence=ConfidenceLevel.LOW,
        degraded_sources=("identity:autodiscover",),
        domain_count=12,
        tenant_domains=("stale.onmicrosoft.com", "alpha.invalid"),
    )
    cached = tenant_info_from_dict(tenant_info_to_dict(raw))

    visible = collection_observable_info(cached)
    structured = format_tenant_dict(cached)
    rich_panel = _render(cached)
    mcp_text = _format_lookup_tenant(cached, (), "text", False)
    markdown = format_tenant_markdown(cached)

    assert visible.default_domain == "alpha.invalid"
    assert visible.domain_count == 0
    assert visible.tenant_domains == ()
    assert structured["default_domain"] == "alpha.invalid"
    assert "stale.onmicrosoft.com" not in rich_panel
    assert "stale.onmicrosoft.com" not in mcp_text
    assert "stale.onmicrosoft.com" not in markdown


def test_autodiscover_failure_masks_source_default_domain_before_merge() -> None:
    raw = SourceResult(
        source_name="autodiscover",
        default_domain="stale.onmicrosoft.com",
        tenant_domains=("stale.onmicrosoft.com",),
        degraded_sources=("identity:autodiscover",),
    )

    visible = collection_observable_result(raw)

    assert visible.default_domain is None
    assert visible.tenant_domains == ()
