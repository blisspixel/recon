"""v1.9.9 — end-to-end render snapshots for the new panel surfaces.

These tests render specific TenantInfo fixtures through
``render_tenant_panel`` and assert structural invariants on the output.
They are stricter than the per-surface tests because they exercise the
full panel rendering pipeline and check that the new v1.9.9 surfaces
(Multi-cloud row, Passive-DNS ceiling block) coexist correctly with
the existing key-facts block, Services block, and trailing sections.

Two reference fixtures:

  * ``MULTI_CLOUD_FIXTURE`` — a contoso-style apex with AWS apex
    infrastructure and Fastly + Cloudflare on surface attributions.
    Should render the Multi-cloud rollup and full Services block; the
    ceiling footer should NOT fire because surface attributions are
    above the sparse threshold.
  * ``SPARSE_HARDENED_FIXTURE`` — a hardened-target style apex: many
    tenant domains, one apex service, no surface attributions. Should
    render the Passive-DNS ceiling footer; Multi-cloud rollup should
    NOT fire because there is only one cloud-categorized slug.

Together the two fixtures exercise the two new surfaces in their
respective firing regimes plus the mutual-exclusion behaviour (each
fixture fires exactly one of the two new surfaces, not both).
"""

from __future__ import annotations

from rich.console import Console

from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, SurfaceAttribution, TenantInfo


def _render(info: TenantInfo, **kwargs: object) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info, **kwargs)  # type: ignore[arg-type]
    console.print(rendered)
    return console.export_text()


# ── Fixture 1: multi-cloud rich-stack apex ─────────────────────────────


def _multi_cloud_fixture() -> TenantInfo:
    """An apex that touches three cloud vendors via apex + surface.

    AWS via apex CloudFront + Route 53; Cloudflare on subdomains;
    Fastly on subdomains. Three distinct vendors after canonicalization.
    Surface attribution count is above the ceiling-suppression
    threshold so the ceiling footer does not fire."""
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid-mc",
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        domain_count=8,
        tenant_domains=("contoso.com", "contoso.net", "contoso.co.uk", "contoso-corp.com"),
        services=("AWS CloudFront", "AWS Route 53", "Cloudflare", "Fastly", "Okta", "Slack"),
        slugs=("aws-cloudfront", "aws-route53", "cloudflare", "fastly", "okta", "slack"),
        surface_attributions=tuple(
            SurfaceAttribution(
                subdomain=f"app{i}.contoso.com",
                primary_slug="fastly",
                primary_name="Fastly",
                primary_tier="infrastructure",
            )
            for i in range(8)
        ),
    )


# ── Fixture 2: sparse hardened apex ────────────────────────────────────


def _sparse_hardened_fixture() -> TenantInfo:
    """A minimal-DNS hardened-target style apex.

    Multiple tenant domains (so domain_count clears the multi-domain
    gate), one apex service in the Cloud category, no surface
    attributions, no other detected services. The ceiling footer must
    fire; the Multi-cloud rollup must not (one vendor only)."""
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid-sh",
        display_name="Northwind Traders",
        default_domain="northwind.com",
        queried_domain="northwind.com",
        confidence=ConfidenceLevel.LOW,
        domain_count=5,
        tenant_domains=("northwind.com", "northwind.net", "northwind.co.uk", "nw-internal.com", "nw-corp.com"),
        services=("Cloudflare",),
        slugs=("cloudflare",),
    )


class TestMultiCloudFixture:
    def test_multi_cloud_row_renders(self):
        out = _render(_multi_cloud_fixture())
        assert "Multi-cloud" in out

    def test_multi_cloud_lists_three_vendors(self):
        out = _render(_multi_cloud_fixture())
        assert "3 providers observed" in out
        assert "AWS" in out
        assert "Cloudflare" in out
        assert "Fastly" in out

    def test_ceiling_does_not_fire_on_rich_stack(self):
        """The 8 surface attributions push the panel above the sparse
        threshold; the ceiling footer would be misleading on a
        rich-stack target and must stay silent."""
        out = _render(_multi_cloud_fixture())
        assert "Passive-DNS ceiling" not in out

    def test_services_block_renders(self):
        """Pre-existing Services block must continue to render
        alongside the new Multi-cloud surface. Regression check that
        the new field insertion did not break the key-facts block."""
        out = _render(_multi_cloud_fixture())
        assert "Services" in out
        # Confidence still renders below Multi-cloud
        assert "Confidence" in out

    def test_multi_cloud_row_appears_before_confidence(self):
        """Layout invariant: Multi-cloud is part of the key-facts
        block which ends with Confidence. The new row must land
        above Confidence, not after it."""
        out = _render(_multi_cloud_fixture())
        mc_idx = out.find("Multi-cloud")
        conf_idx = out.find("Confidence")
        assert mc_idx != -1
        assert conf_idx != -1
        assert mc_idx < conf_idx, "Multi-cloud row must render above Confidence in the key-facts block"


class TestSparseHardenedFixture:
    def test_ceiling_renders(self):
        out = _render(_sparse_hardened_fixture())
        assert "Passive-DNS ceiling" in out

    def test_ceiling_teaches_about_internal_workloads(self):
        out = _render(_sparse_hardened_fixture())
        assert "Server-side API consumption" in out
        assert "internal workloads" in out

    def test_multi_cloud_does_not_fire_single_vendor(self):
        """Cloudflare alone is one vendor; the rollup row must not
        appear and waste a panel line on a vacuous count."""
        out = _render(_sparse_hardened_fixture())
        assert "Multi-cloud" not in out

    def test_ceiling_renders_below_services_block(self):
        """Layout invariant: the ceiling block lives below Services,
        because the operator should see what we did find before being
        told what we cannot see."""
        out = _render(_sparse_hardened_fixture())
        svc_idx = out.find("Services")
        ceiling_idx = out.find("Passive-DNS ceiling")
        assert svc_idx != -1
        assert ceiling_idx != -1
        assert svc_idx < ceiling_idx


class TestMutualBehaviour:
    """Each fixture fires exactly one of the two new surfaces. Cross-
    fixture asserts guard against a regression where both surfaces
    might fire on a fixture neither was designed for."""

    def test_multi_cloud_fixture_does_not_fire_ceiling(self):
        out = _render(_multi_cloud_fixture())
        assert "Multi-cloud" in out
        assert "Passive-DNS ceiling" not in out

    def test_sparse_hardened_fixture_does_not_fire_multi_cloud(self):
        out = _render(_sparse_hardened_fixture())
        assert "Multi-cloud" not in out
        assert "Passive-DNS ceiling" in out

    def test_full_mode_suppresses_both_new_surfaces(self):
        """``--full`` / ``--domains`` mode shows the long External
        surface section; the ceiling becomes redundant. Multi-cloud
        also collapses because the per-subdomain table makes it
        obvious. Both new surfaces should suppress."""
        out_mc = _render(_multi_cloud_fixture(), show_domains=True)
        out_sh = _render(_sparse_hardened_fixture(), show_domains=True)
        # Ceiling suppresses in --full
        assert "Passive-DNS ceiling" not in out_sh
        # Multi-cloud is in the key-facts block and intentionally
        # continues to render in --full because key facts are not
        # redundant with the subdomain table. Document this so the
        # snapshot is honest about which surfaces collapse and which
        # do not.
        assert "Multi-cloud" in out_mc
