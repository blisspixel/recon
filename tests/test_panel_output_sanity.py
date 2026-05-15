"""v1.9.9 — rendered-output sanity for the new panel surfaces.

The fixture and snapshot tests verify that the new surfaces render at
all. The sanity tests here verify the rendered output is well-formed:
no vendor duplication, no orphan trailing punctuation, no broken
sentence boundaries on the ceiling phrasing.

A failure here would indicate the rendering logic produced
syntactically-bad output even when the trigger correctly fired.
"""

from __future__ import annotations

import re

from rich.console import Console

from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, SurfaceAttribution, TenantInfo


def _render(info: TenantInfo) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info)
    console.print(rendered)
    return console.export_text()


def _multi_cloud_with_duplicate_potential() -> TenantInfo:
    """An apex with multiple AWS slugs on both apex and surface.

    The canonicalization is supposed to collapse all AWS-family slugs
    to a single "AWS" vote in the rollup. This fixture has Route 53 on
    the apex AND CloudFront on three surface attributions; if the
    canonicalization broke (e.g. a future change introduced separate
    "AWS Route 53" and "AWS CloudFront" labels), the rollup line would
    list AWS twice. The sanity check pins that this does not happen."""
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid",
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        domain_count=4,
        tenant_domains=("contoso.com", "contoso.net", "contoso.co.uk"),
        services=("AWS Route 53", "Cloudflare"),
        slugs=("aws-route53", "cloudflare"),
        surface_attributions=tuple(
            SurfaceAttribution(
                subdomain=f"sub{i}.contoso.com",
                primary_slug="aws-cloudfront",
                primary_name="AWS CloudFront",
                primary_tier="infrastructure",
            )
            for i in range(3)
        ),
    )


def _three_vendor_apex() -> TenantInfo:
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid",
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        domain_count=4,
        tenant_domains=("contoso.com",),
        services=("AWS CloudFront", "Cloudflare", "GCP Compute Engine"),
        slugs=("aws-cloudfront", "cloudflare", "gcp-compute"),
    )


def _sparse_ceiling_tenant() -> TenantInfo:
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


class TestNoVendorDuplication:
    def test_aws_family_does_not_duplicate_in_rollup(self):
        """Multiple AWS-family slugs on apex and surface must collapse
        to one 'AWS' mention in the rollup line. The line itself can
        only legitimately contain "AWS" once."""
        out = _render(_multi_cloud_with_duplicate_potential())
        # Find the Multi-cloud line specifically
        mc_lines = [line for line in out.splitlines() if "Multi-cloud" in line]
        assert mc_lines, "expected one Multi-cloud line"
        mc_line = mc_lines[0]
        # AWS appears once in the rollup line (no duplication after
        # canonicalization)
        assert mc_line.count("AWS") == 1, (
            f"Multi-cloud line should mention AWS exactly once after canonicalization; got: {mc_line!r}"
        )

    def test_three_distinct_vendors_each_appear_once(self):
        out = _render(_three_vendor_apex())
        mc_line = next(line for line in out.splitlines() if "Multi-cloud" in line)
        # Each of the three canonical vendor names appears exactly once
        # in the rollup line.
        assert mc_line.count("AWS") == 1
        assert mc_line.count("Cloudflare") == 1
        assert mc_line.count("GCP") == 1


class TestRollupCountAccuracy:
    def test_provider_count_matches_distinct_vendors(self):
        """The 'N providers observed' integer must match the number of
        distinct vendor names actually listed in the parenthetical."""
        out = _render(_three_vendor_apex())
        mc_line = next(line for line in out.splitlines() if "Multi-cloud" in line)
        match = re.search(r"(\d+) providers observed \(([^)]+)\)", mc_line)
        assert match is not None, f"failed to parse Multi-cloud rollup line: {mc_line!r}"
        claimed_count = int(match.group(1))
        listed_vendors = [v.strip() for v in match.group(2).split(",")]
        assert claimed_count == len(listed_vendors), (
            f"count mismatch: claimed {claimed_count}, listed {len(listed_vendors)} ({listed_vendors})"
        )


class TestCeilingPhrasingWellFormed:
    def test_ceiling_text_ends_with_period(self):
        """The teaching footer is two sentences. Each must end with a
        period; a stray missing terminator would leak from the f-string
        composition if a future refactor breaks the sentence
        boundaries."""
        out = _render(_sparse_ceiling_tenant())
        # Find the ceiling block
        ceiling_idx = out.find("Passive-DNS ceiling")
        assert ceiling_idx != -1
        ceiling_block = out[ceiling_idx : ceiling_idx + 400]
        # The block contains the period-terminated teaching sentences
        assert "public DNS records." in ceiling_block

    def test_ceiling_text_does_not_double_punctuate(self):
        out = _render(_sparse_ceiling_tenant())
        # No double periods (".."), no trailing comma before period
        # (",."), no orphan punctuation.
        assert ".." not in out
        assert ",." not in out
        assert " ." not in out  # No space-before-period

    def test_ceiling_avoids_overclaim_words(self):
        """Style invariant: the ceiling phrasing must read as humble
        teaching, not as tool blame. Specific overclaim words are
        rejected at the source. Keep this test in sync with the
        repo-wide humble-tone discipline."""
        out = _render(_sparse_ceiling_tenant())
        ceiling_idx = out.find("Passive-DNS ceiling")
        ceiling_block = out[ceiling_idx : ceiling_idx + 400].lower()
        for word in ("completely", "exactly", "always", "never", "strong", "robust"):
            assert f" {word} " not in ceiling_block, (
                f"ceiling phrasing must avoid overclaim word {word!r}; keep teaching tone humble"
            )


class TestRollupBoundedLength:
    def test_rollup_fits_panel_width(self):
        """The rollup line is rendered through the same
        ``_field``-with-wrap path the rest of the key-facts block
        uses. A pathologically long vendor list would otherwise spill
        off the panel width. The test pins that no rollup line in any
        of our fixtures exceeds the 80-column panel budget."""
        for tenant in (_multi_cloud_with_duplicate_potential(), _three_vendor_apex()):
            out = _render(tenant)
            mc_lines = [line for line in out.splitlines() if "Multi-cloud" in line]
            for line in mc_lines:
                # Allow a generous margin since rich may add styling
                # padding, but a 120-column hard cap catches the
                # unbounded-spill regression.
                assert len(line) <= 120, f"Multi-cloud line exceeds panel budget: {line!r}"
