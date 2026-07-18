"""Apex-level multi-cloud rollup indicator.

The default panel grew a one-line ``Multi-cloud`` indicator that fires
when the apex's public footprint touches more than one canonical cloud
vendor. The per-slug Cloud row and per-subdomain Subdomain row already
expose the full distribution; the rollup is the at-a-glance summary so
an operator immediately sees ``AWS + Cloudflare + GCP`` without reading
two later sections.

These tests pin the rollup's two contracts:

  * Vendor canonicalization: sibling slugs (e.g. ``aws-route53`` and
    ``aws-cloudfront``) collapse to a single ``AWS`` vote. The rollup
    counts vendors, not slugs.
  * Trigger discipline: fires on ≥ 2 distinct vendors; stays silent on
    a single-cloud apex so the panel does not gain a vacuous row.
"""

from __future__ import annotations

from rich.console import Console

from recon_tool.formatter import (
    canonical_cloud_vendor,
    count_cloud_vendors,
    render_tenant_panel,
)
from recon_tool.models import ConfidenceLevel, EvidenceRecord, SurfaceAttribution, TenantInfo


def _render_to_string(info: TenantInfo) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info)
    console.print(rendered)
    return console.export_text()


def _tenant(**overrides: object) -> TenantInfo:
    base: dict[str, object] = {
        "tenant_id": "tid",
        "display_name": "Synthetic Alpha, Ltd",
        "default_domain": "alpha.invalid",
        "queried_domain": "alpha.invalid",
        "confidence": ConfidenceLevel.HIGH,
        "domain_count": 4,
    }
    base.update(overrides)
    return TenantInfo(**base)  # type: ignore[arg-type]


class TestCanonicalCloudVendor:
    def test_aws_family_collapses_to_aws(self):
        assert canonical_cloud_vendor("aws-route53") == "AWS"
        assert canonical_cloud_vendor("aws-cloudfront") == "AWS"
        assert canonical_cloud_vendor("aws-ec2") == "AWS"
        assert canonical_cloud_vendor("aws-s3") == "AWS"

    def test_azure_family_collapses_to_azure(self):
        assert canonical_cloud_vendor("azure-dns") == "Azure"
        assert canonical_cloud_vendor("azure-cdn") == "Azure"
        assert canonical_cloud_vendor("azure-appservice") == "Azure"

    def test_gcp_includes_firebase(self):
        """Firebase is part of GCP for rollup purposes; otherwise a
        Firebase-only apex would read as a separate vendor from a GCP
        compute apex, which doesn't match how operators think about the
        Google cloud footprint."""
        assert canonical_cloud_vendor("gcp-compute") == "GCP"
        assert canonical_cloud_vendor("firebase-hosting") == "GCP"
        assert canonical_cloud_vendor("firebase-realtime") == "GCP"

    def test_alibaba_family_collapses(self):
        assert canonical_cloud_vendor("alibaba-api") == "Alibaba Cloud"
        assert canonical_cloud_vendor("alibaba-cdn") == "Alibaba Cloud"

    def test_standalone_vendors_keep_identity(self):
        assert canonical_cloud_vendor("cloudflare") == "Cloudflare"
        assert canonical_cloud_vendor("fastly") == "Fastly"
        assert canonical_cloud_vendor("akamai") == "Akamai"
        assert canonical_cloud_vendor("vercel") == "Vercel"
        assert canonical_cloud_vendor("supabase") == "Supabase"

    def test_non_cloud_slug_returns_none(self):
        """A non-cloud slug must not pretend to be a cloud vendor.
        The rollup explicitly excludes things like Slack or Auth0
        because they are SaaS, not cloud infrastructure."""
        assert canonical_cloud_vendor("slack") is None
        assert canonical_cloud_vendor("auth0") is None
        assert canonical_cloud_vendor("nonexistent-slug-xyz") is None


class TestCountCloudVendors:
    def test_two_aws_slugs_count_as_one_vendor(self):
        counts = count_cloud_vendors(("aws-route53", "aws-cloudfront"))
        assert counts == {"AWS": 2}

    def test_multi_vendor_apex(self):
        counts = count_cloud_vendors(("aws-route53", "cloudflare", "gcp-compute"))
        assert counts == {"AWS": 1, "Cloudflare": 1, "GCP": 1}

    def test_apex_and_surface_streams_merge(self):
        counts = count_cloud_vendors(
            apex_slugs=("aws-route53",),
            surface_slugs=("aws-cloudfront", "fastly"),
        )
        assert counts == {"AWS": 2, "Fastly": 1}

    def test_non_cloud_slugs_dropped_silently(self):
        counts = count_cloud_vendors(("aws-route53", "slack", "auth0"))
        assert counts == {"AWS": 1}

    def test_ns_and_caa_roles_do_not_count_as_cloud_workloads(self):
        evidence = (
            EvidenceRecord("NS", "ns-1.awsdns.example", "AWS Route 53", "aws-route53"),
            EvidenceRecord("CAA", '0 issue "amazon.com"', "CAA: AWS Certificate Manager", "aws-acm"),
        )

        counts = count_cloud_vendors(
            ("aws-route53", "aws-acm"),
            apex_evidence=evidence,
        )

        assert counts == {}

    def test_cname_role_counts_as_a_cloud_endpoint_binding(self):
        evidence = (EvidenceRecord("CNAME", "www.alpha.invalid -> edge.cloudflare.net", "Cloudflare", "cloudflare"),)

        counts = count_cloud_vendors(("cloudflare",), apex_evidence=evidence)

        assert counts == {"Cloudflare": 1}

    def test_caa_only_slug_never_counts_as_a_cloud_workload(self):
        counts = count_cloud_vendors(("aws-acm", "cloudflare"))

        assert counts == {"Cloudflare": 1}

    def test_explicitly_empty_evidence_excludes_untyped_apex_slugs(self):
        counts = count_cloud_vendors(("aws-route53", "cloudflare"), apex_evidence=())

        assert counts == {}


class TestRollupRenderingFires:
    def test_multi_cloud_apex_renders_rollup(self):
        info = _tenant(
            services=("AWS CloudFront", "Cloudflare", "GCP Compute Engine"),
            slugs=("aws-cloudfront", "cloudflare", "gcp-compute"),
            evidence=(
                EvidenceRecord("CNAME", "www -> cloudfront.net", "AWS CloudFront", "aws-cloudfront"),
                EvidenceRecord("CNAME", "edge -> cloudflare.net", "Cloudflare", "cloudflare"),
                EvidenceRecord("A", "192.0.2.1 -> googleusercontent.com", "GCP Compute Engine", "gcp-compute"),
            ),
        )
        out = _render_to_string(info)
        assert "Multi-cloud" in out
        assert "3 providers observed" in out

    def test_rollup_lists_vendor_labels(self):
        info = _tenant(
            services=("AWS CloudFront", "Cloudflare"),
            slugs=("aws-cloudfront", "cloudflare"),
            evidence=(
                EvidenceRecord("CNAME", "www -> cloudfront.net", "AWS CloudFront", "aws-cloudfront"),
                EvidenceRecord("CNAME", "edge -> cloudflare.net", "Cloudflare", "cloudflare"),
            ),
        )
        out = _render_to_string(info)
        assert "AWS" in out
        assert "Cloudflare" in out

    def test_apex_aws_with_subdomain_fastly_fires(self):
        """The rollup must count surface_attributions, not just apex
        slugs. An AWS-fronted apex with Fastly-fronted subdomains is
        the canonical multi-cloud case the rollup was added for."""
        info = _tenant(
            services=("AWS CloudFront",),
            slugs=("aws-cloudfront",),
            evidence=(EvidenceRecord("CNAME", "www -> cloudfront.net", "AWS CloudFront", "aws-cloudfront"),),
            surface_attributions=(
                SurfaceAttribution(
                    subdomain="api.alpha.invalid",
                    primary_slug="fastly",
                    primary_name="Fastly",
                    primary_tier="infrastructure",
                ),
            ),
        )
        out = _render_to_string(info)
        assert "Multi-cloud" in out


class TestRollupSuppressed:
    def test_legacy_cloudflare_and_route53_do_not_create_a_role_based_rollup(self):
        info = _tenant(
            services=("AWS Route 53", "Cloudflare"),
            slugs=("aws-route53", "cloudflare"),
            evidence=(),
        )

        out = _render_to_string(info)

        assert "Multi-cloud" not in out
        assert "AWS Route 53 (role unavailable)" in out
        assert "Cloudflare (role unavailable)" in out

    def test_ns_only_vendors_do_not_create_a_multi_cloud_workload_claim(self):
        info = _tenant(
            services=("AWS Route 53", "Cloudflare"),
            slugs=("aws-route53", "cloudflare"),
            evidence=(
                EvidenceRecord("NS", "ns-1.awsdns.example", "AWS Route 53", "aws-route53"),
                EvidenceRecord("NS", "ns1.cloudflare.example", "Cloudflare", "cloudflare"),
            ),
        )

        out = _render_to_string(info)

        assert "Multi-cloud" not in out
        assert "AWS Route 53 (DNS)" in out
        assert "Cloudflare (DNS)" in out

    def test_txt_cloudflare_and_ns_route53_do_not_create_multi_cloud_claim(self):
        info = _tenant(
            services=("AWS Route 53", "Cloudflare"),
            slugs=("aws-route53", "cloudflare"),
            evidence=(
                EvidenceRecord("NS", "ns-1.awsdns.example", "AWS Route 53", "aws-route53"),
                EvidenceRecord("TXT", "cloudflare-verify=opaque", "Cloudflare", "cloudflare"),
            ),
        )

        out = _render_to_string(info)

        assert "Multi-cloud" not in out
        assert "Cloudflare (public TXT account indicator)" in out

    def test_caa_authorization_does_not_create_a_multi_cloud_workload_claim(self):
        info = _tenant(
            services=("CAA: AWS Certificate Manager", "Cloudflare"),
            slugs=("aws-acm", "cloudflare"),
            evidence=(
                EvidenceRecord("CAA", '0 issue "amazon.com"', "CAA: AWS Certificate Manager", "aws-acm"),
                EvidenceRecord("CNAME", "www.alpha.invalid -> edge.cloudflare.net", "Cloudflare", "cloudflare"),
            ),
        )

        out = _render_to_string(info)

        assert "Multi-cloud" not in out
        assert "CAA: Amazon authorized" in out

    def test_single_vendor_apex_no_rollup(self):
        """A pure-AWS apex must not gain a Multi-cloud row; the row
        would read as vacuous and waste a panel line."""
        info = _tenant(
            services=("AWS CloudFront", "AWS Route 53"),
            slugs=("aws-cloudfront", "aws-route53"),
        )
        out = _render_to_string(info)
        assert "Multi-cloud" not in out

    def test_no_cloud_slugs_no_rollup(self):
        """An apex whose detected slugs are all SaaS (Slack, Auth0)
        and contain no cloud-vendor slugs should not render the
        Multi-cloud row even though there are many distinct services."""
        info = _tenant(
            services=("Slack", "Auth0", "Atlassian"),
            slugs=("slack", "auth0", "atlassian"),
        )
        out = _render_to_string(info)
        assert "Multi-cloud" not in out

    def test_aws_route53_and_aws_cloudfront_no_rollup(self):
        """Two slugs from the same vendor family collapse — the row
        must not fire because the canonicalized vendor count is 1."""
        info = _tenant(
            services=("AWS Route 53", "AWS CloudFront", "AWS S3"),
            slugs=("aws-route53", "aws-cloudfront", "aws-s3"),
        )
        out = _render_to_string(info)
        assert "Multi-cloud" not in out
