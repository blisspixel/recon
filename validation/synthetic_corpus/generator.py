"""Synthetic-realistic TenantInfo corpus generator.

Generates ~20 TenantInfo JSON fixtures modeled after common public
stack shapes observed in defensive review. All apex names use the
Microsoft fictional brand convention (Contoso, Northwind, Fabrikam,
Adatum, Tailspin, Wingtip, Litware, Trey Research). No real
organizations are depicted.

The corpus exists so the v1.9.9 detection-gap UX surfaces (Multi-cloud
rollup, Passive-DNS ceiling) can be exercised against realistic stack
shapes rather than only the minimal unit-test fixtures. It is the
publicly-reproducible counterpart to the gitignored private corpus
under ``validation/corpus-private/``.

Run::

    python validation/synthetic_corpus/generator.py

Output: ``validation/synthetic_corpus/fixtures/<shape>.json`` for each
shape in the registry below. Re-running overwrites existing fixtures
deterministically (no randomness — each fixture is hand-curated for
its intended trigger behaviour).

The aggregator (``validation/corpus_aggregator.py``) can then be run
against these fixtures::

    python validation/corpus_aggregator.py \\
        validation/synthetic_corpus/results.json \\
        --output validation/synthetic_corpus/aggregate.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.cache import _CACHE_VERSION  # noqa: E402

OUTPUT_DIR = Path(__file__).resolve().parent / "fixtures"


def _base_tenant(**fields: Any) -> dict[str, Any]:
    """Default TenantInfo dict. Required fields are stubbed; overrides
    fill in the realistic shape."""
    base = {
        "cache_version": _CACHE_VERSION,
        "tenant_id": "synthetic",
        "display_name": "Contoso, Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": "high",
        "domain_count": 1,
        "tenant_domains": [],
        "services": [],
        "slugs": [],
        "sources": [],
        "surface_attributions": [],
    }
    base.update(fields)
    return base


def _surface_attrib(subdomain: str, slug: str, name: str, tier: str = "infrastructure") -> dict[str, Any]:
    return {
        "subdomain": subdomain,
        "primary_slug": slug,
        "primary_name": name,
        "primary_tier": tier,
    }


# ── Realistic stack shapes ─────────────────────────────────────────────


def m365_okta_enterprise() -> dict[str, Any]:
    """Mid-size enterprise on Microsoft 365 with Okta SSO. Common
    posture: 5+ tenant domains, M365 + Okta + Slack + Wiz, AWS-fronted
    SaaS subdomains."""
    return _base_tenant(
        tenant_id="contoso-mid",
        display_name="Contoso Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence="high",
        domain_count=7,
        tenant_domains=[
            "contoso.com",
            "contoso.net",
            "contoso.co.uk",
            "contoso-corp.com",
            "contoso-mail.com",
            "contoso.io",
            "contoso.eu",
        ],
        services=["Microsoft 365", "Okta", "Slack", "Wiz", "Cloudflare", "AWS CloudFront", "Atlassian"],
        slugs=["microsoft365", "okta", "slack", "wiz", "cloudflare", "aws-cloudfront", "atlassian"],
        surface_attributions=[
            _surface_attrib("api.contoso.com", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("app.contoso.com", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("status.contoso.com", "fastly", "Fastly"),
            _surface_attrib("support.contoso.com", "zendesk", "Zendesk", "application"),
        ],
    )


def google_workspace_aws_native() -> dict[str, Any]:
    """Google Workspace primary identity, AWS-native infrastructure.
    Common shape for engineering-heavy organizations."""
    return _base_tenant(
        tenant_id="northwind-eng",
        display_name="Northwind Traders",
        default_domain="northwind.com",
        queried_domain="northwind.com",
        confidence="high",
        domain_count=5,
        tenant_domains=["northwind.com", "northwind.net", "northwind.dev", "nw-corp.com", "nw-eng.io"],
        services=["Google Workspace", "AWS Route 53", "AWS CloudFront", "AWS S3", "GitHub", "Slack"],
        slugs=["googleworkspace", "aws-route53", "aws-cloudfront", "aws-s3", "github", "slack"],
        surface_attributions=[
            _surface_attrib("api.northwind.com", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("docs.northwind.com", "aws-s3", "AWS S3"),
            _surface_attrib("blog.northwind.com", "aws-cloudfront", "AWS CloudFront"),
        ],
    )


def multi_cloud_saas_heavy() -> dict[str, Any]:
    """A SaaS-heavy organization that touches three cloud vendors
    across apex + surface. Multi-cloud rollup should fire prominently."""
    return _base_tenant(
        tenant_id="fabrikam-saas",
        display_name="Fabrikam, Inc.",
        default_domain="fabrikam.com",
        queried_domain="fabrikam.com",
        confidence="high",
        domain_count=6,
        tenant_domains=[
            "fabrikam.com",
            "fabrikam.io",
            "fabrikam-cloud.com",
            "fabrikam.net",
            "fabrikam-eu.com",
            "fabrikam-jp.com",
        ],
        services=["Microsoft 365", "Cloudflare", "AWS CloudFront", "GCP Compute Engine", "Snowflake", "Slack"],
        slugs=["microsoft365", "cloudflare", "aws-cloudfront", "gcp-compute", "snowflake", "slack"],
        surface_attributions=[
            _surface_attrib("api.fabrikam.com", "fastly", "Fastly"),
            _surface_attrib("app.fabrikam.com", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("data.fabrikam.com", "snowflake", "Snowflake", "application"),
            _surface_attrib("ml.fabrikam.com", "gcp-compute", "GCP Compute Engine"),
            _surface_attrib("status.fabrikam.com", "atlassian", "Atlassian Statuspage", "application"),
        ],
    )


def hardened_minimal_dns() -> dict[str, Any]:
    """Hardened-target shape: many tenant domains, minimal public DNS,
    wildcard certs only. Ceiling footer should fire."""
    return _base_tenant(
        tenant_id="adatum-hard",
        display_name="Adatum Corporation",
        default_domain="adatum.com",
        queried_domain="adatum.com",
        confidence="low",
        domain_count=8,
        tenant_domains=[
            "adatum.com",
            "adatum.net",
            "adatum.co.uk",
            "adatum-corp.com",
            "adatum-secure.com",
            "adatum.eu",
            "adatum.jp",
            "adatum.au",
        ],
        services=["Cloudflare"],
        slugs=["cloudflare"],
    )


def gcp_native_startup() -> dict[str, Any]:
    """GCP-native startup. Firebase + GCP compute, single-cloud
    pattern. Multi-cloud rollup must NOT fire (all-GCP)."""
    return _base_tenant(
        tenant_id="tailspin-startup",
        display_name="Tailspin Toys",
        default_domain="tailspin.com",
        queried_domain="tailspin.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["tailspin.com", "tailspin.io", "tailspin-app.com"],
        services=["Google Workspace", "Firebase Hosting", "GCP Compute Engine", "GCP Cloud Functions"],
        slugs=["googleworkspace", "firebase-hosting", "gcp-compute", "gcp-cloud-functions"],
        surface_attributions=[
            _surface_attrib("app.tailspin.com", "firebase-hosting", "Firebase Hosting"),
            _surface_attrib("api.tailspin.com", "gcp-cloud-functions", "GCP Cloud Functions"),
        ],
    )


def azure_native_enterprise() -> dict[str, Any]:
    """Azure-native enterprise with Entra ID. Single-cloud Azure
    pattern. Multi-cloud rollup must NOT fire."""
    return _base_tenant(
        tenant_id="wingtip-azure",
        display_name="Wingtip Toys",
        default_domain="wingtip.com",
        queried_domain="wingtip.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["wingtip.com", "wingtip.net", "wingtip.eu", "wingtip-corp.com"],
        services=["Microsoft 365", "Azure DNS", "Azure CDN", "Azure App Service", "Azure Blob Storage"],
        slugs=["microsoft365", "azure-dns", "azure-cdn", "azure-appservice", "azure-blob"],
        surface_attributions=[
            _surface_attrib("api.wingtip.com", "azure-appservice", "Azure App Service"),
            _surface_attrib("cdn.wingtip.com", "azure-cdn", "Azure CDN"),
        ],
    )


def small_single_domain_org() -> dict[str, Any]:
    """A legitimately-small organization with one tenant domain.
    Ceiling footer must NOT fire (small org is not architecturally
    surprising)."""
    return _base_tenant(
        tenant_id="litware-small",
        display_name="Litware, Inc.",
        default_domain="litware.com",
        queried_domain="litware.com",
        confidence="high",
        domain_count=1,
        tenant_domains=["litware.com"],
        services=["Microsoft 365"],
        slugs=["microsoft365"],
    )


def saas_only_no_cloud() -> dict[str, Any]:
    """An organization detected via many SaaS slugs but no cloud
    infrastructure slugs. Multi-cloud rollup must NOT fire even
    though there are many distinct services."""
    return _base_tenant(
        tenant_id="treyresearch-saas",
        display_name="Trey Research",
        default_domain="treyresearch.com",
        queried_domain="treyresearch.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["treyresearch.com", "treyresearch.net", "trey-research.io"],
        services=["Microsoft 365", "Slack", "Atlassian", "Salesforce", "HubSpot"],
        slugs=["microsoft365", "slack", "atlassian", "salesforce", "hubspot"],
    )


def hybrid_dual_email() -> dict[str, Any]:
    """Dual-email-provider posture: Microsoft 365 + Google Workspace
    co-existence with mixed cloud footprint."""
    return _base_tenant(
        tenant_id="contoso-hybrid",
        display_name="Contoso Mergers",
        default_domain="contoso-merger.com",
        queried_domain="contoso-merger.com",
        confidence="medium",
        domain_count=6,
        tenant_domains=[
            "contoso-merger.com",
            "contoso.com",
            "contoso.net",
            "contoso-acquired.com",
            "merger-corp.com",
            "contoso-eu.com",
        ],
        services=["Microsoft 365", "Google Workspace", "Okta", "Proofpoint", "AWS Route 53", "Cloudflare"],
        slugs=["microsoft365", "googleworkspace", "okta", "proofpoint", "aws-route53", "cloudflare"],
        surface_attributions=[
            _surface_attrib("api.contoso-merger.com", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("sso.contoso-merger.com", "okta", "Okta", "application"),
        ],
    )


def cdn_fronted_minimal() -> dict[str, Any]:
    """An apex fronted by a CDN, minimal additional public footprint.
    Sparse but not multi-domain — neither v1.9.9 surface should fire
    prominently."""
    return _base_tenant(
        tenant_id="northwind-cdn",
        display_name="Northwind Boutique",
        default_domain="northwind-boutique.com",
        queried_domain="northwind-boutique.com",
        confidence="medium",
        domain_count=2,
        tenant_domains=["northwind-boutique.com", "northwind-shop.com"],
        services=["Cloudflare", "Shopify"],
        slugs=["cloudflare", "shopify"],
        surface_attributions=[
            _surface_attrib("shop.northwind-boutique.com", "shopify", "Shopify", "application"),
        ],
    )


def vercel_jamstack() -> dict[str, Any]:
    """Modern Jamstack: Vercel for the apex, GitHub for source,
    Cloudflare DNS. Multi-cloud rollup fires (Vercel + Cloudflare)."""
    return _base_tenant(
        tenant_id="fabrikam-jam",
        display_name="Fabrikam Marketing",
        default_domain="fabrikam-marketing.com",
        queried_domain="fabrikam-marketing.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["fabrikam-marketing.com", "fabrikam.io", "fabrikam-blog.com"],
        services=["Google Workspace", "Vercel", "Cloudflare", "GitHub", "Stripe"],
        slugs=["googleworkspace", "vercel", "cloudflare", "github", "stripe"],
        surface_attributions=[
            _surface_attrib("www.fabrikam-marketing.com", "vercel", "Vercel"),
            _surface_attrib("docs.fabrikam-marketing.com", "vercel", "Vercel"),
        ],
    )


def healthcare_compliance() -> dict[str, Any]:
    """Healthcare-vertical posture: M365 + heavy security stack,
    Cloudflare. Multi-cloud fires (AWS + Cloudflare). Ceiling does not
    fire (rich-stack)."""
    return _base_tenant(
        tenant_id="adatum-health",
        display_name="Adatum Health",
        default_domain="adatum-health.com",
        queried_domain="adatum-health.com",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "adatum-health.com",
            "adatum-care.com",
            "adatum-hospital.com",
            "adatum.health",
            "adatum-rx.com",
        ],
        services=[
            "Microsoft 365",
            "Okta",
            "Cloudflare",
            "AWS CloudFront",
            "Proofpoint",
            "Mimecast",
            "Wiz",
            "CrowdStrike",
        ],
        slugs=["microsoft365", "okta", "cloudflare", "aws-cloudfront", "proofpoint", "mimecast", "wiz", "crowdstrike"],
        surface_attributions=[
            _surface_attrib("patient.adatum-health.com", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("portal.adatum-health.com", "okta", "Okta", "application"),
        ],
    )


def public_sector_hardened() -> dict[str, Any]:
    """Government / public-sector hardened posture: GovCloud
    indicators, minimal public DNS, sparse evidence."""
    return _base_tenant(
        tenant_id="tailspin-gov",
        display_name="Tailspin Public Services",
        default_domain="tailspin-public.gov",
        queried_domain="tailspin-public.gov",
        confidence="low",
        domain_count=4,
        tenant_domains=["tailspin-public.gov", "tailspin-state.gov", "tailspin-services.gov", "tailspin-portal.gov"],
        services=["Microsoft 365", "AWS Route 53"],
        slugs=["microsoft365", "aws-route53"],
    )


def media_publisher_heavy_cdn() -> dict[str, Any]:
    """Media publisher with heavy CDN footprint. Multi-cloud fires
    (Fastly + Cloudflare + AWS)."""
    return _base_tenant(
        tenant_id="wingtip-media",
        display_name="Wingtip Media",
        default_domain="wingtip-media.com",
        queried_domain="wingtip-media.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["wingtip-media.com", "wingtip-news.com", "wingtip-tv.com", "wingtip-stream.com"],
        services=["Google Workspace", "Cloudflare", "Fastly", "AWS S3", "AWS CloudFront"],
        slugs=["googleworkspace", "cloudflare", "fastly", "aws-s3", "aws-cloudfront"],
        surface_attributions=[_surface_attrib(f"cdn{i}.wingtip-media.com", "fastly", "Fastly") for i in range(8)]
        + [
            _surface_attrib("video.wingtip-media.com", "aws-cloudfront", "AWS CloudFront"),
        ],
    )


def fintech_high_security() -> dict[str, Any]:
    """Fintech with heavy security and federated identity. Rich-stack;
    multi-cloud fires, ceiling does not."""
    return _base_tenant(
        tenant_id="litware-fin",
        display_name="Litware Capital",
        default_domain="litware-capital.com",
        queried_domain="litware-capital.com",
        confidence="high",
        domain_count=6,
        tenant_domains=[
            "litware-capital.com",
            "litware-banking.com",
            "litware-invest.com",
            "litware-trade.com",
            "litware-corp.com",
            "litware-secure.com",
        ],
        services=[
            "Microsoft 365",
            "Okta",
            "AWS CloudFront",
            "AWS Route 53",
            "Cloudflare",
            "Wiz",
            "CrowdStrike",
            "Proofpoint",
            "Snyk",
        ],
        slugs=[
            "microsoft365",
            "okta",
            "aws-cloudfront",
            "aws-route53",
            "cloudflare",
            "wiz",
            "crowdstrike",
            "proofpoint",
            "snyk",
        ],
        surface_attributions=[
            _surface_attrib("api.litware-capital.com", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("portal.litware-capital.com", "okta", "Okta", "application"),
            _surface_attrib("trade.litware-capital.com", "fastly", "Fastly"),
        ],
    )


def education_lms_heavy() -> dict[str, Any]:
    """Higher-ed posture: Canvas LMS + GWS + AWS. Multi-cloud rollup
    fires (AWS only — Canvas is not in the rollup map; this tests the
    SaaS-not-cloud discipline)."""
    return _base_tenant(
        tenant_id="trey-university",
        display_name="Trey University",
        default_domain="trey-university.edu",
        queried_domain="trey-university.edu",
        confidence="high",
        domain_count=5,
        tenant_domains=["trey-university.edu", "trey-u.edu", "trey-campus.edu", "trey-online.edu", "trey-alumni.edu"],
        services=["Google Workspace", "Canvas LMS", "AWS Route 53", "AWS CloudFront", "Zoom"],
        slugs=["googleworkspace", "canvas-lms", "aws-route53", "aws-cloudfront", "zoom"],
        surface_attributions=[
            _surface_attrib("learn.trey-university.edu", "canvas-lms", "Canvas LMS", "application"),
            _surface_attrib("portal.trey-university.edu", "aws-cloudfront", "AWS CloudFront"),
        ],
    )


def heroku_legacy_app() -> dict[str, Any]:
    """Heroku-hosted legacy application with Cloudflare DNS.
    Multi-cloud rollup must fire (Heroku + Cloudflare = 2 vendors)."""
    return _base_tenant(
        tenant_id="contoso-legacy",
        display_name="Contoso Legacy Apps",
        default_domain="contoso-legacy.com",
        queried_domain="contoso-legacy.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["contoso-legacy.com", "contoso-old.com", "legacy-contoso.net"],
        services=["Microsoft 365", "Heroku", "Cloudflare", "GitHub"],
        slugs=["microsoft365", "heroku", "cloudflare", "github"],
        surface_attributions=[
            _surface_attrib("app.contoso-legacy.com", "heroku", "Heroku", "application"),
        ],
    )


def empty_minimal() -> dict[str, Any]:
    """A degraded-lookup result: minimal data, no detected services.
    Tests that the renderer handles near-empty inputs without
    triggering any v1.9.9 surface."""
    return _base_tenant(
        tenant_id="northwind-min",
        display_name="Northwind Minimal",
        default_domain="northwind-min.com",
        queried_domain="northwind-min.com",
        confidence="low",
        domain_count=1,
        tenant_domains=["northwind-min.com"],
    )


def two_aws_slugs_one_vendor() -> dict[str, Any]:
    """AWS-only apex with multiple AWS-family slugs. Confirms
    canonicalization: Multi-cloud must NOT fire even with 4 slugs."""
    return _base_tenant(
        tenant_id="fabrikam-aws-only",
        display_name="Fabrikam Cloud Services",
        default_domain="fabrikam-cloud.com",
        queried_domain="fabrikam-cloud.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["fabrikam-cloud.com", "fabrikam.io", "fabrikam-cs.com"],
        services=["AWS Route 53", "AWS CloudFront", "AWS S3", "AWS EC2"],
        slugs=["aws-route53", "aws-cloudfront", "aws-s3", "aws-ec2"],
    )


# ── v1.9.10 stratified corpus expansion ───────────────────────────────
#
# Six cloud strata, ~10 fixtures each, brings the synthetic corpus to
# ~60 fixtures total for the v1.9.10 pre-lock validation. Each
# fixture is named with a ``stratum_<id>_<scenario>`` prefix so the
# per-stratum aggregator can group them automatically.
#
# Stratum mapping (matches the v1.9.10 roadmap quality bar):
#   gcp:       known-GCP customers
#   azure:     known-Azure non-O365 customers
#   oracle:    known-Oracle customers
#   alibaba:   known-Alibaba customers
#   paas:      known-PaaS / Vercel / Netlify customers
#   sse:       known-SSE/SASE-fronted customers
#
# All apex names use the Microsoft fictional brand convention. The
# scenarios within each stratum vary scale, identity, security stack,
# and surface attribution density to exercise the trigger discipline
# across realistic intra-stratum variation.

# Stratum: GCP


def stratum_gcp_pure_native() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-gcp-pure",
        display_name="Contoso Analytics",
        default_domain="contoso-analytics.com",
        queried_domain="contoso-analytics.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["contoso-analytics.com", "contoso-data.com", "contoso-ml.com", "contoso-bi.com"],
        services=["Google Workspace", "Firebase Hosting", "GCP Compute Engine", "GCP Cloud Functions", "GCP Storage"],
        slugs=["googleworkspace", "firebase-hosting", "gcp-compute", "gcp-cloud-functions", "gcp-storage"],
    )


def stratum_gcp_with_okta() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-gcp-okta",
        display_name="Northwind Engineering",
        default_domain="northwind-eng.com",
        queried_domain="northwind-eng.com",
        confidence="high",
        domain_count=5,
        tenant_domains=["northwind-eng.com", "northwind.dev", "northwind-prod.com", "nw-eng.io", "nw-stage.com"],
        services=["Google Workspace", "Okta", "GCP Compute Engine", "GCP Storage", "Cloudflare"],
        slugs=["googleworkspace", "okta", "gcp-compute", "gcp-storage", "cloudflare"],
        surface_attributions=[
            _surface_attrib("api.northwind-eng.com", "gcp-compute", "GCP Compute Engine"),
            _surface_attrib("portal.northwind-eng.com", "okta", "Okta", "application"),
        ],
    )


def stratum_gcp_with_security_stack() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="fabrikam-gcp-sec",
        display_name="Fabrikam Cloud Security",
        default_domain="fabrikam-cs.com",
        queried_domain="fabrikam-cs.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["fabrikam-cs.com", "fabrikam-soc.com", "fabrikam-ir.com", "fabrikam-vuln.com"],
        services=["Google Workspace", "GCP Compute Engine", "GCP Storage", "Wiz", "CrowdStrike", "Snyk"],
        slugs=["googleworkspace", "gcp-compute", "gcp-storage", "wiz", "crowdstrike", "snyk"],
    )


def stratum_gcp_apigee_heavy() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="adatum-gcp-apigee",
        display_name="Adatum API Platform",
        default_domain="adatum-api.com",
        queried_domain="adatum-api.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["adatum-api.com", "adatum-gateway.com", "adatum-services.com"],
        services=["Google Workspace", "Apigee", "GCP Compute Engine", "GCP Cloud Functions"],
        slugs=["googleworkspace", "apigee", "gcp-compute", "gcp-cloud-functions"],
        surface_attributions=[
            _surface_attrib("api.adatum-api.com", "apigee", "Apigee", "application"),
            _surface_attrib("v2.adatum-api.com", "apigee", "Apigee", "application"),
        ],
    )


def stratum_gcp_firebase_only() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="tailspin-firebase",
        display_name="Tailspin Mobile",
        default_domain="tailspin-mobile.com",
        queried_domain="tailspin-mobile.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["tailspin-mobile.com", "tailspin-app.com", "tailspin-api.com"],
        services=["Google Workspace", "Firebase Hosting", "Firebase Realtime Database"],
        slugs=["googleworkspace", "firebase-hosting", "firebase-realtime"],
        surface_attributions=[
            _surface_attrib("app.tailspin-mobile.com", "firebase-hosting", "Firebase Hosting"),
            _surface_attrib("api.tailspin-mobile.com", "firebase-realtime", "Firebase Realtime"),
        ],
    )


def stratum_gcp_minimal_hardened() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="wingtip-gcp-min",
        display_name="Wingtip GCP Hardened",
        default_domain="wingtip-secure.com",
        queried_domain="wingtip-secure.com",
        confidence="low",
        domain_count=4,
        tenant_domains=["wingtip-secure.com", "wingtip-prod.com", "wingtip-internal.com", "wingtip-corp.com"],
        services=["GCP DNS"],
        slugs=["gcp-dns"],
    )


def stratum_gcp_dual_with_aws() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="litware-gcp-aws",
        display_name="Litware Multi-Cloud",
        default_domain="litware-mc.com",
        queried_domain="litware-mc.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["litware-mc.com", "litware-east.com", "litware-west.com", "litware-eu.com"],
        services=["Google Workspace", "GCP Compute Engine", "AWS S3", "AWS CloudFront"],
        slugs=["googleworkspace", "gcp-compute", "aws-s3", "aws-cloudfront"],
        surface_attributions=[
            _surface_attrib("backup.litware-mc.com", "aws-s3", "AWS S3"),
            _surface_attrib("static.litware-mc.com", "aws-cloudfront", "AWS CloudFront"),
        ],
    )


def stratum_gcp_data_pipeline() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="trey-gcp-data",
        display_name="Trey Data Sciences",
        default_domain="trey-data.com",
        queried_domain="trey-data.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["trey-data.com", "trey-bi.com", "trey-ml.com"],
        services=["Google Workspace", "GCP Compute Engine", "GCP Storage", "Snowflake", "Databricks"],
        slugs=["googleworkspace", "gcp-compute", "gcp-storage", "snowflake", "databricks"],
    )


def stratum_gcp_cloud_run_modern() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-gcp-cr",
        display_name="Contoso Modern Stack",
        default_domain="contoso-modern.com",
        queried_domain="contoso-modern.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["contoso-modern.com", "contoso-app.com", "contoso-stage.com"],
        services=["Google Workspace", "GCP Cloud Functions", "Firebase Hosting", "Cloudflare"],
        slugs=["googleworkspace", "gcp-cloud-functions", "firebase-hosting", "cloudflare"],
        surface_attributions=[
            _surface_attrib("app.contoso-modern.com", "firebase-hosting", "Firebase Hosting"),
        ],
    )


def stratum_gcp_idp_heavy() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-gcp-idp",
        display_name="Northwind GCP IdP",
        default_domain="northwind-idp.com",
        queried_domain="northwind-idp.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["northwind-idp.com", "northwind-sso.com", "northwind-id.com", "northwind-auth.com"],
        services=["Google Workspace", "Okta", "GCP Compute Engine", "Auth0"],
        slugs=["googleworkspace", "okta", "gcp-compute", "auth0"],
        surface_attributions=[
            _surface_attrib("sso.northwind-idp.com", "okta", "Okta", "application"),
            _surface_attrib("login.northwind-idp.com", "auth0", "Auth0", "application"),
        ],
    )


# Stratum: Azure non-O365


def stratum_azure_native_no_m365() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-az-noM365",
        display_name="Contoso Azure Native",
        default_domain="contoso-az.com",
        queried_domain="contoso-az.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["contoso-az.com", "contoso-azure.com", "contoso-eastus.com", "contoso-eu.com"],
        services=["Google Workspace", "Azure DNS", "Azure App Service", "Azure CDN", "Azure Blob Storage"],
        slugs=["googleworkspace", "azure-dns", "azure-appservice", "azure-cdn", "azure-blob"],
        surface_attributions=[
            _surface_attrib("api.contoso-az.com", "azure-appservice", "Azure App Service"),
            _surface_attrib("static.contoso-az.com", "azure-cdn", "Azure CDN"),
        ],
    )


def stratum_azure_with_okta_sso() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-az-okta",
        display_name="Northwind Azure SSO",
        default_domain="northwind-az.com",
        queried_domain="northwind-az.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["northwind-az.com", "nw-az-east.com", "nw-az-west.com", "nw-az-eu.com"],
        services=["Google Workspace", "Okta", "Azure DNS", "Azure App Service", "Azure Front Door"],
        slugs=["googleworkspace", "okta", "azure-dns", "azure-appservice", "azure-fd"],
    )


def stratum_azure_static_web_apps() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="fabrikam-az-swa",
        display_name="Fabrikam SWA Sites",
        default_domain="fabrikam-swa.com",
        queried_domain="fabrikam-swa.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["fabrikam-swa.com", "fabrikam-marketing.com", "fabrikam-blog.com"],
        services=["Google Workspace", "Azure DNS", "Azure Static Web Apps"],
        slugs=["googleworkspace", "azure-dns", "azure-static-web-apps"],
        surface_attributions=[
            _surface_attrib("www.fabrikam-swa.com", "azure-static-web-apps", "Azure Static Web Apps"),
        ],
    )


def stratum_azure_with_proofpoint() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="adatum-az-pp",
        display_name="Adatum Azure with Proofpoint",
        default_domain="adatum-az.com",
        queried_domain="adatum-az.com",
        confidence="high",
        domain_count=5,
        tenant_domains=["adatum-az.com", "adatum-azure.com", "adatum-cloud.com", "adatum-corp.com", "adatum-eu.com"],
        services=["Google Workspace", "Proofpoint", "Azure DNS", "Azure App Service", "Azure Container Apps"],
        slugs=["googleworkspace", "proofpoint", "azure-dns", "azure-appservice", "azure-container-apps"],
    )


def stratum_azure_govcloud() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="tailspin-az-gov",
        display_name="Tailspin Government Cloud",
        default_domain="tailspin-gov.gov",
        queried_domain="tailspin-gov.gov",
        confidence="medium",
        domain_count=4,
        tenant_domains=["tailspin-gov.gov", "tailspin-state.gov", "tailspin-fed.gov", "tailspin-portal.gov"],
        services=["Microsoft 365", "Azure DNS", "Azure App Service"],
        slugs=["microsoft365", "azure-dns", "azure-appservice"],
    )


def stratum_azure_minimal() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="wingtip-az-min",
        display_name="Wingtip Azure Minimal",
        default_domain="wingtip-az.com",
        queried_domain="wingtip-az.com",
        confidence="low",
        domain_count=4,
        tenant_domains=["wingtip-az.com", "wingtip-prod.com", "wingtip-staging.com", "wingtip-internal.com"],
        services=["Azure DNS"],
        slugs=["azure-dns"],
    )


def stratum_azure_with_databricks() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="litware-az-db",
        display_name="Litware Azure Analytics",
        default_domain="litware-an.com",
        queried_domain="litware-an.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["litware-an.com", "litware-data.com", "litware-bi.com", "litware-ml.com"],
        services=["Google Workspace", "Azure DNS", "Azure App Service", "Databricks", "Snowflake"],
        slugs=["googleworkspace", "azure-dns", "azure-appservice", "databricks", "snowflake"],
    )


def stratum_azure_dual_cloud() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="trey-az-aws",
        display_name="Trey Azure-AWS Dual",
        default_domain="trey-dual.com",
        queried_domain="trey-dual.com",
        confidence="high",
        domain_count=5,
        tenant_domains=["trey-dual.com", "trey-east.com", "trey-west.com", "trey-eu.com", "trey-corp.com"],
        services=["Microsoft 365", "Azure App Service", "AWS S3", "AWS CloudFront", "Cloudflare"],
        slugs=["microsoft365", "azure-appservice", "aws-s3", "aws-cloudfront", "cloudflare"],
        surface_attributions=[
            _surface_attrib("static.trey-dual.com", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("eu.trey-dual.com", "azure-appservice", "Azure App Service"),
        ],
    )


def stratum_azure_api_management() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-az-apim",
        display_name="Contoso Azure APIs",
        default_domain="contoso-apim.com",
        queried_domain="contoso-apim.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["contoso-apim.com", "contoso-gateway.com", "contoso-svc.com"],
        services=["Google Workspace", "Azure DNS", "Azure API Management", "Azure App Service"],
        slugs=["googleworkspace", "azure-dns", "azure-api-management", "azure-appservice"],
        surface_attributions=[
            _surface_attrib("api.contoso-apim.com", "azure-api-management", "Azure API Management"),
        ],
    )


def stratum_azure_idp_managed() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="adatum-az-idp",
        display_name="Adatum Azure IdP",
        default_domain="adatum-idp.com",
        queried_domain="adatum-idp.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["adatum-idp.com", "adatum-sso.com", "adatum-mfa.com", "adatum-portal.com"],
        services=["Microsoft 365", "Azure DNS", "Azure App Service", "Auth0"],
        slugs=["microsoft365", "azure-dns", "azure-appservice", "auth0"],
        surface_attributions=[
            _surface_attrib("login.adatum-idp.com", "auth0", "Auth0", "application"),
        ],
    )


# Stratum: Oracle


def stratum_oracle_fusion_apps() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-oracle-fusion",
        display_name="Contoso Oracle Fusion",
        default_domain="contoso-erp.com",
        queried_domain="contoso-erp.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["contoso-erp.com", "contoso-hcm.com", "contoso-fin.com", "contoso-corp.com"],
        services=["Microsoft 365", "Oracle Fusion ERP", "Oracle Cloud", "Okta"],
        slugs=["microsoft365", "oracle-fusion", "oracle-cloud", "okta"],
    )


def stratum_oracle_oci_only() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-oci",
        display_name="Northwind OCI",
        default_domain="northwind-oci.com",
        queried_domain="northwind-oci.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["northwind-oci.com", "northwind-cloud.com", "northwind-svc.com"],
        services=["Google Workspace", "Oracle Cloud", "Cloudflare"],
        slugs=["googleworkspace", "oracle-cloud", "cloudflare"],
    )


def stratum_oracle_with_legacy() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="fabrikam-oracle-legacy",
        display_name="Fabrikam Oracle Hybrid",
        default_domain="fabrikam-oracle.com",
        queried_domain="fabrikam-oracle.com",
        confidence="medium",
        domain_count=5,
        tenant_domains=[
            "fabrikam-oracle.com",
            "fabrikam-erp.com",
            "fabrikam-hcm.com",
            "fabrikam-corp.com",
            "fabrikam-legacy.com",
        ],
        services=["Microsoft 365", "Oracle Fusion ERP", "Oracle Cloud", "Proofpoint"],
        slugs=["microsoft365", "oracle-fusion", "oracle-cloud", "proofpoint"],
    )


def stratum_oracle_apex_dev() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="adatum-oracle-apex",
        display_name="Adatum Oracle APEX",
        default_domain="adatum-apex.com",
        queried_domain="adatum-apex.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["adatum-apex.com", "adatum-dev.com", "adatum-app.com"],
        services=["Google Workspace", "Oracle Cloud"],
        slugs=["googleworkspace", "oracle-cloud"],
    )


def stratum_oracle_minimal() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="tailspin-oracle-min",
        display_name="Tailspin Oracle Minimal",
        default_domain="tailspin-oracle.com",
        queried_domain="tailspin-oracle.com",
        confidence="low",
        domain_count=3,
        tenant_domains=["tailspin-oracle.com", "tailspin-erp.com", "tailspin-corp.com"],
        services=["Oracle Cloud"],
        slugs=["oracle-cloud"],
    )


def stratum_oracle_dual_with_aws() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="wingtip-oracle-aws",
        display_name="Wingtip Oracle-AWS Dual",
        default_domain="wingtip-oracle-aws.com",
        queried_domain="wingtip-oracle-aws.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["wingtip-oracle-aws.com", "wingtip-erp.com", "wingtip-aws.com", "wingtip-eu.com"],
        services=["Microsoft 365", "Oracle Fusion ERP", "Oracle Cloud", "AWS S3", "AWS CloudFront"],
        slugs=["microsoft365", "oracle-fusion", "oracle-cloud", "aws-s3", "aws-cloudfront"],
    )


def stratum_oracle_with_security() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="litware-oracle-sec",
        display_name="Litware Oracle Secured",
        default_domain="litware-oracle.com",
        queried_domain="litware-oracle.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["litware-oracle.com", "litware-erp.com", "litware-fin.com", "litware-soc.com"],
        services=["Microsoft 365", "Oracle Cloud", "Okta", "Wiz", "CrowdStrike"],
        slugs=["microsoft365", "oracle-cloud", "okta", "wiz", "crowdstrike"],
    )


def stratum_oracle_global() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="trey-oracle-global",
        display_name="Trey Oracle Global",
        default_domain="trey-oracle.com",
        queried_domain="trey-oracle.com",
        confidence="high",
        domain_count=6,
        tenant_domains=[
            "trey-oracle.com",
            "trey-eu.com",
            "trey-jp.com",
            "trey-au.com",
            "trey-br.com",
            "trey-corp.com",
        ],
        services=["Google Workspace", "Oracle Cloud", "Oracle Fusion ERP", "Cloudflare"],
        slugs=["googleworkspace", "oracle-cloud", "oracle-fusion", "cloudflare"],
    )


def stratum_oracle_idp_with_okta() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-oracle-okta",
        display_name="Contoso Oracle Identity",
        default_domain="contoso-oid.com",
        queried_domain="contoso-oid.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["contoso-oid.com", "contoso-sso.com", "contoso-fed.com", "contoso-corp.com"],
        services=["Google Workspace", "Okta", "Oracle Cloud"],
        slugs=["googleworkspace", "okta", "oracle-cloud"],
        surface_attributions=[
            _surface_attrib("sso.contoso-oid.com", "okta", "Okta", "application"),
        ],
    )


def stratum_oracle_with_apex_only() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-oracle-bare",
        display_name="Northwind Oracle Bare",
        default_domain="northwind-or.com",
        queried_domain="northwind-or.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["northwind-or.com", "northwind-svc.com", "northwind-internal.com"],
        services=["Oracle Cloud"],
        slugs=["oracle-cloud"],
    )


# Stratum: Alibaba


def stratum_alibaba_native() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-ali",
        display_name="Contoso Alibaba",
        default_domain="contoso-ali.com",
        queried_domain="contoso-ali.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["contoso-ali.com", "contoso-cn.com", "contoso-apac.com", "contoso-corp.com"],
        services=["Google Workspace", "Alibaba Cloud", "Alibaba CDN"],
        slugs=["googleworkspace", "alibaba-cloud", "alibaba-cdn"],
        surface_attributions=[
            _surface_attrib("cdn.contoso-ali.com", "alibaba-cdn", "Alibaba CDN"),
        ],
    )


def stratum_alibaba_global() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-ali",
        display_name="Northwind Alibaba Global",
        default_domain="northwind-ali.com",
        queried_domain="northwind-ali.com",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "northwind-ali.com",
            "northwind-cn.com",
            "northwind-jp.com",
            "northwind-sg.com",
            "northwind-corp.com",
        ],
        services=["Google Workspace", "Alibaba Cloud", "Alibaba API", "Alibaba CDN"],
        slugs=["googleworkspace", "alibaba-cloud", "alibaba-api", "alibaba-cdn"],
    )


def stratum_alibaba_with_security() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="fabrikam-ali",
        display_name="Fabrikam Alibaba Secured",
        default_domain="fabrikam-ali.com",
        queried_domain="fabrikam-ali.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["fabrikam-ali.com", "fabrikam-cn.com", "fabrikam-corp.com"],
        services=["Microsoft 365", "Alibaba Cloud", "Wiz"],
        slugs=["microsoft365", "alibaba-cloud", "wiz"],
    )


def stratum_alibaba_minimal() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="adatum-ali-min",
        display_name="Adatum Alibaba Minimal",
        default_domain="adatum-ali.com",
        queried_domain="adatum-ali.com",
        confidence="low",
        domain_count=3,
        tenant_domains=["adatum-ali.com", "adatum-cn.com", "adatum-corp.com"],
        services=["Alibaba Cloud"],
        slugs=["alibaba-cloud"],
    )


def stratum_alibaba_dual_with_aws() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="tailspin-ali-aws",
        display_name="Tailspin Alibaba-AWS",
        default_domain="tailspin-ali-aws.com",
        queried_domain="tailspin-ali-aws.com",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "tailspin-ali-aws.com",
            "tailspin-cn.com",
            "tailspin-us.com",
            "tailspin-eu.com",
            "tailspin-corp.com",
        ],
        services=["Microsoft 365", "Alibaba Cloud", "Alibaba CDN", "AWS S3", "AWS CloudFront"],
        slugs=["microsoft365", "alibaba-cloud", "alibaba-cdn", "aws-s3", "aws-cloudfront"],
    )


def stratum_alibaba_ecommerce() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="wingtip-ali-shop",
        display_name="Wingtip Alibaba Commerce",
        default_domain="wingtip-shop.com",
        queried_domain="wingtip-shop.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["wingtip-shop.com", "wingtip-cn.com", "wingtip-store.com", "wingtip-corp.com"],
        services=["Google Workspace", "Alibaba Cloud", "Alibaba CDN"],
        slugs=["googleworkspace", "alibaba-cloud", "alibaba-cdn"],
        surface_attributions=[
            _surface_attrib("shop.wingtip-shop.com", "alibaba-cdn", "Alibaba CDN"),
            _surface_attrib("store.wingtip-shop.com", "alibaba-cdn", "Alibaba CDN"),
        ],
    )


def stratum_alibaba_with_oss() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="litware-ali-oss",
        display_name="Litware Alibaba OSS",
        default_domain="litware-ali.com",
        queried_domain="litware-ali.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["litware-ali.com", "litware-cn.com", "litware-storage.com"],
        services=["Microsoft 365", "Alibaba Cloud"],
        slugs=["microsoft365", "alibaba-cloud"],
    )


def stratum_alibaba_with_apim() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="trey-ali-api",
        display_name="Trey Alibaba API",
        default_domain="trey-ali-api.com",
        queried_domain="trey-ali-api.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["trey-ali-api.com", "trey-cn-api.com", "trey-svc.com"],
        services=["Google Workspace", "Alibaba Cloud", "Alibaba API"],
        slugs=["googleworkspace", "alibaba-cloud", "alibaba-api"],
        surface_attributions=[
            _surface_attrib("api.trey-ali-api.com", "alibaba-api", "Alibaba API"),
        ],
    )


def stratum_alibaba_minimal_cdn() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-ali-cdn-only",
        display_name="Contoso Alibaba CDN Only",
        default_domain="contoso-acdn.com",
        queried_domain="contoso-acdn.com",
        confidence="low",
        domain_count=3,
        tenant_domains=["contoso-acdn.com", "contoso-static.com", "contoso-svc.com"],
        services=["Alibaba CDN"],
        slugs=["alibaba-cdn"],
    )


def stratum_alibaba_with_dingtalk_proxy() -> dict[str, Any]:
    """Alibaba customer with collaboration via Slack (DingTalk
    not in catalog)."""
    return _base_tenant(
        tenant_id="northwind-ali-dt",
        display_name="Northwind Alibaba Collab",
        default_domain="northwind-ad.com",
        queried_domain="northwind-ad.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["northwind-ad.com", "northwind-cn-team.com", "northwind-collab.com", "northwind-corp.com"],
        services=["Microsoft 365", "Alibaba Cloud", "Slack"],
        slugs=["microsoft365", "alibaba-cloud", "slack"],
    )


# Stratum: PaaS / Vercel / Netlify


def stratum_paas_vercel_full() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-paas-vc",
        display_name="Contoso Vercel Stack",
        default_domain="contoso-vc.com",
        queried_domain="contoso-vc.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["contoso-vc.com", "contoso-app.com", "contoso-blog.com"],
        services=["Google Workspace", "Vercel", "Cloudflare", "GitHub"],
        slugs=["googleworkspace", "vercel", "cloudflare", "github"],
        surface_attributions=[
            _surface_attrib("www.contoso-vc.com", "vercel", "Vercel"),
            _surface_attrib("app.contoso-vc.com", "vercel", "Vercel"),
        ],
    )


def stratum_paas_netlify_jamstack() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-paas-nl",
        display_name="Northwind Netlify",
        default_domain="northwind-nl.com",
        queried_domain="northwind-nl.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["northwind-nl.com", "northwind-marketing.com", "northwind-docs.com"],
        services=["Google Workspace", "Netlify", "Cloudflare"],
        slugs=["googleworkspace", "netlify", "cloudflare"],
        surface_attributions=[
            _surface_attrib("www.northwind-nl.com", "netlify", "Netlify"),
            _surface_attrib("docs.northwind-nl.com", "netlify", "Netlify"),
        ],
    )


def stratum_paas_vercel_with_auth0() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="fabrikam-paas-auth",
        display_name="Fabrikam Vercel + Auth0",
        default_domain="fabrikam-vc.com",
        queried_domain="fabrikam-vc.com",
        confidence="high",
        domain_count=3,
        tenant_domains=["fabrikam-vc.com", "fabrikam-app.com", "fabrikam-id.com"],
        services=["Google Workspace", "Vercel", "Auth0", "Cloudflare"],
        slugs=["googleworkspace", "vercel", "auth0", "cloudflare"],
        surface_attributions=[
            _surface_attrib("login.fabrikam-vc.com", "auth0", "Auth0", "application"),
        ],
    )


def stratum_paas_railway_app() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="adatum-paas-rw",
        display_name="Adatum Railway",
        default_domain="adatum-rw.com",
        queried_domain="adatum-rw.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["adatum-rw.com", "adatum-app.com", "adatum-api.com"],
        services=["Google Workspace", "Railway", "Cloudflare"],
        slugs=["googleworkspace", "railway", "cloudflare"],
        surface_attributions=[
            _surface_attrib("api.adatum-rw.com", "railway", "Railway"),
        ],
    )


def stratum_paas_render_app() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="tailspin-paas-rd",
        display_name="Tailspin Render",
        default_domain="tailspin-rd.com",
        queried_domain="tailspin-rd.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["tailspin-rd.com", "tailspin-app.com", "tailspin-svc.com"],
        services=["Google Workspace", "Render", "Cloudflare"],
        slugs=["googleworkspace", "render", "cloudflare"],
    )


def stratum_paas_flyio_distributed() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="wingtip-paas-fly",
        display_name="Wingtip Fly.io",
        default_domain="wingtip-fly.com",
        queried_domain="wingtip-fly.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["wingtip-fly.com", "wingtip-edge.com", "wingtip-app.com"],
        services=["Google Workspace", "Fly.io", "Cloudflare"],
        slugs=["googleworkspace", "flyio", "cloudflare"],
    )


def stratum_paas_vercel_minimal() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="litware-paas-vc-min",
        display_name="Litware Vercel Minimal",
        default_domain="litware-vc.com",
        queried_domain="litware-vc.com",
        confidence="low",
        domain_count=3,
        tenant_domains=["litware-vc.com", "litware-blog.com", "litware-corp.com"],
        services=["Vercel"],
        slugs=["vercel"],
    )


def stratum_paas_netlify_minimal() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="trey-paas-nl-min",
        display_name="Trey Netlify Minimal",
        default_domain="trey-nl.com",
        queried_domain="trey-nl.com",
        confidence="low",
        domain_count=3,
        tenant_domains=["trey-nl.com", "trey-blog.com", "trey-corp.com"],
        services=["Netlify"],
        slugs=["netlify"],
    )


def stratum_paas_cloudflare_pages() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-paas-cfp",
        display_name="Contoso Cloudflare Pages",
        default_domain="contoso-cfp.com",
        queried_domain="contoso-cfp.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["contoso-cfp.com", "contoso-pages.com", "contoso-app.com"],
        services=["Google Workspace", "Cloudflare", "Cloudflare Pages"],
        slugs=["googleworkspace", "cloudflare", "cloudflare-pages"],
        surface_attributions=[
            _surface_attrib("www.contoso-cfp.com", "cloudflare-pages", "Cloudflare Pages"),
        ],
    )


def stratum_paas_multi_paas() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-paas-multi",
        display_name="Northwind Multi-PaaS",
        default_domain="northwind-mp.com",
        queried_domain="northwind-mp.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["northwind-mp.com", "northwind-vc.com", "northwind-nl.com", "northwind-corp.com"],
        services=["Google Workspace", "Vercel", "Netlify", "Cloudflare"],
        slugs=["googleworkspace", "vercel", "netlify", "cloudflare"],
    )


# Stratum: SSE / SASE


def stratum_sse_zscaler_fronted() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-sse-zs",
        display_name="Contoso Zscaler",
        default_domain="contoso-zs.com",
        queried_domain="contoso-zs.com",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "contoso-zs.com",
            "contoso-portal.com",
            "contoso-svc.com",
            "contoso-corp.com",
            "contoso-eu.com",
        ],
        services=["Microsoft 365", "Zscaler", "AWS Route 53"],
        slugs=["microsoft365", "zscaler", "aws-route53"],
    )


def stratum_sse_netskope_fronted() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-sse-ns",
        display_name="Northwind Netskope",
        default_domain="northwind-ns.com",
        queried_domain="northwind-ns.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["northwind-ns.com", "northwind-cloud.com", "northwind-corp.com", "northwind-eu.com"],
        services=["Microsoft 365", "Netskope", "Cloudflare"],
        slugs=["microsoft365", "netskope", "cloudflare"],
    )


def stratum_sse_cloudflare_one() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="fabrikam-sse-cf1",
        display_name="Fabrikam Cloudflare One",
        default_domain="fabrikam-cf1.com",
        queried_domain="fabrikam-cf1.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["fabrikam-cf1.com", "fabrikam-zt.com", "fabrikam-portal.com", "fabrikam-corp.com"],
        services=["Microsoft 365", "Cloudflare", "Okta"],
        slugs=["microsoft365", "cloudflare", "okta"],
    )


def stratum_sse_prisma_access() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="adatum-sse-pa",
        display_name="Adatum Prisma Access",
        default_domain="adatum-pa.com",
        queried_domain="adatum-pa.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["adatum-pa.com", "adatum-zt.com", "adatum-portal.com", "adatum-corp.com"],
        services=["Microsoft 365", "Prisma Access", "Palo Alto Networks"],
        slugs=["microsoft365", "prisma-access", "paloalto"],
    )


def stratum_sse_cato_sase() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="tailspin-sse-cato",
        display_name="Tailspin Cato SASE",
        default_domain="tailspin-cato.com",
        queried_domain="tailspin-cato.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["tailspin-cato.com", "tailspin-sase.com", "tailspin-portal.com", "tailspin-corp.com"],
        services=["Microsoft 365", "Cato Networks", "AWS Route 53"],
        slugs=["microsoft365", "cato-networks", "aws-route53"],
    )


def stratum_sse_minimal_zscaler() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="wingtip-sse-zs-min",
        display_name="Wingtip Zscaler Minimal",
        default_domain="wingtip-zs.com",
        queried_domain="wingtip-zs.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["wingtip-zs.com", "wingtip-corp.com", "wingtip-eu.com"],
        services=["Microsoft 365", "Zscaler"],
        slugs=["microsoft365", "zscaler"],
    )


def stratum_sse_dual_sse() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="litware-sse-dual",
        display_name="Litware Dual SSE",
        default_domain="litware-dse.com",
        queried_domain="litware-dse.com",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "litware-dse.com",
            "litware-zt.com",
            "litware-sase.com",
            "litware-portal.com",
            "litware-corp.com",
        ],
        services=["Microsoft 365", "Zscaler", "Netskope", "Cloudflare"],
        slugs=["microsoft365", "zscaler", "netskope", "cloudflare"],
    )


def stratum_sse_with_okta_sso() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="trey-sse-okta",
        display_name="Trey SSE + Okta",
        default_domain="trey-sse.com",
        queried_domain="trey-sse.com",
        confidence="high",
        domain_count=4,
        tenant_domains=["trey-sse.com", "trey-zt.com", "trey-sso.com", "trey-corp.com"],
        services=["Microsoft 365", "Zscaler", "Okta"],
        slugs=["microsoft365", "zscaler", "okta"],
        surface_attributions=[
            _surface_attrib("sso.trey-sse.com", "okta", "Okta", "application"),
        ],
    )


def stratum_sse_paloalto_only() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="contoso-sse-pa-only",
        display_name="Contoso PA Only",
        default_domain="contoso-pa.com",
        queried_domain="contoso-pa.com",
        confidence="medium",
        domain_count=3,
        tenant_domains=["contoso-pa.com", "contoso-firewall.com", "contoso-corp.com"],
        services=["Microsoft 365", "Palo Alto Networks"],
        slugs=["microsoft365", "paloalto"],
    )


def stratum_sse_government() -> dict[str, Any]:
    return _base_tenant(
        tenant_id="northwind-sse-gov",
        display_name="Northwind Government SASE",
        default_domain="northwind-gov.gov",
        queried_domain="northwind-gov.gov",
        confidence="high",
        domain_count=4,
        tenant_domains=["northwind-gov.gov", "northwind-fed.gov", "northwind-state.gov", "northwind-portal.gov"],
        services=["Microsoft 365", "Zscaler", "Palo Alto Networks"],
        slugs=["microsoft365", "zscaler", "paloalto"],
    )


# ── Registry and runner ────────────────────────────────────────────────


REGISTRY: dict[str, Any] = {
    # v1.9.9 base corpus (19 fixtures, mixed strata)
    "m365_okta_enterprise": m365_okta_enterprise,
    "google_workspace_aws_native": google_workspace_aws_native,
    "multi_cloud_saas_heavy": multi_cloud_saas_heavy,
    "hardened_minimal_dns": hardened_minimal_dns,
    "gcp_native_startup": gcp_native_startup,
    "azure_native_enterprise": azure_native_enterprise,
    "small_single_domain_org": small_single_domain_org,
    "saas_only_no_cloud": saas_only_no_cloud,
    "hybrid_dual_email": hybrid_dual_email,
    "cdn_fronted_minimal": cdn_fronted_minimal,
    "vercel_jamstack": vercel_jamstack,
    "healthcare_compliance": healthcare_compliance,
    "public_sector_hardened": public_sector_hardened,
    "media_publisher_heavy_cdn": media_publisher_heavy_cdn,
    "fintech_high_security": fintech_high_security,
    "education_lms_heavy": education_lms_heavy,
    "heroku_legacy_app": heroku_legacy_app,
    "empty_minimal": empty_minimal,
    "two_aws_slugs_one_vendor": two_aws_slugs_one_vendor,
    # v1.9.10 stratified expansion — Stratum: GCP
    "stratum_gcp_pure_native": stratum_gcp_pure_native,
    "stratum_gcp_with_okta": stratum_gcp_with_okta,
    "stratum_gcp_with_security_stack": stratum_gcp_with_security_stack,
    "stratum_gcp_apigee_heavy": stratum_gcp_apigee_heavy,
    "stratum_gcp_firebase_only": stratum_gcp_firebase_only,
    "stratum_gcp_minimal_hardened": stratum_gcp_minimal_hardened,
    "stratum_gcp_dual_with_aws": stratum_gcp_dual_with_aws,
    "stratum_gcp_data_pipeline": stratum_gcp_data_pipeline,
    "stratum_gcp_cloud_run_modern": stratum_gcp_cloud_run_modern,
    "stratum_gcp_idp_heavy": stratum_gcp_idp_heavy,
    # Stratum: Azure non-O365
    "stratum_azure_native_no_m365": stratum_azure_native_no_m365,
    "stratum_azure_with_okta_sso": stratum_azure_with_okta_sso,
    "stratum_azure_static_web_apps": stratum_azure_static_web_apps,
    "stratum_azure_with_proofpoint": stratum_azure_with_proofpoint,
    "stratum_azure_govcloud": stratum_azure_govcloud,
    "stratum_azure_minimal": stratum_azure_minimal,
    "stratum_azure_with_databricks": stratum_azure_with_databricks,
    "stratum_azure_dual_cloud": stratum_azure_dual_cloud,
    "stratum_azure_api_management": stratum_azure_api_management,
    "stratum_azure_idp_managed": stratum_azure_idp_managed,
    # Stratum: Oracle
    "stratum_oracle_fusion_apps": stratum_oracle_fusion_apps,
    "stratum_oracle_oci_only": stratum_oracle_oci_only,
    "stratum_oracle_with_legacy": stratum_oracle_with_legacy,
    "stratum_oracle_apex_dev": stratum_oracle_apex_dev,
    "stratum_oracle_minimal": stratum_oracle_minimal,
    "stratum_oracle_dual_with_aws": stratum_oracle_dual_with_aws,
    "stratum_oracle_with_security": stratum_oracle_with_security,
    "stratum_oracle_global": stratum_oracle_global,
    "stratum_oracle_idp_with_okta": stratum_oracle_idp_with_okta,
    "stratum_oracle_with_apex_only": stratum_oracle_with_apex_only,
    # Stratum: Alibaba
    "stratum_alibaba_native": stratum_alibaba_native,
    "stratum_alibaba_global": stratum_alibaba_global,
    "stratum_alibaba_with_security": stratum_alibaba_with_security,
    "stratum_alibaba_minimal": stratum_alibaba_minimal,
    "stratum_alibaba_dual_with_aws": stratum_alibaba_dual_with_aws,
    "stratum_alibaba_ecommerce": stratum_alibaba_ecommerce,
    "stratum_alibaba_with_oss": stratum_alibaba_with_oss,
    "stratum_alibaba_with_apim": stratum_alibaba_with_apim,
    "stratum_alibaba_minimal_cdn": stratum_alibaba_minimal_cdn,
    "stratum_alibaba_with_dingtalk_proxy": stratum_alibaba_with_dingtalk_proxy,
    # Stratum: PaaS / Vercel / Netlify
    "stratum_paas_vercel_full": stratum_paas_vercel_full,
    "stratum_paas_netlify_jamstack": stratum_paas_netlify_jamstack,
    "stratum_paas_vercel_with_auth0": stratum_paas_vercel_with_auth0,
    "stratum_paas_railway_app": stratum_paas_railway_app,
    "stratum_paas_render_app": stratum_paas_render_app,
    "stratum_paas_flyio_distributed": stratum_paas_flyio_distributed,
    "stratum_paas_vercel_minimal": stratum_paas_vercel_minimal,
    "stratum_paas_netlify_minimal": stratum_paas_netlify_minimal,
    "stratum_paas_cloudflare_pages": stratum_paas_cloudflare_pages,
    "stratum_paas_multi_paas": stratum_paas_multi_paas,
    # Stratum: SSE / SASE
    "stratum_sse_zscaler_fronted": stratum_sse_zscaler_fronted,
    "stratum_sse_netskope_fronted": stratum_sse_netskope_fronted,
    "stratum_sse_cloudflare_one": stratum_sse_cloudflare_one,
    "stratum_sse_prisma_access": stratum_sse_prisma_access,
    "stratum_sse_cato_sase": stratum_sse_cato_sase,
    "stratum_sse_minimal_zscaler": stratum_sse_minimal_zscaler,
    "stratum_sse_dual_sse": stratum_sse_dual_sse,
    "stratum_sse_with_okta_sso": stratum_sse_with_okta_sso,
    "stratum_sse_paloalto_only": stratum_sse_paloalto_only,
    "stratum_sse_government": stratum_sse_government,
}


# Canonical stratum names matched by ``_stratum_from_registry_key`` below.
# Listed long-form to longest-match-first so ``alibaba`` is preferred over
# any incidental ``ali`` substring.
_STRATUM_NAMES: tuple[str, ...] = ("alibaba", "oracle", "azure", "paas", "sse", "gcp")


def _stratum_from_registry_key(registry_key: str) -> str:
    """Derive the stratum from the REGISTRY key.

    The REGISTRY key is the authoritative grouping signal: stratum
    fixtures use the ``stratum_<id>_<scenario>`` convention and base-
    corpus fixtures do not. Bucketing from ``tenant_id`` was the
    v1.9.10 design, and a v1.9.11 audit found it was unreliable
    because several stratum fixtures use brand-style tenant_ids
    (``tailspin-firebase`` for GCP, ``northwind-oci`` for Oracle)
    that lack the substring marker the aggregator was scanning for.
    Deriving from the registry key removes that ambiguity entirely.
    """
    if not registry_key.startswith("stratum_"):
        return "baseline"
    suffix = registry_key[len("stratum_") :]
    for name in _STRATUM_NAMES:
        if suffix.startswith(name + "_") or suffix == name:
            return name
    return "baseline"


def _tag(registry_key: str, fixture: dict[str, Any]) -> dict[str, Any]:
    """Inject the authoritative ``_stratum`` tag and return the fixture.

    Mutates a copy rather than the caller's dict so re-running the
    generator stays deterministic and side-effect-free per builder.
    The tag prefix ``_`` keeps the field out of any TenantInfo
    deserialization path (``recon_tool.cache.tenant_info_from_dict``
    ignores fields it does not recognize).
    """
    tagged = dict(fixture)
    tagged["_stratum"] = _stratum_from_registry_key(registry_key)
    return tagged


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, builder in REGISTRY.items():
        fixture = _tag(name, builder())
        path = OUTPUT_DIR / f"{name}.json"
        path.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.name}")

    # Also emit a single combined results.json for the aggregator.
    combined = [_tag(name, builder()) for name, builder in REGISTRY.items()]
    combined_path = Path(__file__).resolve().parent / "results.json"
    combined_path.write_text(json.dumps(combined, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {combined_path.name} ({len(combined)} fixtures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
