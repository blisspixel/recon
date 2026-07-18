"""Synthetic-realistic TenantInfo corpus generator.

Generates TenantInfo JSON fixtures modeled after common public stack
shapes observed in defensive review. Every target identity is an
explicit synthetic sentinel under the reserved ``.invalid`` namespace.
No real or company-shaped target identity is retained.

The corpus exists so the v1.9.9 detection-gap UX surfaces (Multi-cloud
rollup, Passive-DNS ceiling) can be exercised against realistic stack
shapes rather than only the minimal unit-test fixtures. It is the
publicly-reproducible counterpart to the gitignored private corpus
under ``validation/corpus-private/``.

Run::

    python validation/synthetic_corpus/generator.py

Output: ``validation/synthetic_corpus/fixtures/<shape>.json`` for each
shape in the registry below. Re-running overwrites existing fixtures
deterministically (no randomness - each fixture is hand-curated for
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
from hashlib import sha256
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

OUTPUT_DIR = Path(__file__).resolve().parent / "fixtures"
FIXTURE_CACHE_VERSION = 1


def _base_tenant(**fields: Any) -> dict[str, Any]:
    """Build a realistic shape; ``_tag`` adds its public identity fields."""
    base = {
        "cache_version": FIXTURE_CACHE_VERSION,
        "default_domain": "synthetic-alpha-com.invalid",
        "queried_domain": "synthetic-alpha-com.invalid",
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
        default_domain="synthetic-alpha-com.invalid",
        queried_domain="synthetic-alpha-com.invalid",
        confidence="high",
        domain_count=7,
        tenant_domains=[
            "synthetic-alpha-com.invalid",
            "synthetic-alpha-net.invalid",
            "synthetic-alpha-co-uk.invalid",
            "synthetic-alpha-corp-com.invalid",
            "synthetic-alpha-mail-com.invalid",
            "synthetic-alpha-io.invalid",
            "synthetic-alpha-eu.invalid",
        ],
        services=["Microsoft 365", "Okta", "Slack", "Wiz", "Cloudflare", "AWS CloudFront", "Atlassian"],
        slugs=["microsoft365", "okta", "slack", "wiz", "cloudflare", "aws-cloudfront", "atlassian"],
        surface_attributions=[
            _surface_attrib("api.synthetic-alpha-com.invalid", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("app.synthetic-alpha-com.invalid", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("status.synthetic-alpha-com.invalid", "fastly", "Fastly"),
            _surface_attrib("support.synthetic-alpha-com.invalid", "zendesk", "Zendesk", "application"),
        ],
    )


def google_workspace_aws_native() -> dict[str, Any]:
    """Google Workspace primary identity, AWS-native infrastructure.
    Common shape for engineering-heavy organizations."""
    return _base_tenant(
        default_domain="synthetic-beta-com.invalid",
        queried_domain="synthetic-beta-com.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-beta-com.invalid",
            "synthetic-beta-net.invalid",
            "synthetic-beta-dev.invalid",
            "synthetic-beta-corp-com.invalid",
            "synthetic-beta-eng-io.invalid",
        ],
        services=["Google Workspace", "AWS Route 53", "AWS CloudFront", "AWS S3", "GitHub", "Slack"],
        slugs=["googleworkspace", "aws-route53", "aws-cloudfront", "aws-s3", "github", "slack"],
        surface_attributions=[
            _surface_attrib("api.synthetic-beta-com.invalid", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("docs.synthetic-beta-com.invalid", "aws-s3", "AWS S3"),
            _surface_attrib("blog.synthetic-beta-com.invalid", "aws-cloudfront", "AWS CloudFront"),
        ],
    )


def multi_cloud_saas_heavy() -> dict[str, Any]:
    """A SaaS-heavy organization that touches three cloud vendors
    across apex + surface. Multi-cloud rollup should fire prominently."""
    return _base_tenant(
        default_domain="synthetic-gamma-com.invalid",
        queried_domain="synthetic-gamma-com.invalid",
        confidence="high",
        domain_count=6,
        tenant_domains=[
            "synthetic-gamma-com.invalid",
            "synthetic-gamma-io.invalid",
            "synthetic-gamma-cloud-com.invalid",
            "synthetic-gamma-net.invalid",
            "synthetic-gamma-eu-com.invalid",
            "synthetic-gamma-jp-com.invalid",
        ],
        services=["Microsoft 365", "Cloudflare", "AWS CloudFront", "GCP Compute Engine", "Snowflake", "Slack"],
        slugs=["microsoft365", "cloudflare", "aws-cloudfront", "gcp-compute", "snowflake", "slack"],
        surface_attributions=[
            _surface_attrib("api.synthetic-gamma-com.invalid", "fastly", "Fastly"),
            _surface_attrib("app.synthetic-gamma-com.invalid", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("data.synthetic-gamma-com.invalid", "snowflake", "Snowflake", "application"),
            _surface_attrib("ml.synthetic-gamma-com.invalid", "gcp-compute", "GCP Compute Engine"),
            _surface_attrib("status.synthetic-gamma-com.invalid", "atlassian", "Atlassian Statuspage", "application"),
        ],
    )


def hardened_minimal_dns() -> dict[str, Any]:
    """Hardened-target shape: many tenant domains, minimal public DNS,
    wildcard certs only. Ceiling footer should fire."""
    return _base_tenant(
        default_domain="synthetic-delta-com.invalid",
        queried_domain="synthetic-delta-com.invalid",
        confidence="low",
        domain_count=8,
        tenant_domains=[
            "synthetic-delta-com.invalid",
            "synthetic-delta-net.invalid",
            "synthetic-delta-co-uk.invalid",
            "synthetic-delta-corp-com.invalid",
            "synthetic-delta-secure-com.invalid",
            "synthetic-delta-eu.invalid",
            "synthetic-delta-jp.invalid",
            "synthetic-delta-au.invalid",
        ],
        services=["Cloudflare"],
        slugs=["cloudflare"],
    )


def gcp_native_startup() -> dict[str, Any]:
    """GCP-native startup. Firebase + GCP compute, single-cloud
    pattern. Multi-cloud rollup must NOT fire (all-GCP)."""
    return _base_tenant(
        default_domain="synthetic-epsilon-com.invalid",
        queried_domain="synthetic-epsilon-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-epsilon-com.invalid",
            "synthetic-epsilon-io.invalid",
            "synthetic-epsilon-app-com.invalid",
        ],
        services=["Google Workspace", "Firebase Hosting", "GCP Compute Engine", "GCP Cloud Functions"],
        slugs=["googleworkspace", "firebase-hosting", "gcp-compute", "gcp-cloud-functions"],
        surface_attributions=[
            _surface_attrib("app.synthetic-epsilon-com.invalid", "firebase-hosting", "Firebase Hosting"),
            _surface_attrib("api.synthetic-epsilon-com.invalid", "gcp-cloud-functions", "GCP Cloud Functions"),
        ],
    )


def azure_native_enterprise() -> dict[str, Any]:
    """Azure-native enterprise with Entra ID. Single-cloud Azure
    pattern. Multi-cloud rollup must NOT fire."""
    return _base_tenant(
        default_domain="synthetic-zeta-com.invalid",
        queried_domain="synthetic-zeta-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-zeta-com.invalid",
            "synthetic-zeta-net.invalid",
            "synthetic-zeta-eu.invalid",
            "synthetic-zeta-corp-com.invalid",
        ],
        services=["Microsoft 365", "Azure DNS", "Azure CDN", "Azure App Service", "Azure Blob Storage"],
        slugs=["microsoft365", "azure-dns", "azure-cdn", "azure-appservice", "azure-blob"],
        surface_attributions=[
            _surface_attrib("api.synthetic-zeta-com.invalid", "azure-appservice", "Azure App Service"),
            _surface_attrib("cdn.synthetic-zeta-com.invalid", "azure-cdn", "Azure CDN"),
        ],
    )


def small_single_domain_org() -> dict[str, Any]:
    """A legitimately-small organization with one tenant domain.
    Ceiling footer must NOT fire (small org is not architecturally
    surprising)."""
    return _base_tenant(
        default_domain="synthetic-eta-com.invalid",
        queried_domain="synthetic-eta-com.invalid",
        confidence="high",
        domain_count=1,
        tenant_domains=["synthetic-eta-com.invalid"],
        services=["Microsoft 365"],
        slugs=["microsoft365"],
    )


def saas_only_no_cloud() -> dict[str, Any]:
    """An organization detected via many SaaS slugs but no cloud
    infrastructure slugs. Multi-cloud rollup must NOT fire even
    though there are many distinct services."""
    return _base_tenant(
        default_domain="synthetic-theta-research-com.invalid",
        queried_domain="synthetic-theta-research-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-theta-research-com.invalid",
            "synthetic-theta-research-net.invalid",
            "synthetic-theta-research-io.invalid",
        ],
        services=["Microsoft 365", "Slack", "Atlassian", "Salesforce", "HubSpot"],
        slugs=["microsoft365", "slack", "atlassian", "salesforce", "hubspot"],
    )


def hybrid_dual_email() -> dict[str, Any]:
    """Dual-email-provider posture: Microsoft 365 + Google Workspace
    co-existence with mixed cloud footprint."""
    return _base_tenant(
        default_domain="synthetic-alpha-merger-com.invalid",
        queried_domain="synthetic-alpha-merger-com.invalid",
        confidence="medium",
        domain_count=6,
        tenant_domains=[
            "synthetic-alpha-merger-com.invalid",
            "synthetic-alpha-com.invalid",
            "synthetic-alpha-net.invalid",
            "synthetic-alpha-acquired-com.invalid",
            "synthetic-merger-corp-com.invalid",
            "synthetic-alpha-eu-com.invalid",
        ],
        services=["Microsoft 365", "Google Workspace", "Okta", "Proofpoint", "AWS Route 53", "Cloudflare"],
        slugs=["microsoft365", "googleworkspace", "okta", "proofpoint", "aws-route53", "cloudflare"],
        surface_attributions=[
            _surface_attrib("api.synthetic-alpha-merger-com.invalid", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("sso.synthetic-alpha-merger-com.invalid", "okta", "Okta", "application"),
        ],
    )


def cdn_fronted_minimal() -> dict[str, Any]:
    """An apex fronted by a CDN, minimal additional public footprint.
    Sparse but not multi-domain - neither v1.9.9 surface should fire
    prominently."""
    return _base_tenant(
        default_domain="synthetic-beta-boutique-com.invalid",
        queried_domain="synthetic-beta-boutique-com.invalid",
        confidence="medium",
        domain_count=2,
        tenant_domains=["synthetic-beta-boutique-com.invalid", "synthetic-beta-shop-com.invalid"],
        services=["Cloudflare", "Shopify"],
        slugs=["cloudflare", "shopify"],
        surface_attributions=[
            _surface_attrib("shop.synthetic-beta-boutique-com.invalid", "shopify", "Shopify", "application"),
        ],
    )


def vercel_jamstack() -> dict[str, Any]:
    """Modern Jamstack: Vercel for the apex, GitHub for source,
    Cloudflare DNS. Multi-cloud rollup fires (Vercel + Cloudflare)."""
    return _base_tenant(
        default_domain="synthetic-gamma-marketing-com.invalid",
        queried_domain="synthetic-gamma-marketing-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-gamma-marketing-com.invalid",
            "synthetic-gamma-io.invalid",
            "synthetic-gamma-blog-com.invalid",
        ],
        services=["Google Workspace", "Vercel", "Cloudflare", "GitHub", "Stripe"],
        slugs=["googleworkspace", "vercel", "cloudflare", "github", "stripe"],
        surface_attributions=[
            _surface_attrib("www.synthetic-gamma-marketing-com.invalid", "vercel", "Vercel"),
            _surface_attrib("docs.synthetic-gamma-marketing-com.invalid", "vercel", "Vercel"),
        ],
    )


def healthcare_compliance() -> dict[str, Any]:
    """Healthcare-vertical posture: M365 + heavy security stack,
    Cloudflare. Multi-cloud fires (AWS + Cloudflare). Ceiling does not
    fire (rich-stack)."""
    return _base_tenant(
        default_domain="synthetic-delta-health-com.invalid",
        queried_domain="synthetic-delta-health-com.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-delta-health-com.invalid",
            "synthetic-delta-care-com.invalid",
            "synthetic-delta-hospital-com.invalid",
            "synthetic-delta-health.invalid",
            "synthetic-delta-rx-com.invalid",
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
            _surface_attrib("patient.synthetic-delta-health-com.invalid", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("portal.synthetic-delta-health-com.invalid", "okta", "Okta", "application"),
        ],
    )


def public_sector_hardened() -> dict[str, Any]:
    """Government / public-sector hardened posture: GovCloud
    indicators, minimal public DNS, sparse evidence."""
    return _base_tenant(
        default_domain="synthetic-epsilon-public-gov.invalid",
        queried_domain="synthetic-epsilon-public-gov.invalid",
        confidence="low",
        domain_count=4,
        tenant_domains=[
            "synthetic-epsilon-public-gov.invalid",
            "synthetic-epsilon-state-gov.invalid",
            "synthetic-epsilon-services-gov.invalid",
            "synthetic-epsilon-portal-gov.invalid",
        ],
        services=["Microsoft 365", "AWS Route 53"],
        slugs=["microsoft365", "aws-route53"],
    )


def media_publisher_heavy_cdn() -> dict[str, Any]:
    """Media publisher with heavy CDN footprint. Multi-cloud fires
    (Fastly + Cloudflare + AWS)."""
    return _base_tenant(
        default_domain="synthetic-zeta-media-com.invalid",
        queried_domain="synthetic-zeta-media-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-zeta-media-com.invalid",
            "synthetic-zeta-news-com.invalid",
            "synthetic-zeta-tv-com.invalid",
            "synthetic-zeta-stream-com.invalid",
        ],
        services=["Google Workspace", "Cloudflare", "Fastly", "AWS S3", "AWS CloudFront"],
        slugs=["googleworkspace", "cloudflare", "fastly", "aws-s3", "aws-cloudfront"],
        surface_attributions=[
            _surface_attrib(f"cdn{i}.synthetic-zeta-media-com.invalid", "fastly", "Fastly") for i in range(8)
        ]
        + [
            _surface_attrib("video.synthetic-zeta-media-com.invalid", "aws-cloudfront", "AWS CloudFront"),
        ],
    )


def fintech_high_security() -> dict[str, Any]:
    """Fintech with heavy security and federated identity. Rich-stack;
    multi-cloud fires, ceiling does not."""
    return _base_tenant(
        default_domain="synthetic-eta-capital-com.invalid",
        queried_domain="synthetic-eta-capital-com.invalid",
        confidence="high",
        domain_count=6,
        tenant_domains=[
            "synthetic-eta-capital-com.invalid",
            "synthetic-eta-banking-com.invalid",
            "synthetic-eta-invest-com.invalid",
            "synthetic-eta-trade-com.invalid",
            "synthetic-eta-corp-com.invalid",
            "synthetic-eta-secure-com.invalid",
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
            _surface_attrib("api.synthetic-eta-capital-com.invalid", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("portal.synthetic-eta-capital-com.invalid", "okta", "Okta", "application"),
            _surface_attrib("trade.synthetic-eta-capital-com.invalid", "fastly", "Fastly"),
        ],
    )


def education_lms_heavy() -> dict[str, Any]:
    """Higher-ed posture: Canvas LMS + GWS + AWS. Multi-cloud rollup
    fires (AWS only - Canvas is not in the rollup map; this tests the
    SaaS-not-cloud discipline)."""
    return _base_tenant(
        default_domain="synthetic-theta-university-edu.invalid",
        queried_domain="synthetic-theta-university-edu.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-theta-university-edu.invalid",
            "synthetic-theta-u-edu.invalid",
            "synthetic-theta-campus-edu.invalid",
            "synthetic-theta-online-edu.invalid",
            "synthetic-theta-alumni-edu.invalid",
        ],
        services=["Google Workspace", "Canvas LMS", "AWS Route 53", "AWS CloudFront", "Zoom"],
        slugs=["googleworkspace", "canvas-lms", "aws-route53", "aws-cloudfront", "zoom"],
        surface_attributions=[
            _surface_attrib("learn.synthetic-theta-university-edu.invalid", "canvas-lms", "Canvas LMS", "application"),
            _surface_attrib("portal.synthetic-theta-university-edu.invalid", "aws-cloudfront", "AWS CloudFront"),
        ],
    )


def heroku_legacy_app() -> dict[str, Any]:
    """Heroku-hosted legacy application with Cloudflare DNS.
    Multi-cloud rollup must fire (Heroku + Cloudflare = 2 vendors)."""
    return _base_tenant(
        default_domain="synthetic-alpha-legacy-com.invalid",
        queried_domain="synthetic-alpha-legacy-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-alpha-legacy-com.invalid",
            "synthetic-alpha-old-com.invalid",
            "legacy-synthetic-alpha-net.invalid",
        ],
        services=["Microsoft 365", "Heroku", "Cloudflare", "GitHub"],
        slugs=["microsoft365", "heroku", "cloudflare", "github"],
        surface_attributions=[
            _surface_attrib("app.synthetic-alpha-legacy-com.invalid", "heroku", "Heroku", "application"),
        ],
    )


def empty_minimal() -> dict[str, Any]:
    """A degraded-lookup result: minimal data, no detected services.
    Tests that the renderer handles near-empty inputs without
    triggering any v1.9.9 surface."""
    return _base_tenant(
        default_domain="synthetic-beta-min-com.invalid",
        queried_domain="synthetic-beta-min-com.invalid",
        confidence="low",
        domain_count=1,
        tenant_domains=["synthetic-beta-min-com.invalid"],
    )


def two_aws_slugs_one_vendor() -> dict[str, Any]:
    """AWS-only apex with multiple AWS-family slugs. Confirms
    canonicalization: Multi-cloud must NOT fire even with 4 slugs."""
    return _base_tenant(
        default_domain="synthetic-gamma-cloud-com.invalid",
        queried_domain="synthetic-gamma-cloud-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-gamma-cloud-com.invalid",
            "synthetic-gamma-io.invalid",
            "synthetic-gamma-cs-com.invalid",
        ],
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
# All target identities use explicit synthetic sentinels under the
# reserved ``.invalid`` namespace. Scenarios within each stratum vary
# scale, identity, security stack, and surface attribution density to
# exercise trigger discipline across realistic intra-stratum variation.

# Stratum: GCP


def stratum_gcp_pure_native() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-analytics-com.invalid",
        queried_domain="synthetic-alpha-analytics-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-alpha-analytics-com.invalid",
            "synthetic-alpha-data-com.invalid",
            "synthetic-alpha-ml-com.invalid",
            "synthetic-alpha-bi-com.invalid",
        ],
        services=["Google Workspace", "Firebase Hosting", "GCP Compute Engine", "GCP Cloud Functions", "GCP Storage"],
        slugs=["googleworkspace", "firebase-hosting", "gcp-compute", "gcp-cloud-functions", "gcp-storage"],
    )


def stratum_gcp_with_okta() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-eng-com.invalid",
        queried_domain="synthetic-beta-eng-com.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-beta-eng-com.invalid",
            "synthetic-beta-dev.invalid",
            "synthetic-beta-prod-com.invalid",
            "synthetic-beta-eng-io.invalid",
            "synthetic-beta-stage-com.invalid",
        ],
        services=["Google Workspace", "Okta", "GCP Compute Engine", "GCP Storage", "Cloudflare"],
        slugs=["googleworkspace", "okta", "gcp-compute", "gcp-storage", "cloudflare"],
        surface_attributions=[
            _surface_attrib("api.synthetic-beta-eng-com.invalid", "gcp-compute", "GCP Compute Engine"),
            _surface_attrib("portal.synthetic-beta-eng-com.invalid", "okta", "Okta", "application"),
        ],
    )


def stratum_gcp_with_security_stack() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-gamma-cs-com.invalid",
        queried_domain="synthetic-gamma-cs-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-gamma-cs-com.invalid",
            "synthetic-gamma-soc-com.invalid",
            "synthetic-gamma-ir-com.invalid",
            "synthetic-gamma-vuln-com.invalid",
        ],
        services=["Google Workspace", "GCP Compute Engine", "GCP Storage", "Wiz", "CrowdStrike", "Snyk"],
        slugs=["googleworkspace", "gcp-compute", "gcp-storage", "wiz", "crowdstrike", "snyk"],
    )


def stratum_gcp_apigee_heavy() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-delta-api-com.invalid",
        queried_domain="synthetic-delta-api-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-delta-api-com.invalid",
            "synthetic-delta-gateway-com.invalid",
            "synthetic-delta-services-com.invalid",
        ],
        services=["Google Workspace", "Apigee", "GCP Compute Engine", "GCP Cloud Functions"],
        slugs=["googleworkspace", "apigee", "gcp-compute", "gcp-cloud-functions"],
        surface_attributions=[
            _surface_attrib("api.synthetic-delta-api-com.invalid", "apigee", "Apigee", "application"),
            _surface_attrib("v2.synthetic-delta-api-com.invalid", "apigee", "Apigee", "application"),
        ],
    )


def stratum_gcp_firebase_only() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-epsilon-mobile-com.invalid",
        queried_domain="synthetic-epsilon-mobile-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-epsilon-mobile-com.invalid",
            "synthetic-epsilon-app-com.invalid",
            "synthetic-epsilon-api-com.invalid",
        ],
        services=["Google Workspace", "Firebase Hosting", "Firebase Realtime Database"],
        slugs=["googleworkspace", "firebase-hosting", "firebase-realtime"],
        surface_attributions=[
            _surface_attrib("app.synthetic-epsilon-mobile-com.invalid", "firebase-hosting", "Firebase Hosting"),
            _surface_attrib("api.synthetic-epsilon-mobile-com.invalid", "firebase-realtime", "Firebase Realtime"),
        ],
    )


def stratum_gcp_minimal_hardened() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-zeta-secure-com.invalid",
        queried_domain="synthetic-zeta-secure-com.invalid",
        confidence="low",
        domain_count=4,
        tenant_domains=[
            "synthetic-zeta-secure-com.invalid",
            "synthetic-zeta-prod-com.invalid",
            "synthetic-zeta-internal-com.invalid",
            "synthetic-zeta-corp-com.invalid",
        ],
        services=["GCP DNS"],
        slugs=["gcp-dns"],
    )


def stratum_gcp_dual_with_aws() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-eta-mc-com.invalid",
        queried_domain="synthetic-eta-mc-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-eta-mc-com.invalid",
            "synthetic-eta-east-com.invalid",
            "synthetic-eta-west-com.invalid",
            "synthetic-eta-eu-com.invalid",
        ],
        services=["Google Workspace", "GCP Compute Engine", "AWS S3", "AWS CloudFront"],
        slugs=["googleworkspace", "gcp-compute", "aws-s3", "aws-cloudfront"],
        surface_attributions=[
            _surface_attrib("backup.synthetic-eta-mc-com.invalid", "aws-s3", "AWS S3"),
            _surface_attrib("static.synthetic-eta-mc-com.invalid", "aws-cloudfront", "AWS CloudFront"),
        ],
    )


def stratum_gcp_data_pipeline() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-theta-data-com.invalid",
        queried_domain="synthetic-theta-data-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-theta-data-com.invalid",
            "synthetic-theta-bi-com.invalid",
            "synthetic-theta-ml-com.invalid",
        ],
        services=["Google Workspace", "GCP Compute Engine", "GCP Storage", "Snowflake", "Databricks"],
        slugs=["googleworkspace", "gcp-compute", "gcp-storage", "snowflake", "databricks"],
    )


def stratum_gcp_cloud_run_modern() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-modern-com.invalid",
        queried_domain="synthetic-alpha-modern-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-alpha-modern-com.invalid",
            "synthetic-alpha-app-com.invalid",
            "synthetic-alpha-stage-com.invalid",
        ],
        services=["Google Workspace", "GCP Cloud Functions", "Firebase Hosting", "Cloudflare"],
        slugs=["googleworkspace", "gcp-cloud-functions", "firebase-hosting", "cloudflare"],
        surface_attributions=[
            _surface_attrib("app.synthetic-alpha-modern-com.invalid", "firebase-hosting", "Firebase Hosting"),
        ],
    )


def stratum_gcp_idp_heavy() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-idp-com.invalid",
        queried_domain="synthetic-beta-idp-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-beta-idp-com.invalid",
            "synthetic-beta-sso-com.invalid",
            "synthetic-beta-id-com.invalid",
            "synthetic-beta-auth-com.invalid",
        ],
        services=["Google Workspace", "Okta", "GCP Compute Engine", "Auth0"],
        slugs=["googleworkspace", "okta", "gcp-compute", "auth0"],
        surface_attributions=[
            _surface_attrib("sso.synthetic-beta-idp-com.invalid", "okta", "Okta", "application"),
            _surface_attrib("login.synthetic-beta-idp-com.invalid", "auth0", "Auth0", "application"),
        ],
    )


# Stratum: Azure non-O365


def stratum_azure_native_no_m365() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-az-com.invalid",
        queried_domain="synthetic-alpha-az-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-alpha-az-com.invalid",
            "synthetic-alpha-azure-com.invalid",
            "synthetic-alpha-eastus-com.invalid",
            "synthetic-alpha-eu-com.invalid",
        ],
        services=["Google Workspace", "Azure DNS", "Azure App Service", "Azure CDN", "Azure Blob Storage"],
        slugs=["googleworkspace", "azure-dns", "azure-appservice", "azure-cdn", "azure-blob"],
        surface_attributions=[
            _surface_attrib("api.synthetic-alpha-az-com.invalid", "azure-appservice", "Azure App Service"),
            _surface_attrib("static.synthetic-alpha-az-com.invalid", "azure-cdn", "Azure CDN"),
        ],
    )


def stratum_azure_with_okta_sso() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-az-com.invalid",
        queried_domain="synthetic-beta-az-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-beta-az-com.invalid",
            "synthetic-beta-az-east-com.invalid",
            "synthetic-beta-az-west-com.invalid",
            "synthetic-beta-az-eu-com.invalid",
        ],
        services=["Google Workspace", "Okta", "Azure DNS", "Azure App Service", "Azure Front Door"],
        slugs=["googleworkspace", "okta", "azure-dns", "azure-appservice", "azure-fd"],
    )


def stratum_azure_static_web_apps() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-gamma-swa-com.invalid",
        queried_domain="synthetic-gamma-swa-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-gamma-swa-com.invalid",
            "synthetic-gamma-marketing-com.invalid",
            "synthetic-gamma-blog-com.invalid",
        ],
        services=["Google Workspace", "Azure DNS", "Azure Static Web Apps"],
        slugs=["googleworkspace", "azure-dns", "azure-static-web-apps"],
        surface_attributions=[
            _surface_attrib("www.synthetic-gamma-swa-com.invalid", "azure-static-web-apps", "Azure Static Web Apps"),
        ],
    )


def stratum_azure_with_proofpoint() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-delta-az-com.invalid",
        queried_domain="synthetic-delta-az-com.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-delta-az-com.invalid",
            "synthetic-delta-azure-com.invalid",
            "synthetic-delta-cloud-com.invalid",
            "synthetic-delta-corp-com.invalid",
            "synthetic-delta-eu-com.invalid",
        ],
        services=["Google Workspace", "Proofpoint", "Azure DNS", "Azure App Service", "Azure Container Apps"],
        slugs=["googleworkspace", "proofpoint", "azure-dns", "azure-appservice", "azure-container-apps"],
    )


def stratum_azure_govcloud() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-epsilon-gov-gov.invalid",
        queried_domain="synthetic-epsilon-gov-gov.invalid",
        confidence="medium",
        domain_count=4,
        tenant_domains=[
            "synthetic-epsilon-gov-gov.invalid",
            "synthetic-epsilon-state-gov.invalid",
            "synthetic-epsilon-fed-gov.invalid",
            "synthetic-epsilon-portal-gov.invalid",
        ],
        services=["Microsoft 365", "Azure DNS", "Azure App Service"],
        slugs=["microsoft365", "azure-dns", "azure-appservice"],
    )


def stratum_azure_minimal() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-zeta-az-com.invalid",
        queried_domain="synthetic-zeta-az-com.invalid",
        confidence="low",
        domain_count=4,
        tenant_domains=[
            "synthetic-zeta-az-com.invalid",
            "synthetic-zeta-prod-com.invalid",
            "synthetic-zeta-staging-com.invalid",
            "synthetic-zeta-internal-com.invalid",
        ],
        services=["Azure DNS"],
        slugs=["azure-dns"],
    )


def stratum_azure_with_databricks() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-eta-an-com.invalid",
        queried_domain="synthetic-eta-an-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-eta-an-com.invalid",
            "synthetic-eta-data-com.invalid",
            "synthetic-eta-bi-com.invalid",
            "synthetic-eta-ml-com.invalid",
        ],
        services=["Google Workspace", "Azure DNS", "Azure App Service", "Databricks", "Snowflake"],
        slugs=["googleworkspace", "azure-dns", "azure-appservice", "databricks", "snowflake"],
    )


def stratum_azure_dual_cloud() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-theta-dual-com.invalid",
        queried_domain="synthetic-theta-dual-com.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-theta-dual-com.invalid",
            "synthetic-theta-east-com.invalid",
            "synthetic-theta-west-com.invalid",
            "synthetic-theta-eu-com.invalid",
            "synthetic-theta-corp-com.invalid",
        ],
        services=["Microsoft 365", "Azure App Service", "AWS S3", "AWS CloudFront", "Cloudflare"],
        slugs=["microsoft365", "azure-appservice", "aws-s3", "aws-cloudfront", "cloudflare"],
        surface_attributions=[
            _surface_attrib("static.synthetic-theta-dual-com.invalid", "aws-cloudfront", "AWS CloudFront"),
            _surface_attrib("eu.synthetic-theta-dual-com.invalid", "azure-appservice", "Azure App Service"),
        ],
    )


def stratum_azure_api_management() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-apim-com.invalid",
        queried_domain="synthetic-alpha-apim-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-alpha-apim-com.invalid",
            "synthetic-alpha-gateway-com.invalid",
            "synthetic-alpha-svc-com.invalid",
        ],
        services=["Google Workspace", "Azure DNS", "Azure API Management", "Azure App Service"],
        slugs=["googleworkspace", "azure-dns", "azure-api-management", "azure-appservice"],
        surface_attributions=[
            _surface_attrib("api.synthetic-alpha-apim-com.invalid", "azure-api-management", "Azure API Management"),
        ],
    )


def stratum_azure_idp_managed() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-delta-idp-com.invalid",
        queried_domain="synthetic-delta-idp-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-delta-idp-com.invalid",
            "synthetic-delta-sso-com.invalid",
            "synthetic-delta-mfa-com.invalid",
            "synthetic-delta-portal-com.invalid",
        ],
        services=["Microsoft 365", "Azure DNS", "Azure App Service", "Auth0"],
        slugs=["microsoft365", "azure-dns", "azure-appservice", "auth0"],
        surface_attributions=[
            _surface_attrib("login.synthetic-delta-idp-com.invalid", "auth0", "Auth0", "application"),
        ],
    )


# Stratum: Oracle


def stratum_oracle_fusion_apps() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-erp-com.invalid",
        queried_domain="synthetic-alpha-erp-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-alpha-erp-com.invalid",
            "synthetic-alpha-hcm-com.invalid",
            "synthetic-alpha-fin-com.invalid",
            "synthetic-alpha-corp-com.invalid",
        ],
        services=["Microsoft 365", "Oracle Fusion ERP", "Oracle Cloud", "Okta"],
        slugs=["microsoft365", "oracle-fusion", "oracle-cloud", "okta"],
    )


def stratum_oracle_oci_only() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-oci-com.invalid",
        queried_domain="synthetic-beta-oci-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-beta-oci-com.invalid",
            "synthetic-beta-cloud-com.invalid",
            "synthetic-beta-svc-com.invalid",
        ],
        services=["Google Workspace", "Oracle Cloud", "Cloudflare"],
        slugs=["googleworkspace", "oracle-cloud", "cloudflare"],
    )


def stratum_oracle_with_legacy() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-gamma-oracle-com.invalid",
        queried_domain="synthetic-gamma-oracle-com.invalid",
        confidence="medium",
        domain_count=5,
        tenant_domains=[
            "synthetic-gamma-oracle-com.invalid",
            "synthetic-gamma-erp-com.invalid",
            "synthetic-gamma-hcm-com.invalid",
            "synthetic-gamma-corp-com.invalid",
            "synthetic-gamma-legacy-com.invalid",
        ],
        services=["Microsoft 365", "Oracle Fusion ERP", "Oracle Cloud", "Proofpoint"],
        slugs=["microsoft365", "oracle-fusion", "oracle-cloud", "proofpoint"],
    )


def stratum_oracle_apex_dev() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-delta-apex-com.invalid",
        queried_domain="synthetic-delta-apex-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-delta-apex-com.invalid",
            "synthetic-delta-dev-com.invalid",
            "synthetic-delta-app-com.invalid",
        ],
        services=["Google Workspace", "Oracle Cloud"],
        slugs=["googleworkspace", "oracle-cloud"],
    )


def stratum_oracle_minimal() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-epsilon-oracle-com.invalid",
        queried_domain="synthetic-epsilon-oracle-com.invalid",
        confidence="low",
        domain_count=3,
        tenant_domains=[
            "synthetic-epsilon-oracle-com.invalid",
            "synthetic-epsilon-erp-com.invalid",
            "synthetic-epsilon-corp-com.invalid",
        ],
        services=["Oracle Cloud"],
        slugs=["oracle-cloud"],
    )


def stratum_oracle_dual_with_aws() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-zeta-oracle-aws-com.invalid",
        queried_domain="synthetic-zeta-oracle-aws-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-zeta-oracle-aws-com.invalid",
            "synthetic-zeta-erp-com.invalid",
            "synthetic-zeta-aws-com.invalid",
            "synthetic-zeta-eu-com.invalid",
        ],
        services=["Microsoft 365", "Oracle Fusion ERP", "Oracle Cloud", "AWS S3", "AWS CloudFront"],
        slugs=["microsoft365", "oracle-fusion", "oracle-cloud", "aws-s3", "aws-cloudfront"],
    )


def stratum_oracle_with_security() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-eta-oracle-com.invalid",
        queried_domain="synthetic-eta-oracle-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-eta-oracle-com.invalid",
            "synthetic-eta-erp-com.invalid",
            "synthetic-eta-fin-com.invalid",
            "synthetic-eta-soc-com.invalid",
        ],
        services=["Microsoft 365", "Oracle Cloud", "Okta", "Wiz", "CrowdStrike"],
        slugs=["microsoft365", "oracle-cloud", "okta", "wiz", "crowdstrike"],
    )


def stratum_oracle_global() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-theta-oracle-com.invalid",
        queried_domain="synthetic-theta-oracle-com.invalid",
        confidence="high",
        domain_count=6,
        tenant_domains=[
            "synthetic-theta-oracle-com.invalid",
            "synthetic-theta-eu-com.invalid",
            "synthetic-theta-jp-com.invalid",
            "synthetic-theta-au-com.invalid",
            "synthetic-theta-br-com.invalid",
            "synthetic-theta-corp-com.invalid",
        ],
        services=["Google Workspace", "Oracle Cloud", "Oracle Fusion ERP", "Cloudflare"],
        slugs=["googleworkspace", "oracle-cloud", "oracle-fusion", "cloudflare"],
    )


def stratum_oracle_idp_with_okta() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-oid-com.invalid",
        queried_domain="synthetic-alpha-oid-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-alpha-oid-com.invalid",
            "synthetic-alpha-sso-com.invalid",
            "synthetic-alpha-fed-com.invalid",
            "synthetic-alpha-corp-com.invalid",
        ],
        services=["Google Workspace", "Okta", "Oracle Cloud"],
        slugs=["googleworkspace", "okta", "oracle-cloud"],
        surface_attributions=[
            _surface_attrib("sso.synthetic-alpha-oid-com.invalid", "okta", "Okta", "application"),
        ],
    )


def stratum_oracle_with_apex_only() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-or-com.invalid",
        queried_domain="synthetic-beta-or-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-beta-or-com.invalid",
            "synthetic-beta-svc-com.invalid",
            "synthetic-beta-internal-com.invalid",
        ],
        services=["Oracle Cloud"],
        slugs=["oracle-cloud"],
    )


# Stratum: Alibaba


def stratum_alibaba_native() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-ali-com.invalid",
        queried_domain="synthetic-alpha-ali-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-alpha-ali-com.invalid",
            "synthetic-alpha-cn-com.invalid",
            "synthetic-alpha-apac-com.invalid",
            "synthetic-alpha-corp-com.invalid",
        ],
        services=["Google Workspace", "Alibaba Cloud", "Alibaba CDN"],
        slugs=["googleworkspace", "alibaba-cloud", "alibaba-cdn"],
        surface_attributions=[
            _surface_attrib("cdn.synthetic-alpha-ali-com.invalid", "alibaba-cdn", "Alibaba CDN"),
        ],
    )


def stratum_alibaba_global() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-ali-com.invalid",
        queried_domain="synthetic-beta-ali-com.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-beta-ali-com.invalid",
            "synthetic-beta-cn-com.invalid",
            "synthetic-beta-jp-com.invalid",
            "synthetic-beta-sg-com.invalid",
            "synthetic-beta-corp-com.invalid",
        ],
        services=["Google Workspace", "Alibaba Cloud", "Alibaba API", "Alibaba CDN"],
        slugs=["googleworkspace", "alibaba-cloud", "alibaba-api", "alibaba-cdn"],
    )


def stratum_alibaba_with_security() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-gamma-ali-com.invalid",
        queried_domain="synthetic-gamma-ali-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-gamma-ali-com.invalid",
            "synthetic-gamma-cn-com.invalid",
            "synthetic-gamma-corp-com.invalid",
        ],
        services=["Microsoft 365", "Alibaba Cloud", "Wiz"],
        slugs=["microsoft365", "alibaba-cloud", "wiz"],
    )


def stratum_alibaba_minimal() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-delta-ali-com.invalid",
        queried_domain="synthetic-delta-ali-com.invalid",
        confidence="low",
        domain_count=3,
        tenant_domains=[
            "synthetic-delta-ali-com.invalid",
            "synthetic-delta-cn-com.invalid",
            "synthetic-delta-corp-com.invalid",
        ],
        services=["Alibaba Cloud"],
        slugs=["alibaba-cloud"],
    )


def stratum_alibaba_dual_with_aws() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-epsilon-ali-aws-com.invalid",
        queried_domain="synthetic-epsilon-ali-aws-com.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-epsilon-ali-aws-com.invalid",
            "synthetic-epsilon-cn-com.invalid",
            "synthetic-epsilon-us-com.invalid",
            "synthetic-epsilon-eu-com.invalid",
            "synthetic-epsilon-corp-com.invalid",
        ],
        services=["Microsoft 365", "Alibaba Cloud", "Alibaba CDN", "AWS S3", "AWS CloudFront"],
        slugs=["microsoft365", "alibaba-cloud", "alibaba-cdn", "aws-s3", "aws-cloudfront"],
    )


def stratum_alibaba_ecommerce() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-zeta-shop-com.invalid",
        queried_domain="synthetic-zeta-shop-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-zeta-shop-com.invalid",
            "synthetic-zeta-cn-com.invalid",
            "synthetic-zeta-store-com.invalid",
            "synthetic-zeta-corp-com.invalid",
        ],
        services=["Google Workspace", "Alibaba Cloud", "Alibaba CDN"],
        slugs=["googleworkspace", "alibaba-cloud", "alibaba-cdn"],
        surface_attributions=[
            _surface_attrib("shop.synthetic-zeta-shop-com.invalid", "alibaba-cdn", "Alibaba CDN"),
            _surface_attrib("store.synthetic-zeta-shop-com.invalid", "alibaba-cdn", "Alibaba CDN"),
        ],
    )


def stratum_alibaba_with_oss() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-eta-ali-com.invalid",
        queried_domain="synthetic-eta-ali-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-eta-ali-com.invalid",
            "synthetic-eta-cn-com.invalid",
            "synthetic-eta-storage-com.invalid",
        ],
        services=["Microsoft 365", "Alibaba Cloud"],
        slugs=["microsoft365", "alibaba-cloud"],
    )


def stratum_alibaba_with_apim() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-theta-ali-api-com.invalid",
        queried_domain="synthetic-theta-ali-api-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-theta-ali-api-com.invalid",
            "synthetic-theta-cn-api-com.invalid",
            "synthetic-theta-svc-com.invalid",
        ],
        services=["Google Workspace", "Alibaba Cloud", "Alibaba API"],
        slugs=["googleworkspace", "alibaba-cloud", "alibaba-api"],
        surface_attributions=[
            _surface_attrib("api.synthetic-theta-ali-api-com.invalid", "alibaba-api", "Alibaba API"),
        ],
    )


def stratum_alibaba_minimal_cdn() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-acdn-com.invalid",
        queried_domain="synthetic-alpha-acdn-com.invalid",
        confidence="low",
        domain_count=3,
        tenant_domains=[
            "synthetic-alpha-acdn-com.invalid",
            "synthetic-alpha-static-com.invalid",
            "synthetic-alpha-svc-com.invalid",
        ],
        services=["Alibaba CDN"],
        slugs=["alibaba-cdn"],
    )


def stratum_alibaba_with_dingtalk_proxy() -> dict[str, Any]:
    """Alibaba customer with collaboration via Slack (DingTalk
    not in catalog)."""
    return _base_tenant(
        default_domain="synthetic-beta-ad-com.invalid",
        queried_domain="synthetic-beta-ad-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-beta-ad-com.invalid",
            "synthetic-beta-cn-team-com.invalid",
            "synthetic-beta-collab-com.invalid",
            "synthetic-beta-corp-com.invalid",
        ],
        services=["Microsoft 365", "Alibaba Cloud", "Slack"],
        slugs=["microsoft365", "alibaba-cloud", "slack"],
    )


# Stratum: PaaS / Vercel / Netlify


def stratum_paas_vercel_full() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-vc-com.invalid",
        queried_domain="synthetic-alpha-vc-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-alpha-vc-com.invalid",
            "synthetic-alpha-app-com.invalid",
            "synthetic-alpha-blog-com.invalid",
        ],
        services=["Google Workspace", "Vercel", "Cloudflare", "GitHub"],
        slugs=["googleworkspace", "vercel", "cloudflare", "github"],
        surface_attributions=[
            _surface_attrib("www.synthetic-alpha-vc-com.invalid", "vercel", "Vercel"),
            _surface_attrib("app.synthetic-alpha-vc-com.invalid", "vercel", "Vercel"),
        ],
    )


def stratum_paas_netlify_jamstack() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-nl-com.invalid",
        queried_domain="synthetic-beta-nl-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-beta-nl-com.invalid",
            "synthetic-beta-marketing-com.invalid",
            "synthetic-beta-docs-com.invalid",
        ],
        services=["Google Workspace", "Netlify", "Cloudflare"],
        slugs=["googleworkspace", "netlify", "cloudflare"],
        surface_attributions=[
            _surface_attrib("www.synthetic-beta-nl-com.invalid", "netlify", "Netlify"),
            _surface_attrib("docs.synthetic-beta-nl-com.invalid", "netlify", "Netlify"),
        ],
    )


def stratum_paas_vercel_with_auth0() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-gamma-vc-com.invalid",
        queried_domain="synthetic-gamma-vc-com.invalid",
        confidence="high",
        domain_count=3,
        tenant_domains=[
            "synthetic-gamma-vc-com.invalid",
            "synthetic-gamma-app-com.invalid",
            "synthetic-gamma-id-com.invalid",
        ],
        services=["Google Workspace", "Vercel", "Auth0", "Cloudflare"],
        slugs=["googleworkspace", "vercel", "auth0", "cloudflare"],
        surface_attributions=[
            _surface_attrib("login.synthetic-gamma-vc-com.invalid", "auth0", "Auth0", "application"),
        ],
    )


def stratum_paas_railway_app() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-delta-rw-com.invalid",
        queried_domain="synthetic-delta-rw-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-delta-rw-com.invalid",
            "synthetic-delta-app-com.invalid",
            "synthetic-delta-api-com.invalid",
        ],
        services=["Google Workspace", "Railway", "Cloudflare"],
        slugs=["googleworkspace", "railway", "cloudflare"],
        surface_attributions=[
            _surface_attrib("api.synthetic-delta-rw-com.invalid", "railway", "Railway"),
        ],
    )


def stratum_paas_render_app() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-epsilon-rd-com.invalid",
        queried_domain="synthetic-epsilon-rd-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-epsilon-rd-com.invalid",
            "synthetic-epsilon-app-com.invalid",
            "synthetic-epsilon-svc-com.invalid",
        ],
        services=["Google Workspace", "Render", "Cloudflare"],
        slugs=["googleworkspace", "render", "cloudflare"],
    )


def stratum_paas_flyio_distributed() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-zeta-fly-com.invalid",
        queried_domain="synthetic-zeta-fly-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-zeta-fly-com.invalid",
            "synthetic-zeta-edge-com.invalid",
            "synthetic-zeta-app-com.invalid",
        ],
        services=["Google Workspace", "Fly.io", "Cloudflare"],
        slugs=["googleworkspace", "flyio", "cloudflare"],
    )


def stratum_paas_vercel_minimal() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-eta-vc-com.invalid",
        queried_domain="synthetic-eta-vc-com.invalid",
        confidence="low",
        domain_count=3,
        tenant_domains=[
            "synthetic-eta-vc-com.invalid",
            "synthetic-eta-blog-com.invalid",
            "synthetic-eta-corp-com.invalid",
        ],
        services=["Vercel"],
        slugs=["vercel"],
    )


def stratum_paas_netlify_minimal() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-theta-nl-com.invalid",
        queried_domain="synthetic-theta-nl-com.invalid",
        confidence="low",
        domain_count=3,
        tenant_domains=[
            "synthetic-theta-nl-com.invalid",
            "synthetic-theta-blog-com.invalid",
            "synthetic-theta-corp-com.invalid",
        ],
        services=["Netlify"],
        slugs=["netlify"],
    )


def stratum_paas_cloudflare_pages() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-cfp-com.invalid",
        queried_domain="synthetic-alpha-cfp-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-alpha-cfp-com.invalid",
            "synthetic-alpha-pages-com.invalid",
            "synthetic-alpha-app-com.invalid",
        ],
        services=["Google Workspace", "Cloudflare", "Cloudflare Pages"],
        slugs=["googleworkspace", "cloudflare", "cloudflare-pages"],
        surface_attributions=[
            _surface_attrib("www.synthetic-alpha-cfp-com.invalid", "cloudflare-pages", "Cloudflare Pages"),
        ],
    )


def stratum_paas_multi_paas() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-mp-com.invalid",
        queried_domain="synthetic-beta-mp-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-beta-mp-com.invalid",
            "synthetic-beta-vc-com.invalid",
            "synthetic-beta-nl-com.invalid",
            "synthetic-beta-corp-com.invalid",
        ],
        services=["Google Workspace", "Vercel", "Netlify", "Cloudflare"],
        slugs=["googleworkspace", "vercel", "netlify", "cloudflare"],
    )


# Stratum: SSE / SASE


def stratum_sse_zscaler_fronted() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-zs-com.invalid",
        queried_domain="synthetic-alpha-zs-com.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-alpha-zs-com.invalid",
            "synthetic-alpha-portal-com.invalid",
            "synthetic-alpha-svc-com.invalid",
            "synthetic-alpha-corp-com.invalid",
            "synthetic-alpha-eu-com.invalid",
        ],
        services=["Microsoft 365", "Zscaler", "AWS Route 53"],
        slugs=["microsoft365", "zscaler", "aws-route53"],
    )


def stratum_sse_netskope_fronted() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-ns-com.invalid",
        queried_domain="synthetic-beta-ns-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-beta-ns-com.invalid",
            "synthetic-beta-cloud-com.invalid",
            "synthetic-beta-corp-com.invalid",
            "synthetic-beta-eu-com.invalid",
        ],
        services=["Microsoft 365", "Netskope", "Cloudflare"],
        slugs=["microsoft365", "netskope", "cloudflare"],
    )


def stratum_sse_cloudflare_one() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-gamma-cf1-com.invalid",
        queried_domain="synthetic-gamma-cf1-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-gamma-cf1-com.invalid",
            "synthetic-gamma-zt-com.invalid",
            "synthetic-gamma-portal-com.invalid",
            "synthetic-gamma-corp-com.invalid",
        ],
        services=["Microsoft 365", "Cloudflare", "Okta"],
        slugs=["microsoft365", "cloudflare", "okta"],
    )


def stratum_sse_prisma_access() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-delta-pa-com.invalid",
        queried_domain="synthetic-delta-pa-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-delta-pa-com.invalid",
            "synthetic-delta-zt-com.invalid",
            "synthetic-delta-portal-com.invalid",
            "synthetic-delta-corp-com.invalid",
        ],
        services=["Microsoft 365", "Prisma Access", "Palo Alto Networks"],
        slugs=["microsoft365", "prisma-access", "paloalto"],
    )


def stratum_sse_cato_sase() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-epsilon-cato-com.invalid",
        queried_domain="synthetic-epsilon-cato-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-epsilon-cato-com.invalid",
            "synthetic-epsilon-sase-com.invalid",
            "synthetic-epsilon-portal-com.invalid",
            "synthetic-epsilon-corp-com.invalid",
        ],
        services=["Microsoft 365", "Cato Networks", "AWS Route 53"],
        slugs=["microsoft365", "cato-networks", "aws-route53"],
    )


def stratum_sse_minimal_zscaler() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-zeta-zs-com.invalid",
        queried_domain="synthetic-zeta-zs-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-zeta-zs-com.invalid",
            "synthetic-zeta-corp-com.invalid",
            "synthetic-zeta-eu-com.invalid",
        ],
        services=["Microsoft 365", "Zscaler"],
        slugs=["microsoft365", "zscaler"],
    )


def stratum_sse_dual_sse() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-eta-dse-com.invalid",
        queried_domain="synthetic-eta-dse-com.invalid",
        confidence="high",
        domain_count=5,
        tenant_domains=[
            "synthetic-eta-dse-com.invalid",
            "synthetic-eta-zt-com.invalid",
            "synthetic-eta-sase-com.invalid",
            "synthetic-eta-portal-com.invalid",
            "synthetic-eta-corp-com.invalid",
        ],
        services=["Microsoft 365", "Zscaler", "Netskope", "Cloudflare"],
        slugs=["microsoft365", "zscaler", "netskope", "cloudflare"],
    )


def stratum_sse_with_okta_sso() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-theta-sse-com.invalid",
        queried_domain="synthetic-theta-sse-com.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-theta-sse-com.invalid",
            "synthetic-theta-zt-com.invalid",
            "synthetic-theta-sso-com.invalid",
            "synthetic-theta-corp-com.invalid",
        ],
        services=["Microsoft 365", "Zscaler", "Okta"],
        slugs=["microsoft365", "zscaler", "okta"],
        surface_attributions=[
            _surface_attrib("sso.synthetic-theta-sse-com.invalid", "okta", "Okta", "application"),
        ],
    )


def stratum_sse_paloalto_only() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-alpha-pa-com.invalid",
        queried_domain="synthetic-alpha-pa-com.invalid",
        confidence="medium",
        domain_count=3,
        tenant_domains=[
            "synthetic-alpha-pa-com.invalid",
            "synthetic-alpha-firewall-com.invalid",
            "synthetic-alpha-corp-com.invalid",
        ],
        services=["Microsoft 365", "Palo Alto Networks"],
        slugs=["microsoft365", "paloalto"],
    )


def stratum_sse_government() -> dict[str, Any]:
    return _base_tenant(
        default_domain="synthetic-beta-gov-gov.invalid",
        queried_domain="synthetic-beta-gov-gov.invalid",
        confidence="high",
        domain_count=4,
        tenant_domains=[
            "synthetic-beta-gov-gov.invalid",
            "synthetic-beta-fed-gov.invalid",
            "synthetic-beta-state-gov.invalid",
            "synthetic-beta-portal-gov.invalid",
        ],
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
    # v1.9.10 stratified expansion - Stratum: GCP
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


def _scenario_id(registry_key: str) -> str:
    """Return a stable numeric public identifier derived from the registry key."""
    digest = sha256(registry_key.encode("utf-8")).digest()
    return f"{int.from_bytes(digest[:8], 'big') % 1_000_000_000_000:012d}"


_SCENARIO_ID_BY_KEY = {key: _scenario_id(key) for key in REGISTRY}
if len(set(_SCENARIO_ID_BY_KEY.values())) != len(_SCENARIO_ID_BY_KEY):
    raise RuntimeError("synthetic scenario identifier collision")


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
    (``synthetic-epsilon-firebase`` for GCP, ``synthetic-beta-oci`` for Oracle)
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
    """Inject authoritative public tags and constrained synthetic identity.

    Mutates a copy rather than the caller's dict so re-running the
    generator stays deterministic and side-effect-free per builder.
    The tag prefix ``_`` keeps the field out of any TenantInfo
    deserialization path (``recon_tool.cache.tenant_info_from_dict``
    ignores fields it does not recognize). Numbered public identity fields
    prevent descriptive fixture labels from being mistaken for organizations.
    """
    tagged = dict(fixture)
    scenario = _SCENARIO_ID_BY_KEY[registry_key]
    tagged["display_name"] = f"Synthetic Scenario {scenario}"
    tagged["tenant_id"] = f"synthetic-scenario-{scenario}"
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
