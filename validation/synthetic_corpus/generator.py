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


# ── Registry and runner ────────────────────────────────────────────────


REGISTRY: dict[str, Any] = {
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
}


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, builder in REGISTRY.items():
        fixture = builder()
        path = OUTPUT_DIR / f"{name}.json"
        path.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.name}")

    # Also emit a single combined results.json for the aggregator.
    combined = [builder() for builder in REGISTRY.values()]
    combined_path = Path(__file__).resolve().parent / "results.json"
    combined_path.write_text(json.dumps(combined, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {combined_path.name} ({len(combined)} fixtures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
