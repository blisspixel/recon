"""Rich terminal output formatting for domain intelligence.

Console management: All output goes through get_console(). The CLI module
should use get_console() instead of creating its own Console instance, so
that set_console() in tests captures everything.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from recon_tool.exposure import (
    ExposureAssessment,
    GapReport,
    PostureComparison,
)
from recon_tool.fingerprints import load_fingerprints
from recon_tool.models import (
    CandidateValue,
    ChainReport,
    ConfidenceLevel,
    DeltaReport,
    ExplanationRecord,
    MergeConflicts,
    Observation,
    ReconLookupError,
    SourceResult,
    TenantInfo,
    serialize_conflicts_array,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CSV_COLUMNS",
    "detect_provider",
    "format_batch_csv",
    "format_chain_dict",
    "format_chain_json",
    "format_comparison_dict",
    "format_comparison_json",
    "format_delta_dict",
    "format_delta_json",
    "format_explanations_list",
    "format_explanations_markdown",
    "format_exposure_dict",
    "format_exposure_json",
    "format_gaps_dict",
    "format_gaps_json",
    "format_posture_observations",
    "format_tenant_csv_row",
    "format_tenant_dict",
    "format_tenant_json",
    "format_tenant_markdown",
    "get_console",
    "render_chain_panel",
    "render_conflict_annotation",
    "render_delta_panel",
    "render_error",
    "render_explanations_panel",
    "render_exposure_panel",
    "render_gaps_panel",
    "render_posture_panel",
    "render_source_status_panel",
    "render_sources_detail",
    "render_tenant_panel",
    "render_verbose_sources",
    "render_warning",
    "set_console",
]

# Default console — can be overridden via get_console/set_console for testing.
# Why a global instead of dependency injection? Because Rich's Console is used
# by dozens of call sites (render_*, cli status spinners, etc.) and threading
# a console parameter through every function would be noisy. The global is
# effectively a singleton with a test seam via set_console().
_console: Console | None = None


def get_console() -> Console:
    """Return the active console instance, creating a default if needed.

    On Windows, the default stdout encoding is often cp1252 which cannot
    represent the Unicode characters used in panel rendering (confidence
    dots, arrows, em-dashes, box-drawing). Reconfigure stdout to UTF-8
    with replacement-on-error so the tool never crashes on unencodable
    glyphs — worst case the user sees "?" in place of a decorator
    character instead of a traceback.
    """
    global _console  # noqa: PLW0603
    if _console is None:
        import sys
        from typing import cast

        try:
            stdout_any: Any = cast(Any, sys.stdout)
            if hasattr(stdout_any, "reconfigure"):
                stdout_any.reconfigure(encoding="utf-8", errors="replace")
            stderr_any: Any = cast(Any, sys.stderr)
            if hasattr(stderr_any, "reconfigure"):
                stderr_any.reconfigure(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.debug("stdout UTF-8 reconfigure failed: %s", exc)
        _console = Console()
    return _console


def set_console(console: Console) -> None:
    """Replace the active console (for testing)."""
    global _console  # noqa: PLW0603
    _console = console


CONFIDENCE_COLORS: dict[ConfidenceLevel, str] = {
    ConfidenceLevel.HIGH: "#a3d9a5",  # soft sage green
    ConfidenceLevel.MEDIUM: "#7ec8e3",  # muted sky blue
    ConfidenceLevel.LOW: "#e07a5f",  # warm terracotta
}

CONFIDENCE_DOTS: dict[ConfidenceLevel, str] = {
    ConfidenceLevel.HIGH: "●●●",
    ConfidenceLevel.MEDIUM: "●●○",
    ConfidenceLevel.LOW: "●○○",
}

# M365-specific service keywords for display categorization (--services, markdown).
# COUPLING WARNING: If you add a new M365 service to fingerprints.yaml, you may
# need to add a keyword here too, or it will show up under "Tech Stack" instead
# of "M365" in the --services view. Detection logic uses slugs (not these keywords).
# NOTE: provider_group on fingerprints takes precedence when available.
_M365_KEYWORDS = frozenset(
    {
        "exchange",
        "teams",
        "intune",
        "mdm",
        "dkim",
        "microsoft",
        "domain verified",
    }
)


def _get_slug_provider_groups() -> dict[str, str]:
    """Build a slug → provider_group mapping from loaded fingerprints."""
    return {fp.slug: fp.provider_group for fp in load_fingerprints() if fp.provider_group is not None}


def _slug_to_relationship_metadata() -> dict[str, dict[str, str | None]]:
    """Return ``{slug: {product_family, parent_vendor, bimi_org}}`` for every
    fingerprint with at least one populated relationship-metadata field.

    Pure data lookup — drives the v1.8 ``fingerprint_metadata`` block in
    ``format_tenant_dict``. Slugs without any populated field are
    omitted; callers do not need to filter again.
    """
    out: dict[str, dict[str, str | None]] = {}
    for fp in load_fingerprints():
        if fp.product_family is None and fp.parent_vendor is None and fp.bimi_org is None:
            continue
        out[fp.slug] = {
            "product_family": fp.product_family,
            "parent_vendor": fp.parent_vendor,
            "bimi_org": fp.bimi_org,
        }
    return out


def _get_slug_display_groups() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
    """Build a slug → display_group mapping from loaded fingerprints."""
    return {fp.slug: fp.display_group for fp in load_fingerprints() if fp.display_group is not None}


def _get_name_to_slug() -> dict[str, str]:
    """Build a service name → slug mapping from loaded fingerprints."""
    return {fp.name: fp.slug for fp in load_fingerprints()}


def _service_provider_group(svc: str) -> str | None:
    """Return the provider_group for a service name, or None if not found."""
    name_to_slug = _get_name_to_slug()
    slug = name_to_slug.get(svc)
    if slug is None:
        return None
    return _get_slug_provider_groups().get(slug)


def _is_gws_service(svc: str) -> bool:
    """Check if a service name should be categorized as Google Workspace."""
    pg = _service_provider_group(svc)
    if pg is not None:
        return pg == "google-workspace"
    # Fallback heuristic for services added with "Google Workspace" prefix
    return svc.lower().startswith("google workspace")


# Services filtered from the compact (default) view because they appear
# in insights instead. Uses exact prefix matching to avoid false positives
# (e.g. a service named "Advanced DNS Security" won't be hidden).
_SKIP_COMPACT_PREFIXES = (
    "dmarc",
    "domain verified",
    "spf:",
    "spf complexity",
    "dns:",
    "cdn:",
    "hosting:",
    "waf:",
    "domain connect",
)

# Exact substrings that must appear as standalone tokens in the service name.
_SKIP_COMPACT_EXACT = frozenset({"(SPF)", "(site verified)"})

_SPARSE_INSIGHT_PREFIXES = (
    "Sparse public signal —",
    "Next step — see docs/weak-areas.md",
)


def _is_m365_service(svc: str) -> bool:
    """Check if a service name should be categorized as M365.

    Checks fingerprint provider_group first, falls back to _M365_KEYWORDS.
    """
    pg = _service_provider_group(svc)
    if pg is not None:
        return pg == "microsoft365"
    svc_lower = svc.lower()
    return any(kw in svc_lower for kw in _M365_KEYWORDS)


def _is_sparse_insight(line: str) -> bool:
    """Return True when an insight line is part of sparse-result diagnosis."""
    return line.startswith(_SPARSE_INSIGHT_PREFIXES)


# ── v0.9.3 panel constants ─────────────────────────────────────────────

_PANEL_WIDTH = 78  # One char narrower than an 80-col terminal to avoid
# wrap-to-next-line artefacts when the last cell is
# filled. The v0.9.3 layout has no border, so the
# effective content width equals the panel width.
_LABEL_WIDTH = 13  # columns for Provider/Tenant/Auth/Confidence labels
_CATEGORY_WIDTH = 15  # columns for Services sub-category labels

# Category display order. Each service is classified into exactly one
# of these by _categorize_service; "Business Apps" is the fallback.
_SERVICE_CATEGORIES_ORDER: tuple[str, ...] = (
    "Email",
    "Identity",
    "Cloud",
    "Security",
    "AI",
    "Collaboration",
    "Business Apps",
)

# Service → display-category classification. Checked in order; the first
# matcher wins. Prefer slug lookups over service-name substring matches
# so two services with similar names don't both fall into Other.
_CATEGORY_BY_SLUG: dict[str, str] = {
    # Email providers / gateways / deliverability
    "microsoft365": "Email",
    "google-workspace": "Email",
    "zoho": "Email",
    "protonmail": "Email",
    "proofpoint": "Email",
    "mimecast": "Email",
    "barracuda": "Email",
    "trendmicro": "Email",
    "symantec": "Email",
    "trellix": "Email",
    "cisco-ironport": "Email",
    "cisco-email": "Email",
    "sendgrid": "Email",
    "mailgun": "Email",
    "postmark": "Email",
    "sparkpost": "Email",
    "brevo": "Email",
    "mailchimp": "Email",
    "aws-ses": "Email",
    "autospf": "Email",
    "ondmarc": "Email",
    "dmarcian": "Email",
    "easydmarc": "Email",
    "valimail": "Email",
    "agari": "Email",
    "proofpoint-efd": "Email",
    "uriports": "Email",
    "dmarc-advisor": "Email",
    "powerdmarc": "Email",
    "mimecast-dmarc-analyzer": "Email",
    # Identity
    "okta": "Identity",
    "auth0": "Identity",
    "onelogin": "Identity",
    # v1.9.3.9: additional identity providers
    "jumpcloud": "Identity",
    "aws-cognito": "Identity",
    "duo": "Identity",
    "ping-identity": "Identity",
    "cyberark": "Identity",
    "beyond-identity": "Identity",
    "1password": "Identity",
    "google-federated": "Identity",
    "google-managed": "Identity",
    "cisco-identity": "Identity",
    # v0.9.3: identity-hub slugs emitted by _detect_idp_hub when
    # shibboleth.example.edu / weblogin.example.edu / idp.example.edu
    # resolve. Strong signal that the org runs federated SSO.
    "federated-sso-hub": "Identity",
    "okta-sso-hub": "Identity",
    "adfs-sso-hub": "Identity",
    # v0.9.3: Exchange on-prem / hybrid slug emitted by
    # _detect_exchange_onprem when owa./outlook./exchange.
    # subdomains resolve. Indicates self-hosted or hybrid
    # Exchange deployment rather than Exchange Online.
    "exchange-onprem": "Email",
    # Synthetic slug for orgs running their own mail infrastructure
    # (MX hosts under the queried apex or otherwise not matching any
    # recognized cloud / gateway fingerprint).
    "self-hosted-mail": "Email",
    # Cloud / Infrastructure
    "aws-route53": "Cloud",
    "aws-cloudfront": "Cloud",
    "aws-elb": "Cloud",
    "aws-s3": "Cloud",
    "aws-eb": "Cloud",
    "aws-acm": "Cloud",
    "azure-dns": "Cloud",
    "azure-cdn": "Cloud",
    "azure-appservice": "Cloud",
    "azure-fd": "Cloud",
    "azure-tm": "Cloud",
    "gcp-dns": "Cloud",
    "gcp-app": "Cloud",
    "cloudflare": "Cloud",
    "akamai": "Cloud",
    "fastly": "Cloud",
    "imperva": "Cloud",
    "vercel": "Cloud",
    "netlify": "Cloud",
    "flyio": "Cloud",
    "railway": "Cloud",
    "render": "Cloud",
    # v0.9.3: hosting-provider detection from A → PTR
    "aws-ec2": "Cloud",
    "aws-compute": "Cloud",
    "azure-vm": "Cloud",
    "gcp-compute": "Cloud",
    "linode": "Cloud",
    "digitalocean": "Cloud",
    "hetzner": "Cloud",
    "ovh": "Cloud",
    "vultr": "Cloud",
    "cdn77": "Cloud",
    "bunnycdn": "Cloud",
    # v1.9.3.9: cloud-vendor coverage additions (Cloud)
    "firebase-hosting": "Cloud",
    "gcp-cloud-functions": "Cloud",
    "firebase-realtime": "Cloud",
    "gcp-storage": "Cloud",
    "aws-amplify": "Cloud",
    "azure-blob": "Cloud",
    "azure-static-web-apps": "Cloud",
    "azure-container-apps": "Cloud",
    "azure-api-management": "Cloud",
    "oracle-cloud": "Cloud",
    "ibm-cloud": "Cloud",
    "alibaba-api": "Cloud",
    "alibaba-cdn": "Cloud",
    "alibaba-cloud": "Cloud",
    "replit": "Cloud",
    "glitch": "Cloud",
    # Security
    "crowdstrike": "Security",
    "sentinelone": "Security",
    "sophos": "Security",
    "knowbe4": "Security",
    "zscaler": "Security",
    "netskope": "Security",
    "paloalto": "Security",
    "cato": "Security",
    "wiz": "Security",
    "snyk": "Security",
    "github-advanced-security": "Security",
    "sonatype": "Security",
    "cosign-attestation": "Security",
    "lakera": "Security",
    # v1.9.3.9: cloud-vendor coverage additions (Security)
    "aws-waf": "Security",
    "cato-networks": "Security",
    "prisma-access": "Security",
    "letsencrypt": "Security",
    "digicert": "Security",
    "sectigo": "Security",
    "globalsign": "Security",
    "google-trust": "Security",
    # AI
    "openai": "AI",
    "anthropic": "AI",
    "mistral": "AI",
    "perplexity": "AI",
    "crewai-aid": "AI",
    "langsmith": "AI",
    "mcp-discovery": "AI",
    "dify": "AI",
    "n8n": "AI",
    "autogen": "AI",
    # Collaboration / Productivity
    "slack": "Collaboration",
    "notion": "Collaboration",
    "miro": "Collaboration",
    "atlassian": "Collaboration",
    "figma": "Collaboration",
    "dropbox": "Collaboration",
    "box": "Collaboration",
    "egnyte": "Collaboration",
    "clickup": "Collaboration",
    "asana": "Collaboration",
    "monday": "Collaboration",
    "loom": "Collaboration",
    "canva": "Collaboration",
    "zoom": "Collaboration",
    "airtable": "Collaboration",
    "github": "Collaboration",
    "gitlab": "Collaboration",
    "linear": "Collaboration",
    "disciple-media": "Collaboration",
    # v0.9.3: higher-ed LMS / SIS / student-facing platforms
    "canvas-lms": "Collaboration",
    "blackboard": "Collaboration",
    "moodle": "Collaboration",
    # v1.9.3.9: cloud-vendor coverage additions (Business Apps / Data)
    "oracle-fusion": "Business Apps",
    "looker-studio": "Data & Analytics",
    "ellucian-banner": "Business Apps",
    "handshake": "Business Apps",
    "tophat": "Collaboration",
    # v0.9.3: sales & marketing platforms missed in earlier passes
    "d365-marketing": "Business Apps",
    "sfmc": "Business Apps",
    "kartra": "Business Apps",
    "emma": "Email",
    "icontact": "Email",
    "mailerlite": "Email",
    # v0.9.3: infrastructure verification tokens (netlify already
    # mapped in Cloud above via the main fingerprint block; wpengine
    # is new; vmware-cloud is new)
    "wpengine": "Cloud",
    "vmware-cloud": "Cloud",
    # v0.9.3: nonprofit platforms
    "salesforce-npsp": "Business Apps",
    "blackbaud": "Business Apps",
    "classy": "Business Apps",
    # v1.5: surface-attribution slugs that should bucket as Cloud rather
    # than landing in the Business Apps fallback. AWS App Runner and
    # MuleSoft Anypoint are PaaS / iPaaS infrastructure; Cloudinary is a
    # media CDN; Apigee is an API gateway; AWS Global Accelerator is an
    # AWS networking service; Heroku and GitHub Pages are PaaS.
    "aws-app-runner": "Cloud",
    "aws-global-accelerator": "Cloud",
    "mulesoft": "Cloud",
    "cloudinary": "Cloud",
    "apigee": "Cloud",
    "cloudflare-pages": "Cloud",
    "github-pages": "Cloud",
    "heroku": "Cloud",
    "webflow": "Cloud",
    "sucuri": "Security",
    # Surface-attribution slugs that should bucket beyond Business Apps fallback.
    "intercom": "Collaboration",
    "submittable": "Collaboration",
    "pagerduty": "Security",
    "statuspage": "Collaboration",
    "betteruptime": "Collaboration",
    "bitly": "Business Apps",
    "shortio": "Business Apps",
    "unbounce": "Business Apps",
    "adobe-marketing": "Business Apps",
    "eloqua": "Business Apps",
    "pardot": "Business Apps",
    "wordpress-vip": "Cloud",
    "workos": "Identity",
    "beehiiv": "Business Apps",
    "docebo": "Collaboration",
    "skilljar": "Collaboration",
    "bizzabo": "Business Apps",
    "instatus": "Collaboration",
    "frontify": "Business Apps",
    "readme": "Collaboration",
    "swoogo": "Business Apps",
    "uptimerobot": "Collaboration",
    "blink": "Business Apps",
    "godaddy-email": "Email",
    "cloud-gov": "Cloud",
    "jobs2web": "Business Apps",
    "presspage": "Business Apps",
    "localist": "Collaboration",
    "rainfocus": "Business Apps",
    "aws-api-gateway": "Cloud",
    "aws-nlb": "Cloud",
    # v1.6.1 corpus run
    "paradox-ai": "Collaboration",
    "jibe": "Business Apps",
    "career-page": "Business Apps",
    "happydance": "Business Apps",
    "easyredir": "Business Apps",
    "gigya": "Identity",
    "f5-xc": "Cloud",
    "radware-cloud": "Security",
    "forgerock": "Identity",
    "ioriver": "Cloud",
    "section-io": "Cloud",
    "azion": "Cloud",
    "acquia": "Cloud",
    "pagely": "Cloud",
    "zuddl": "Business Apps",
    "postman-hosted": "Collaboration",
    "site24x7": "Collaboration",
    # v1.9.2.1 catalog growth from corpus-private/consolidated.txt scan.
    "akamai-eaa": "Security",
    "amplience": "Business Apps",
    "bigmarker": "Collaboration",
    "campuspress": "Collaboration",
    "certain-cvent": "Business Apps",
    "easydns": "Cloud",
    "edgetcdn-bitban": "Cloud",
    "edgio-cdn": "Cloud",
    "fanatics": "Business Apps",
    "fluid-topics": "Collaboration",
    "fortiweb-cloud": "Security",
    "framer": "Business Apps",
    "gandi-webredir": "Cloud",
    "gatsby-events": "Collaboration",
    "gitbook": "Collaboration",
    "hostinger-email": "Email",
    "ionos": "Cloud",
    "kinsta": "Cloud",
    "lumen-cdn": "Cloud",
    "medianova-cdn": "Cloud",
    "merlincdn": "Cloud",
    "mintlify": "Collaboration",
    "movable-ink": "Business Apps",
    "prowly": "Business Apps",
    "q4-ir": "Business Apps",
    "rackspace-email": "Email",
    "refined-site": "Collaboration",
    "sap-commerce": "Business Apps",
    "stova-aventri": "Collaboration",
    "talentera": "Business Apps",
    "terminus-sigstr": "Business Apps",
    "tistory": "Business Apps",
    "tumblr": "Business Apps",
    "uberflip": "Business Apps",
    "weglot": "Collaboration",
    "wordpress-com": "Business Apps",
}

# Email service-name prefixes that bypass slug lookup. These catch
# DNS-derived service labels like "DMARC", "DKIM", "SPF: strict (-all)",
# "MTA-STS", "BIMI" which don't have a matching fingerprint slug.
_EMAIL_SERVICE_PREFIXES: tuple[str, ...] = (
    "DMARC",
    "DKIM",
    "SPF",
    "MTA-STS",
    "BIMI",
    "TLS-RPT",
    "Exchange Autodiscover",  # v0.9.3: M365 autodiscover infrastructure
    "Autodiscover",
)

# v0.9.3 refinement: service entries that are verification receipts,
# domain-ownership tokens, or registrar artefacts rather than deployed
# products. These get filtered out of the categorized Services block
# because showing "Google (site verified)" alongside "Google Workspace"
# reads as if the org uses two Google products when actually it's the
# same Search Console verification token counted twice.
_FILTERED_SERVICE_SUFFIXES: tuple[str, ...] = (
    "(site verified)",
    "(domain verified)",
    "(verification)",
)
_FILTERED_SERVICE_PREFIXES: tuple[str, ...] = (
    "Domain Connect",  # registrar handoff metadata, not a deployed product
)

# v0.9.3 refinement: qualifier map for Cloud-category services. Without
# this, "AWS Route 53" under "Cloud" reads as "primary cloud = AWS",
# which is almost always wrong — Route 53 is authoritative DNS, not
# compute. The qualifier makes the service type explicit so a CISO
# scanning the output can't accidentally confuse DNS hosting with a
# cloud compute / storage platform.
#
# Values:
#   "DNS"   — authoritative DNS hosting only
#   "CDN"   — content delivery / edge network
#   "WAF"   — web application firewall
#   "edge"  — edge compute / JAMstack platforms
_CLOUD_SLUG_QUALIFIERS: dict[str, str] = {
    # DNS hosting
    "aws-route53": "DNS",
    "azure-dns": "DNS",
    "gcp-dns": "DNS",
    # CDN
    "aws-cloudfront": "CDN",
    "azure-cdn": "CDN",
    "akamai": "CDN",
    "fastly": "CDN",
    "cloudflare": "CDN",
    "cdn77": "CDN",
    "bunnycdn": "CDN",
    # WAF
    "imperva": "WAF",
    # Edge / serverless / JAMstack
    "vercel": "edge",
    "netlify": "edge",
    "flyio": "edge",
    "railway": "edge",
    "render": "edge",
    # v0.9.3: hosting provider detected via A → PTR reverse DNS.
    # The "(hosting)" qualifier disambiguates from CDN / DNS
    # entries so a CISO reading the Cloud row can tell at a glance
    # which services are delivering compute vs which are just
    # fronting traffic.
    "aws-ec2": "hosting",
    "aws-compute": "hosting",
    "azure-vm": "hosting",
    "gcp-compute": "hosting",
    "linode": "hosting",
    "digitalocean": "hosting",
    "hetzner": "hosting",
    "ovh": "hosting",
    "vultr": "hosting",
    # Non-DNS AWS / Azure / GCP — these ARE compute/storage so no suffix
    # (the raw name is enough — "AWS S3", "Azure App Service", …).
}

# v0.9.3 refinement: explicit display names for slugs whose
# corresponding fingerprint name is different, OR whose slug has no
# fingerprint entry at all. Without this, slugs like "google-managed"
# render as raw strings in the categorized services block.
_SLUG_DISPLAY_OVERRIDES: dict[str, str] = {
    "google-managed": "Google Workspace (managed identity)",
    "google-federated": "Google Workspace (federated identity)",
    # v0.9.3: hosting-provider slugs emitted by dns._detect_hosting_from_a_record.
    # These come from A → PTR reverse-DNS matching, not from the
    # regular fingerprints.yaml pipeline, so there's no fingerprint
    # name to fall back to. Give them explicit user-facing names
    # here. The per-run region (e.g. "ca-central-1") is preserved
    # in the evidence record's raw_value, visible via --explain /
    # --json. The default panel shows the provider only, to keep
    # the Cloud row compact.
    "aws-ec2": "AWS EC2",
    "aws-compute": "AWS",
    "aws-elb": "AWS ELB",
    "azure-vm": "Azure VM",
    "gcp-compute": "GCP Compute Engine",
    "linode": "Linode",
    "digitalocean": "DigitalOcean",
    "hetzner": "Hetzner",
    "ovh": "OVH",
    "vultr": "Vultr",
    # v0.9.3: identity-hub slugs emitted by
    # dns._detect_idp_hub. These don't have fingerprint entries
    # so the raw slug would leak into the Identity row without
    # an explicit override.
    "federated-sso-hub": "SSO hub",
    "okta-sso-hub": "Okta SSO hub",
    "adfs-sso-hub": "ADFS SSO hub",
    # v0.9.3: Exchange on-prem / hybrid slug emitted by
    # dns._detect_exchange_onprem. No fingerprint backs it —
    # the display override is how the Email-row entry gets a
    # human-readable name.
    "exchange-onprem": "Exchange Server (on-prem / hybrid)",
}


def _pick_single_primary(joined: str) -> tuple[str, list[str]]:
    """Split a ``" + "``-joined provider string into one primary and
    one or more secondaries.

    When ``likely_primary_email_provider`` carries multiple names
    (e.g. ``"Google Workspace + Microsoft 365"`` because DKIM
    selectors for both were observed), the panel previously read as
    ambiguous "dual" email. That was overclaim — the same DNS
    footprint fits a single primary with legacy selectors just as
    well. This helper picks one primary and demotes the others to
    secondary so the panel reads unambiguously.

    Selection rule: prefer Microsoft 365 first (the most common
    enterprise primary in practice), then Google Workspace, then the
    original list order. Deterministic and documented so users can
    re-derive it.
    """
    if " + " not in joined:
        return joined, []
    parts = [p.strip() for p in joined.split(" + ") if p.strip()]
    if not parts:
        return joined, []
    preference = ["Microsoft 365", "Google Workspace", "Zoho Mail", "ProtonMail"]
    for pref in preference:
        if pref in parts:
            secondaries = [p for p in parts if p != pref]
            return pref, secondaries
    return parts[0], parts[1:]


def detect_provider(
    services: tuple[str, ...] | set[str],
    slugs: tuple[str, ...] | set[str] = (),
    primary_email_provider: str | None = None,
    email_gateway: str | None = None,
    likely_primary_email_provider: str | None = None,
    has_mx_records: bool = True,
    email_confirmed_slugs: frozenset[str] | None = None,
) -> str:
    """Detect and format the provider line with email topology awareness.

    Target format (v0.9.3 rewrite):
      - ``Microsoft 365 (primary) via Proofpoint gateway`` — strict primary + gateway
      - ``Microsoft 365 (primary) via Trend Micro gateway + Google Workspace (secondary)``
        — primary + gateway + a separately detected secondary
      - ``Microsoft 365 (primary)`` — strict primary, no gateway
      - ``Microsoft 365 (likely primary) via Trend Micro gateway`` — inferred primary
      - ``Proofpoint gateway (no inferable downstream)`` — gateway only, unknown downstream
      - ``Microsoft 365; Google Workspace`` — slug-only fallback

    The critical change from pre-v0.9.3: when
    ``likely_primary_email_provider`` lists multiple providers (e.g.
    ``"Google Workspace + Microsoft 365"``), one is promoted to the
    single primary and the rest become ``"(secondary)"`` — never
    ``"(dual)"``. The old format implied ambiguous active dual-use
    which is usually wrong on enterprise targets. See
    ``_pick_single_primary`` for the selection rule.

    Falls back to slug-based detection when topology fields are all
    None (backward compatible).
    """
    # v0.9.3: Exchange on-prem / hybrid detection is a strong
    # signal that the domain's email goes to a self-hosted
    # Exchange cluster, regardless of what the identity-endpoint
    # sources say about dormant Google / Microsoft 365 accounts.
    # When the exchange-onprem slug is present AND there's no
    # MX-backed primary provider, surface "Exchange Server
    # (on-prem / hybrid)" as the primary and treat any
    # slug-based M365 / Google signals as secondary account
    # registrations. This catches cases like vatican.va where
    # the real answer is "runs Exchange on their own servers"
    # but the tool was labelling it "Google Workspace".
    slug_set_early = set(slugs)
    if "exchange-onprem" in slug_set_early and not primary_email_provider:
        if "microsoft365" in slug_set_early:
            # Exchange autodiscover + M365 tenant = Microsoft 365 (cloud
            # or hybrid). M365 is the platform; autodiscover is just an
            # endpoint. Don't lead with "Exchange Server (on-prem)".
            primary_segment = "Microsoft 365"
            if email_gateway:
                primary_segment = f"{primary_segment} via {email_gateway} gateway"
            segments = [primary_segment]
            if "google-workspace" in slug_set_early:
                segments.append("Google Workspace (account detected)")
            return " + ".join(segments)
        # Genuinely on-prem Exchange — no M365 tenant found
        other_accounts: list[str] = []
        if "google-workspace" in slug_set_early:
            other_accounts.append("Google Workspace")
        primary_segment = "Exchange Server (on-prem / hybrid)"
        if email_gateway:
            primary_segment = f"{primary_segment} behind {email_gateway} gateway"
        segments = [primary_segment]
        for acct in other_accounts:
            segments.append(f"{acct} (account detected)")
        return " + ".join(segments)

    # If we have topology data, use it
    if primary_email_provider or email_gateway or likely_primary_email_provider:
        primary_name: str | None = None
        primary_label: str = ""
        inferred_secondaries: list[str] = []

        if primary_email_provider:
            primary_name, inferred_secondaries = _pick_single_primary(primary_email_provider)
            primary_label = "(primary)"
        elif likely_primary_email_provider:
            primary_name, inferred_secondaries = _pick_single_primary(likely_primary_email_provider)
            primary_label = "(likely primary)"

        # Collect slug-based secondaries — providers detected via TXT
        # or DKIM but not already in the primary line.
        slug_set = set(slugs)
        slug_secondaries: list[str] = []
        for slug, name in [
            ("microsoft365", "Microsoft 365"),
            ("google-workspace", "Google Workspace"),
            ("zoho", "Zoho Mail"),
            ("protonmail", "ProtonMail"),
        ]:
            if slug in slug_set:
                if primary_name and name == primary_name:
                    continue
                if name in inferred_secondaries:
                    continue
                # v0.10.1: only show slug-based secondary if confirmed
                # via email routing (MX or DKIM). Account-only detections
                # (OIDC, TXT tokens) are noise in the Provider line.
                if email_confirmed_slugs is not None and slug not in email_confirmed_slugs:
                    continue
                slug_secondaries.append(name)

        # Full secondary list combines the two sources, deduped.
        all_secondaries: list[str] = []
        for n in inferred_secondaries + slug_secondaries:
            if n not in all_secondaries:
                all_secondaries.append(n)

        segments: list[str] = []
        if primary_name:
            head = f"{primary_name} {primary_label}".strip()
            if email_gateway:
                head = f"{head} via {email_gateway} gateway"
            segments.append(head)
        elif email_gateway:
            segments.append(f"{email_gateway} gateway (no inferable downstream)")

        for sec in all_secondaries:
            segments.append(f"{sec} (secondary)")

        if segments:
            return " + ".join(segments)
        return "Unknown (no known provider pattern matched)"

    # Fallback: slug-based detection with v0.9.3 honesty constraint.
    #
    # This path runs when primary_email_provider, email_gateway,
    # and likely_primary_email_provider are ALL None — which means
    # the merge pipeline didn't find an MX record matching a known
    # provider slug. Two very different situations land here:
    #
    #   (a) The domain has NO MX records at all. The provider slug
    #       was added by a non-MX source (Google Identity Routing
    #       endpoint, Microsoft OIDC discovery, TXT verification
    #       tokens). Calling this "(primary)" was the v0.9.2 bug —
    #       a dormant Google Workspace account registration was
    #       rendered as "Google Workspace (primary)" on a domain
    #       with zero MX records. The honest label here is
    #       "(account detected, no MX)".
    #
    #   (b) The domain HAS MX records but they point to a host
    #       recon doesn't recognize — Apache's own mail servers,
    #       a custom self-hosted Postfix, a niche provider not in
    #       the fingerprint set. Calling this "(account detected,
    #       no MX)" is ALSO a lie — MX records exist, email IS
    #       being received, the tool just can't name the host.
    #       The honest label here is "(account detected, custom
    #       MX)".
    #
    # Callers that know whether MX records exist pass
    # has_mx_records accordingly; the default is True (the
    # conservative choice — avoids over-promising "no MX" when
    # we don't know).
    slug_set = set(slugs)
    providers = []
    if "microsoft365" in slug_set:
        providers.append("Microsoft 365")
    if "google-workspace" in slug_set:
        providers.append("Google Workspace")
    if "zoho" in slug_set:
        providers.append("Zoho Mail")
    if "protonmail" in slug_set:
        providers.append("ProtonMail")
    if not providers and "aws-ses" in slug_set:
        providers.append("AWS SES")
    if providers:
        qualifier = "account detected, no MX" if not has_mx_records else "account detected, custom MX"
        return " + ".join(f"{p} ({qualifier})" for p in providers)
    # C2: when nothing matches any known provider, distinguish "we have no
    # idea" from "MX observed but custom/self-hosted" when possible. The
    # caller only has slugs here, so the best we can do is return a hint
    # that invites the user to run --explain to see what was actually
    # queried. "Unknown" stays as the word so the existing panel colour
    # and alignment aren't disturbed.
    return "Unknown (no known provider pattern matched)"


def _wrap_service_list(
    services: list[str],
    label_width: int = 14,
    panel_width: int = 80,
    panel_pad: int = 2,
) -> str:
    """Join services with comma-separation, wrapping lines to align under the label.

    The available content width inside a Rich Panel is:
        panel_width - 2 (border chars) - 2 * panel_pad (left + right padding)

    The first line starts after the label (e.g. "  Services:   "), so it has
    fewer chars available than continuation lines.  Continuation lines are
    indented with spaces so text aligns with the first service name.
    """
    content_width = panel_width - 2 - 2 * panel_pad
    # First line: "  " prefix + label already consumed by caller
    first_line_max = content_width - 2 - label_width
    # Continuation lines: indented by label_width (no "  " prefix needed)
    cont_line_max = content_width - label_width
    continuation_indent = " " * label_width

    joined = ", ".join(services)
    # If it fits on one line, just return it
    if len(joined) <= first_line_max:
        return joined

    # Word-wrap at comma boundaries.
    # Account for trailing comma (1 char) on non-final lines when checking fit.
    lines: list[str] = []
    current_line = ""
    for svc in services:
        candidate = svc if not current_line else f"{current_line}, {svc}"
        limit = first_line_max if not lines else cont_line_max
        # Reserve 1 char for the trailing comma on non-final lines
        if current_line and len(candidate) + 1 > limit:
            lines.append(current_line + ",")
            current_line = svc
        else:
            current_line = candidate
    if current_line:
        lines.append(current_line)

    return ("\n" + continuation_indent).join(lines)


def _wrap_text(text: str, max_width: int) -> list[str]:
    """Word-wrap a plain text string to fit within max_width characters."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if len(candidate) > max_width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [text]


def _slug_for_service(service: str, fp_slug_map: dict[str, str]) -> str | None:
    """Look up the slug for a service name, if any.

    Uses the fingerprint name → slug map. Prefix-stripped variants
    (``"Google Workspace: Gmail"`` → ``"google-workspace"``) are also
    tried so module-suffixed services classify with their parent.
    """
    if service in fp_slug_map:
        return fp_slug_map[service]
    # Strip "Google Workspace: " and similar module prefixes
    for prefix in ("Google Workspace: ", "Microsoft 365: "):
        if service.startswith(prefix):
            return fp_slug_map.get(service[: len(prefix) - 2])
    return None


def _categorize_service(service: str, slug: str | None) -> str:
    """Classify a service into one of _SERVICE_CATEGORIES_ORDER.

    Classification rules (first match wins):
        1. Slug lookup via _CATEGORY_BY_SLUG
        2. Email prefix match (DMARC, DKIM, SPF, …)
        3. Category-name substring match (for services whose name
           carries a category hint like "DNS: Cloudflare")
        4. Fallback: "Business Apps"
    """
    if slug and slug in _CATEGORY_BY_SLUG:
        return _CATEGORY_BY_SLUG[slug]
    for prefix in _EMAIL_SERVICE_PREFIXES:
        if service.startswith(prefix):
            return "Email"
    lower = service.lower()
    # Structural hints baked into service names by the DNS parser
    if lower.startswith(("dns:", "cdn:", "hosting:", "waf:")):
        return "Cloud"
    if "google workspace" in lower or "microsoft 365" in lower:
        return "Email"
    if "identity" in lower or "idp" in lower:
        return "Identity"
    if "security" in lower or "endpoint" in lower:
        return "Security"
    if "teams" in lower or "xmpp" in lower or "jabber" in lower or "slack" in lower:
        return "Collaboration"
    if "intune" in lower or "mdm" in lower:
        return "Identity"
    return "Business Apps"


def _categorize_services(info: TenantInfo) -> dict[str, list[str]]:
    """Group TenantInfo services into display categories.

    Two-pass classification:
        1. For each detected slug with a known category, resolve the
           slug to its fingerprint display name and file it under
           that category. This is the authoritative path — a slug's
           category is pinned in ``_CATEGORY_BY_SLUG``.
        2. For each remaining service (not yet filed via slug — e.g.
           DNS-derived labels like "DMARC", "DKIM", "SPF: strict"),
           classify by prefix / name pattern via
           ``_categorize_service``.

    Preserves input ordering within each category. Categories with
    no services are omitted from the returned dict.
    """
    try:
        fps = load_fingerprints()
        slug_to_name: dict[str, str] = {fp.slug: fp.name for fp in fps}
        name_to_slug: dict[str, str] = {fp.name: fp.slug for fp in fps}
    except Exception:
        slug_to_name = {}
        name_to_slug = {}

    def _is_artifact(name: str) -> bool:
        """Verification tokens and registrar handoffs — filtered out."""
        return any(name.endswith(suf) for suf in _FILTERED_SERVICE_SUFFIXES) or any(
            name.startswith(pfx) for pfx in _FILTERED_SERVICE_PREFIXES
        )

    by_cat: dict[str, list[str]] = {c: [] for c in _SERVICE_CATEGORIES_ORDER}
    seen_services: set[str] = set()
    slugs_filed: set[str] = set()  # slugs pass 1 has already filed

    # Pass 1: slug-authoritative classification. A detected slug with
    # a known category pulls in its canonical fingerprint display name.
    # v0.9.3 refinement: an explicit override in _SLUG_DISPLAY_OVERRIDES
    # wins over the fingerprint display name — this covers slugs like
    # "google-managed" that don't have a fingerprint entry. Cloud
    # services get a type qualifier ("(DNS)", "(CDN)", "(edge)") so
    # Route 53 doesn't read as a cloud-compute claim.
    for slug in info.slugs:
        cat = _CATEGORY_BY_SLUG.get(slug)
        if not cat:
            continue
        name = _SLUG_DISPLAY_OVERRIDES.get(slug) or slug_to_name.get(slug, slug)
        # Filter verification/registrar artefacts — these aren't
        # deployed products, they're ownership tokens.
        if _is_artifact(name):
            continue
        # v0.9.3 refinement: strip the "CAA: " prefix when rendering
        # a CAA-derived fingerprint under a non-Security category.
        # In Security the CAA consolidation collapses these into a
        # single "CAA: N issuers restricted" line; in Cloud / Email /
        # other categories the "CAA: " prefix leaks into the row
        # ("CAA: AWS Certificate Manager" in the Cloud row reads as
        # a products-detected claim). The actual detection mechanism
        # (CAA record → slug) belongs in --explain, not the name.
        if cat != "Security" and name.startswith("CAA: "):
            name = name[len("CAA: ") :]
        if cat == "Cloud":
            qualifier = _CLOUD_SLUG_QUALIFIERS.get(slug)
            if qualifier:
                name = f"{name} ({qualifier})"
        if name in seen_services:
            continue
        by_cat[cat].append(name)
        seen_services.add(name)
        slugs_filed.add(slug)

    # Pass 2: service names without a slug match — use prefix / name
    # classification. Skip services whose slug has already been filed
    # in pass 1 so we don't double-count the same detection under two
    # different display names (e.g. "Atlassian" and
    # "Atlassian (Jira/Confluence)" both mapping to slug "atlassian").
    # Defensive substring check covers the case where TenantInfo was
    # hand-built with abbreviated service names that don't round-trip
    # through name_to_slug.
    seen_lower_prefixes = {s.lower().split(" (")[0] for s in seen_services}
    for svc in info.services:
        if svc in seen_services:
            continue
        if _is_artifact(svc):
            continue
        svc_prefix = svc.lower().split(" (")[0]
        if svc_prefix in seen_lower_prefixes:
            continue
        slug = _slug_for_service(svc, name_to_slug)
        if slug and slug in slugs_filed:
            # Already covered under its canonical display name in pass 1
            continue
        cat = _categorize_service(svc, slug)
        by_cat.setdefault(cat, []).append(svc)
        seen_services.add(svc)
        seen_lower_prefixes.add(svc_prefix)

    # v0.9.3 refinement: drop Identity row entries that just echo an
    # Email provider. On a Google-only domain the Identity row
    # shows "Google Workspace (managed identity)" alongside the
    # Email row's "Google Workspace" — same fact in two places. The
    # Auth line already says "Managed (Google Workspace)", so the
    # Identity row adds nothing. Keep Identity entries that
    # represent a DISTINCT identity provider (Okta, Duo, CyberArk,
    # Ping) — only drop pure echoes of the email-provider family.
    email_provider_names = {n for n in by_cat.get("Email", []) if n}
    identity = by_cat.get("Identity", [])
    filtered_identity: list[str] = []
    for ident in identity:
        # Strip the "(managed identity)" / "(federated identity)"
        # suffix to compare with the email-provider name.
        ident_core = ident
        for suffix in (" (managed identity)", " (federated identity)"):
            if ident.endswith(suffix):
                ident_core = ident[: -len(suffix)]
                break
        # Drop when the core name is already in the Email row
        if ident_core in email_provider_names:
            continue
        filtered_identity.append(ident)
    by_cat["Identity"] = filtered_identity

    # v0.9.3 refinement: consolidate CAA issuer fingerprints.
    # Each "CAA: <issuer>" fingerprint fires as its own Security
    # entry, so a domain with four CAA record issuers ends up showing
    # "CAA: DigiCert, CAA: Google Trust Services, CAA: Let's Encrypt,
    # CAA: Sectigo" under Security — which overwhelms the row AND
    # misrepresents CAA records as deployed security tools. Collapse
    # them into one compact "CAA: N issuers restricted" entry. The
    # full issuer list is still available via --full / --verbose and
    # in the --json output; the default panel just shows the count so
    # the Security row's visual budget goes to actually-deployed
    # security tools first.
    security = by_cat.get("Security", [])
    caa_entries: list[str] = [s for s in security if s.startswith("CAA:")]
    if len(caa_entries) >= 1:
        non_caa = [s for s in security if not s.startswith("CAA:")]
        count = len(caa_entries)
        consolidated = f"CAA: {count} issuer{'s' if count != 1 else ''} restricted"
        by_cat["Security"] = [*non_caa, consolidated]

    # v0.10: infer bundled AI services from platform presence.
    # Copilot is bundled into M365, Gemini into Google Workspace.
    # These have no DNS fingerprint — they're invisible to passive
    # detection. But if the platform is present, the AI tool is
    # likely available. Hedge with "(likely)" to distinguish from
    # DNS-confirmed detections like Anthropic.
    ai_names = {n.lower() for n in by_cat.get("AI", [])}
    if "microsoft365" in info.slugs and "microsoft copilot" not in ai_names:
        by_cat.setdefault("AI", []).append("Microsoft Copilot (likely)")
    if "google-workspace" in info.slugs and "google gemini" not in ai_names:
        by_cat.setdefault("AI", []).append("Google Gemini (likely)")

    return {c: svcs for c in _SERVICE_CATEGORIES_ORDER if (svcs := by_cat.get(c))}


def _compact_email_summary(info: TenantInfo, email_services: list[str]) -> list[str]:
    """Build a short Email row when default deduplication removes everything.

    The default panel intentionally avoids a full protocol laundry list, but an
    empty Email row makes Microsoft/Google mail targets look sparse even when
    the lookup found solid email evidence. Keep one compact line with provider,
    gateway, and the main hardening controls.
    """
    service_set = set(email_services)
    summary: list[str] = []

    def _add(value: str | None) -> None:
        if value and value not in summary:
            summary.append(value)

    def _add_provider_list(value: str | None) -> None:
        if not value:
            return
        for part in value.split(" + "):
            _add(part.strip())

    _add_provider_list(info.primary_email_provider)
    if not summary:
        _add_provider_list(info.likely_primary_email_provider)
    if not summary:
        for provider in ("Microsoft 365", "Google Workspace", "Zoho Mail", "ProtonMail", "AWS SES"):
            if provider in service_set:
                _add(provider)

    _add(info.email_gateway)

    if info.dmarc_policy:
        _add(f"DMARC {info.dmarc_policy}")
    elif "DMARC" in service_set:
        _add("DMARC")

    if any(s.startswith("DKIM") for s in email_services):
        _add("DKIM")

    if any(s.startswith("SPF: strict") for s in email_services):
        _add("SPF strict")
    elif any(s.startswith("SPF: softfail") for s in email_services):
        _add("SPF softfail")

    if info.mta_sts_mode and info.mta_sts_mode != "none":
        _add(f"MTA-STS {info.mta_sts_mode}")
    elif "MTA-STS" in service_set:
        _add("MTA-STS")

    if "BIMI" in service_set:
        _add("BIMI")

    return summary


# High-signal subdomain prefixes for compact related-domain display.
# Tuned to match the v0.9.3 UI goal: the related line should fit in 1-2
# lines and show the names a security analyst cares about first.
_HIGH_SIGNAL_RELATED_PREFIXES: tuple[str, ...] = (
    "login.",
    "sso.",
    "auth.",
    "idp.",
    "api.",
    "admin.",
    "portal.",
    "dashboard.",
    "support.",
    "status.",
    "app.",
    "cdn.",
)


def _pick_high_signal_related(
    related: tuple[str, ...],
    limit: int = 8,
) -> tuple[list[str], int]:
    """Pick the top ``limit`` high-signal related domains.

    High-signal = matches one of the ``_HIGH_SIGNAL_RELATED_PREFIXES``.
    Falls back to the first ``limit`` non-wildcard entries when too
    few high-signal names are present. Returns a tuple of
    ``(picked, total_count)`` so callers can emit the "N total" footer.

    v0.9.3 refinement: ``*.onmicrosoft.com`` entries are filtered out.
    These are Microsoft 365 tenant artefacts — they appear in the
    related list because the user realm / autodiscover path surfaces
    them, but they carry no "related brand" signal. A CISO reading
    "high-signal related domains" doesn't want to see the tenant's
    own internal domain listed as if it were a separate discovery.
    """

    def _is_high_signal_candidate(d: str) -> bool:
        # Filter out tenant artefacts and wildcards
        if "*" in d:
            return False
        # .onmicrosoft.com and .onmicrosoft.us are M365 tenant
        # artefacts, not brand-related domains worth surfacing.
        return not d.endswith((".onmicrosoft.com", ".onmicrosoft.us"))

    non_wild = [d for d in related if _is_high_signal_candidate(d)]
    total = len(non_wild)
    high: list[str] = []
    for d in non_wild:
        first_label = d.split(".", 1)[0] + "."
        if any(d.startswith(pfx) or first_label == pfx for pfx in _HIGH_SIGNAL_RELATED_PREFIXES):
            high.append(d)
        if len(high) >= limit:
            break
    if len(high) < limit:
        for d in non_wild:
            if d in high:
                continue
            high.append(d)
            if len(high) >= limit:
                break
    return high, total


def _confidence_is_high(level: ConfidenceLevel) -> bool:
    """True only for HIGH — used by the disciplined color palette so
    Medium / Low never trigger alarmist coloring."""
    return level == ConfidenceLevel.HIGH


def render_tenant_panel(
    info: TenantInfo,
    show_services: bool = False,
    show_domains: bool = False,
    verbose: bool = False,
    explain: bool = False,
    confidence_mode: str = "hedged",
):  # -> rich renderable
    """Render TenantInfo as a plain-text hero layout (v0.9.3 redesign).

    Replaces the old bordered Panel with a flat, professional layout
    that foregrounds Services, keeps Related domains compact, and
    uses color sparingly and intelligently.

    Layout (default mode)
        Company name (bold, full width)
        apex.domain.com (dim)
        ──────────────────────────────── (dim horizontal rule)

        Provider     <detect_provider output>
        Tenant       <tenant_id> • <region>          (only if present)
        Auth         <auth_type> + <GWS auth>        (only if present)
        Confidence   ●●○ Medium (N sources)          (green only on High)

        Services                                     (bold cyan header)
          Email          svc, svc, svc
          Identity       svc, svc
          …

        High-signal related domains                  (bold cyan header)
          login.x, sso.x, api.x … (N total — use --full to see all)

        Note: …                                     (yellow only when degraded)

    --verbose, --explain, --domains add additional sections after the
    core layout without breaking its structure. The function name is
    preserved for backward compatibility — callers still pass its
    return value to ``console.print``.
    """
    from rich.console import Group

    # Core layout blocks are accumulated into a list and wrapped in a
    # Rich Group at the end. Each block is a Text instance so we can
    # style per-segment without fighting markup.
    blocks: list[Any] = []

    def _spacer() -> None:
        """Insert a blank line between sections to separate them visually."""
        blocks.append(Text(""))

    # ── Hero header ────────────────────────────────────────────────
    # v0.9.3 refinement: when display_name falls back to the raw
    # domain (no company name extractable), render it once as bold
    # instead of showing the same string twice.
    header = Text()
    header.append(info.display_name, style="bold")
    if info.default_domain and info.default_domain != info.display_name:
        header.append("\n")
        header.append(info.default_domain, style="dim")
    blocks.append(header)
    rule = Text("─" * _PANEL_WIDTH, style="dim")
    blocks.append(rule)

    # ── Key facts block ────────────────────────────────────────────
    facts = Text()

    def _field(label: str, value: str, value_style: str = "") -> None:
        """Emit one "  Label    value\\n" row, wrapping the value at
        the panel width with a continuation indent matching the
        label column. Without the explicit wrap, Rich auto-breaks
        long values mid-line and the continuation lands at column 0
        — which is what produced the ugly "Google \\nWorkspace" wrap
        on long Provider strings before v0.9.3."""
        indent_width = 2 + _LABEL_WIDTH  # "  " + label column
        max_width = _PANEL_WIDTH - indent_width
        lines = _wrap_text(value, max_width)
        for i, line in enumerate(lines):
            if i == 0:
                facts.append("  ")
                facts.append(label.ljust(_LABEL_WIDTH), style="dim")
            else:
                facts.append(" " * indent_width)
            facts.append(line, style=value_style)
            facts.append("\n")

    has_mx_records = any(e.source_type == "MX" for e in info.evidence)
    # v0.10.1: only show secondary providers confirmed via email routing
    email_confirmed_slugs = frozenset(e.slug for e in info.evidence if e.source_type in ("MX", "DKIM"))
    provider_line = detect_provider(
        info.services,
        info.slugs,
        primary_email_provider=info.primary_email_provider,
        email_gateway=info.email_gateway,
        likely_primary_email_provider=info.likely_primary_email_provider,
        has_mx_records=has_mx_records,
        email_confirmed_slugs=email_confirmed_slugs,
    )
    _field("Provider", provider_line)

    if info.tenant_id:
        tenant_line = info.tenant_id
        if info.region:
            tenant_line += f" • {info.region}"
        _field("Tenant", tenant_line)
    elif info.region:
        _field("Region", info.region)

    # Auth — combine M365 and GWS auth labels when both are present.
    # v0.9.3 refinement: when both auth_type and google_auth_type are
    # the same value (e.g. both "Managed"), collapse to one label with
    # the providers named in parentheses instead of repeating the word.
    # "Managed (Entra ID + Google Workspace)" reads cleaner than
    # "Managed + Managed (GWS)".
    #
    # v0.9.3 hardening: GetUserRealm returns NameSpaceType=Unknown for
    # domains that aren't real M365 tenants. That gets parsed into
    # auth_type="Unknown" which then leaked as "Unknown + Managed (GWS)"
    # on Google-only targets. Treat "Unknown" as effectively no auth
    # info at the display layer so the panel doesn't surface a
    # meaningless token.
    effective_auth: str | None = info.auth_type
    if effective_auth and effective_auth.strip().lower() == "unknown":
        effective_auth = None

    auth_parts: list[str] = []
    if effective_auth and info.google_auth_type:
        if effective_auth == info.google_auth_type:
            providers: list[str] = []
            # v0.9.3 hardening: only claim "Entra ID" when the
            # microsoft365 slug is actually detected. A tenant_id
            # from OIDC discovery is sometimes set on domains that
            # registered an Entra ID tenant but don't actively use
            # M365 as their identity / email provider (seen on a
            # Google-primary domain with a dormant MS tenant).
            # Saying "Entra ID" in that case is a confident-wrong
            # claim. Without the slug, fall back to the neutral
            # "Microsoft" label.
            if "microsoft365" in info.slugs:
                providers.append("Entra ID")
            else:
                providers.append("Microsoft")
            gws = "Google Workspace"
            if info.google_idp_name:
                gws += f" via {info.google_idp_name}"
            providers.append(gws)
            auth_parts.append(f"{effective_auth} ({' + '.join(providers)})")
        else:
            auth_parts.append(effective_auth)
            gws_label = info.google_auth_type
            if info.google_idp_name:
                gws_label += f" via {info.google_idp_name}"
            # v0.9.3 refinement: spell out "(Google Workspace)" so
            # the Auth line reads as natural language instead of
            # terminal shorthand. Previously this branch emitted
            # "(GWS)" while the same-auth collapsed branch emitted
            # the full name — inconsistent depending on whether
            # the two auth types happened to match.
            auth_parts.append(f"{gws_label} (Google Workspace)")
    elif effective_auth:
        auth_parts.append(effective_auth)
    elif info.google_auth_type:
        gws_label = info.google_auth_type
        if info.google_idp_name:
            gws_label += f" via {info.google_idp_name}"
        auth_parts.append(f"{gws_label} (Google Workspace)")
    if auth_parts:
        _field("Auth", " + ".join(auth_parts))

    # Sovereignty — only when cloud_instance indicates non-commercial
    if info.cloud_instance and "microsoftonline.com" not in info.cloud_instance.lower():
        sov_label = info.cloud_instance
        if info.tenant_region_sub_scope:
            sov_label += f" ({info.tenant_region_sub_scope})"
        _field("Cloud", sov_label)

    # Confidence — green only for High, default otherwise.
    dots = CONFIDENCE_DOTS[info.confidence]
    conf_value = f"{dots} {info.confidence.value.capitalize()} ({len(info.sources)} sources)"
    _field("Confidence", conf_value, value_style="green" if _confidence_is_high(info.confidence) else "")

    blocks.append(facts)

    # ── Services section ──────────────────────────────────────────
    if info.services:
        _spacer()
        svc_block = Text()
        svc_block.append("Services", style="bold")
        svc_block.append("\n")
        categorized = _categorize_services(info)
        # v0.10: in default mode, strip noise from Email row.
        # (1) Protocol/config entries (DKIM, DMARC, SPF, etc.) — the
        #     email security score insight already covers these.
        # (2) Provider-line services (Exchange, M365, Google Workspace,
        #     gateway) — already in the header. Repeating them in Email
        #     is saying the same thing twice.
        # If this would erase the entire Email row, keep a compact summary
        # instead so dense email evidence does not render as a sparse panel.
        # In --full mode, show everything.
        if not verbose and "Email" in categorized:
            original_email = list(categorized["Email"])
            _email_noise = {
                "DKIM",
                "DKIM (Exchange Online)",
                "DMARC",
                "MTA-STS",
                "BIMI",
                "TLS-RPT",
                "Exchange Autodiscover",
                "Microsoft 365",
                "Google Workspace",
                "Exchange Server (on-prem / hybrid)",
            }
            # Also strip the gateway — already in Provider line
            _gateway_names = {
                "Proofpoint",
                "Trend Micro Email Security",
                "Mimecast",
                "Barracuda Email Security",
            }
            _all_noise = _email_noise | _gateway_names
            categorized["Email"] = [s for s in categorized["Email"] if s not in _all_noise and not s.startswith("SPF")]
            if not categorized["Email"]:
                email_summary = _compact_email_summary(info, original_email)
                if email_summary:
                    categorized["Email"] = email_summary
                else:
                    del categorized["Email"]
        max_width = _CATEGORY_WIDTH
        for cat, svcs in categorized.items():
            svc_block.append("  ")
            svc_block.append(cat.ljust(max_width), style="dim")
            wrapped = _wrap_service_list(
                svcs,
                label_width=2 + max_width,
                panel_width=_PANEL_WIDTH,
                panel_pad=0,
            )
            svc_block.append(wrapped)
            svc_block.append("\n")

        # Default-mode-only: one extra line summarising services that the
        # CNAME-chain classifier attributed to subdomains. These are kept
        # separate from the apex Services categories above because apex
        # DNS evidence and subdomain CNAME-chain evidence answer different
        # questions and conflating them double-counts. --full users see
        # the full per-subdomain table further down the panel, so we
        # suppress the summary there to avoid redundancy.
        #
        # v1.9.3.10: the Subdomain summary now reports counts per provider
        # (e.g. ``AWS CloudFront (5), Fastly (3), Stripe (12)``) so the
        # multi-cloud picture is visible by default. The prior version
        # listed names without counts, which hid the fact that an apex on
        # one cloud has subdomains across several others. Sorted by count
        # descending so the dominant providers anchor the line.
        if info.surface_attributions and not show_domains:
            # Count per-name occurrences across surface attributions.
            # v1.9.3.10: deliberately NO apex-evidence filter. The
            # Subdomain line answers a different question from the Cloud
            # line above — "how many subdomains are hosted on which
            # provider" vs "what does the apex resolve to". When apex and
            # subdomains share a provider (e.g., apex on AWS Route 53,
            # 15 subdomains on AWS CloudFront), the prior version's
            # filter hid the subdomain counts because the AWS slug was
            # apex-evidenced. That collapsed the multi-cloud distribution.
            # Showing both surfaces with their distinct labels lets
            # operators see at a glance: where the apex sits AND how the
            # subdomain footprint is split across providers.
            name_counts: dict[str, int] = {}
            for sa in info.surface_attributions:
                # Only the *primary* attribution is counted per subdomain;
                # the infra tier (CDN fronting the primary) is the same
                # subdomain, not an additional one, so counting both
                # would double-attribute. Surface infra separately only
                # when there's no primary.
                name = sa.primary_name
                if not sa.primary_slug or not name:
                    name = sa.infra_name
                    if not sa.infra_slug or not name:
                        continue
                name_counts[name] = name_counts.get(name, 0) + 1

            if name_counts:
                # Sort by count descending, then name ascending for
                # diff-stable output on ties.
                ranked = sorted(name_counts.items(), key=lambda p: (-p[1], p[0]))
                # Render: "Name (N), Name (M), ..." — counts make
                # multi-cloud distribution visible at a glance.
                surface_summary = [
                    f"{name} ({count})" for name, count in ranked
                ]
                budget = _PANEL_WIDTH - (2 + max_width) - 2
                joined = ", ".join(surface_summary)
                if len(joined) > budget:
                    # Pack as many fit, reserving room for "+N more".
                    kept: list[str] = []
                    running = 0
                    for s in surface_summary:
                        gap = 2 if kept else 0
                        if running + gap + len(s) > budget - 12:
                            break
                        kept.append(s)
                        running += gap + len(s)
                    remaining = len(surface_summary) - len(kept)
                    joined = (
                        ", ".join(kept) + f", +{remaining} more"
                        if remaining > 0
                        else ", ".join(kept)
                    )
                svc_block.append("  ")
                svc_block.append("Subdomain".ljust(max_width), style="dim")
                svc_block.append(joined)
                svc_block.append("\n")

        blocks.append(svc_block)

    # ── Related domains (compact) ─────────────────────────────────
    if info.related_domains and not show_domains:
        picked, total = _pick_high_signal_related(tuple(info.related_domains))
        if picked:
            _spacer()
            rel = Text()
            rel.append("High-signal related domains", style="bold")
            rel.append("\n")
            rel.append("  ")
            # Render as wrapped comma-list within the panel width
            joined = ", ".join(picked)
            max_width = _PANEL_WIDTH - 2
            for j, line in enumerate(_wrap_text(joined, max_width)):
                if j > 0:
                    rel.append("\n  ")
                rel.append(line, style="dim")
            if total > len(picked):
                remaining = total - len(picked)
                rel.append(
                    f"\n  ({total} total — {remaining} more, use --full to see all)",
                    style="dim italic",
                )
            blocks.append(rel)

    # ── Unclassified surface (default panel; v1.9.3.10) ───────────
    # The chain walker reached CNAME termini that the catalog could
    # not classify. Surface the count + a sample so the operator
    # knows we walked something interesting but couldn't name it.
    # The implicit message of the default panel was "they only use
    # the services we listed" — this corrects it to "they use AT
    # LEAST the services we listed, plus N unclassified surfaces".
    # Humility over completeness: hide the gap is the worst-case
    # failure mode, since absence of evidence reads as evidence of
    # absence to operators who don't know recon's invariants.
    if info.unclassified_cname_chains and not show_domains:
        _spacer()
        unc = Text()
        n = len(info.unclassified_cname_chains)
        noun = "terminus" if n == 1 else "termini"
        unc.append("Unclassified surface", style="bold")
        unc.append("\n  ")
        unc.append(
            f"{n} CNAME chain {noun} reached, no fingerprint match. ",
            style="dim",
        )
        unc.append(
            "We walked them but cannot name them — open a fingerprint PR or run\n  ",
            style="dim",
        )
        unc.append(
            f"`recon discover {info.queried_domain}` to triage candidates.",
            style="dim italic",
        )
        # Show up to 2 representative subdomain → terminus pairs so the
        # operator can sanity-check what's getting missed. More than 2
        # would crowd the default panel; --full / `recon discover` is
        # the path to the complete list.
        examples = list(info.unclassified_cname_chains[:2])
        if examples:
            unc.append("\n  ", style="dim")
            unc.append("examples: ", style="dim")
            sample_strs: list[str] = []
            for uc in examples:
                terminus = uc.chain[-1] if uc.chain else "(no terminus)"
                sample_strs.append(f"{uc.subdomain} → {terminus}")
            unc.append(", ".join(sample_strs), style="dim italic")
        blocks.append(unc)

    # ── Full tenant_domains listing (only with --domains / --full) ─
    if show_domains and info.tenant_domains:
        _spacer()
        dom = Text()
        dom.append(f"Domains ({info.domain_count})", style="bold")
        dom.append("\n")
        for d in info.tenant_domains:
            dom.append(f"  {d}\n", style="dim")
        blocks.append(dom)

    # Full related list when --domains / --full
    if show_domains and info.related_domains:
        _spacer()
        rel = Text()
        rel.append("Related domains", style="bold")
        rel.append("\n")
        rel.append("  ")
        joined = ", ".join(info.related_domains)
        for j, line in enumerate(_wrap_text(joined, _PANEL_WIDTH - 2)):
            if j > 0:
                rel.append("\n  ")
            rel.append(line, style="dim")
        blocks.append(rel)

    # External surface section: per-subdomain attributions from CNAME chains.
    # Two-column layout (subdomain, primary service name) sorted alphabetically
    # by subdomain. No arrows or decorative characters — the gutter does the
    # separating. Default panel hides this; --full / --domains shows it because
    # only operators investigating the external footprint care about the map.
    if show_domains and info.surface_attributions:
        _spacer()
        surf = Text()
        surf.append(f"External surface ({len(info.surface_attributions)})", style="bold")
        surf.append("\n")

        # Group attributions by primary service. Services with many
        # attributions (typically an apex's primary CDN — Fastly fronts 54 of
        # kayak.com's subdomains, Cloudflare 51 of bamboohr.com's) are
        # collapsed to a single block to keep the section scannable. Services
        # with only a handful are shown one-per-line, which preserves the
        # "what is this URL serving" answer for low-frequency findings.
        _COLLAPSE_THRESHOLD = 5
        from collections import defaultdict as _dd

        groups: dict[str, list[Any]] = _dd(list)
        for sa in info.surface_attributions:
            groups[sa.primary_name].append(sa)

        individuals: list[Any] = []
        collapsed: list[tuple[str, list[Any]]] = []
        for service_name, sas in groups.items():
            if len(sas) >= _COLLAPSE_THRESHOLD:
                collapsed.append((service_name, sorted(sas, key=lambda s: s.subdomain)))
            else:
                individuals.extend(sas)

        individuals.sort(key=lambda s: s.subdomain)
        # Largest collapse blocks first — most important to know about.
        collapsed.sort(key=lambda t: -len(t[1]))

        # Column width derived from longest individual subdomain. Min 24
        # so short panels don't crowd; max _PANEL_WIDTH - 30 so long ones
        # don't push the service column off-screen.
        if individuals:
            ind_max = max(len(s.subdomain) for s in individuals)
            col_width = max(24, min(ind_max, _PANEL_WIDTH - 30))
        else:
            col_width = 24

        for sa in individuals:
            sub = sa.subdomain
            if len(sub) > col_width:
                sub = sub[: col_width - 2] + ".."
            # Layered display: when the CNAME chain matched both an
            # application-tier and an infrastructure-tier service (e.g.,
            # Auth0 fronted by Cloudflare), list both.
            services_label = sa.primary_name
            if sa.infra_name:
                services_label = f"{sa.primary_name}, {sa.infra_name}"
            surf.append("  ")
            surf.append(f"{sub:<{col_width}}", style="dim")
            surf.append("  ")
            surf.append(services_label)
            surf.append("\n")

        # Collapsed groups appear after individual rows. One header line per
        # service, followed by the wrapped list of subdomains (with apex
        # stripped to the short label so the wrap fits more per line).
        if collapsed:
            if individuals:
                surf.append("\n")
            apex = info.queried_domain
            for service_name, sas in collapsed:
                surf.append("  ")
                surf.append(f"{service_name} ({len(sas)})", style="bold")
                surf.append("\n")
                short_names: list[str] = []
                for s in sas:
                    sub = s.subdomain
                    # Strip the apex suffix to a bare label (``app`` instead of
                    # ``app.contoso.com``) so the wrapped line fits more.
                    if sub.endswith("." + apex):
                        sub = sub[: -(len(apex) + 1)]
                    elif sub == apex:
                        sub = "(apex)"
                    short_names.append(sub)
                joined = ", ".join(short_names)
                for line in _wrap_text(joined, _PANEL_WIDTH - 4):
                    surf.append("    ")
                    surf.append(line, style="dim")
                    surf.append("\n")

        # Discovery-loop hint: when there are unclassified CNAME chains the
        # surface classifier resolved but couldn't attribute, surface a
        # one-liner inviting the user into the catalog-growth loop. Default
        # panel doesn't get this — only --full / --domains, where the user
        # is already engaged with the surface map.
        if info.unclassified_cname_chains:
            n = len(info.unclassified_cname_chains)
            noun = "subdomain" if n == 1 else "subdomains"
            surf.append("\n  ")
            surf.append(
                f"{n} unclassified {noun} — `recon discover {info.queried_domain}` to surface fingerprint candidates",
                style="dim italic",
            )
            surf.append("\n")

        blocks.append(surf)

    # ── Insights (curated) ────────────────────────────────────────
    if info.insights:
        curated: list[str] = _curate_insights(info.insights, info.services, info.slugs)
        # v0.11: strict confidence mode drops hedging qualifiers when the
        # evidence is dense (High confidence + 3+ sources). Sparse-data
        # output is never touched — the "never overclaim on thin evidence"
        # invariant stays load-bearing.
        from recon_tool.strict_mode import apply_strict_mode, should_apply_strict

        if should_apply_strict(info, confidence_mode):
            curated = list(apply_strict_mode(tuple(curated)))
        if curated:
            _spacer()
            ins = Text()
            ins.append("Insights", style="bold")
            ins.append("\n")
            max_width = _PANEL_WIDTH - 2

            # Promote the email security score to first position (bold).
            score_line: str | None = None
            sparse_insights: list[str] = []
            other_insights: list[str] = []
            for c in curated:
                if c.startswith("Email security ") and score_line is None:
                    score_line = c
                elif _is_sparse_insight(c):
                    sparse_insights.append(c)
                else:
                    other_insights.append(c)

            if score_line is not None:
                for j, line in enumerate(_wrap_text(score_line, max_width)):
                    ins.append("  " if j == 0 else "\n  ")
                    ins.append(line, style="bold")
                ins.append("\n")

            ordered_insights = sparse_insights + other_insights

            # Cap at 5 insights in default mode; --full/--verbose shows all
            display_insights = ordered_insights
            overflow_count = 0
            if not verbose and len(ordered_insights) > 5:
                display_insights = ordered_insights[:5]
                overflow_count = len(ordered_insights) - 5

            for insight in display_insights:
                for j, line in enumerate(_wrap_text(insight, max_width)):
                    ins.append("  " if j == 0 else "\n  ")
                    ins.append(line, style="dim")
                ins.append("\n")

            if overflow_count > 0:
                ins.append("  ")
                ins.append(
                    f"{overflow_count} more — use --full to see all",
                    style="dim italic",
                )
                ins.append("\n")

            blocks.append(ins)

    # ── Certificate summary (only with --verbose or --full) ───────
    if verbose and info.cert_summary is not None:
        _spacer()
        cs = info.cert_summary
        issuer_list = ", ".join(cs.top_issuers) if cs.top_issuers else "unknown"
        certs = Text()
        certs.append("Certs", style="bold")
        certs.append("\n  ")
        certs.append(
            f"{cs.cert_count} total, {cs.issuance_velocity} in last 90d, {cs.issuer_diversity} issuers ({issuer_list})",
            style="dim",
        )
        blocks.append(certs)

    # ── Degraded-sources note (subtle color) ─────────────────────
    # Two tiers of framing:
    #
    # (1) **Info tone** (default, no color) — when only CT sources
    #     are degraded AND the fallback chain successfully reached
    #     another provider. The user should see that a fallback
    #     happened and which provider answered, but it reads as a
    #     routine event, not a warning. Previously this case was
    #     painted yellow and framed as "Some sources unavailable",
    #     which made successful fallback runs look broken.
    #
    # (2) **Warning tone** (yellow) — when a non-CT source is
    #     unavailable OR when every CT provider failed (no
    #     fallback recovery). This is the case where the user's
    #     data is actually incomplete.
    if info.degraded_sources:
        non_ct_degraded = [s for s in info.degraded_sources if s not in ("crt.sh", "certspotter")]
        ct_in_degraded = [s for s in info.degraded_sources if s in ("crt.sh", "certspotter")]
        ct_fallback_succeeded = bool(ct_in_degraded) and info.ct_provider_used is not None
        ct_fallback_failed = bool(ct_in_degraded) and info.ct_provider_used is None
        ct_from_cache = info.ct_cache_age_days is not None
        # v0.9.3 refinement: suppress the "CT fallback: … → … (0
        # subdomains)" line entirely. When the fallback succeeded
        # but returned zero subdomains, the outcome is identical
        # to what the user would see on a clean run of a domain
        # with no related CT data. Mentioning the fallback on
        # every such run is noise — it turns crt.sh's current
        # flakiness into a persistent footer. We only surface
        # the fallback when it actually changed the answer
        # (returned at least one subdomain). If the user needs
        # per-run CT provenance they have --json which always
        # carries ct_provider_used and ct_subdomain_count.
        ct_fallback_informative = ct_fallback_succeeded and info.ct_subdomain_count > 0

        is_warning = bool(non_ct_degraded) or ct_fallback_failed
        label_style = "yellow" if is_warning else "dim"
        body_style = "yellow" if is_warning else "dim"

        note_parts: list[str] = []
        if non_ct_degraded:
            note_parts.append(f"Some sources unavailable ({', '.join(non_ct_degraded)})")
        if ct_fallback_failed:
            note_parts.append(f"All CT providers unavailable ({', '.join(ct_in_degraded)})")
        elif ct_from_cache and ct_fallback_informative:
            # Cache fallback is worth surfacing — the user is seeing stale data
            age = info.ct_cache_age_days
            age_str = "today" if age == 0 else f"{age} day{'s' if age != 1 else ''} old"
            note_parts.append(f"CT: from local cache, {age_str} ({info.ct_subdomain_count} subdomains)")
        # Suppress routine CT fallback notes (crt.sh → certspotter) —
        # infrastructure plumbing that adds noise on nearly every run.
        # CT provenance is always available in --json output.

        if note_parts:
            _spacer()
            note = Text()
            note.append("Note", style=label_style)
            note.append("\n  ")
            note_text = " — ".join(note_parts) + "."
            for j, line in enumerate(_wrap_text(note_text, _PANEL_WIDTH - 2)):
                if j > 0:
                    note.append("\n  ")
                note.append(line, style=body_style)
            blocks.append(note)

    # ── Verbose sections: dual confidence + detection scores + chain
    if verbose:
        _spacer()
        v = Text()
        v.append("Evidence Detail", style="bold")
        v.append("\n")
        v.append(
            f"  Evidence confidence:  {info.evidence_confidence.value.capitalize()}\n",
            style="dim",
        )
        v.append(
            f"  Inference confidence: {info.inference_confidence.value.capitalize()}\n",
            style="dim",
        )
        if info.detection_scores:
            v.append("  Detection scores:\n", style="dim")
            for slug, score in info.detection_scores:
                v.append(f"    {slug}: {score}\n", style="dim")
        if info.evidence:
            v.append("  Evidence chain:\n", style="dim")
            for ev in info.evidence:
                v.append(f"    [{ev.source_type}] {ev.rule_name} -> {ev.slug}\n", style="dim")
        blocks.append(v)

    # ── Explain mode: conflict annotations ────────────────────────
    if explain and info.merge_conflicts and info.merge_conflicts.has_conflicts:
        _spacer()
        conf_block = Text()
        conf_block.append("Conflicts", style="bold")
        conf_block.append("\n")
        for field_name in ("display_name", "auth_type", "region", "tenant_id", "dmarc_policy"):
            ann = render_conflict_annotation(field_name, info.merge_conflicts, verbose=verbose)
            if ann:
                conf_block.append(f"  {field_name}: {ann}\n", style="dim")
        blocks.append(conf_block)

    return Group(*blocks)


def _curate_insights(
    insights: tuple[str, ...],
    services: tuple[str, ...],
    slugs: tuple[str, ...],
) -> list[str]:
    """Filter and deduplicate insights for the v0.9.3 default panel.

    Two kinds of cleanup:

    1. **Drop laundry-list dumps.** Prefixes like ``"Security stack:"``,
       ``"Infrastructure:"``, ``"PKI:"``, and
       ``"Google Workspace modules:"`` all duplicate information that
       the Services block already shows in a categorized, deduped
       form. Low-signal organizational-size hints
       (``"mid-size organization"``, ``"domains in tenant"``) read as
       padding and add nothing.

    2. **Collapse overlapping signal families.** Real runs often
       trigger three or four signals about the same underlying pattern
       because `signals.yaml` has multiple rules covering it from
       different angles. On a dual-provider run (M365 tenant + Google
       Workspace via DKIM) the Insights block used to show:

           Dual provider: Google + Microsoft coexistence
           Dual Email Provider: microsoft365, google-workspace
           Dual Email Delivery Path: microsoft365, google-workspace
           Secondary Email Provider Observed: google-workspace

       Four different wordings of the same fact. v0.9.3 collapses
       these into a single canonical line — keeping the highest-
       signal wording and dropping the rest.

    The collapse rules are intentionally narrow: only overlapping
    signals that describe the same underlying pattern. Real distinct
    signals ("Edge Layering" vs "Zero Trust Pattern Observed") never collapse
    into each other.
    """
    _ = services, slugs  # reserved for future tuning
    drop_prefixes = (
        "Security stack:",
        "Infrastructure:",
        "PKI:",
        "Google Workspace modules:",  # module list also belongs in Services
    )
    # v0.10: aggressively drop insights that restate what the Services
    # block or header already shows. These follow a "Label: slug1, slug2"
    # pattern where the slugs are visible in the categorized Services
    # section. They add zero interpretation — just a differently-worded
    # service list. Keep insights that synthesize (scores, topology,
    # tier inference, migration patterns, security observations).
    restatement_prefixes = (
        # These all follow the "Label: slug1, slug2" pattern where the
        # slugs are already visible in the categorized Services section.
        # They add zero interpretation — just a differently-worded list.
        "Multi-Cloud:",
        "Dev & Engineering Heavy:",
        "Heavy Outbound Stack:",
        "Modern Collaboration:",
        "Google Cloud Investment:",
        "Google-Native Identity:",
        "Dual provider:",
        "Dual Email Provider:",
        "Dual Email Delivery Path:",
        "Google MTA-STS Enforcing:",
        "AI Platform Diversity:",
        "AI Adoption:",  # bare form; "Without Governance" variant kept (security context)
        "Enterprise Security Stack:",
        "Digital Transformation:",
        "Email gateway:",  # already in Provider line
        "Email Gateway Topology:",
        "Email delivery path:",
        "Secondary Email Provider Observed:",
    )
    curated: list[str] = []
    for line in insights:
        if any(line.startswith(pfx) for pfx in drop_prefixes):
            continue
        if any(line.startswith(pfx) for pfx in restatement_prefixes):
            continue
        lower = line.lower()
        if "mid-size organization" in lower or "domains in tenant" in lower:
            continue
        curated.append(line)

    # ── Collapse overlapping signal families ──────────────────────────

    # Dual-provider family: four overlapping signals all describing
    # "both Microsoft 365 and Google Workspace detected". We keep the
    # most informative wording ("Dual provider: Google + Microsoft
    # coexistence") and drop the rest.
    dual_family_prefixes = (
        "Dual Email Provider:",
        "Dual Email Delivery Path:",
        "Secondary Email Provider Observed:",
    )
    has_canonical_dual = any(
        line.startswith("Dual provider:") or "Google + Microsoft coexistence" in line for line in curated
    )
    if has_canonical_dual:
        curated = [line for line in curated if not any(line.startswith(pfx) for pfx in dual_family_prefixes)]
    else:
        # No canonical line — keep at most one of the family as a
        # promoted representative. "Dual Email Delivery Path" is the
        # most information-dense wording of the three, so prefer it.
        family_lines = [line for line in curated if any(line.startswith(pfx) for pfx in dual_family_prefixes)]
        if len(family_lines) >= 2:
            # Preference order for promotion
            pref_order = (
                "Dual Email Delivery Path:",
                "Dual Email Provider:",
                "Secondary Email Provider Observed:",
            )
            chosen: str | None = None
            for pfx in pref_order:
                for line in family_lines:
                    if line.startswith(pfx):
                        chosen = line
                        break
                if chosen:
                    break
            curated = [line for line in curated if line not in family_lines or line == chosen]

    # "Dual Email Provider" signal family overlap with the older
    # "Dual provider: Google + Microsoft coexistence" insight line:
    # when BOTH the canonical insight and the newer "Dual Email
    # Provider" signal fire, keep only the canonical (human-readable)
    # one. Already handled above via has_canonical_dual; this comment
    # just documents the precedence for future maintainers.

    # ── Email security aux-note dedup ──────────────────────────────
    # The score line (v1.0.2+: "Email security: <inventory>") already
    # names what's present/absent. The auxiliary "DMARC: none", "No
    # DMARC record at apex", "No DKIM at common selectors" insights
    # restate the same observation in prose. Keep the score line on
    # the default panel; the aux notes stay in the raw `insights`
    # JSON field for consumers that want them.
    has_score_line = any(line.startswith("Email security:") for line in curated)
    if has_score_line:
        curated = [
            line
            for line in curated
            if not line.startswith("No DMARC record")
            and not line.startswith("No DKIM at common selectors")
            and not line.startswith("No DKIM selectors observed")
            and not line.startswith("DKIM not observed")
            and not line.startswith("DMARC: none")
        ]

    # ── Google Workspace identity echo dedup ───────────────────────
    # The insight "Google Workspace: Managed identity (Google-native)"
    # restates the Auth line AND the Identity row in the Services
    # block. On domains with minimal signal this is the third time
    # the same fact appears in the panel. Drop it — the Auth line
    # already says "Managed (Google Workspace)" and the Services
    # block carries the slug detection.
    return [
        line
        for line in curated
        if line != "Google Workspace: Managed identity (Google-native)"
        and not line.startswith("Google Workspace: Managed identity")
    ]

    # Note on the "Cloud-managed identity indicators" insight: the
    # dedup for dual-provider targets happens upstream in
    # insights._auth_insights, which refuses to emit the line when
    # google_auth_type is set (the Auth line's compound format
    # "Managed (Entra ID + Google Workspace)" already carries the
    # same fact). On pure M365 targets the insight DOES fire and
    # the Auth line just says "Managed", so both surfaces carry
    # distinct information — no dedup needed here.


def render_verbose_sources(results: list[SourceResult]) -> None:
    """Print per-source status lines to console."""
    c = get_console()
    for result in results:
        if result.is_success:
            description = _source_success_description(result)
            c.print(f"  [green]✓[/green] {result.source_name} — {description}")
        else:
            error_msg = result.error or "no data returned"
            c.print(f"  [red]✗[/red] {result.source_name} — {error_msg}")


def _source_success_description(result: SourceResult) -> str:
    """Build a brief description for a successful source result."""
    parts: list[str] = []
    if result.tenant_id:
        parts.append("tenant ID found")
    if result.region:
        parts.append("region confirmed")
    if result.m365_detected and not result.tenant_id:
        parts.append("M365 association detected")
    if result.display_name:
        parts.append("display name found")
    if result.auth_type:
        parts.append(f"auth: {result.auth_type}")
    if result.tenant_domains:
        parts.append(f"{len(result.tenant_domains)} domains")
    if result.dmarc_policy:
        parts.append(f"DMARC: {result.dmarc_policy}")
    return ", ".join(parts) if parts else "data returned"


def render_sources_detail(results: list[SourceResult]) -> Table:
    """Return a rich Table with detailed per-source data."""
    table = Table(title="Source Details")
    table.add_column("Source", style="bold")
    table.add_column("Status")
    table.add_column("Tenant ID")
    table.add_column("Region")
    table.add_column("Details")

    for result in results:
        status = Text("✓ success", style="green") if result.is_success else Text("✗ failed", style="red")
        tenant_id = result.tenant_id or "—"
        region = result.region or "—"
        details = result.error or ("M365 detected" if result.m365_detected else "—")
        table.add_row(result.source_name, status, tenant_id, region, details)

    return table


def render_warning(domain: str, error: ReconLookupError | None = None) -> None:
    """Print a yellow warning for not-found domains.

    When ``error`` is provided and carries per-source failure reasons, the
    concrete reasons are rendered as a dim second line so the user can tell
    whether the domain is genuinely empty or whether a transient failure
    hid real data. Without ``error`` (or when no source_errors are
    populated), the original one-liner is used.
    """
    console = get_console()
    console.print(f"[yellow]No information found for {domain}[/yellow]")
    if error is not None and getattr(error, "source_errors", ()):
        for name, reason in error.source_errors:
            console.print(f"  [dim]{name}: {reason}[/dim]")


def render_error(message: str) -> None:
    """Print a red error message."""
    get_console().print(f"[red]{message}[/red]")


def format_tenant_dict(info: TenantInfo, *, include_unclassified: bool = False) -> dict[str, Any]:
    """Build a dict representation of TenantInfo (shared by JSON and batch).

    When ``include_unclassified`` is True, the resulting dict adds an
    ``unclassified_cname_chains`` array of ``{subdomain, chain}`` records
    for CNAME chains the surface classifier resolved but couldn't attribute.
    Off by default to keep the v1.0 schema contract narrow; opt-in for the
    fingerprint-discovery loop.
    """
    has_mx_records = any(e.source_type == "MX" for e in info.evidence)
    provider = detect_provider(
        info.services,
        info.slugs,
        primary_email_provider=info.primary_email_provider,
        email_gateway=info.email_gateway,
        likely_primary_email_provider=info.likely_primary_email_provider,
        has_mx_records=has_mx_records,
    )
    d: dict[str, Any] = {
        "tenant_id": info.tenant_id,
        "display_name": info.display_name,
        "default_domain": info.default_domain,
        "queried_domain": info.queried_domain,
        "provider": provider,
        "confidence": info.confidence.value,
        "evidence_confidence": info.evidence_confidence.value,
        "inference_confidence": info.inference_confidence.value,
        "region": info.region,
        "auth_type": info.auth_type,
        "dmarc_policy": info.dmarc_policy,
        "domain_count": info.domain_count,
        "sources": list(info.sources),
        "services": list(info.services),
        # v0.9.3: emit slugs explicitly. TenantInfo.slugs is the
        # canonical detected-fact identifier set — downstream
        # tooling matching on specific slugs had to read them out
        # of `detection_scores` before, which was awkward.
        "slugs": list(info.slugs),
        "insights": list(info.insights),
        "tenant_domains": list(info.tenant_domains),
        "related_domains": list(info.related_domains),
        # `partial` means "result is meaningfully incomplete" — reserve it for
        # core-source failures (OIDC, UserRealm, Google Identity, DNS), not
        # CT-provider degradation. crt.sh is chronically flaky and CertSpotter
        # rate-limits frequently; the CT pipeline handles both gracefully via
        # fallback + cache, so their degradation should NOT flip the global
        # `partial` flag. The per-source status is still surfaced in the
        # `degraded_sources` list for consumers who want the detail.
        "partial": any(src not in {"crt.sh", "certspotter"} for src in info.degraded_sources),
        "degraded_sources": list(info.degraded_sources),
        "google_auth_type": info.google_auth_type,
        "google_idp_name": info.google_idp_name,
        "mta_sts_mode": info.mta_sts_mode,
        "site_verification_tokens": list(info.site_verification_tokens),
        "primary_email_provider": info.primary_email_provider,
        "likely_primary_email_provider": info.likely_primary_email_provider,
        "email_gateway": info.email_gateway,
        "dmarc_pct": info.dmarc_pct,
        "ct_provider_used": info.ct_provider_used,
        "ct_subdomain_count": info.ct_subdomain_count,
        "ct_cache_age_days": info.ct_cache_age_days,
        "slug_confidences": [[slug, score] for slug, score in info.slug_confidences],
        # v1.9 EXPERIMENTAL — populated only when --fusion is on.
        # ``conflict_provenance`` (v1.9.1+) is always present per posterior;
        # empty list when no cross-source conflicts dampened the interval.
        # ``evidence_ranked`` (v1.9.3.2+) ranks fired bindings by absolute
        # LLR contribution so consumers can surface the highest-leverage
        # evidence per node. Empty list when no bindings fired.
        "posterior_observations": [
            {
                "name": p.name,
                "description": p.description,
                "posterior": p.posterior,
                "interval_low": p.interval_low,
                "interval_high": p.interval_high,
                "evidence_used": list(p.evidence_used),
                "n_eff": p.n_eff,
                "sparse": p.sparse,
                "conflict_provenance": [
                    {
                        "field": c.field,
                        "sources": list(c.sources),
                        "magnitude": c.magnitude,
                    }
                    for c in p.conflict_provenance
                ],
                "evidence_ranked": [
                    {
                        "kind": e.kind,
                        "name": e.name,
                        "llr": e.llr,
                        "influence_pct": e.influence_pct,
                    }
                    for e in p.evidence_ranked
                ],
            }
            for p in info.posterior_observations
        ],
        # v0.11: surface email_security_score at the top level of --json
        # (previously only available inside the insights string).
        "email_security_score": _compute_email_security_score(info),
        # v0.9.3: sovereignty + lexical fields
        "cloud_instance": info.cloud_instance,
        "tenant_region_sub_scope": info.tenant_region_sub_scope,
        "msgraph_host": info.msgraph_host,
        "lexical_observations": list(info.lexical_observations),
    }
    # v1.0 schema contract: always present (null when unavailable).
    if info.cert_summary is not None:
        d["cert_summary"] = {
            "cert_count": info.cert_summary.cert_count,
            "issuer_diversity": info.cert_summary.issuer_diversity,
            "issuance_velocity": info.cert_summary.issuance_velocity,
            "newest_cert_age_days": info.cert_summary.newest_cert_age_days,
            "oldest_cert_age_days": info.cert_summary.oldest_cert_age_days,
            "top_issuers": list(info.cert_summary.top_issuers),
            # v1.7 — wildcard SAN sibling clusters; empty list when no
            # wildcard cert produced siblings.
            "wildcard_sibling_clusters": [list(cluster) for cluster in info.cert_summary.wildcard_sibling_clusters],
            # v1.7 — temporal CT issuance bursts; relative window deltas only.
            "deployment_bursts": [
                {
                    "window_start": burst.window_start,
                    "window_end": burst.window_end,
                    "span_seconds": burst.span_seconds,
                    "names": list(burst.names),
                }
                for burst in info.cert_summary.deployment_bursts
            ],
        }
    else:
        d["cert_summary"] = None
    if info.bimi_identity is not None:
        d["bimi_identity"] = {
            "organization": info.bimi_identity.organization,
            "country": info.bimi_identity.country,
            "state": info.bimi_identity.state,
            "locality": info.bimi_identity.locality,
            "trademark": info.bimi_identity.trademark,
        }
    else:
        d["bimi_identity"] = None
    if info.evidence:
        d["evidence"] = [
            {
                "source_type": ev.source_type,
                "raw_value": ev.raw_value,
                "rule_name": ev.rule_name,
                "slug": ev.slug,
            }
            for ev in info.evidence
        ]
    # v1.0 schema contract: always present (empty dict when no detections).
    d["detection_scores"] = dict(info.detection_scores)
    # v1.7: Cross-source evidence conflicts — top-level array. Always
    # emitted (empty list when none). Each entry is
    # {field, candidates: [{value, source, confidence}, ...]}. The
    # legacy `conflicts` dict under --explain is unchanged for
    # backwards compatibility.
    d["evidence_conflicts"] = serialize_conflicts_array(info.merge_conflicts)
    # v1.7: chain motifs — observed CDN/edge → origin shapes from CNAME
    # chain analysis. Always emitted (empty list when none). Each entry
    # is one motif firing on one related subdomain.
    d["chain_motifs"] = [
        {
            "motif_name": cm.motif_name,
            "display_name": cm.display_name,
            "confidence": cm.confidence,
            "subdomain": cm.subdomain,
            "chain": list(cm.chain),
        }
        for cm in info.chain_motifs
    ]
    # v1.8: infrastructure clusters — community detection over the CT
    # SAN co-occurrence graph. Always emitted as a stable envelope; the
    # ``algorithm`` field reflects which path produced the partition
    # ("louvain" | "connected_components" | "skipped"). Empty
    # ``clusters`` when no graph could be built.
    if info.infrastructure_clusters is not None:
        ic = info.infrastructure_clusters
        d["infrastructure_clusters"] = {
            "algorithm": ic.algorithm,
            "modularity": ic.modularity,
            "node_count": ic.node_count,
            "edge_count": ic.edge_count,
            "clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "size": c.size,
                    "members": list(c.members),
                    "shared_cert_count": c.shared_cert_count,
                    "dominant_issuer": c.dominant_issuer,
                }
                for c in ic.clusters
            ],
        }
    else:
        d["infrastructure_clusters"] = {
            "algorithm": "skipped",
            "modularity": 0.0,
            "node_count": 0,
            "edge_count": 0,
            "clusters": [],
        }
    # Note: ``edges`` from the InfrastructureClusterReport is intentionally
    # NOT serialized into the default --json envelope. Raw edges can run
    # into the thousands on heavy targets and would balloon the contract.
    # They surface only via the MCP ``export_graph`` tool, which is the
    # explicit consumer path for graph-rendering pipelines.

    # v1.8: per-slug relationship metadata. Always emitted; entries
    # appear only for slugs that fired AND have at least one populated
    # field. Empty object when no detected slug carries metadata. Drives
    # the v1.8 ecosystem hypergraph and downstream display logic — never
    # an ownership claim, just descriptive hints from the fingerprint
    # YAML.
    metadata_lookup = _slug_to_relationship_metadata()
    detected_slug_set = set(info.slugs)
    fingerprint_metadata: dict[str, dict[str, str | None]] = {}
    for slug in sorted(detected_slug_set):
        meta = metadata_lookup.get(slug)
        if meta is None:
            continue
        # Skip entries where every field is None.
        if all(v is None for v in meta.values()):
            continue
        fingerprint_metadata[slug] = meta
    d["fingerprint_metadata"] = fingerprint_metadata
    # v1.5: External surface attributions — per-subdomain SaaS attribution
    # from CNAME chain classification. Always emitted (empty list when none).
    d["surface_attributions"] = [
        {
            "subdomain": sa.subdomain,
            "primary_slug": sa.primary_slug,
            "primary_name": sa.primary_name,
            "primary_tier": sa.primary_tier,
            "infra_slug": sa.infra_slug,
            "infra_name": sa.infra_name,
        }
        for sa in info.surface_attributions
    ]
    # v1.5: opt-in unclassified-chain emission. Off by default keeps the v1.0
    # schema narrow; on for the fingerprint-discovery loop.
    if include_unclassified:
        d["unclassified_cname_chains"] = [
            {"subdomain": uc.subdomain, "chain": list(uc.chain)} for uc in info.unclassified_cname_chains
        ]
    return d


def format_tenant_json(info: TenantInfo, *, include_unclassified: bool = False) -> str:
    """Format TenantInfo as a JSON string."""
    return json.dumps(format_tenant_dict(info, include_unclassified=include_unclassified), indent=2)


def format_tenant_markdown(info: TenantInfo) -> str:
    """Format TenantInfo as a markdown report."""
    lines: list[str] = []
    lines.append(f"# Tenant Report: {info.display_name}")
    lines.append("")
    lines.append(f"**Domain:** {info.queried_domain}  ")
    if info.tenant_id:
        lines.append(f"**Tenant ID:** `{info.tenant_id}`  ")
    lines.append(f"**Default Domain:** {info.default_domain}  ")
    if info.region:
        lines.append(f"**Region:** {info.region}  ")
    if info.auth_type:
        lines.append(f"**Auth Type:** {info.auth_type}  ")
    lines.append(f"**Confidence:** {info.confidence.value} ({len(info.sources)} sources)  ")
    lines.append(
        f"**Evidence Confidence:** {info.evidence_confidence.value}  \n"
        f"**Inference Confidence:** {info.inference_confidence.value}  "
    )
    lines.append("")

    # Services split — group by provider_group when available
    if info.services:
        m365_svcs = [s for s in info.services if _is_m365_service(s)]
        gws_svcs = [s for s in info.services if _is_gws_service(s)]
        other_svcs = [s for s in info.services if not _is_m365_service(s) and not _is_gws_service(s)]

        if m365_svcs:
            lines.append("## Microsoft 365 Services")
            lines.append("")
            for svc in m365_svcs:
                lines.append(f"- {svc}")
            lines.append("")

        if gws_svcs:
            lines.append("## Google Workspace Services")
            lines.append("")
            for svc in gws_svcs:
                lines.append(f"- {svc}")
            lines.append("")

        if other_svcs:
            lines.append("## Tech Stack")
            lines.append("")
            for svc in other_svcs:
                lines.append(f"- {svc}")
            lines.append("")

    # Google Workspace details section
    gws_slugs = set(info.slugs)
    has_gws = any(_is_gws_service(s) for s in info.services) or "google-workspace" in gws_slugs
    if has_gws:
        lines.append("## Google Workspace")
        lines.append("")
        if info.google_auth_type:
            lines.append(f"**Auth Type:** {info.google_auth_type}  ")
        if info.google_idp_name:
            lines.append(f"**Identity Provider:** {info.google_idp_name}  ")
        # Active modules from GWS CNAME detections
        gws_modules = [s.replace("Google Workspace: ", "") for s in info.services if s.startswith("Google Workspace: ")]
        if gws_modules:
            lines.append(f"**Active Modules:** {', '.join(gws_modules)}  ")
        # CSE details
        cse_svcs = [s for s in info.services if "CSE" in s]
        if cse_svcs:
            lines.append(f"**CSE:** {', '.join(cse_svcs)}  ")
        lines.append("")

    # Insights
    if info.insights:
        lines.append("## Insights")
        lines.append("")
        for insight in info.insights:
            lines.append(f"- {insight}")
        lines.append("")

    # Certificate Intelligence
    if info.cert_summary is not None:
        cs = info.cert_summary
        lines.append("## Certificate Intelligence")
        lines.append("")
        lines.append(f"- **Total Certificates:** {cs.cert_count}")
        lines.append(f"- **Issuer Diversity:** {cs.issuer_diversity} distinct issuers")
        lines.append(f"- **Issuance Velocity:** {cs.issuance_velocity} certs in last 90 days")
        lines.append(f"- **Newest Cert Age:** {cs.newest_cert_age_days} days")
        lines.append(f"- **Oldest Cert Age:** {cs.oldest_cert_age_days} days")
        if cs.top_issuers:
            lines.append(f"- **Top Issuers:** {', '.join(cs.top_issuers)}")
        lines.append("")

    # Domains
    if info.tenant_domains:
        lines.append(f"## Tenant Domains ({info.domain_count})")
        lines.append("")
        for d in info.tenant_domains:
            lines.append(f"- {d}")
        lines.append("")

    # Related domains
    if info.related_domains:
        lines.append("## Related Domains")
        lines.append("")
        for d in info.related_domains:
            lines.append(f"- {d}")
        lines.append("")

    # Footer
    lines.append("---")
    if info.degraded_sources:
        sources_list = ", ".join(info.degraded_sources)
        lines.append(
            f"*Note: Some sources were unavailable ({sources_list}) — subdomain discovery may be incomplete.*  "
        )
    lines.append(f"*Sources: {', '.join(info.sources)}*")
    lines.append("")

    return "\n".join(lines)


# ── Posture observation rendering ────────────────────────────────────────

_SALIENCE_INDICATORS: dict[str, str] = {
    "high": "●",
    "medium": "◐",
    "low": "○",
}


def format_posture_observations(observations: tuple[Observation, ...]) -> list[dict[str, Any]]:
    """Format observations as a list of dicts for JSON output."""
    return [
        {
            "category": obs.category,
            "salience": obs.salience,
            "statement": obs.statement,
            "related_slugs": list(obs.related_slugs),
        }
        for obs in observations
    ]


def render_posture_panel(observations: tuple[Observation, ...]) -> Panel | None:
    """Render posture observations as a Rich panel grouped by category."""
    if not observations:
        return None

    # Group by category, preserving order of first appearance
    groups: dict[str, list[Observation]] = {}
    for obs in observations:
        groups.setdefault(obs.category, []).append(obs)

    text = Text()
    first_group = True
    for category, obs_list in groups.items():
        if not first_group:
            text.append("\n\n")
        first_group = False

        text.append(f"  {category.replace('_', ' ').title()}\n", style="bold")
        for obs in obs_list:
            indicator = _SALIENCE_INDICATORS.get(obs.salience, "○")
            text.append(f"  {indicator} ", style="dim")
            text.append(obs.statement)
            text.append("\n")

    return Panel(
        text,
        title="Posture Analysis",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── Delta rendering ─────────────────────────────────────────────────────


def format_delta_dict(report: DeltaReport) -> dict[str, Any]:
    """Format DeltaReport as a dict for JSON output.

    The ``changed_*`` fields are always present in the output. Each is
    either ``null`` (no change observed) or ``{"from": ..., "to": ...}``
    (a change observed). Stable shape matches
    ``docs/recon-schema.json#/$defs/DeltaReport`` so downstream
    validators do not reject no-change or partial-change reports.
    """
    from datetime import datetime, timezone

    def _change_pair(value: tuple[Any, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        return {"from": value[0], "to": value[1]}

    return {
        "domain": report.domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "has_changes": report.has_changes,
        "added_services": list(report.added_services),
        "removed_services": list(report.removed_services),
        "added_slugs": list(report.added_slugs),
        "removed_slugs": list(report.removed_slugs),
        "added_signals": list(report.added_signals),
        "removed_signals": list(report.removed_signals),
        "changed_auth_type": _change_pair(report.changed_auth_type),
        "changed_dmarc_policy": _change_pair(report.changed_dmarc_policy),
        "changed_email_security_score": _change_pair(report.changed_email_security_score),
        "changed_confidence": _change_pair(report.changed_confidence),
        "changed_domain_count": _change_pair(report.changed_domain_count),
    }


def format_delta_json(report: DeltaReport) -> str:
    """Format DeltaReport as a JSON string."""
    return json.dumps(format_delta_dict(report), indent=2)


def render_delta_panel(report: DeltaReport) -> Panel:
    """Render delta report as a Rich panel with +/- markers."""
    text = Text()

    text.append("  Domain: ", style="dim")
    text.append(f"{report.domain}\n")

    if not report.has_changes:
        text.append("\n  No changes detected.", style="dim italic")
    else:
        # Services
        for svc in report.added_services:
            text.append("\n  ")
            text.append("+ ", style="green bold")
            text.append(f"Service: {svc}", style="green")
        for svc in report.removed_services:
            text.append("\n  ")
            text.append("- ", style="red bold")
            text.append(f"Service: {svc}", style="red")

        # Slugs
        for slug in report.added_slugs:
            text.append("\n  ")
            text.append("+ ", style="green bold")
            text.append(f"Slug: {slug}", style="green")
        for slug in report.removed_slugs:
            text.append("\n  ")
            text.append("- ", style="red bold")
            text.append(f"Slug: {slug}", style="red")

        # Signals
        for sig in report.added_signals:
            text.append("\n  ")
            text.append("+ ", style="green bold")
            text.append(f"Signal: {sig}", style="green")
        for sig in report.removed_signals:
            text.append("\n  ")
            text.append("- ", style="red bold")
            text.append(f"Signal: {sig}", style="red")

        # Scalar changes
        if report.changed_auth_type is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(f"Auth: {report.changed_auth_type[0]} → {report.changed_auth_type[1]}", style="yellow")
        if report.changed_dmarc_policy is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(f"DMARC: {report.changed_dmarc_policy[0]} → {report.changed_dmarc_policy[1]}", style="yellow")
        if report.changed_email_security_score is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(
                f"Email Security Score: {report.changed_email_security_score[0]} → "
                f"{report.changed_email_security_score[1]}",
                style="yellow",
            )
        if report.changed_confidence is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(f"Confidence: {report.changed_confidence[0]} → {report.changed_confidence[1]}", style="yellow")
        if report.changed_domain_count is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(
                f"Domain Count: {report.changed_domain_count[0]} → {report.changed_domain_count[1]}",
                style="yellow",
            )

    return Panel(
        text,
        title="Delta Report",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── Chain rendering ──────────────────────────────────────────────────────


def format_chain_dict(report: ChainReport) -> dict[str, Any]:
    """Format ChainReport as a dict for JSON output."""
    return {
        "total_domains": len(report.results),
        "max_depth_reached": report.max_depth_reached,
        "truncated": report.truncated,
        "domains": [
            {
                **format_tenant_dict(r.info),
                "chain_depth": r.chain_depth,
            }
            for r in report.results
        ],
    }


def format_chain_json(report: ChainReport) -> str:
    """Format ChainReport as a JSON string."""
    return json.dumps(format_chain_dict(report), indent=2)


def render_chain_panel(report: ChainReport) -> Panel:
    """Render chain report as a Rich panel with domain tree."""
    text = Text()

    text.append("  Total Domains: ", style="dim")
    text.append(f"{len(report.results)}\n")
    text.append("  Max Depth:     ", style="dim")
    text.append(f"{report.max_depth_reached}\n")
    if report.truncated:
        text.append("  Status:        ", style="dim")
        text.append("Truncated (cap reached)", style="yellow")
        text.append("\n")

    # Domain tree grouped by depth
    if report.results:
        text.append("\n")
        current_depth = -1
        for r in report.results:
            if r.chain_depth != current_depth:
                current_depth = r.chain_depth
                text.append(f"  Depth {current_depth}:\n", style="bold")
            indent = "    " + "  " * r.chain_depth
            provider = detect_provider(r.info.services, r.info.slugs)
            text.append(f"{indent}{r.domain}", style="cyan")
            text.append(f" — {r.info.display_name}", style="dim")
            if provider != "Unknown":
                text.append(f" ({provider})", style="dim")
            text.append("\n")

    return Panel(
        text,
        title="Chain Resolution",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── CSV output ───────────────────────────────────────────────────────────

CSV_COLUMNS: tuple[str, ...] = (
    "domain",
    "provider",
    "display_name",
    "tenant_id",
    "auth_type",
    "confidence",
    "email_security_score",
    "service_count",
    "dmarc_policy",
    "mta_sts_mode",
    "google_auth_type",
)


def _compute_email_security_score(info: TenantInfo) -> int:
    """Compute email security score (0-5) from services, matching insights.py logic."""
    from recon_tool.constants import (
        SVC_BIMI,
        SVC_DKIM,
        SVC_DKIM_EXCHANGE,
        SVC_MTA_STS,
        SVC_SPF_STRICT,
    )

    score = 0
    if info.dmarc_policy in ("reject", "quarantine"):
        score += 1
    if SVC_DKIM_EXCHANGE in info.services or SVC_DKIM in info.services:
        score += 1
    if SVC_SPF_STRICT in info.services:
        score += 1
    if SVC_MTA_STS in info.services:
        score += 1
    if SVC_BIMI in info.services:
        score += 1
    return score


_CSV_FORMULA_PREFIXES = frozenset(("=", "+", "-", "@", "\t", "\r", "\n"))


def _csv_safe(value: str) -> str:
    """Neutralize CSV formula-injection prefixes.

    Spreadsheet applications (Excel, LibreOffice, Google Sheets)
    interpret cells starting with ``=``, ``+``, ``-``, ``@``, ``\\t``,
    ``\\r``, or ``\\n`` as formulas. Some import paths also trim
    leading spaces before formula detection. ``display_name`` comes from the
    GetUserRealm ``FederationBrandName`` response, which is
    attacker-controllable for any domain the user chooses to
    look up. A tenant name like ``=HYPERLINK("http://...")`` would
    execute on open.

    Neutralization strategy: prefix the value with a single quote so
    the spreadsheet treats the cell as literal text. The quote is
    visible in the cell but not in the underlying data consumers
    doing machine parsing — those should use the ``--json`` output
    anyway; ``--csv`` is explicitly the human-spreadsheet path.
    """
    if not value:
        return value
    candidate = value.lstrip(" ")
    if candidate and candidate[0] in _CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


def format_tenant_csv_row(info: TenantInfo) -> dict[str, str]:
    """Build a dict of CSV column values for a single TenantInfo.

    Every textual field passes through ``_csv_safe`` so a malicious
    ``FederationBrandName`` (or any other attacker-influenced field)
    can't execute as a formula when the CSV is opened in a spreadsheet.
    """
    provider = detect_provider(info.services, info.slugs)
    return {
        "domain": _csv_safe(info.queried_domain),
        "provider": _csv_safe(provider),
        "display_name": _csv_safe(info.display_name),
        "tenant_id": _csv_safe(info.tenant_id or ""),
        "auth_type": _csv_safe(info.auth_type or ""),
        "confidence": info.confidence.value,
        "email_security_score": str(_compute_email_security_score(info)),
        "service_count": str(len(info.services)),
        "dmarc_policy": _csv_safe(info.dmarc_policy or ""),
        "mta_sts_mode": _csv_safe(info.mta_sts_mode or ""),
        "google_auth_type": _csv_safe(info.google_auth_type or ""),
    }


def format_batch_csv(infos: list[tuple[str, TenantInfo | None, str | None]]) -> str:
    """Format a list of (domain, info_or_none, error_or_none) as RFC 4180 CSV.

    Returns a string with header row + one data row per domain.
    """
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)

    for domain, info, _error in infos:
        if info is not None:
            row_dict = format_tenant_csv_row(info)
            writer.writerow([_csv_safe(row_dict[col]) for col in CSV_COLUMNS])
        else:
            # Error row: domain + empty fields
            row = [_csv_safe(domain)] + [""] * (len(CSV_COLUMNS) - 1)
            writer.writerow(row)

    return buf.getvalue()


# ── Exposure assessment rendering ────────────────────────────────────────


def format_exposure_dict(assessment: ExposureAssessment) -> dict[str, Any]:
    """Format ExposureAssessment as a dict for JSON output."""

    def _evidence_list(refs: tuple[Any, ...]) -> list[dict[str, str]]:
        return [
            {
                "source_type": r.source_type,
                "raw_value": r.raw_value,
                "rule_name": r.rule_name,
                "slug": r.slug,
            }
            for r in refs
        ]

    ep = assessment.email_posture
    ip = assessment.identity_posture
    infra = assessment.infrastructure_footprint

    d: dict[str, Any] = {
        "domain": assessment.domain,
        "posture_score": assessment.posture_score,
        "posture_score_label": assessment.posture_score_label,
        "email_posture": {
            "dmarc_policy": ep.dmarc_policy,
            "dkim_configured": ep.dkim_configured,
            "spf_strict": ep.spf_strict,
            "mta_sts_mode": ep.mta_sts_mode,
            "email_gateway": ep.email_gateway,
            "bimi_configured": ep.bimi_configured,
            "email_security_score": ep.email_security_score,
            "evidence": _evidence_list(ep.evidence),
        },
        "identity_posture": {
            "auth_type": ip.auth_type,
            "identity_provider": ip.identity_provider,
            "google_auth_type": ip.google_auth_type,
            "google_idp_name": ip.google_idp_name,
            "evidence": _evidence_list(ip.evidence),
        },
        "infrastructure_footprint": {
            "cloud_providers": list(infra.cloud_providers),
            "dns_provider": infra.dns_provider,
            "cdn_waf": list(infra.cdn_waf),
            "certificate_authorities": list(infra.certificate_authorities),
            "evidence": _evidence_list(infra.evidence),
        },
        "consistency_observations": [
            {
                "observation": obs.observation,
                "category": obs.category,
                "evidence": _evidence_list(obs.evidence),
            }
            for obs in assessment.consistency_observations
        ],
        "hardening_status": {
            "controls": [
                {
                    "name": ctrl.name,
                    "present": ctrl.present,
                    "detail": ctrl.detail,
                    "evidence": _evidence_list(ctrl.evidence),
                }
                for ctrl in assessment.hardening_status.controls
            ],
        },
        "disclaimer": assessment.disclaimer,
        "evidence": _evidence_list(assessment.evidence),
    }
    return d


def format_exposure_json(assessment: ExposureAssessment) -> str:
    """Format ExposureAssessment as a JSON string."""
    return json.dumps(format_exposure_dict(assessment), indent=2)


def render_exposure_panel(assessment: ExposureAssessment) -> Panel:
    """Render ExposureAssessment as a Rich panel with categorized sections."""
    text = Text()

    text.append("  Domain: ", style="dim")
    text.append(f"{assessment.domain}\n")
    text.append("  Posture Score: ", style="dim")
    score = assessment.posture_score
    score_style = "#a3d9a5" if score >= 60 else "#7ec8e3" if score >= 30 else "#e07a5f"
    text.append(f"{score}/100", style=score_style)
    text.append(f" ({assessment.posture_score_label})\n", style="dim")

    # Email posture
    ep = assessment.email_posture
    text.append("\n  Email Security\n", style="bold")
    text.append(f"    DMARC:     {ep.dmarc_policy or 'not configured'}\n")
    text.append(f"    DKIM:      {'observed' if ep.dkim_configured else 'not observed at common names'}\n")
    text.append(f"    SPF:       {'strict (-all)' if ep.spf_strict else 'not strict'}\n")
    text.append(f"    MTA-STS:   {ep.mta_sts_mode or 'not configured'}\n")
    text.append(f"    BIMI:      {'configured' if ep.bimi_configured else 'not configured'}\n")
    if ep.email_gateway:
        text.append(f"    Gateway:   {ep.email_gateway}\n")

    # Identity posture
    ip = assessment.identity_posture
    text.append("\n  Identity\n", style="bold")
    text.append(f"    Auth Type: {ip.auth_type or 'unknown'}\n")
    if ip.identity_provider:
        text.append(f"    IdP:       {ip.identity_provider}\n")
    if ip.google_auth_type:
        label = ip.google_auth_type
        if ip.google_idp_name:
            label += f" ({ip.google_idp_name})"
        text.append(f"    GWS Auth:  {label}\n")

    # Infrastructure
    infra = assessment.infrastructure_footprint
    text.append("\n  Infrastructure\n", style="bold")
    if infra.cloud_providers:
        text.append(f"    Cloud:     {', '.join(infra.cloud_providers)}\n")
    if infra.dns_provider:
        text.append(f"    DNS:       {infra.dns_provider}\n")
    if infra.cdn_waf:
        text.append(f"    CDN/WAF:   {', '.join(infra.cdn_waf)}\n")
    if infra.certificate_authorities:
        text.append(f"    CAs:       {', '.join(infra.certificate_authorities)}\n")

    # Consistency observations
    if assessment.consistency_observations:
        text.append("\n  Consistency\n", style="bold")
        for obs in assessment.consistency_observations:
            text.append(f"    ◐ {obs.observation}\n", style="#e6c07b")

    # Hardening status. ``Text.append`` does not parse Rich markup — the
    # style must be passed as the ``style`` kwarg. Writing ``[green]✓[/green]``
    # directly into the string rendered it as literal tags.
    text.append("\n  Hardening Controls\n", style="bold")
    for ctrl in assessment.hardening_status.controls:
        mark = "✓" if ctrl.present else "✗"
        style = "green" if ctrl.present else "red"
        text.append("    ")
        text.append(mark, style=style)
        text.append(f" {ctrl.name}: {ctrl.detail}\n")

    return Panel(
        text,
        title="Exposure Assessment",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── Gap report rendering ────────────────────────────────────────────────

_SEVERITY_COLORS: dict[str, str] = {
    "high": "#e07a5f",
    "medium": "#e6c07b",
    "low": "#7ec8e3",
}

_SEVERITY_INDICATORS: dict[str, str] = {
    "high": "●",
    "medium": "◐",
    "low": "○",
}


def format_gaps_dict(report: GapReport) -> dict[str, Any]:
    """Format GapReport as a dict for JSON output."""
    return {
        "domain": report.domain,
        "gaps": [
            {
                "category": gap.category,
                "severity": gap.severity,
                "observation": gap.observation,
                "recommendation": gap.recommendation,
                "evidence": [
                    {
                        "source_type": r.source_type,
                        "raw_value": r.raw_value,
                        "rule_name": r.rule_name,
                        "slug": r.slug,
                    }
                    for r in gap.evidence
                ],
            }
            for gap in report.gaps
        ],
        "disclaimer": report.disclaimer,
    }


def format_gaps_json(report: GapReport) -> str:
    """Format GapReport as a JSON string."""
    return json.dumps(format_gaps_dict(report), indent=2)


def render_gaps_panel(report: GapReport) -> Panel:
    """Render GapReport as a Rich panel with gaps grouped by category."""
    text = Text()

    text.append("  Domain: ", style="dim")
    text.append(f"{report.domain}\n")

    if not report.gaps:
        text.append("\n  No hardening gaps detected.", style="dim italic")
    else:
        # Group by category
        groups: dict[str, list[Any]] = {}
        for gap in report.gaps:
            groups.setdefault(gap.category, []).append(gap)

        for category, gaps in groups.items():
            text.append(f"\n  {category.replace('_', ' ').title()}\n", style="bold")
            for gap in gaps:
                indicator = _SEVERITY_INDICATORS.get(gap.severity, "○")
                color = _SEVERITY_COLORS.get(gap.severity, "dim")
                text.append(f"    {indicator} ", style=color)
                text.append(f"[{gap.severity}] ", style=color)
                text.append(f"{gap.observation}\n")
                text.append(f"      → {gap.recommendation}\n", style="dim")

    return Panel(
        text,
        title="Hardening Gaps",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── Comparison rendering ────────────────────────────────────────────────


def format_comparison_dict(comparison: PostureComparison) -> dict[str, Any]:
    """Format PostureComparison as a dict for JSON output."""
    return {
        "domain_a": comparison.domain_a,
        "domain_b": comparison.domain_b,
        "metrics": [
            {
                "metric_name": m.metric_name,
                "domain_a_value": m.domain_a_value,
                "domain_b_value": m.domain_b_value,
            }
            for m in comparison.metrics
        ],
        "differences": [
            {
                "description": d.description,
                "domain_a_has": d.domain_a_has,
                "domain_b_has": d.domain_b_has,
            }
            for d in comparison.differences
        ],
        "relative_assessment": [
            {
                "dimension": ra.dimension,
                "summary": ra.summary,
            }
            for ra in comparison.relative_assessment
        ],
        "disclaimer": comparison.disclaimer,
    }


def format_comparison_json(comparison: PostureComparison) -> str:
    """Format PostureComparison as a JSON string."""
    return json.dumps(format_comparison_dict(comparison), indent=2)


# ── Explanation rendering ────────────────────────────────────────────────


# Substrings that mark a SourceResult error as a "soft miss" — the source
# ran cleanly and determined the target isn't theirs — rather than a
# transport/transient failure. Rendering these with `✗` in red misreads
# a legitimate "not a customer" answer as if the tool had broken.
_SOFT_MISS_MARKERS: tuple[str, ...] = (
    "No Google Workspace",
    "No federated IdP redirect",
    "Not a Google Workspace",
    "No M365 tenant",
    "Not a registered M365",
    "HTTP 400 from OIDC discovery",
    "No information could be resolved",
    "no data returned",
)


def _is_soft_miss(error: str | None) -> bool:
    if not error:
        return True  # empty error but is_success False = soft miss
    return any(marker in error for marker in _SOFT_MISS_MARKERS)


def render_source_status_panel(results: list[SourceResult]) -> Panel | None:
    """Render a compact per-source status panel for ``--explain`` output.

    Three states:

    - ``✓`` (green) — source ran and produced a match.
    - ``–`` (dim) — source ran cleanly but the target isn't their
      customer ("not a Workspace domain", "HTTP 400 from OIDC" = not
      an M365 tenant, "no federated IdP redirect", etc.). Previously
      rendered as ``✗`` which misread a legitimate "not a match"
      answer as if the tool had broken.
    - ``✗`` (red) — transport/HTTP failure, timeout, or other genuine
      problem with the source.

    Duplicate rows from enrichment passes (multiple ``dns_records``
    entries from subdomain lookups) are collapsed into one summary
    line per source to keep the panel focused on the primary lookup.
    """
    if not results:
        return None

    # Collapse duplicate source_name rows from enrichment — only keep
    # the first (primary) result per source. Enrichment subdomain
    # lookups appear as additional SourceResults with source_name
    # "dns_records" and their success/failure status is an internal
    # detail, not a primary-source observation.
    seen: set[str] = set()
    primary: list[SourceResult] = []
    for r in results:
        if r.source_name in seen:
            continue
        seen.add(r.source_name)
        primary.append(r)

    text = Text()
    for i, result in enumerate(primary):
        if i > 0:
            text.append("\n")
        if result.is_success:
            description = _source_success_description(result)
            text.append("  ✓ ", style="#a3d9a5")
            text.append(f"{result.source_name}", style="bold")
            text.append(f" — {description}", style="dim")
        elif _is_soft_miss(result.error):
            text.append("  – ", style="dim")
            text.append(f"{result.source_name}", style="bold")
            text.append(f" — {result.error or 'no match'}", style="dim")
        else:
            text.append("  ✗ ", style="#e07a5f")
            text.append(f"{result.source_name}", style="bold")
            text.append(f" — {result.error}", style="dim")
    return Panel(
        text,
        title="Source Status",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


def render_explanations_panel(explanations: list[ExplanationRecord]) -> Panel:
    """Render explanation records as a Rich panel for CLI --explain output."""
    text = Text()

    for i, rec in enumerate(explanations):
        if i > 0:
            text.append("\n\n")

        # Header: item type + name
        type_label = rec.item_type.capitalize()
        text.append(f"  [{type_label}] ", style="bold")
        text.append(f"{rec.item_name}\n")

        # Curated explanation (from YAML explain field)
        if rec.curated_explanation:
            text.append(f"    {rec.curated_explanation}\n", style="dim italic")

        # Fired rules
        if rec.fired_rules:
            text.append("    Rules: ", style="dim")
            text.append(", ".join(rec.fired_rules))
            text.append("\n")

        # Confidence derivation
        if rec.confidence_derivation:
            text.append("    Confidence: ", style="dim")
            text.append(f"{rec.confidence_derivation}\n")

        # Evidence summary
        if rec.matched_evidence:
            text.append(f"    Evidence: {len(rec.matched_evidence)} record(s)\n", style="dim")

        # Weakening conditions
        if rec.weakening_conditions:
            text.append("    Weakening:\n", style="dim")
            for cond in rec.weakening_conditions:
                text.append(f"      • {cond}\n", style="dim")

    return Panel(
        text,
        title="Explanations",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


def format_explanations_list(explanations: list[ExplanationRecord]) -> list[dict[str, Any]]:
    """Serialize explanation records for JSON output."""
    from recon_tool.explanation import serialize_explanation

    return [serialize_explanation(rec) for rec in explanations]


def format_explanations_markdown(explanations: list[ExplanationRecord]) -> str:
    """Render explanation records as markdown subsections."""
    lines: list[str] = []
    lines.append("## Explanations")
    lines.append("")

    for rec in explanations:
        type_label = rec.item_type.capitalize()
        lines.append(f"### [{type_label}] {rec.item_name}")
        lines.append("")

        if rec.curated_explanation:
            lines.append(f"*{rec.curated_explanation}*")
            lines.append("")

        if rec.fired_rules:
            lines.append(f"**Rules:** {', '.join(rec.fired_rules)}  ")

        if rec.confidence_derivation:
            lines.append(f"**Confidence:** {rec.confidence_derivation}  ")

        if rec.matched_evidence:
            lines.append(f"**Evidence:** {len(rec.matched_evidence)} record(s)  ")

        if rec.weakening_conditions:
            lines.append("")
            lines.append("**Weakening conditions:**")
            lines.append("")
            for cond in rec.weakening_conditions:
                lines.append(f"- {cond}")

        lines.append("")

    return "\n".join(lines)


def render_conflict_annotation(
    field_name: str,
    conflicts: MergeConflicts,
    verbose: bool = False,
) -> str:
    """Render a dim conflict indicator for a Rich panel field.

    Returns a string like "  [2 sources disagree]" when the field has conflicts.
    When verbose=True, also lists all candidate values.
    Returns empty string when no conflict exists for the field.
    """
    candidates: tuple[CandidateValue, ...] = getattr(conflicts, field_name, ())
    if not candidates:
        return ""

    unique_values = {c.value for c in candidates}
    if len(unique_values) < 2:
        return ""

    annotation = f"  [{len(candidates)} sources disagree]"

    if verbose:
        parts: list[str] = []
        for c in candidates:
            parts.append(f"{c.value} ({c.source})")
        annotation += f"  ({', '.join(parts)})"

    return annotation
