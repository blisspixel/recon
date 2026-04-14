"""Insight generation engine — derives intelligence signals from collected data.

Decomposes insight generation into focused, testable generators.
Each generator is a pure function: (context) -> list[str].
"""

from __future__ import annotations

from dataclasses import dataclass

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_INTUNE_MDM,
    SVC_MTA_STS,
    SVC_OFFICE_PROPLUS,
    SVC_SPF_STRICT,
)

__all__ = [
    "InsightContext",
    "generate_insights",
]


@dataclass(frozen=True)
class InsightContext:
    """Immutable context passed to all insight generators."""

    services: frozenset[str]
    slugs: frozenset[str]
    auth_type: str | None
    dmarc_policy: str | None
    domain_count: int
    google_auth_type: str | None = None
    google_idp_name: str | None = None

    @classmethod
    def from_sets(
        cls,
        services: set[str],
        slugs: set[str],
        auth_type: str | None,
        dmarc_policy: str | None,
        domain_count: int,
        google_auth_type: str | None = None,
        google_idp_name: str | None = None,
    ) -> InsightContext:
        """Convenience constructor that converts mutable sets to frozensets."""
        return cls(
            services=frozenset(services),
            slugs=frozenset(slugs),
            auth_type=auth_type,
            dmarc_policy=dmarc_policy,
            domain_count=domain_count,
            google_auth_type=google_auth_type,
            google_idp_name=google_idp_name,
        )


# Slug sets for detection
_EXCHANGE_SLUGS = frozenset({"microsoft365"})
_GOOGLE_SLUGS = frozenset({"google-workspace"})

# Slugs that indicate the domain sends/receives email — used to decide
# whether to show the email security score (vs just a bare DMARC line).
_EMAIL_SLUGS = frozenset(
    {
        "aws-ses",
        "sendgrid",
        "mailgun",
        "postmark",
        "sparkpost",
        "brevo",
        "mailchimp",
        "zoho",
        "protonmail",
    }
)

_GATEWAY_SLUG_MAP: dict[str, str] = {
    "proofpoint": "Proofpoint",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "cisco-ironport": "Cisco IronPort",
    "cisco-email": "Cisco Secure Email",
    "trendmicro": "Trend Micro",
    "symantec": "Symantec/Broadcom",
    "trellix": "Trellix (FireEye)",
}

_SEC_TOOL_SLUG_MAP: dict[str, str] = {
    "knowbe4": "KnowBe4 (security training)",
    "crowdstrike": "CrowdStrike (endpoint)",
    "sentinelone": "SentinelOne (endpoint)",
    "sophos": "Sophos (endpoint)",
    "duo": "Duo (MFA)",
    "okta": "Okta (identity)",
    "1password": "1Password (credentials)",
    "paloalto": "Palo Alto (network)",
    "zscaler": "Zscaler (SASE)",
    "netskope": "Netskope (SASE)",
    "wiz": "Wiz (cloud security)",
    "imperva": "Imperva (WAF)",
}

# Identity providers — used to refine the generic "Federated" auth insight
# into a specific "Federated via Okta" when we can see the IdP in DNS.
_IDP_SLUG_MAP: dict[str, str] = {
    "okta": "Okta",
    "duo": "Duo",
    "cisco-identity": "Cisco (Duo/Identity)",
}


# ── Individual insight generators ───────────────────────────────────────
# Each returns a list of insight strings. Pure functions, easy to test.
#
# Some generators (gateway, security_stack, sase, pki) follow a simple
# "match slugs → format string" pattern that could theoretically be
# data-driven like signals.yaml. However, the more complex generators
# (email_security scoring, auth type + IdP correlation, license tier
# inference, dual MDM detection, org size heuristics) require branching
# logic that doesn't reduce to slug matching. Keeping them all as
# functions maintains a uniform interface for the _INSIGHT_GENERATORS
# pipeline and keeps each generator independently testable.


def _auth_insights(ctx: InsightContext) -> list[str]:
    if ctx.auth_type == "Federated":
        # If we can see the identity provider in DNS, name it specifically
        detected_idps = [name for slug, name in _IDP_SLUG_MAP.items() if slug in ctx.slugs]
        if detected_idps:
            return [f"Federated identity indicators observed (likely {', '.join(detected_idps)})"]
        return ["Federated identity indicators (likely ADFS/Okta/Ping — enterprise SSO)"]
    if ctx.auth_type == "Managed":
        # Only claim "Entra ID native" when we actually see M365 evidence.
        # GetUserRealm returns "Managed" for non-Microsoft domains too —
        # it just means "not federated" from Microsoft's perspective.
        has_m365 = bool(ctx.slugs & _EXCHANGE_SLUGS)
        if has_m365:
            return ["Cloud-managed identity indicators (Entra ID native)"]
        return []
    return []


def _email_security_insights(ctx: InsightContext) -> list[str]:
    has_exchange = bool(ctx.slugs & _EXCHANGE_SLUGS)
    has_google = bool(ctx.slugs & _GOOGLE_SLUGS)
    # Email detection: fire the score when we see any email provider, email
    # gateway, email sending service, or DMARC record. If you have DMARC
    # configured, you have email worth scoring.
    has_email = (
        has_exchange
        or has_google
        or bool(ctx.slugs & _EMAIL_SLUGS)
        or any("Email" in s for s in ctx.services)
        or ctx.dmarc_policy is not None  # has DMARC record = has email
    )

    if not has_email:
        if ctx.dmarc_policy:
            return [f"DMARC: {ctx.dmarc_policy}"]
        return []

    insights: list[str] = []
    has_dkim = SVC_DKIM_EXCHANGE in ctx.services or SVC_DKIM in ctx.services
    has_bimi = SVC_BIMI in ctx.services
    has_mta_sts = SVC_MTA_STS in ctx.services
    has_spf_strict = SVC_SPF_STRICT in ctx.services

    score = 0
    score_parts: list[str] = []
    if ctx.dmarc_policy in ("reject", "quarantine"):
        score += 1
        score_parts.append(f"DMARC {ctx.dmarc_policy}")
    if has_dkim:
        score += 1
        score_parts.append("DKIM")
    if has_spf_strict:
        score += 1
        score_parts.append("SPF strict")
    if has_mta_sts:
        score += 1
        score_parts.append("MTA-STS")
    if has_bimi:
        score += 1
        score_parts.append("BIMI")

    labels = {0: "weak", 1: "basic", 2: "moderate", 3: "good", 4: "strong", 5: "excellent"}
    parts_str = ", ".join(score_parts) if score_parts else "no protections detected"
    insights.append(f"Email security {score}/5 {labels.get(score, 'excellent')} ({parts_str})")

    if ctx.dmarc_policy == "none":
        insights.append("DMARC: none — email spoofing protection not enforced")
    elif ctx.dmarc_policy is None:
        insights.append("No DMARC record — potential email security gap")
    if not has_dkim:
        insights.append("No DKIM selectors observed at common names — actual DKIM status unknown")

    return insights


def _org_size_insights(ctx: InsightContext) -> list[str]:
    spf_complexity: str | None = None
    for svc in ctx.services:
        if svc.startswith("SPF complexity:"):
            spf_complexity = svc
            break

    if ctx.domain_count >= 20:
        hint = f"{ctx.domain_count} domains — large enterprise"
        if spf_complexity:
            hint += f", {spf_complexity.lower()}"
        return [hint]
    if ctx.domain_count >= 5:
        hint = f"{ctx.domain_count} domains — mid-size organization"
        if spf_complexity:
            hint += f", {spf_complexity.lower()}"
        return [hint]
    if spf_complexity and "large" in spf_complexity.lower():
        return [f"Large org signal: {spf_complexity.lower()}"]
    if ctx.domain_count >= 2:
        return [f"{ctx.domain_count} domains in tenant"]
    return []


def _gateway_insights(ctx: InsightContext) -> list[str]:
    has_exchange = bool(ctx.slugs & _EXCHANGE_SLUGS)
    gateway = [name for slug, name in _GATEWAY_SLUG_MAP.items() if slug in ctx.slugs]
    if not gateway:
        return []
    gw_str = ", ".join(gateway)
    if has_exchange:
        return [f"Email gateway: {gw_str} in front of Exchange"]
    return [f"Email gateway: {gw_str}"]


def _migration_insights(ctx: InsightContext) -> list[str]:
    if bool(ctx.slugs & _GOOGLE_SLUGS) and bool(ctx.slugs & _EXCHANGE_SLUGS):
        return ["Dual provider: Google + Microsoft coexistence"]
    return []


def _license_insights(ctx: InsightContext) -> list[str]:
    has_intune = SVC_INTUNE_MDM in ctx.services
    has_office_proplus = SVC_OFFICE_PROPLUS in ctx.services

    if has_intune and ctx.auth_type == "Federated":
        return ["M365 E3/E5 indicators (Intune + federated auth)"]
    if has_intune:
        return ["M365 E3+ indicators (Intune enrolled)"]
    if has_office_proplus:
        return ["Office ProPlus indicators (E3+ or Apps for Enterprise)"]
    return []


def _security_stack_insights(ctx: InsightContext) -> list[str]:
    tools = [desc for slug, desc in _SEC_TOOL_SLUG_MAP.items() if slug in ctx.slugs]
    if tools:
        return [f"Security stack: {', '.join(tools)}"]
    return []


def _mdm_insights(ctx: InsightContext) -> list[str]:
    has_intune = SVC_INTUNE_MDM in ctx.services
    has_jamf = "jamf" in ctx.slugs
    has_kandji = "kandji" in ctx.slugs
    # Dual MDM: Windows (Intune) + Mac (Jamf or Kandji)
    mac_mdm = has_jamf or has_kandji
    mac_name = "Jamf" if has_jamf else "Kandji" if has_kandji else None
    if has_intune and mac_mdm:
        return [f"Dual MDM: Intune + {mac_name} (Windows + Mac fleet)"]
    if has_jamf:
        return ["Mac management (Jamf)"]
    if has_kandji:
        return ["Mac management (Kandji)"]
    return []


def _infrastructure_insights(ctx: InsightContext) -> list[str]:
    cloud = []
    for svc in sorted(ctx.services):
        if svc.startswith(("DNS:", "CDN:", "Hosting:", "WAF:")):
            cloud.append(svc.split(": ", 1)[1])
    if cloud:
        return [f"Infrastructure: {', '.join(cloud)}"]
    return []


_SASE_SLUGS: dict[str, str] = {
    "zscaler": "Zscaler",
    "netskope": "Netskope",
    # NOTE: Cloudflare is NOT here. Using Cloudflare DNS/CDN (detected via NS
    # records) is not the same as deploying Cloudflare Zero Trust / Access.
    # We'd need a specific TXT verification record to detect Zero Trust.
    "paloalto": "Palo Alto",
}


def _sase_insights(ctx: InsightContext) -> list[str]:
    """Detect SASE/ZTNA/SSE deployment from network security vendors."""
    providers = [name for slug, name in _SASE_SLUGS.items() if slug in ctx.slugs]
    if len(providers) >= 2:
        return [f"SASE/ZTNA: {', '.join(providers)} (multi-vendor edge security)"]
    if providers:
        return [f"SASE/ZTNA: {providers[0]}"]
    return []


_PKI_SLUG_MAP: dict[str, str] = {
    "letsencrypt": "Let's Encrypt",
    "digicert": "DigiCert",
    "sectigo": "Sectigo",
    "aws-acm": "AWS ACM",
    "google-trust": "Google Trust",
    "globalsign": "GlobalSign",
}


def _pki_insights(ctx: InsightContext) -> list[str]:
    """Surface certificate authority choices from CAA records."""
    cas = [name for slug, name in _PKI_SLUG_MAP.items() if slug in ctx.slugs]
    if cas:
        return [f"PKI: {', '.join(cas)}"]
    return []


def _google_auth_insights(ctx: InsightContext) -> list[str]:
    """Surface Google Workspace federated/managed identity insights."""
    if "google-federated" in ctx.slugs:
        if ctx.google_idp_name:
            return [f"Google Workspace: Federated identity via {ctx.google_idp_name}"]
        return ["Google Workspace: Federated identity (external IdP)"]
    if "google-managed" in ctx.slugs:
        return ["Google Workspace: Managed identity (Google-native)"]
    return []


# Google Workspace module service prefix used to detect active modules.
_GWS_MODULE_PREFIX = "Google Workspace: "


def _google_modules_insights(ctx: InsightContext) -> list[str]:
    """Surface a summary of active Google Workspace modules."""
    modules = sorted(svc[len(_GWS_MODULE_PREFIX) :] for svc in ctx.services if svc.startswith(_GWS_MODULE_PREFIX))
    if modules:
        return [f"Google Workspace modules: {', '.join(modules)}"]
    return []


def _email_topology_insights(ctx: InsightContext) -> list[str]:
    """Surface email gateway topology and secondary provider detection."""
    insights: list[str] = []

    # Gateway topology insight
    gateway = [name for slug, name in _GATEWAY_SLUG_MAP.items() if slug in ctx.slugs]
    has_exchange = bool(ctx.slugs & _EXCHANGE_SLUGS)
    has_google = bool(ctx.slugs & _GOOGLE_SLUGS)

    primary = []
    if has_exchange:
        primary.append("Microsoft 365")
    if has_google:
        primary.append("Google Workspace")

    if gateway and primary:
        gw_str = ", ".join(gateway)
        pri_str = " + ".join(primary)
        insights.append(f"Email delivery path: {gw_str} gateway → {pri_str}")

    return insights


# ── Ordered pipeline of all generators ──────────────────────────────────

_INSIGHT_GENERATORS = [
    _auth_insights,
    _google_auth_insights,
    _email_security_insights,
    _org_size_insights,
    _gateway_insights,
    _email_topology_insights,
    _migration_insights,
    _license_insights,
    _security_stack_insights,
    _sase_insights,
    _mdm_insights,
    _pki_insights,
    _google_modules_insights,
    _infrastructure_insights,
]


def generate_insights(
    services: set[str],
    slugs: set[str],
    auth_type: str | None,
    dmarc_policy: str | None,
    domain_count: int,
    google_auth_type: str | None = None,
    google_idp_name: str | None = None,
) -> list[str]:
    """Derive intelligence signals from collected data.

    Runs all insight generators in order and collects results.
    Each generator is a pure function operating on an immutable context.
    """
    ctx = InsightContext.from_sets(
        services,
        slugs,
        auth_type,
        dmarc_policy,
        domain_count,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
    )
    insights: list[str] = []
    for generator in _INSIGHT_GENERATORS:
        insights.extend(generator(ctx))
    return insights
