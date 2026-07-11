"""Insight generation engine — derives intelligence signals from collected data.

Decomposes insight generation into focused, testable generators.
Each generator is a pure function: (context) -> list[str].
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DKIM_GOOGLE,
    SVC_INTUNE_MDM,
    SVC_MTA_STS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
    effective_dmarc_policy,
)
from recon_tool.email_security import claim_safe_email_services
from recon_tool.models import EvidenceRecord
from recon_tool.validator import host_has_suffix

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
    dmarc_effective_policy: str | None
    domain_count: int
    google_auth_type: str | None = None
    google_idp_name: str | None = None
    # OIDC tenant metadata enrichment
    cloud_instance: str | None = None
    tenant_region_sub_scope: str | None = None
    msgraph_host: str | None = None
    # Evidence-aware email topology. ``email_gateway`` is populated only from
    # MX evidence. ``primary_email_provider`` is either MX-backed or promoted
    # from DKIM when MX names a gateway; ``likely_primary_email_provider`` is
    # the explicitly weaker non-MX inference.
    primary_email_provider: str | None = None
    likely_primary_email_provider: str | None = None
    email_gateway: str | None = None
    # True when ANY MX records exist, even if they point
    # to a host recon doesn't recognize (custom Postfix, etc.).
    # Distinguishes "no email at all" from
    # "custom email we can't name." Used by
    # _no_email_infrastructure_insights to avoid claiming "no
    # email" when the catalog cannot classify observed MX hosts.
    has_mx_records: bool = False
    # Service names whose source record establishes the role encoded by the
    # name. Extensible names stay in ``services`` as inventory, but only this
    # subset may drive module, edge, hosting, DNS, or WAF claims.
    role_scoped_services: frozenset[str] = frozenset()

    @classmethod
    def from_sets(
        cls,
        services: set[str],
        slugs: set[str],
        auth_type: str | None,
        dmarc_policy: str | None,
        domain_count: int,
        dmarc_effective_policy: str | None = None,
        google_auth_type: str | None = None,
        google_idp_name: str | None = None,
        cloud_instance: str | None = None,
        tenant_region_sub_scope: str | None = None,
        msgraph_host: str | None = None,
        primary_email_provider: str | None = None,
        likely_primary_email_provider: str | None = None,
        email_gateway: str | None = None,
        has_mx_records: bool = False,
        evidence: Iterable[EvidenceRecord] = (),
    ) -> InsightContext:
        """Convenience constructor that converts mutable sets to frozensets."""
        evidence = tuple(evidence)
        claim_services = claim_safe_email_services(services, evidence)
        role_scoped_services: set[str] = set()
        for service in claim_services:
            source_types = {
                record.source_type.upper() for record in evidence if record.rule_name.casefold() == service.casefold()
            }
            role_observed = (
                (
                    service.startswith("Google Workspace: ")
                    and any(source_type.startswith("CNAME") for source_type in source_types)
                )
                or (service == "Google Workspace CSE" and "HTTP" in source_types)
                or (service.startswith("DNS:") and "NS" in source_types)
                or (
                    service.startswith(("CDN:", "Hosting:", "WAF:"))
                    and any(
                        source_type.startswith("CNAME") or source_type in {"A", "PTR"} for source_type in source_types
                    )
                )
            )
            if role_observed:
                role_scoped_services.add(service)
        return cls(
            services=frozenset(claim_services),
            slugs=frozenset(slugs),
            auth_type=auth_type,
            dmarc_policy=dmarc_policy,
            dmarc_effective_policy=(
                dmarc_effective_policy if dmarc_effective_policy is not None else effective_dmarc_policy(dmarc_policy)
            ),
            domain_count=domain_count,
            google_auth_type=google_auth_type,
            google_idp_name=google_idp_name,
            cloud_instance=cloud_instance,
            tenant_region_sub_scope=tenant_region_sub_scope,
            msgraph_host=msgraph_host,
            primary_email_provider=primary_email_provider,
            likely_primary_email_provider=likely_primary_email_provider,
            email_gateway=email_gateway,
            has_mx_records=has_mx_records,
            role_scoped_services=frozenset(role_scoped_services),
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

_SEC_TOOL_SLUG_MAP: dict[str, str] = {
    "knowbe4": "KnowBe4 (security training)",
    "crowdstrike": "CrowdStrike (endpoint)",
    "sentinelone": "SentinelOne (endpoint)",
    "sophos": "Sophos (endpoint)",
    "duo": "Duo (MFA)",
    "okta": "Okta (identity)",
    "1password": "1Password (credentials)",
    "paloalto": "Palo Alto (network)",
    "zscaler": "Zscaler (network security)",
    "netskope": "Netskope (network security)",
    "wiz": "Wiz (cloud security)",
    "imperva": "Imperva (WAF)",
}

# Identity vendors with comparatively specific public fingerprints. These
# indicators can accompany a federated namespace, but they do not establish
# which vendor operates the external IdP.
# `cisco-identity` is deliberately excluded: its only trigger is the TXT
# token `cisco-ci-domain-verification=`, which is used by many Cisco
# products (Duo, Customer Identity, Secure Email, Intersight) and is not
# evidence of the SSO provider — it just means the org registered with
# Cisco for something.
_IDENTITY_VENDOR_SLUG_MAP: dict[str, str] = {
    "okta": "Okta",
    "duo": "Duo",
}

_SPARSE_NON_SUBSTANTIVE_PREFIXES = ("SPF complexity:",)

_EDGE_SERVICE_PREFIXES = ("DNS:", "CDN:", "WAF:")

_SPARSE_DOC_HINT = (
    "Next step: see docs/weak-areas.md for passive-only blind spots. "
    "For an operator-supplied domain set, run `recon batch <candidates.txt>`; "
    "for bounded related-host discovery, run `recon <domain> --chain --depth 2`."
)


def _substantive_services(ctx: InsightContext) -> list[str]:
    """Return services that count toward signal richness for sparse heuristics."""
    return [svc for svc in ctx.services if not svc.startswith(_SPARSE_NON_SUBSTANTIVE_PREFIXES)]


def _edge_services(ctx: InsightContext) -> list[str]:
    """Return distinct edge-layer services visible in the service list."""
    found: list[str] = []
    for svc in sorted(ctx.role_scoped_services):
        if not svc.startswith(_EDGE_SERVICE_PREFIXES):
            continue
        _, _, provider = svc.partition(": ")
        if provider and provider not in found:
            found.append(provider)
    return found


# ── Individual insight generators ───────────────────────────────────────
# Each returns a list of insight strings. Pure functions, easy to test.
#
# Some generators (security vendors, network security, PKI) follow a simple
# "match slugs → format string" pattern that could theoretically be
# data-driven like signals.yaml. However, the more complex generators
# (email-security scoring and auth type + IdP correlation) require branching
# logic that doesn't reduce to slug matching. Keeping them all as
# functions maintains a uniform interface for the _INSIGHT_GENERATORS
# pipeline and keeps each generator independently testable.


def _auth_insights(ctx: InsightContext) -> list[str]:
    if ctx.auth_type == "Federated":
        vendors = [name for slug, name in _IDENTITY_VENDOR_SLUG_MAP.items() if slug in ctx.slugs]
        if vendors:
            return [f"Federated identity observed; identity-vendor indicators: {', '.join(vendors)}"]
        return ["Federated identity observed; external IdP not identified"]
    if ctx.auth_type == "Managed":
        # Only claim "Entra ID native" when we actually see M365 evidence.
        # GetUserRealm returns "Managed" for non-Microsoft domains too —
        # it just means "not federated" from Microsoft's perspective.
        has_m365 = bool(ctx.slugs & _EXCHANGE_SLUGS)
        if not has_m365:
            return []
        # Refinement: on dual-provider targets (M365 + Google
        # Workspace both present), the Auth line compound format
        # already reads "Managed (Entra ID + Google Workspace)" so
        # this insight would be pure restatement. Drop it then. On
        # pure M365 targets the Auth line is just "Managed" — keep
        # the insight there so the user sees the "Entra ID native"
        # distinction vs. ADFS federation.
        if ctx.google_auth_type:
            return []
        return ["Cloud-managed identity indicators (Entra ID native)"]
    return []


def _has_scoreable_email(ctx: InsightContext) -> bool:
    """Whether there is email worth scoring.

    Honesty fix: a bare Exchange / Google-Workspace slug can come from a
    non-MX source (Google Identity Routing reporting a registered account,
    Microsoft OIDC reporting a tenant), which does not prove the domain receives
    email there. On a domain with zero MX records and no DMARC, an "Email
    security 0/5 weak" score reads as "configured but badly secured" when the
    truth is "no email configured to score". So a provider slug only counts
    alongside an MX-backed signal (a strict or inferred primary, a real DMARC
    record, or a dedicated outbound-email slug).
    """
    has_exchange = bool(ctx.slugs & _EXCHANGE_SLUGS)
    has_google = bool(ctx.slugs & _GOOGLE_SLUGS)
    has_mx_signal = bool(
        ctx.primary_email_provider
        or ctx.likely_primary_email_provider
        or ctx.dmarc_policy is not None
        or bool(ctx.slugs & _EMAIL_SLUGS)
    )
    return (
        (has_exchange and has_mx_signal)
        or (has_google and has_mx_signal)
        or bool(ctx.slugs & _EMAIL_SLUGS)
        or bool(ctx.services & {SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_DKIM_GOOGLE, SVC_SPF_STRICT, SVC_MTA_STS, SVC_BIMI})
        or ctx.has_mx_records
        or ctx.email_gateway is not None
        or ctx.dmarc_policy is not None  # has DMARC record = has email
    )


def _email_score_parts(ctx: InsightContext) -> tuple[list[str], bool]:
    """The observed email-hardening controls, in score order.

    A gateway and enforcing DMARC do not establish DKIM. Only an observed DKIM
    service marker receives credit; untested custom selectors remain an explicit
    passive-collection caveat.
    """
    has_dkim = bool(ctx.services & {SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_DKIM_GOOGLE})
    has_bimi = SVC_BIMI in ctx.services
    has_mta_sts = SVC_MTA_STS in ctx.services
    has_spf_strict = SVC_SPF_STRICT in ctx.services
    enforcing_policy = ctx.dmarc_effective_policy
    score_parts: list[str] = []
    if enforcing_policy in ("reject", "quarantine"):
        score_parts.append(f"DMARC {enforcing_policy}")
    if has_dkim:
        score_parts.append("DKIM")
    if has_spf_strict:
        score_parts.append("SPF strict")
    if has_mta_sts:
        score_parts.append("MTA-STS")
    if has_bimi:
        score_parts.append("BIMI")
    return score_parts, has_dkim


def _non_scoring_email_summary(ctx: InsightContext) -> str:
    """Summary line when no strict control scored: name what IS configured
    (DMARC monitoring, soft/neutral SPF) rather than implying absence, which
    would misread a monitoring-mode deployment as nothing at all."""
    observed_non_scoring: list[str] = []
    if ctx.dmarc_policy is not None and ctx.dmarc_effective_policy == "none":
        observed_non_scoring.append("DMARC monitoring only")
    if SVC_SPF_SOFTFAIL in ctx.services and SVC_SPF_STRICT not in ctx.services:
        observed_non_scoring.append("SPF soft/neutral")
    if observed_non_scoring:
        return ", ".join(observed_non_scoring) + " - no strict controls"
    return "no strict controls observed"


def _email_security_insights(ctx: InsightContext) -> list[str]:
    if not _has_scoreable_email(ctx):
        if ctx.dmarc_policy:
            if ctx.dmarc_effective_policy and ctx.dmarc_effective_policy != ctx.dmarc_policy:
                return [f"DMARC: {ctx.dmarc_policy} (effective {ctx.dmarc_effective_policy})"]
            return [f"DMARC: {ctx.dmarc_policy}"]
        return []

    score_parts, has_dkim = _email_score_parts(ctx)
    parts_str = ", ".join(score_parts) if score_parts else _non_scoring_email_summary(ctx)

    # Panel line: inventory of observed controls, no fraction or grade. The N/5
    # form was still read as a grade even without the verdict word, and the
    # controls are not equally weighted (DMARC reject is load-bearing, BIMI is
    # decorative). The machine-readable email_security_score field stays in
    # --json for consumers that need to sort/filter (see docs/schema.md).
    descriptor = "observed controls" if score_parts else "observed configuration"
    insights: list[str] = [f"Email security: {descriptor}: {parts_str}"]

    # Auxiliary notes name the consequence the score line only implies.
    if ctx.dmarc_policy is not None and ctx.dmarc_effective_policy == "none":
        if ctx.dmarc_policy == "none":
            insights.append("DMARC: none - monitoring mode, not enforced")
        else:
            insights.append("DMARC: effective none after rollout or testing tags")
    elif ctx.dmarc_policy is None:
        insights.append("No valid DMARC policy record observed at apex")
    if not has_dkim:
        insights.append("No DKIM at common selectors observed (other selector names may exist)")

    return insights


def _tenant_domain_insights(ctx: InsightContext) -> list[str]:
    """Report tenant-discovery cardinality without inferring organization size."""
    if ctx.domain_count >= 2:
        return [f"Microsoft tenant discovery returned {ctx.domain_count} domains"]
    return []


def _gateway_insights(ctx: InsightContext) -> list[str]:
    """Report a gateway only when MX evidence established the topology field."""
    if ctx.email_gateway is None:
        return []
    return [f"MX gateway observed: {ctx.email_gateway}"]


def _provider_overlap_insights(ctx: InsightContext) -> list[str]:
    """Report simultaneous provider indicators without assigning a cause."""
    if bool(ctx.slugs & _GOOGLE_SLUGS) and bool(ctx.slugs & _EXCHANGE_SLUGS):
        return ["Provider indicators co-observed: Google Workspace, Microsoft 365"]
    return []


def _security_vendor_insights(ctx: InsightContext) -> list[str]:
    """Report public vendor indicators without claiming an active stack."""
    tools = [desc for slug, desc in _SEC_TOOL_SLUG_MAP.items() if slug in ctx.slugs]
    if tools:
        return [f"Security-vendor indicators observed: {', '.join(tools)}"]
    return []


def _device_management_insights(ctx: InsightContext) -> list[str]:
    """Report device-management vendor indicators without inferring a fleet."""
    providers: list[str] = []
    if SVC_INTUNE_MDM in ctx.services:
        providers.append("Intune")
    if "jamf" in ctx.slugs:
        providers.append("Jamf")
    if "kandji" in ctx.slugs:
        providers.append("Kandji")
    if not providers:
        return []
    label = "indicator" if len(providers) == 1 else "indicators"
    return [f"Device-management vendor {label} observed: {', '.join(providers)}"]


def _infrastructure_insights(ctx: InsightContext) -> list[str]:
    cloud = []
    for svc in sorted(ctx.role_scoped_services):
        if svc.startswith(("DNS:", "CDN:", "Hosting:", "WAF:")):
            cloud.append(svc.split(": ", 1)[1])
    if cloud:
        return [f"Infrastructure: {', '.join(cloud)}"]
    return []


_NETWORK_SECURITY_SLUGS: dict[str, str] = {
    "zscaler": "Zscaler",
    "netskope": "Netskope",
    # NOTE: Cloudflare is NOT here. Using Cloudflare DNS/CDN (detected via NS
    # records) is not the same as deploying Cloudflare Zero Trust / Access.
    # We'd need a specific TXT verification record to detect Zero Trust.
    "paloalto": "Palo Alto",
}


def _network_security_insights(ctx: InsightContext) -> list[str]:
    """Report network-security vendor indicators without inferring deployment."""
    providers = [name for slug, name in _NETWORK_SECURITY_SLUGS.items() if slug in ctx.slugs]
    if not providers:
        return []
    label = "indicator" if len(providers) == 1 else "indicators"
    return [f"Network-security vendor {label} observed: {', '.join(providers)}"]


_PKI_SLUG_MAP: dict[str, str] = {
    "letsencrypt": "Let's Encrypt",
    "digicert": "DigiCert",
    "sectigo": "Sectigo",
    "aws-acm": "AWS ACM",
    "google-trust": "Google Trust",
}


def _pki_insights(ctx: InsightContext) -> list[str]:
    """Surface certificate issuer authorizations from CAA records."""
    cas = [name for slug, name in _PKI_SLUG_MAP.items() if slug in ctx.slugs]
    if cas:
        return [f"CAA issuer authorization observed: {', '.join(cas)}"]
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


# Google Workspace module service prefix used to surface module indicators.
_GWS_MODULE_PREFIX = "Google Workspace: "


def _google_modules_insights(ctx: InsightContext) -> list[str]:
    """Surface observed Google Workspace module indicators."""
    modules = sorted(
        svc[len(_GWS_MODULE_PREFIX) :] for svc in ctx.role_scoped_services if svc.startswith(_GWS_MODULE_PREFIX)
    )
    if modules:
        return [f"Google Workspace module indicators observed: {', '.join(modules)}"]
    return []


def _no_email_infrastructure_insights(ctx: InsightContext) -> list[str]:
    """Emit an explicit hedged observation when a domain has
    no observable email infrastructure at all.

    The decisive signal is ``has_mx_records``: when True, the domain
    has at least one MX record (even if the host isn't a recognized
    provider, such as a custom Postfix deployment), so
    email IS configured and this insight must not fire. When False,
    we additionally check that no DMARC record exists, no DKIM
    selectors were seen, and no outbound-email service slug was
    detected — only then can we honestly say "no email
    infrastructure observed."

    Getting this wrong in either direction is bad: firing on a
    custom-MX domain would falsely claim there is no email. Not
    firing on a domain with a dormant account-registration signal
    would let the user reach the wrong conclusion that email is
    routed to that provider.

    The wording is two-sided: no email can mean web-only
    presence, parked domain, staging property, or email handled
    on a different apex. Observation, not a verdict.
    """
    # Most important check: if MX records exist at all, there IS
    # email. Don't fire the "no email" insight on custom/self-
    # hosted mail servers.
    if ctx.has_mx_records:
        return []
    if ctx.primary_email_provider or ctx.likely_primary_email_provider or ctx.email_gateway:
        return []
    if ctx.dmarc_policy is not None:
        return []
    if ctx.slugs & _EMAIL_SLUGS:
        return []
    if any(s.startswith("SPF") for s in ctx.services):
        return []
    return [
        "No observable email infrastructure in the bounded checks: no MX, SPF, "
        "or DMARC record and no DKIM response at the common selectors probed. "
        "Consistent with a web-only presence, a parked domain, a staging property, "
        "or email handled on a different domain. Observation, not a verdict."
    ]


def _sparse_signal_insights(ctx: InsightContext) -> list[str]:
    """Emit a hedged multi-sided observation when a domain's
    public signal is thin.

    On a parked or dormant domain, a heavily proxied namespace,
    or an apex with services hosted elsewhere, recon can only report what's observable
    — and without this explanation a user looking at a panel with
    three service entries and a low confidence can reasonably
    think the tool is broken. Saying explicitly "sparse public
    signal — few observable records" frames the situation
    honestly: this is what's knowable from passive public sources, and
    it's not a tool failure.

    The observation is followed by a concrete next-step hint
    pointing at chain and batch modes, the two
    workflows that can reveal bounded structure beyond a single
    apex (CT-driven recursive discovery and cross-batch token or
    display-name clustering). These workflows still report public
    relationships; they do not establish organizational ownership.

    Fires only when service count is low. The threshold is
    deliberately generous — anything above 5 services is rich
    enough that the user can see the picture on their own.
    """
    substantive = _substantive_services(ctx)
    if len(substantive) >= 5:
        return []
    # Suppress on domains where we still got a tenant_id — that's
    # not really "sparse", it's "M365 tenant only". The existing
    # auth/provider lines already carry the signal.
    if ctx.auth_type in ("Federated", "Managed") and any("microsoft 365" in s.lower() for s in ctx.services):
        return []

    edge = _edge_services(ctx)
    has_unclassified_mail = ctx.has_mx_records and (
        "self-hosted-mail" in ctx.slugs
        or "exchange-onprem" in ctx.slugs
        or (
            ctx.primary_email_provider is None
            and ctx.likely_primary_email_provider is None
            and ctx.email_gateway is None
        )
    )

    if has_unclassified_mail:
        return [
            "Sparse public signal: custom or unclassified MX. MX records exist, "
            "but the public evidence does not identify their operator or hosting "
            "model. Observation, not a verdict.",
            _SPARSE_DOC_HINT,
        ]

    if edge and len(substantive) <= 3:
        visible_edge = ", ".join(edge[:2])
        if len(edge) > 2:
            visible_edge = f"{visible_edge}, and other edge services"
        return [
            f"Sparse public signal — edge-heavy footprint. {visible_edge} sits "
            "in front of the apex, which can hide origin and SaaS detail from "
            "passive public-source collection. Observation, not a verdict.",
            _SPARSE_DOC_HINT,
        ]

    if (
        not ctx.has_mx_records
        and ctx.auth_type is None
        and ctx.google_auth_type is None
        and not edge
        and len(substantive) <= 2
    ):
        return [
            "Sparse public signal — minimal public DNS footprint. Very little is "
            "exposed beyond basic records, which is consistent with a "
            "web-only property, a parked or dormant domain, or services hosted "
            "on a different apex. Observation, not a verdict.",
            _SPARSE_DOC_HINT,
        ]

    return [
        "Sparse public signal — few observable records beyond MX and "
        "identity. Consistent with a parked or dormant domain, a heavily "
        "proxied namespace, or services hosted on a different apex. "
        "Observation, not a verdict.",
        _SPARSE_DOC_HINT,
    ]


def _sovereignty_insights(ctx: InsightContext) -> list[str]:
    """Surface Microsoft tenant sovereignty / cloud-instance info.

    Distinguishes commercial M365, US Government Community Cloud (GCC),
    GCC High / DoD, and Azure China 21Vianet tenants based on the
    OIDC discovery response's cloud_instance_name extension. All
    insights are hedged with "(observed)" so they don't read as
    confident verdicts about regulatory regime.
    """
    ci = (ctx.cloud_instance or "").lower()
    sub = (ctx.tenant_region_sub_scope or "").strip()
    mh = (ctx.msgraph_host or "").lower()

    if not ci and not sub and not mh:
        return []

    results: list[str] = []

    if host_has_suffix(ci, "microsoftonline.us") or host_has_suffix(mh, "graph.microsoft.us"):
        if sub and sub.upper() in ("DOD", "GCCH"):
            results.append(
                f"Likely US Government GCC High / DoD tenant (observed cloud_instance={ci or 'microsoftonline.us'}, "
                f"tenant_region_sub_scope={sub})"
            )
        else:
            results.append(
                f"Likely US Government Community Cloud (GCC) tenant "
                f"(observed cloud_instance={ci or 'microsoftonline.us'})"
            )
    elif host_has_suffix(ci, "partner.microsoftonline.cn") or host_has_suffix(mh, "microsoftgraphchina.cn"):
        results.append(
            f"Likely Azure China 21Vianet tenant (observed cloud_instance={ci or 'partner.microsoftonline.cn'})"
        )
    elif host_has_suffix(ci, "b2clogin.com"):
        results.append(f"Azure AD B2C tenant (observed cloud_instance={ci})")
    elif ci and not host_has_suffix(ci, "microsoftonline.com"):
        # Non-commercial cloud_instance we don't specifically recognize —
        # surface it verbatim so users can investigate.
        results.append(f"Non-commercial Microsoft cloud instance observed: {ci}")

    return results


# ── Ordered pipeline of all generators ──────────────────────────────────

_INSIGHT_GENERATORS = [
    _auth_insights,
    _sovereignty_insights,
    _google_auth_insights,
    _email_security_insights,
    _tenant_domain_insights,
    _gateway_insights,
    _provider_overlap_insights,
    _security_vendor_insights,
    _network_security_insights,
    _device_management_insights,
    _pki_insights,
    _google_modules_insights,
    _infrastructure_insights,
    _no_email_infrastructure_insights,
    _sparse_signal_insights,
]


def generate_insights(
    services: set[str],
    slugs: set[str],
    auth_type: str | None,
    dmarc_policy: str | None,
    domain_count: int,
    google_auth_type: str | None = None,
    google_idp_name: str | None = None,
    cloud_instance: str | None = None,
    tenant_region_sub_scope: str | None = None,
    msgraph_host: str | None = None,
    primary_email_provider: str | None = None,
    likely_primary_email_provider: str | None = None,
    email_gateway: str | None = None,
    has_mx_records: bool = False,
    dmarc_effective_policy: str | None = None,
    evidence: Iterable[EvidenceRecord] = (),
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
        dmarc_effective_policy=dmarc_effective_policy,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
        cloud_instance=cloud_instance,
        tenant_region_sub_scope=tenant_region_sub_scope,
        msgraph_host=msgraph_host,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
        email_gateway=email_gateway,
        has_mx_records=has_mx_records,
        evidence=evidence,
    )
    insights: list[str] = []
    for generator in _INSIGHT_GENERATORS:
        insights.extend(generator(ctx))
    return insights
