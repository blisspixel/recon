"""Insight generation engine — derives intelligence signals from collected data.

Decomposes insight generation into focused, testable generators.
Each generator is a pure function that emits string-compatible values carrying
the evidence association selected at the branch that rendered the text.
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
from recon_tool.insight_claims import (
    GeneratedInsight as _GeneratedInsight,
)
from recon_tool.insight_claims import (
    claim_text as _claim_text,
)
from recon_tool.insight_claims import (
    claimable_services as _claimable_services,
)
from recon_tool.insight_claims import (
    claimable_slugs as _claimable_slugs,
)
from recon_tool.insight_claims import (
    combine_evidence as _combine_evidence,
)
from recon_tool.insight_claims import (
    evidence_for_rule_names as _evidence_for_rule_names,
)
from recon_tool.insight_claims import (
    evidence_for_slugs as _evidence_for_slugs,
)
from recon_tool.insight_claims import (
    evidence_for_source_types as _evidence_for_source_types,
)
from recon_tool.merger_tables import GATEWAY_SLUGS
from recon_tool.models import EvidenceRecord, InsightClaim
from recon_tool.sovereignty_insights import sovereignty_insights
from recon_tool.sparse_insights import sparse_signal_insights

__all__ = [
    "INSIGHT_GENERATOR_RULE_IDS",
    "InsightContext",
    "generate_insight_claims",
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
    # Canonical retained records used to attach exact evidence occurrences to
    # claims while the generator that emitted them is still known.
    evidence: tuple[EvidenceRecord, ...] = ()
    # Runtime merge/projection contexts are evidence-bound even when their
    # canonical evidence sequence is empty. Direct generator calls keep the
    # historical convenience behavior for isolated unit use.
    evidence_bound: bool = False

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
        evidence_bound: bool = False,
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
            evidence=evidence,
            evidence_bound=evidence_bound,
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
    realm_evidence = tuple(
        record
        for record in ctx.evidence
        if record.rule_name == "GetUserRealm" and record.raw_value.casefold().startswith("namespacetype=")
    )
    if ctx.auth_type == "Federated":
        vendor_slugs = _claimable_slugs(ctx, frozenset(_IDENTITY_VENDOR_SLUG_MAP))
        vendors = [name for slug, name in _IDENTITY_VENDOR_SLUG_MAP.items() if slug in vendor_slugs]
        if vendors:
            vendor_evidence = _evidence_for_slugs(ctx, vendor_slugs)
            return [
                _claim_text(
                    f"Federated identity observed; identity-vendor indicators: {', '.join(vendors)}",
                    evidence=_combine_evidence(ctx, realm_evidence, vendor_evidence),
                    scope=("identity:user_realm",),
                )
            ]
        return [
            _claim_text(
                "Federated identity observed; external IdP not identified",
                evidence=realm_evidence,
                scope=("identity:user_realm", "dns:apex_txt", "dns:cname"),
                allows_scope_only=True,
            )
        ]
    if ctx.auth_type == "Managed":
        # Only claim "Entra ID native" when we actually see M365 evidence.
        # GetUserRealm returns "Managed" for non-Microsoft domains too —
        # it just means "not federated" from Microsoft's perspective.
        m365_slugs = _claimable_slugs(ctx, _EXCHANGE_SLUGS)
        has_m365 = bool(m365_slugs)
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
        return [
            _claim_text(
                "Cloud-managed identity indicators (Entra ID native)",
                evidence=_combine_evidence(ctx, realm_evidence, _evidence_for_slugs(ctx, m365_slugs)),
                scope=("identity:user_realm",),
            )
        ]
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
    has_outbound = bool(_claimable_slugs(ctx, _EMAIL_SLUGS))
    has_mx_signal = bool(
        ctx.primary_email_provider or ctx.likely_primary_email_provider or ctx.dmarc_policy is not None or has_outbound
    )
    return (
        (has_exchange and has_mx_signal)
        or (has_google and has_mx_signal)
        or has_outbound
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


_EMAIL_OBSERVATION_SCOPE = (
    "dns:mx",
    "dns:apex_txt",
    "dns:dmarc",
    "dns:dkim_common_selectors",
    "http:mta_sts_policy",
    "dns:bimi",
)


def _email_summary_evidence(ctx: InsightContext) -> tuple[EvidenceRecord, ...]:
    """Return only occurrences read to render or qualify the summary line."""
    control_services = frozenset(
        {
            SVC_DKIM,
            SVC_DKIM_EXCHANGE,
            SVC_DKIM_GOOGLE,
            SVC_SPF_STRICT,
            SVC_SPF_SOFTFAIL,
            SVC_MTA_STS,
            SVC_BIMI,
        }
    )
    controls = _evidence_for_rule_names(ctx, ctx.services & control_services)
    dmarc = _evidence_for_source_types(ctx, frozenset({"DMARC"})) if ctx.dmarc_policy is not None else ()
    mx = (
        _evidence_for_source_types(ctx, frozenset({"MX"}))
        if (ctx.has_mx_records or ctx.primary_email_provider or ctx.likely_primary_email_provider or ctx.email_gateway)
        else ()
    )
    outbound = _evidence_for_slugs(ctx, ctx.slugs & _EMAIL_SLUGS)
    return _combine_evidence(ctx, controls, dmarc, mx, outbound)


def _email_security_insights(ctx: InsightContext) -> list[str]:
    if not _has_scoreable_email(ctx):
        if ctx.dmarc_policy:
            dmarc_evidence = _evidence_for_source_types(ctx, frozenset({"DMARC"}))
            if ctx.dmarc_effective_policy and ctx.dmarc_effective_policy != ctx.dmarc_policy:
                return [
                    _claim_text(
                        f"DMARC: {ctx.dmarc_policy} (effective {ctx.dmarc_effective_policy})",
                        evidence=dmarc_evidence,
                        scope=("dns:dmarc",),
                        allows_scope_only=True,
                    )
                ]
            return [
                _claim_text(
                    f"DMARC: {ctx.dmarc_policy}",
                    evidence=dmarc_evidence,
                    scope=("dns:dmarc",),
                    allows_scope_only=True,
                )
            ]
        return []

    score_parts, has_dkim = _email_score_parts(ctx)
    parts_str = ", ".join(score_parts) if score_parts else _non_scoring_email_summary(ctx)

    # Panel line: inventory of observed controls, no fraction or grade. The N/5
    # form was still read as a grade even without the verdict word, and the
    # controls are not equally weighted (DMARC reject is load-bearing, BIMI is
    # decorative). The machine-readable email_security_score field stays in
    # --json for consumers that need to sort/filter (see docs/schema.md).
    descriptor = "observed controls" if score_parts else "observed configuration"
    insights: list[str] = [
        _claim_text(
            f"Email security: {descriptor}: {parts_str}",
            evidence=_email_summary_evidence(ctx),
            scope=_EMAIL_OBSERVATION_SCOPE,
            allows_scope_only=True,
        )
    ]

    # Auxiliary notes name the consequence the score line only implies.
    if ctx.dmarc_policy is not None and ctx.dmarc_effective_policy == "none":
        if ctx.dmarc_policy == "none":
            insights.append(
                _claim_text(
                    "DMARC: none - monitoring mode, not enforced",
                    evidence=_evidence_for_source_types(ctx, frozenset({"DMARC"})),
                    scope=("dns:dmarc",),
                    allows_scope_only=True,
                )
            )
        else:
            insights.append(
                _claim_text(
                    "DMARC: effective none after rollout or testing tags",
                    evidence=_evidence_for_source_types(ctx, frozenset({"DMARC"})),
                    scope=("dns:dmarc",),
                    allows_scope_only=True,
                )
            )
    elif ctx.dmarc_policy is None:
        insights.append(
            _claim_text(
                "No valid DMARC policy record observed at apex",
                evidence=_evidence_for_slugs(ctx, frozenset({"dmarc-invalid"})),
                scope=("dns:dmarc",),
                allows_scope_only=True,
            )
        )
    if not has_dkim:
        insights.append(
            _claim_text(
                "No DKIM at common selectors observed (other selector names may exist)",
                scope=("dns:dkim_common_selectors",),
                allows_scope_only=True,
            )
        )

    return insights


def _tenant_domain_insights(ctx: InsightContext) -> list[str]:
    """Report tenant-discovery cardinality without inferring organization size."""
    if ctx.domain_count >= 2:
        return [
            _claim_text(
                f"Microsoft tenant discovery returned {ctx.domain_count} domains",
                evidence=_evidence_for_rule_names(ctx, frozenset({"Autodiscover"})),
                scope=("identity:autodiscover",),
                allows_scope_only=True,
            )
        ]
    return []


def _gateway_insights(ctx: InsightContext) -> list[str]:
    """Report a gateway only when MX evidence established the topology field."""
    if ctx.email_gateway is None:
        return []
    gateway_slugs = frozenset(
        record.slug for record in ctx.evidence if record.source_type.upper() == "MX" and record.slug in GATEWAY_SLUGS
    )
    return [
        _claim_text(
            f"MX gateway observed: {ctx.email_gateway}",
            evidence=_evidence_for_slugs(ctx, gateway_slugs, source_types=frozenset({"MX"})),
            scope=("dns:mx",),
            allows_scope_only=True,
        )
    ]


def _provider_overlap_insights(ctx: InsightContext) -> list[str]:
    """Report simultaneous provider indicators without assigning a cause."""
    google_slugs = _claimable_slugs(ctx, _GOOGLE_SLUGS)
    exchange_slugs = _claimable_slugs(ctx, _EXCHANGE_SLUGS)
    if google_slugs and exchange_slugs:
        return [
            _claim_text(
                "Provider indicators co-observed: Google Workspace, Microsoft 365",
                evidence=_evidence_for_slugs(ctx, google_slugs | exchange_slugs),
                scope=(),
            )
        ]
    return []


def _security_vendor_insights(ctx: InsightContext) -> list[str]:
    """Report public vendor indicators without claiming an active stack."""
    active_slugs = _claimable_slugs(ctx, frozenset(_SEC_TOOL_SLUG_MAP))
    tools = [desc for slug, desc in _SEC_TOOL_SLUG_MAP.items() if slug in active_slugs]
    if tools:
        return [
            _claim_text(
                f"Security-vendor indicators observed: {', '.join(tools)}",
                evidence=_evidence_for_slugs(ctx, active_slugs),
                scope=(),
            )
        ]
    return []


def _device_management_insights(ctx: InsightContext) -> list[str]:
    """Report device-management vendor indicators without inferring a fleet."""
    providers: list[str] = []
    intune_services = _claimable_services(ctx, frozenset({SVC_INTUNE_MDM}))
    device_slugs = _claimable_slugs(ctx, frozenset({"jamf", "kandji"}))
    if intune_services:
        providers.append("Intune")
    if "jamf" in device_slugs:
        providers.append("Jamf")
    if "kandji" in device_slugs:
        providers.append("Kandji")
    if not providers:
        return []
    label = "indicator" if len(providers) == 1 else "indicators"
    return [
        _claim_text(
            f"Device-management vendor {label} observed: {', '.join(providers)}",
            evidence=_combine_evidence(
                ctx,
                _evidence_for_rule_names(ctx, intune_services),
                _evidence_for_slugs(ctx, device_slugs),
            ),
            scope=(),
        )
    ]


def _infrastructure_insights(ctx: InsightContext) -> list[str]:
    cloud = []
    for svc in sorted(ctx.role_scoped_services):
        if svc.startswith(("DNS:", "CDN:", "Hosting:", "WAF:")):
            _role, separator, provider = svc.partition(": ")
            if separator and provider:
                cloud.append(provider)
    if cloud:
        active_services = frozenset(
            service for service in ctx.role_scoped_services if service.startswith(("DNS:", "CDN:", "Hosting:", "WAF:"))
        )
        return [
            _claim_text(
                f"Infrastructure: {', '.join(cloud)}",
                evidence=_evidence_for_rule_names(ctx, active_services),
                scope=(),
            )
        ]
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
    active_slugs = _claimable_slugs(ctx, frozenset(_NETWORK_SECURITY_SLUGS))
    providers = [name for slug, name in _NETWORK_SECURITY_SLUGS.items() if slug in active_slugs]
    if not providers:
        return []
    label = "indicator" if len(providers) == 1 else "indicators"
    return [
        _claim_text(
            f"Network-security vendor {label} observed: {', '.join(providers)}",
            evidence=_evidence_for_slugs(ctx, active_slugs),
            scope=(),
        )
    ]


_PKI_SLUG_MAP: dict[str, str] = {
    "letsencrypt": "Let's Encrypt",
    "digicert": "DigiCert",
    "sectigo": "Sectigo",
    "aws-acm": "AWS ACM",
    "google-trust": "Google Trust",
}


def _pki_insights(ctx: InsightContext) -> list[str]:
    """Surface certificate issuer authorizations from CAA records."""
    active_slugs = _claimable_slugs(ctx, frozenset(_PKI_SLUG_MAP))
    cas = [name for slug, name in _PKI_SLUG_MAP.items() if slug in active_slugs]
    if cas:
        return [
            _claim_text(
                f"CAA issuer authorization observed: {', '.join(cas)}",
                evidence=_evidence_for_slugs(ctx, active_slugs, source_types=frozenset({"CAA"})),
                scope=(),
            )
        ]
    return []


def _google_auth_insights(ctx: InsightContext) -> list[str]:
    """Surface Google Workspace federated/managed identity insights."""
    active_slugs = _claimable_slugs(ctx, frozenset({"google-federated", "google-managed"}))
    evidence = _evidence_for_slugs(ctx, active_slugs)
    if "google-federated" in active_slugs:
        if ctx.google_idp_name:
            return [
                _claim_text(
                    f"Google Workspace: Federated identity via {ctx.google_idp_name}",
                    evidence=evidence,
                    scope=("identity:google_routing",),
                )
            ]
        return [
            _claim_text(
                "Google Workspace: Federated identity (external IdP)",
                evidence=evidence,
                scope=("identity:google_routing",),
            )
        ]
    if "google-managed" in active_slugs:
        return [
            _claim_text(
                "Google Workspace: Managed identity (Google-native)",
                evidence=evidence,
                scope=("identity:google_routing",),
            )
        ]
    return []


# Google Workspace module service prefix used to surface module indicators.
_GWS_MODULE_PREFIX = "Google Workspace: "


def _google_modules_insights(ctx: InsightContext) -> list[str]:
    """Surface observed Google Workspace module indicators."""
    modules = sorted(
        svc[len(_GWS_MODULE_PREFIX) :] for svc in ctx.role_scoped_services if svc.startswith(_GWS_MODULE_PREFIX)
    )
    if modules:
        active_services = frozenset(
            service for service in ctx.role_scoped_services if service.startswith(_GWS_MODULE_PREFIX)
        )
        return [
            _claim_text(
                f"Google Workspace module indicators observed: {', '.join(modules)}",
                evidence=_evidence_for_rule_names(ctx, active_services),
                scope=(),
            )
        ]
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
    # Reuse the same typed predicate as the email-control summary. This keeps
    # the two generators mutually exclusive when a control is observable even
    # without MX, such as DKIM, MTA-STS, BIMI, or strict SPF.
    if _has_scoreable_email(ctx):
        return []
    if ctx.primary_email_provider or ctx.likely_primary_email_provider or ctx.email_gateway:
        return []
    if ctx.dmarc_policy is not None:
        return []
    if _claimable_slugs(ctx, _EMAIL_SLUGS):
        return []
    if any(s.startswith("SPF") for s in ctx.services):
        return []
    return [
        _claim_text(
            "No observable email infrastructure in the bounded checks: no MX, SPF, "
            "or DMARC record and no DKIM response at the common selectors probed. "
            "Consistent with a web-only presence, a parked domain, a staging property, "
            "or email handled on a different domain. Observation, not a verdict.",
            scope=("dns:mx", "dns:apex_txt", "dns:dmarc", "dns:dkim_common_selectors"),
            allows_scope_only=True,
        )
    ]


def _null_mx_insights(ctx: InsightContext) -> list[str]:
    """Report an RFC 7505 Null MX apex as an explicit publisher declaration.

    A single ``0 .`` MX record is not a missing or unclassified mail host.
    It is the documented way for a publisher to state that the domain
    accepts no mail, so it is reported as an observed declaration rather
    than folded into the sparse or no-infrastructure wording. It describes
    the apex only; other hosts in the namespace may still receive mail.
    """
    if "null-mx" not in ctx.slugs:
        return []
    return [
        _claim_text(
            "Null MX observed at the apex (RFC 7505): the publisher declares that "
            "this domain accepts no mail. Subdomains and other apexes are out of "
            "scope for that declaration. Observation, not a verdict.",
            evidence=_evidence_for_slugs(
                ctx,
                frozenset({"null-mx"}),
                source_types=frozenset({"MX"}),
            ),
            scope=(),
        )
    ]


def _sovereignty_insights(ctx: InsightContext) -> list[str]:
    return sovereignty_insights(ctx)


def _sparse_signal_insights(ctx: InsightContext) -> list[str]:
    return sparse_signal_insights(ctx)


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
    _null_mx_insights,
    _sparse_signal_insights,
]

INSIGHT_GENERATOR_RULE_IDS = frozenset(generator.__name__ for generator in _INSIGHT_GENERATORS)


def generate_insight_claims(ctx: InsightContext) -> list[InsightClaim]:
    """Derive insights with exact generator and retained-evidence lineage.

    The association is captured inside the ordered generation loop, while the
    emitting generator is known. This avoids reconstructing lineage later from
    rendered text. Absence-shaped claims carry the bounded observation scopes
    whose successful collection makes the negative statement reportable.
    """
    claims: list[InsightClaim] = []
    for generator in _INSIGHT_GENERATORS:
        generator_rule_id = generator.__name__
        for generated in generator(ctx):
            if not isinstance(generated, _GeneratedInsight):
                msg = f"Insight generator {generator_rule_id} returned an unattributed string"
                raise RuntimeError(msg)
            supporting_evidence = generated.supporting_evidence
            observation_scope = generated.observation_scope
            if not supporting_evidence and not generated.allows_scope_only:
                continue
            if not supporting_evidence and not observation_scope:
                msg = f"Insight {generator_rule_id} has no evidence or observation scope"
                raise RuntimeError(msg)
            claims.append(
                InsightClaim(
                    text=str(generated),
                    generator_rule_id=generator_rule_id,
                    supporting_evidence=supporting_evidence,
                    observation_scope=observation_scope,
                    evidence_required=not generated.allows_scope_only,
                )
            )
    return claims


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
    """Return the stable string projection of exact generated claims."""
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
    return [claim.text for claim in generate_insight_claims(ctx)]
