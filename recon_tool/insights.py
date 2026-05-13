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
    # v0.9.3: OIDC tenant metadata enrichment
    cloud_instance: str | None = None
    tenant_region_sub_scope: str | None = None
    msgraph_host: str | None = None
    # v0.9.3: MX-backed email topology. These are populated only
    # from actual MX evidence, so "primary_email_provider is not
    # None" is the honest test for "does this domain receive
    # email via the named provider". Used by _email_security_insights
    # to refuse scoring on no-MX domains and by
    # _no_email_insights to emit the explicit "no email"
    # observation.
    primary_email_provider: str | None = None
    likely_primary_email_provider: str | None = None
    email_gateway: str | None = None
    # v0.9.3: True when ANY MX records exist, even if they point
    # to a host recon doesn't recognize (Apache's own mail servers,
    # custom Postfix, etc.). Distinguishes "no email at all" from
    # "custom email we can't name." Used by
    # _no_email_infrastructure_insights to avoid claiming "no
    # email" on domains with custom self-hosted mail servers.
    has_mx_records: bool = False

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
        cloud_instance: str | None = None,
        tenant_region_sub_scope: str | None = None,
        msgraph_host: str | None = None,
        primary_email_provider: str | None = None,
        likely_primary_email_provider: str | None = None,
        email_gateway: str | None = None,
        has_mx_records: bool = False,
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
            cloud_instance=cloud_instance,
            tenant_region_sub_scope=tenant_region_sub_scope,
            msgraph_host=msgraph_host,
            primary_email_provider=primary_email_provider,
            likely_primary_email_provider=likely_primary_email_provider,
            email_gateway=email_gateway,
            has_mx_records=has_mx_records,
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
# Only slugs that are actually evidence of the org's SSO IdP belong here.
# `cisco-identity` is deliberately excluded: its only trigger is the TXT
# token `cisco-ci-domain-verification=`, which is used by many Cisco
# products (Duo, Customer Identity, Secure Email, Intersight) and is not
# evidence of the SSO provider — it just means the org registered with
# Cisco for something.
_IDP_SLUG_MAP: dict[str, str] = {
    "okta": "Okta",
    "duo": "Duo",
}

_SPARSE_NON_SUBSTANTIVE_PREFIXES = ("SPF complexity:",)

_EDGE_SERVICE_PREFIXES = ("DNS:", "CDN:", "WAF:")

_SPARSE_DOC_HINT = (
    "Next step — see docs/weak-areas.md for passive-only blind spots. "
    "If this looks like a parent or portfolio apex, run "
    "`recon batch <candidates.txt>` or `recon chain <domain> --depth 2`."
)


def _substantive_services(ctx: InsightContext) -> list[str]:
    """Return services that count toward signal richness for sparse heuristics."""
    return [svc for svc in ctx.services if not svc.startswith(_SPARSE_NON_SUBSTANTIVE_PREFIXES)]


def _edge_services(ctx: InsightContext) -> list[str]:
    """Return distinct edge-layer services visible in the service list."""
    found: list[str] = []
    for svc in sorted(ctx.services):
        if not svc.startswith(_EDGE_SERVICE_PREFIXES):
            continue
        _, _, provider = svc.partition(": ")
        if provider and provider not in found:
            found.append(provider)
    return found


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
        if not has_m365:
            return []
        # v0.9.3 refinement: on dual-provider targets (M365 + Google
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


def _email_security_insights(ctx: InsightContext) -> list[str]:
    has_exchange = bool(ctx.slugs & _EXCHANGE_SLUGS)
    has_google = bool(ctx.slugs & _GOOGLE_SLUGS)
    # v0.9.3 honesty fix: a bare Exchange/Google-Workspace slug can
    # come from a non-MX source (Google Identity Routing endpoint
    # reporting a registered account, Microsoft OIDC reporting a
    # tenant). Those don't prove the domain actually RECEIVES email
    # via that provider. On a domain with zero MX records and no
    # DMARC, the "Email security 0/5 weak" score reads as "email is
    # configured but badly secured" when the truth is "there is no
    # email configured to score."
    #
    # The `primary_email_provider` context field is populated only
    # from MX evidence. When it's None AND the slug was matched via
    # a non-MX identity source, we can't honestly score email
    # security — there's no email to score. Require at least one of:
    #   - primary_email_provider (strict MX-backed primary)
    #   - likely_primary_email_provider (inferred MX downstream)
    #   - dmarc_policy (a real DMARC record)
    #   - a dedicated outbound-email slug (sendgrid, mailgun, etc.)
    # before scoring.
    has_mx_signal = bool(
        ctx.primary_email_provider
        or ctx.likely_primary_email_provider
        or ctx.dmarc_policy is not None
        or bool(ctx.slugs & _EMAIL_SLUGS)
    )
    # Email detection: fire the score when we see any email provider, email
    # gateway, email sending service, or DMARC record. If you have DMARC
    # configured, you have email worth scoring.
    has_email = (
        (has_exchange and has_mx_signal)
        or (has_google and has_mx_signal)
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

    # Gateway-inferred DKIM: Fortune-500-scale orgs with a commercial gateway
    # (Proofpoint / Mimecast / Cisco IronPort / Barracuda / Trend / Trellix /
    # Symantec) AND an enforcing DMARC policy almost always DO sign with DKIM
    # — the gateway handles it automatically using custom selectors we can't
    # enumerate. Without this inference, the apex score penalized these
    # orgs for a control they effectively have. The annotation stays hedged
    # ("via gateway") so the user can see the inference chain.
    dkim_inferred_via_gateway = (
        not has_dkim and ctx.email_gateway is not None and ctx.dmarc_policy in ("quarantine", "reject")
    )

    score = 0
    score_parts: list[str] = []
    if ctx.dmarc_policy in ("reject", "quarantine"):
        score += 1
        score_parts.append(f"DMARC {ctx.dmarc_policy}")
    if has_dkim:
        score += 1
        score_parts.append("DKIM")
    elif dkim_inferred_via_gateway:
        score += 1
        score_parts.append(f"DKIM (inferred via {ctx.email_gateway})")
    if has_spf_strict:
        score += 1
        score_parts.append("SPF strict")
    if has_mta_sts:
        score += 1
        score_parts.append("MTA-STS")
    if has_bimi:
        score += 1
        score_parts.append("BIMI")

    # When DMARC is in monitoring mode (p=none) or SPF is soft/neutral,
    # something IS configured — it's just not enforcing. Surface that
    # explicitly rather than saying "no protections detected" which
    # misreads monitoring-mode deployment as absence.
    if not score_parts:
        observed_non_scoring: list[str] = []
        if ctx.dmarc_policy == "none":
            observed_non_scoring.append("DMARC monitoring only")
        if any(s.startswith("SPF:") for s in ctx.services) and not has_spf_strict:
            observed_non_scoring.append("SPF soft/neutral")
        if observed_non_scoring:
            parts_str = ", ".join(observed_non_scoring) + " — no strict controls"
        else:
            parts_str = "no strict controls observed"
    else:
        parts_str = ", ".join(score_parts)

    # Panel line: inventory of observed controls, no fraction or grade.
    # The N/5 form that v1.0.2 introduced was still read as a grade
    # (3/5 → "mediocre") even without the verdict word. The individual
    # controls aren't equally weighted either (DMARC reject is load-
    # bearing, BIMI is decorative), so an equal-count fraction misled.
    # The machine-readable email_security_score field stays in --json
    # for consumers that genuinely need to sort/filter batch output —
    # see `email_security_score` in docs/schema.md.
    _ = score  # used only to choose between score_parts and fallback branch above
    insights.append(f"Email security: {parts_str}")

    # Auxiliary notes — score line captures the parts; these name the
    # consequence. "DMARC monitoring" in the score line is the configured
    # mode; "not enforced" in the aux line is the user-facing takeaway.
    if ctx.dmarc_policy == "none":
        insights.append("DMARC: none — monitoring mode, not enforced")
    elif ctx.dmarc_policy is None:
        insights.append("No DMARC record at apex")
    if not has_dkim and not dkim_inferred_via_gateway:
        insights.append("No DKIM at common selectors (custom selectors possible)")

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


def _no_email_infrastructure_insights(ctx: InsightContext) -> list[str]:
    """v0.9.3: emit an explicit hedged observation when a domain has
    no observable email infrastructure at all.

    The decisive signal is ``has_mx_records``: when True, the domain
    has at least one MX record (even if the host isn't a recognized
    provider like Apache's own mail server or a custom Postfix), so
    email IS configured and this insight must not fire. When False,
    we additionally check that no DMARC record exists, no DKIM
    selectors were seen, and no outbound-email service slug was
    detected — only then can we honestly say "no email
    infrastructure observed."

    Getting this wrong in either direction is bad: firing on a
    custom-MX domain like apache.org would falsely claim the
    Apache Software Foundation has no email, which is obviously
    wrong. Not firing on a dormant-Google-Workspace-account
    domain like balcaninnovations.com would let the user reach
    the wrong conclusion that email is going to Gmail.

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
        "No email infrastructure observed — no MX records and no "
        "SPF/DMARC/DKIM. Consistent with a web-only presence, a "
        "parked domain, a staging property, or email handled on "
        "a different domain. Observation, not a verdict."
    ]


def _sparse_signal_insights(ctx: InsightContext) -> list[str]:
    """v0.9.3: emit a hedged multi-sided observation when a domain's
    public signal is thin.

    On a legitimate small-business domain, a parked / dormant
    domain, a heavily-proxied target, or a holding / portfolio
    company landing page, recon can only report what's observable
    — and without this explanation a user looking at a panel with
    three service entries and a low confidence can reasonably
    think the tool is broken. Saying explicitly "sparse public
    signal — few observable records" frames the situation
    honestly: this is what's knowable from passive DNS alone, and
    it's not a tool failure.

    The observation is followed by a concrete next-step hint
    pointing at `recon chain` and `recon batch` — the two
    workflows that can actually reveal structure beyond a single
    apex (CT-driven recursive discovery, and cross-batch token /
    display-name clustering). Single-domain passive lookups
    genuinely can't do portfolio / subsidiary detection — be
    honest about it and suggest the right workflow.

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
    has_custom_mail = ctx.has_mx_records and (
        "self-hosted-mail" in ctx.slugs
        or "exchange-onprem" in ctx.slugs
        or (
            ctx.primary_email_provider is None
            and ctx.likely_primary_email_provider is None
            and ctx.email_gateway is None
        )
    )

    if has_custom_mail:
        return [
            "Sparse public signal — custom or self-hosted mail infrastructure. "
            "MX records exist, but the visible evidence points to a self-hosted "
            "or hybrid delivery path rather than a richly fingerprinted SaaS "
            "tenant. Observation, not a verdict.",
            _SPARSE_DOC_HINT,
        ]

    if edge and len(substantive) <= 3:
        visible_edge = ", ".join(edge[:2])
        if len(edge) > 2:
            visible_edge = f"{visible_edge}, and other edge services"
        return [
            f"Sparse public signal — edge-heavy footprint. {visible_edge} sits "
            "in front of the apex, which can hide origin and SaaS detail from "
            "passive DNS-only collection. Observation, not a verdict.",
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
            "exposed beyond basic records, which is consistent with a small "
            "web-only property, a parked or dormant domain, or services hosted "
            "on a different apex. Observation, not a verdict.",
            _SPARSE_DOC_HINT,
        ]

    return [
        "Sparse public signal — few observable records beyond MX and "
        "identity. Consistent with a small organization, a parked or "
        "dormant domain, a heavily-proxied target, or a holding / "
        "portfolio company landing page. Observation, not a verdict.",
        _SPARSE_DOC_HINT,
    ]


def _sovereignty_insights(ctx: InsightContext) -> list[str]:
    """v0.9.3: surface Microsoft tenant sovereignty / cloud-instance info.

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

    if "microsoftonline.us" in ci or "graph.microsoft.us" in mh:
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
    elif "partner.microsoftonline.cn" in ci or "microsoftgraphchina.cn" in mh:
        results.append(
            f"Likely Azure China 21Vianet tenant (observed cloud_instance={ci or 'partner.microsoftonline.cn'})"
        )
    elif "b2clogin.com" in ci or ci.endswith("b2clogin.com"):
        results.append(f"Azure AD B2C tenant (observed cloud_instance={ci})")
    elif ci and "microsoftonline.com" not in ci:
        # Non-commercial cloud_instance we don't specifically recognize —
        # surface it verbatim so users can investigate.
        results.append(f"Non-commercial Microsoft cloud instance observed: {ci}")

    return results


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
    _sovereignty_insights,
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
        cloud_instance=cloud_instance,
        tenant_region_sub_scope=tenant_region_sub_scope,
        msgraph_host=msgraph_host,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
        email_gateway=email_gateway,
        has_mx_records=has_mx_records,
    )
    insights: list[str] = []
    for generator in _INSIGHT_GENERATORS:
        insights.extend(generator(ctx))
    return insights
