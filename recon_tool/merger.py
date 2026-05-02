"""Result merger, confidence scoring, and insight generation."""

from __future__ import annotations

import contextlib

from recon_tool.absence import evaluate_absence_signals, evaluate_positive_absence
from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_STRICT,
)
from recon_tool.insights import generate_insights
from recon_tool.lexical import lexical_observations
from recon_tool.models import (
    BIMIIdentity,
    CandidateValue,
    CertSummary,
    ConfidenceLevel,
    EvidenceRecord,
    MergeConflicts,
    ReconLookupError,
    SignalContext,
    SourceResult,
    SurfaceAttribution,
    TenantInfo,
)
from recon_tool.signals import evaluate_signals, load_signals

__all__ = [
    "build_insights_with_signals",
    "compute_confidence",
    "compute_detection_scores",
    "compute_evidence_confidence",
    "compute_inference_confidence",
    "merge_results",
]

# Gateway slugs — MX-detected slugs that represent email security gateways
# rather than primary email providers. Shared with insights.py.
_GATEWAY_SLUGS: frozenset[str] = frozenset(
    {
        "proofpoint",
        "mimecast",
        "barracuda",
        "cisco-ironport",
        "cisco-email",
        "symantec",
        "trellix",
        "trendmicro",
    }
)

# Provider slugs that can be primary email providers (MX-based)
_EMAIL_PROVIDER_SLUG_NAMES: dict[str, str] = {
    "microsoft365": "Microsoft 365",
    "google-workspace": "Google Workspace",
    "zoho": "Zoho Mail",
    "protonmail": "ProtonMail",
    "aws-ses": "AWS SES",
    # Synthetic slug emitted by dns._detect_mx when every MX host lives
    # under the queried apex (i.e. operator-owned mail infrastructure).
    # Gives large orgs with self-operated mail a concrete primary-provider
    # label instead of falling through to the weaker "Exchange Server
    # (on-prem / hybrid)" attribution.
    "self-hosted-mail": "Self-hosted mail",
}

_GATEWAY_SLUG_NAMES: dict[str, str] = {
    "proofpoint": "Proofpoint",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "cisco-ironport": "Cisco IronPort",
    "cisco-email": "Cisco Secure Email",
    "symantec": "Symantec/Broadcom",
    "trellix": "Trellix (FireEye)",
    "trendmicro": "Trend Micro",
}


# Non-MX evidence source types that carry signal about the downstream email
# provider even when MX points to a gateway. Ordered by strength of signal.
_PROVIDER_INFERENCE_SOURCES: frozenset[str] = frozenset(
    {
        "TXT",  # SPF includes, site-verification tokens
        "DKIM",  # google._domainkey, selector1._domainkey
        "HTTP",  # Google identity endpoint responses, Microsoft OIDC
        "OIDC",  # Microsoft OIDC discovery
        "USERREALM",  # Microsoft GetUserRealm
    }
)

# Mapping from slug to the display name used when inferring a likely
# downstream email provider from non-MX evidence. Must be a subset of the
# strict provider map so the two stay consistent when both fire.
_LIKELY_PROVIDER_SLUG_NAMES: dict[str, str] = {
    "microsoft365": "Microsoft 365",
    "google-workspace": "Google Workspace",
    "zoho": "Zoho Mail",
    "protonmail": "ProtonMail",
}


# v0.9.3: humanize raw slugs for insight text. Without this, insight
# strings leak identifiers like "google-managed", "crewai-aid",
# "cosign-attestation" that read as developer jargon to users. Map
# known technical slugs to user-friendly display names; everything
# else falls back to a title-cased version of the slug with dashes
# replaced by spaces.
_SLUG_HUMAN_NAMES: dict[str, str] = {
    "microsoft365": "Microsoft 365",
    "google-workspace": "Google Workspace",
    "google-federated": "Google Workspace (federated)",
    "google-managed": "Google Workspace (managed)",
    "google-site": "Google Search Console",
    "google-trust": "Google Trust Services",
    "google-workspace-modules": "Google Workspace modules",
    "google-cse": "Google Workspace CSE",
    "aws-ses": "AWS SES",
    "aws-route53": "Route 53",
    "aws-cloudfront": "CloudFront",
    "aws-s3": "S3",
    "aws-elb": "ELB",
    "aws-eb": "Elastic Beanstalk",
    "aws-acm": "AWS ACM",
    "azure-dns": "Azure DNS",
    "azure-appservice": "Azure App Service",
    "azure-cdn": "Azure CDN",
    "azure-fd": "Azure Front Door",
    "azure-tm": "Azure Traffic Manager",
    "gcp-dns": "GCP Cloud DNS",
    "gcp-app": "GCP App Engine",
    "mta-sts-enforce": "MTA-STS enforce",
    "mta-sts-testing": "MTA-STS testing",
    "tls-rpt": "TLS-RPT",
    "proofpoint-efd": "Proofpoint EFD",
    "dmarc-advisor": "DMARC Advisor",
    "mimecast-dmarc-analyzer": "Mimecast DMARC Analyzer",
    "1password": "1Password",
    "ping-identity": "Ping Identity",
    "beyond-identity": "Beyond Identity",
    "github-advanced-security": "GitHub Advanced Security",
    "cosign-attestation": "Cosign attestation",
    "crewai-aid": "CrewAI",
    "mcp-discovery": "MCP discovery",
    "langsmith": "LangSmith",
    "cisco-ironport": "Cisco IronPort",
    "cisco-email": "Cisco Secure Email",
    "cisco-identity": "Cisco Identity",
    "knowbe4": "KnowBe4",
    "sentinelone": "SentinelOne",
    "crowdstrike": "CrowdStrike",
    "paloalto": "Palo Alto",
    "letsencrypt": "Let's Encrypt",
    # v0.9.3 refinement: proper-case brand names so insight text
    # doesn't title-case them into wrong forms like "Sendgrid" or
    # "Cloudflare" when they have distinctive casing.
    "sendgrid": "SendGrid",
    "mailgun": "Mailgun",
    "mailchimp": "Mailchimp",
    "postmark": "Postmark",
    "sparkpost": "SparkPost",
    "brevo": "Brevo",
    "protonmail": "ProtonMail",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "onelogin": "OneLogin",
    "auth0": "Auth0",
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "mistral": "Mistral",
    "perplexity": "Perplexity",
    "autospf": "AutoSPF",
    "ondmarc": "OnDMARC (Red Sift)",
    "dmarcian": "dmarcian",
    "easydmarc": "EasyDMARC",
    "valimail": "Valimail",
    "uriports": "URIports",
    "powerdmarc": "PowerDMARC",
    "agari": "Agari",
    "lakera": "Lakera",
    "cyberark": "CyberArk",
    "okta": "Okta",
    "auth": "Auth0",
    "duo": "Duo Security",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "flyio": "Fly.io",
    "railway": "Railway",
    "github": "GitHub",
    "gitlab": "GitLab",
    "atlassian": "Atlassian",
    "slack": "Slack",
    "notion": "Notion",
    "figma": "Figma",
    "miro": "Miro",
    "dropbox": "Dropbox",
    "zoom": "Zoom",
    "disciple-media": "Disciple Media",
    "kartra": "Kartra",
    "salesforce": "Salesforce",
    "salesforce-mc": "Salesforce Marketing Cloud",
    "hubspot": "HubSpot",
    "servicenow": "ServiceNow",
    "docusign": "DocuSign",
    "imperva": "Imperva",
    "wiz": "Wiz",
    "snyk": "Snyk",
    "zscaler": "Zscaler",
    "netskope": "Netskope",
    "proofpoint": "Proofpoint",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "sophos": "Sophos",
    "sectigo": "Sectigo",
    "digicert": "DigiCert",
    "globalsign": "GlobalSign",
    "trendmicro": "Trend Micro",
    "trellix": "Trellix",
    "symantec": "Symantec",
}


# Known short acronyms that should stay uppercase in the slug
# fallback. This is intentionally narrow — random 2-3 char words
# like "new" or "old" should title-case, not shout.
_SLUG_ACRONYMS: frozenset[str] = frozenset(
    {"sso", "idp", "waf", "mfa", "cdn", "dns", "vpn", "mdm", "iam", "api", "cse", "pki"}
)


def _humanize_slug(slug: str) -> str:
    """Map a raw slug to a user-friendly display name.

    Used by insight text formatting so strings like
    ``"Google-Native Identity: google-workspace, google-managed"``
    render as ``"Google-Native Identity: Google Workspace, Google
    Workspace (managed)"`` instead of leaking raw identifiers.

    Fallback for unmapped slugs: title-case with dashes replaced
    by spaces. A narrow set of known acronyms (sso, idp, waf, …)
    stays uppercase; everything else title-cases.
    """
    if slug in _SLUG_HUMAN_NAMES:
        return _SLUG_HUMAN_NAMES[slug]
    parts = slug.replace("_", "-").split("-")
    out: list[str] = []
    for part in parts:
        if part.lower() in _SLUG_ACRONYMS:
            out.append(part.upper())
        else:
            out.append(part.capitalize())
    return " ".join(out)


# v0.9.3: when a signal's matched-slug list contains both a base
# slug (``google-workspace``) and a variant slug (``google-managed``,
# ``google-federated``) that represents the same product with an
# identity-mode qualifier, collapse the variant into the base. Without
# this, insight text read as ``"Google Workspace, Google Workspace
# (managed)"`` — same product listed twice with different qualifiers.
# The variant is dropped only when the base is present; on a signal
# that fires only on the variant, the variant stays so the user
# still sees the identity-mode distinction.
_VARIANT_SLUG_PARENTS: dict[str, str] = {
    "google-managed": "google-workspace",
    "google-federated": "google-workspace",
    "google-site": "google-workspace",
    "google-workspace-modules": "google-workspace",
}


def _dedup_variant_slugs(slugs: tuple[str, ...]) -> tuple[str, ...]:
    """Drop variant slugs from ``slugs`` when their parent is also
    present. Preserves input order."""
    slug_set = set(slugs)
    out: list[str] = []
    seen: set[str] = set()
    for slug in slugs:
        parent = _VARIANT_SLUG_PARENTS.get(slug)
        if parent and parent in slug_set:
            continue
        if slug in seen:
            continue
        out.append(slug)
        seen.add(slug)
    return tuple(out)


def _compute_email_topology(
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[str | None, str | None, str | None]:
    """Compute email topology from evidence records.

    Returns a triple of ``(primary_email_provider, email_gateway,
    likely_primary_email_provider)``:

    - ``primary_email_provider`` — stated when MX directly names a provider
      (e.g. ``aspmx.l.google.com`` → Google Workspace). Strict: only set from
      MX evidence. Never set when MX only contains an enterprise gateway.

    - ``email_gateway`` — stated when MX names an enterprise email security
      gateway (Proofpoint, Mimecast, Symantec, Barracuda, Trellix, Trend
      Micro, Cisco IronPort / Secure Email).

    - ``likely_primary_email_provider`` — inferred when a gateway is in MX
      but no direct provider appears there, AND non-MX evidence (DKIM
      selectors, identity-endpoint responses, TXT verification tokens)
      points to a specific downstream. Hedged: the word "likely" in the
      field name is load-bearing — this is inference, not a direct record.
      Only set when ``primary_email_provider`` is ``None``, so the two
      fields never contradict each other.
    """
    mx_evidence = [e for e in evidence if e.source_type == "MX"]
    mx_slugs = {e.slug for e in mx_evidence}

    # Identify gateways
    gateway_slugs = mx_slugs & _GATEWAY_SLUGS
    gateway_names = sorted(_GATEWAY_SLUG_NAMES[s] for s in gateway_slugs if s in _GATEWAY_SLUG_NAMES)
    email_gateway = " + ".join(gateway_names) if gateway_names else None

    # Identify primary providers (MX slugs that are NOT gateways)
    provider_slugs = mx_slugs - _GATEWAY_SLUGS
    provider_names = sorted(_EMAIL_PROVIDER_SLUG_NAMES[s] for s in provider_slugs if s in _EMAIL_PROVIDER_SLUG_NAMES)
    primary_email_provider = " + ".join(provider_names) if provider_names else None

    # Inference: when a gateway is present but no MX-based primary, look at
    # non-MX evidence for provider slugs. Two tiers:
    #
    # (1) DKIM evidence — strong. DKIM selectors prove the provider handles
    #     email signing for this domain. Promotes to primary_email_provider.
    #
    # (2) Other non-MX evidence (TXT tokens, OIDC, UserRealm) — weaker.
    #     Sets likely_primary_email_provider (hedged).
    #
    # Only fires if an actual gateway is in MX — without that anchor we
    # can't distinguish legacy residue from a missed primary.
    likely_primary_email_provider: str | None = None
    if email_gateway and primary_email_provider is None:
        # Tier 1: DKIM-confirmed providers (strong signal)
        dkim_provider_slugs = {
            e.slug for e in evidence if e.source_type == "DKIM" and e.slug in _LIKELY_PROVIDER_SLUG_NAMES
        }
        if dkim_provider_slugs:
            dkim_names = sorted(_LIKELY_PROVIDER_SLUG_NAMES[s] for s in dkim_provider_slugs)
            primary_email_provider = " + ".join(dkim_names)
        else:
            # Tier 2: weaker non-MX evidence
            non_mx_provider_slugs = {
                e.slug
                for e in evidence
                if e.source_type in _PROVIDER_INFERENCE_SOURCES and e.slug in _LIKELY_PROVIDER_SLUG_NAMES
            }
            if non_mx_provider_slugs:
                likely_names = sorted(_LIKELY_PROVIDER_SLUG_NAMES[s] for s in non_mx_provider_slugs)
                likely_primary_email_provider = " + ".join(likely_names)

    return primary_email_provider, email_gateway, likely_primary_email_provider


def _downgrade_confidence(level: ConfidenceLevel) -> ConfidenceLevel:
    """Step a confidence level down by one rung (HIGH → MEDIUM → LOW → LOW)."""
    if level == ConfidenceLevel.HIGH:
        return ConfidenceLevel.MEDIUM
    if level == ConfidenceLevel.MEDIUM:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.LOW


def _min_confidence(a: ConfidenceLevel, b: ConfidenceLevel) -> ConfidenceLevel:
    """Return the lower of two confidence levels (HIGH > MEDIUM > LOW)."""
    order = {ConfidenceLevel.HIGH: 2, ConfidenceLevel.MEDIUM: 1, ConfidenceLevel.LOW: 0}
    return a if order[a] <= order[b] else b


def compute_evidence_confidence(results: list[SourceResult]) -> ConfidenceLevel:
    """Compute evidence confidence from the number of successful sources.

    3+ successful sources → HIGH, 2 → MEDIUM, 1 or fewer → LOW.
    """
    successful = sum(1 for r in results if r.is_success)
    if successful >= 3:
        return ConfidenceLevel.HIGH
    if successful >= 2:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def compute_inference_confidence(results: list[SourceResult]) -> ConfidenceLevel:
    """Compute inference confidence from the strength of the logical chain.

    HIGH when tenant_id from OIDC + corroborating source, or 3+ independent
    record types confirm the same provider.
    LOW when single record type with no corroboration.
    MEDIUM otherwise.

    Corroboration (v0.9.2): now accepts Google Workspace auth type as a
    valid signal in addition to Microsoft-side fields. A domain with an
    OIDC tenant_id AND a Google identity endpoint response is fully
    corroborated from two independent providers — the previous check
    missed this case and gave such domains MEDIUM inference instead of
    HIGH.
    """
    has_tenant_id = any(r.tenant_id is not None for r in results)
    has_corroboration = any(
        r.is_success
        and r.source_name != "oidc_discovery"
        and (r.m365_detected or r.display_name or r.auth_type or r.google_auth_type or len(r.tenant_domains) > 0)
        for r in results
    )

    if has_tenant_id and has_corroboration:
        return ConfidenceLevel.HIGH

    # Check for multiple independent record types confirming same provider
    all_evidence: list[EvidenceRecord] = []
    for r in results:
        all_evidence.extend(r.evidence)

    if all_evidence:
        source_types = {e.source_type for e in all_evidence}
        if len(source_types) >= 3:
            return ConfidenceLevel.HIGH

    successful = sum(1 for r in results if r.is_success)
    if successful >= 2:
        return ConfidenceLevel.MEDIUM

    return ConfidenceLevel.LOW


def _build_detection_weight_map() -> dict[tuple[str, str], float]:
    """Build a (slug, source_type) → max weight mapping from loaded fingerprints.

    For each fingerprint, for each detection rule, maps (fp.slug, det.type)
    to the maximum weight seen across all fingerprints sharing that slug+type.
    """
    from recon_tool.fingerprints import load_fingerprints

    weight_map: dict[tuple[str, str], float] = {}
    for fp in load_fingerprints():
        for det in fp.detections:
            key = (fp.slug, det.type.upper())
            existing = weight_map.get(key)
            if existing is None or det.weight > existing:
                weight_map[key] = det.weight
    return weight_map


def compute_detection_scores(
    evidence: tuple[EvidenceRecord, ...],
    weights: dict[tuple[str, str], float] | None = None,
) -> tuple[tuple[str, str], ...]:
    """Compute per-slug detection confidence from weighted evidence.

    Groups evidence by slug, computes a weighted sum of distinct source_types
    per slug using detection weights. Each (slug, source_type) pair contributes
    its weight once (max weight if duplicated).

    Thresholds: weighted_sum >= 2.5 → "high", >= 1.5 → "medium", else "low".

    When all weights are 1.0 (default), the weighted sum equals the count of
    distinct source types, preserving existing behavior:
    3+ types (sum >= 3.0 >= 2.5) → "high", 2 types (sum 2.0 >= 1.5) → "medium",
    1 type (sum 1.0 < 1.5) → "low".

    Args:
        evidence: Tuple of EvidenceRecord instances.
        weights: Optional mapping of (slug, source_type) → weight.
            If None, weights are loaded automatically from fingerprints.
            Pass an explicit dict to override (useful for testing).

    Returns tuple of (slug, score) pairs sorted by slug.
    """
    if not evidence:
        return ()

    if weights is None:
        weights = _build_detection_weight_map()

    # For each slug, track the max weight per distinct source_type
    slug_source_weights: dict[str, dict[str, float]] = {}
    for ev in evidence:
        per_source = slug_source_weights.setdefault(ev.slug, {})
        w = weights.get((ev.slug, ev.source_type), 1.0)
        # Keep max weight if multiple evidence records share (slug, source_type)
        if ev.source_type not in per_source or w > per_source[ev.source_type]:
            per_source[ev.source_type] = w

    scores: list[tuple[str, str]] = []
    for slug in sorted(slug_source_weights):
        weighted_sum = sum(slug_source_weights[slug].values())
        if weighted_sum >= 2.5:
            scores.append((slug, "high"))
        elif weighted_sum >= 1.5:
            scores.append((slug, "medium"))
        else:
            scores.append((slug, "low"))
    return tuple(scores)


def build_insights_with_signals(
    services: set[str],
    slugs: set[str],
    auth_type: str | None,
    dmarc_policy: str | None,
    domain_count: int,
    email_security_score: int | None = None,
    spf_include_count: int | None = None,
    issuance_velocity: int | None = None,
    google_auth_type: str | None = None,
    google_idp_name: str | None = None,
    dmarc_pct: int | None = None,
    primary_email_provider: str | None = None,
    likely_primary_email_provider: str | None = None,
    email_gateway: str | None = None,
    cloud_instance: str | None = None,
    tenant_region_sub_scope: str | None = None,
    msgraph_host: str | None = None,
    has_mx_records: bool = False,
) -> list[str]:
    """Generate insights and append signal intelligence.

    Shared by merge_results (initial merge) and _enrich_from_related
    (related domain enrichment) to avoid duplicating the insight+signal
    formatting pipeline.
    """
    insights = generate_insights(
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
    context = SignalContext(
        detected_slugs=frozenset(slugs),
        dmarc_policy=dmarc_policy,
        auth_type=auth_type,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
        dmarc_pct=dmarc_pct,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
    )
    active_signals = evaluate_signals(context)
    for sig in active_signals:
        # v0.9.3 hardening: meta-signals (requires_signals only, no
        # candidates) have empty sig.matched. Emit a bare name instead
        # of a "Name: " dead-end that used to render with no value.
        # Also humanize known slugs and dedup variant slugs so
        # insight text doesn't leak raw identifiers like
        # "google-managed" to users.
        if sig.matched:
            deduped = _dedup_variant_slugs(tuple(sig.matched))
            matched_names = ", ".join(_humanize_slug(s) for s in deduped)
            insights.append(f"{sig.name}: {matched_names}")
        else:
            insights.append(sig.name)

    # Third pass: absence evaluation (missing counterparts)
    all_signal_defs = load_signals()
    absence_signals = evaluate_absence_signals(active_signals, all_signal_defs, context.detected_slugs)
    for sig in absence_signals:
        if sig.matched:
            deduped = _dedup_variant_slugs(tuple(sig.matched))
            matched_names = ", ".join(_humanize_slug(s) for s in deduped)
            insights.append(f"{sig.name}: {matched_names}")
        else:
            insights.append(sig.name)

    # v0.9.3: positive-when-absent pass — hedged hardening observations.
    # Runs on the *base* fired set (not including absence signals) so a
    # hardening observation only fires from a genuine positive signal
    # match, never from an absence signal firing.
    positive_observations = evaluate_positive_absence(active_signals, all_signal_defs, context.detected_slugs)
    for sig in positive_observations:
        insights.append(f"{sig.name}: {sig.description}")

    return insights


def compute_confidence(results: list[SourceResult]) -> tuple[ConfidenceLevel, bool]:
    """Compute confidence based on cross-validation of results.

    For M365 domains: confidence is based on tenant_id presence plus
    corroboration from other sources (UserRealm display name, auth type,
    tenant domains). A single tenant_id with corroborating M365 evidence
    from another source is HIGH — the sources are independent and agree.

    For non-M365 domains: confidence is based on the richness of DNS data.
    DNS records are authoritative (you either have the record or you don't),
    so rich DNS data warrants high confidence in the overall picture.

    Returns:
        Tuple of (confidence_level, has_conflicting_tenant_ids).
    """
    tenant_ids = [r.tenant_id for r in results if r.tenant_id is not None]

    if tenant_ids:
        unique_ids = set(tenant_ids)
        if len(unique_ids) > 1:
            return ConfidenceLevel.LOW, True

        # We have at least one tenant_id. Check for corroboration from
        # other sources — UserRealm returning m365_detected + real data
        # (display_name, auth_type, or tenant_domains) counts as independent
        # confirmation that this is a real M365 tenant.
        tenant_id_sources = {r.source_name for r in results if r.tenant_id is not None}
        corroborating = [
            r
            for r in results
            if r.source_name not in tenant_id_sources
            and r.is_success
            and (r.m365_detected or r.display_name or r.auth_type or len(r.tenant_domains) > 0)
        ]
        if corroborating:
            return ConfidenceLevel.HIGH, False
        if len(tenant_ids) >= 2:
            return ConfidenceLevel.HIGH, False
        return ConfidenceLevel.MEDIUM, False

    # No tenant_id — check DNS service richness.
    # DNS records are authoritative, so even a single source with services
    # is meaningful. More services = higher confidence in the overall picture.
    total_services = sum(len(r.detected_services) for r in results)
    successful_sources = sum(1 for r in results if r.is_success)

    if total_services >= 8 and successful_sources >= 2:
        return ConfidenceLevel.HIGH, False
    if total_services >= 3 or successful_sources >= 2:
        return ConfidenceLevel.MEDIUM, False
    if total_services > 0:
        return ConfidenceLevel.LOW, False
    return ConfidenceLevel.LOW, False


def merge_results(
    results: list[SourceResult],
    queried_domain: str,
) -> TenantInfo:
    """Merge multiple SourceResults into a single TenantInfo with insights."""
    tenant_id: str | None = None
    display_name: str | None = None
    default_domain: str | None = None
    region: str | None = None
    auth_type: str | None = None
    dmarc_policy: str | None = None
    all_domains: set[str] = set()
    google_auth_type: str | None = None
    google_idp_name: str | None = None
    bimi_identity: BIMIIdentity | None = None
    mta_sts_mode: str | None = None
    all_site_verification_tokens: set[str] = set()

    # First-wins merge: for each field, the first source (in priority order)
    # that provides a non-None value wins. This is intentional — sources are
    # ordered by reliability (OIDC > UserRealm > DNS), so the first non-None
    # value is the most trustworthy. A "most-complete-wins" strategy would
    # require scoring each result, adding complexity for little benefit.
    #
    # Conflict tracking: collect all non-None candidate values per tracked field
    # so we can surface disagreements when 2+ sources provide different values.
    _tracked_candidates: dict[str, list[CandidateValue]] = {
        "display_name": [],
        "auth_type": [],
        "region": [],
        "tenant_id": [],
        "dmarc_policy": [],
        "google_auth_type": [],
    }

    # v0.11: placeholder tenant display names that are meaningless to a
    # user. "Default Directory" is what Microsoft shows when a tenant
    # owner never set a custom name — it's a placeholder, not the
    # organization's name. Fall through to better signals (BIMI, domain).
    _PLACEHOLDER_DISPLAY_NAMES: frozenset[str] = frozenset(
        {
            "default directory",
            "directory",
        }
    )

    def _is_placeholder(name: str | None) -> bool:
        if not name:
            return True
        return name.strip().lower() in _PLACEHOLDER_DISPLAY_NAMES

    for result in results:
        if tenant_id is None and result.tenant_id is not None:
            tenant_id = result.tenant_id
        if _is_placeholder(display_name) and not _is_placeholder(result.display_name):
            display_name = result.display_name
        if default_domain is None and result.default_domain is not None:
            default_domain = result.default_domain
        if region is None and result.region is not None:
            region = result.region
        if auth_type is None and result.auth_type is not None:
            auth_type = result.auth_type
        if dmarc_policy is None and result.dmarc_policy is not None:
            dmarc_policy = result.dmarc_policy
        if google_auth_type is None and result.google_auth_type is not None:
            google_auth_type = result.google_auth_type
        if google_idp_name is None and result.google_idp_name is not None:
            google_idp_name = result.google_idp_name
        if bimi_identity is None and result.bimi_identity is not None:
            bimi_identity = result.bimi_identity
        if mta_sts_mode is None and result.mta_sts_mode is not None:
            mta_sts_mode = result.mta_sts_mode
        all_domains.update(result.tenant_domains)
        all_site_verification_tokens.update(result.site_verification_tokens)

        # Collect candidates for conflict tracking
        _src_confidence = "high" if result.is_complete else ("medium" if result.is_success else "low")
        if result.display_name is not None:
            _tracked_candidates["display_name"].append(
                CandidateValue(value=result.display_name, source=result.source_name, confidence=_src_confidence)
            )
        if result.auth_type is not None:
            _tracked_candidates["auth_type"].append(
                CandidateValue(value=result.auth_type, source=result.source_name, confidence=_src_confidence)
            )
        if result.region is not None:
            _tracked_candidates["region"].append(
                CandidateValue(value=result.region, source=result.source_name, confidence=_src_confidence)
            )
        if result.tenant_id is not None:
            _tracked_candidates["tenant_id"].append(
                CandidateValue(value=result.tenant_id, source=result.source_name, confidence=_src_confidence)
            )
        if result.dmarc_policy is not None:
            _tracked_candidates["dmarc_policy"].append(
                CandidateValue(value=result.dmarc_policy, source=result.source_name, confidence=_src_confidence)
            )
        if result.google_auth_type is not None:
            _tracked_candidates["google_auth_type"].append(
                CandidateValue(value=result.google_auth_type, source=result.source_name, confidence=_src_confidence)
            )

    # Build MergeConflicts: only populate fields where 2+ sources disagree
    _conflict_fields: dict[str, tuple[CandidateValue, ...]] = {}
    for field_name, candidates in _tracked_candidates.items():
        if len(candidates) >= 2:
            unique_values = {c.value for c in candidates}
            if len(unique_values) >= 2:
                _conflict_fields[field_name] = tuple(candidates)
    merge_conflicts: MergeConflicts | None = None
    if _conflict_fields:
        merge_conflicts = MergeConflicts(**_conflict_fields)

    # Only raise `all_sources_failed` when EVERY source returned an error.
    # If any source produced a clean result (even with empty services/slugs),
    # we honor the successful lookup by emitting a sparse TenantInfo with
    # `provider = "Unknown (no known provider pattern matched)"` downstream.
    # This keeps batch runs uniform (sparse domains don't mix errors with
    # successes) and matches the hedged-observation invariant: "we looked
    # and found nothing" is a valid, honest answer — not an error.
    if tenant_id is None and all(r.error is not None for r in results):
        source_errors: tuple[tuple[str, str], ...] = tuple(
            (r.source_name, r.error) for r in results if r.error is not None
        )
        reasons = "; ".join(f"{n}: {e}" for n, e in source_errors)
        raise ReconLookupError(
            domain=queried_domain,
            message=(f"No information could be resolved for {queried_domain}. All sources returned errors: {reasons}"),
            error_type="all_sources_failed",
            source_errors=source_errors,
        )

    if display_name is None or _is_placeholder(display_name):
        # BIMI VMC organization name as fallback — always preferred if present
        if bimi_identity is not None and bimi_identity.organization:
            display_name = bimi_identity.organization
        else:
            # Prefer the queried domain over the tenant_id UUID for display.
            # A raw UUID reads as debugging output; the domain reads as
            # the company identifier.
            display_name = queried_domain
    if default_domain is None:
        default_domain = queried_domain

    confidence, has_id_conflict = compute_confidence(results)
    sources = tuple(r.source_name for r in results if r.is_success)

    all_services: set[str] = set()
    all_slugs: set[str] = set()
    all_related: set[str] = set()
    for result in results:
        all_services.update(result.detected_services)
        all_slugs.update(result.detected_slugs)
        all_related.update(result.related_domains)

    # Remove domains we already know about from related_domains
    all_related -= all_domains
    all_related.discard(queried_domain.lower())

    domain_count = len(all_domains)
    tenant_domains = tuple(sorted(all_domains))

    # Compute email_security_score: count presence of DMARC, any DKIM, SPF strict, MTA-STS, BIMI (0-5)
    _score_services = {SVC_DMARC, SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_SPF_STRICT, SVC_MTA_STS, SVC_BIMI}
    email_security_score = min(sum(1 for svc in all_services if svc in _score_services), 5)

    # Extract spf_include_count from services like "SPF complexity: N includes"
    spf_include_count: int | None = None

    for svc in all_services:
        if svc.startswith("SPF complexity:"):
            with contextlib.suppress(ValueError, IndexError):
                spf_include_count = int(svc.split(":")[1].strip().split()[0])
            break

    # Extract issuance_velocity from cert_summary if available
    issuance_velocity: int | None = None

    # Propagate first non-None cert_summary from any source
    cert_summary: CertSummary | None = None
    for result in results:
        if result.cert_summary is not None:
            cert_summary = result.cert_summary
            break

    if cert_summary is not None:
        issuance_velocity = cert_summary.issuance_velocity

    # Propagate CT provider attribution from any source (v0.9.2)
    ct_provider_used: str | None = None
    ct_subdomain_count: int = 0
    ct_cache_age_days: int | None = None
    for result in results:
        if result.ct_provider_used:
            ct_provider_used = result.ct_provider_used
            ct_subdomain_count = result.ct_subdomain_count
            ct_cache_age_days = result.ct_cache_age_days
            break

    # v0.9.3: propagate OIDC tenant metadata (first non-None wins).
    # These fields only populate on OIDCSource results.
    cloud_instance: str | None = None
    tenant_region_sub_scope: str | None = None
    msgraph_host: str | None = None
    for result in results:
        if cloud_instance is None and result.cloud_instance is not None:
            cloud_instance = result.cloud_instance
        if tenant_region_sub_scope is None and result.tenant_region_sub_scope is not None:
            tenant_region_sub_scope = result.tenant_region_sub_scope
        if msgraph_host is None and result.msgraph_host is not None:
            msgraph_host = result.msgraph_host
        if cloud_instance and tenant_region_sub_scope and msgraph_host:
            break

    # Propagate evidence from all sources (needed before insights for topology)
    all_evidence: list[EvidenceRecord] = []
    for result in results:
        all_evidence.extend(result.evidence)
    evidence_tuple = tuple(all_evidence)

    # Compute email topology from evidence
    primary_email_provider, email_gateway, likely_primary_email_provider = _compute_email_topology(evidence_tuple)

    # Extract dmarc_pct from source results (first non-None wins)
    dmarc_pct: int | None = None
    for result in results:
        if result.dmarc_pct is not None:
            dmarc_pct = result.dmarc_pct
            break

    # v0.9.3: has_mx_records is True if ANY MX evidence record
    # exists, regardless of whether the host matched a known
    # provider slug. Used by downstream insight generators to
    # distinguish "no email at all" from "custom / self-hosted
    # email" — both cases have primary_email_provider None but
    # very different user-facing meanings.
    has_mx_records = any(e.source_type == "MX" for e in evidence_tuple)

    # Build insights list, then append signal intelligence.
    insights = build_insights_with_signals(
        all_services,
        all_slugs,
        auth_type,
        dmarc_policy,
        domain_count,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
        dmarc_pct=dmarc_pct,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
        email_gateway=email_gateway,
        cloud_instance=cloud_instance,
        tenant_region_sub_scope=tenant_region_sub_scope,
        msgraph_host=msgraph_host,
        has_mx_records=has_mx_records,
    )

    # Surface conflicting tenant IDs — this is high-value intel that explains
    # why confidence is LOW and may indicate a misconfigured or transitioning tenant.
    if has_id_conflict:
        conflicting = sorted({r.tenant_id for r in results if r.tenant_id is not None})
        insights.insert(0, f"Conflicting tenant IDs detected: {', '.join(conflicting)}")

    # Collect degraded_sources from all results, deduplicate
    all_degraded: set[str] = set()
    for result in results:
        all_degraded.update(result.degraded_sources)

    # Compute dual confidence
    evidence_confidence = compute_evidence_confidence(results)
    inference_confidence = compute_inference_confidence(results)
    # Backward-compatible confidence: min of the two dimensions
    confidence = _min_confidence(confidence, _min_confidence(evidence_confidence, inference_confidence))

    # A7: downgrade confidence when a degraded source genuinely
    # impairs the picture.
    #
    # v0.9.3 refinement: skip the downgrade when the ONLY degraded
    # sources are CT providers AND a CT fallback successfully
    # returned data. In that case the fallback recovered the
    # information; penalising confidence for a successful recovery
    # undersells the actual quality of the result. The fallback
    # chain only recovers if at least one CT provider answered
    # (ct_provider_used is set).
    ct_only_degradation = bool(all_degraded) and all(s in ("crt.sh", "certspotter") for s in all_degraded)
    ct_fallback_recovered = ct_only_degradation and ct_provider_used is not None
    if all_degraded and not ct_fallback_recovered:
        confidence = _downgrade_confidence(confidence)
        evidence_confidence = _downgrade_confidence(evidence_confidence)

    # Compute per-detection corroboration scores
    detection_scores = compute_detection_scores(evidence_tuple)

    # v0.9.3: lexical taxonomy observations from CT-discovered subdomains.
    # Pure re-projection of related_domains through a rule-based parser —
    # no new network calls, no generated candidates. Observations are
    # exposed on TenantInfo.lexical_observations AND appended to insights
    # for the default panel display.
    lex_obs = lexical_observations(
        [d for d in all_related if "*" not in d],
        base_domain=queried_domain,
    )
    lexical_observation_statements: tuple[str, ...] = tuple(o.statement for o in lex_obs)
    for obs in lex_obs:
        insights.append(f"{obs.category}: {obs.statement}")

    # Collect surface_attributions across sources. dns_records is currently
    # the only source that emits these, but propagating through the merger
    # keeps the shape future-proof if another source ever produces them.
    seen_subdomains: set[str] = set()
    merged_surface: list[SurfaceAttribution] = []
    for result in results:
        for sa in result.surface_attributions:
            if sa.subdomain in seen_subdomains:
                continue
            seen_subdomains.add(sa.subdomain)
            merged_surface.append(sa)
    surface_tuple: tuple[SurfaceAttribution, ...] = tuple(sorted(merged_surface, key=lambda s: s.subdomain))

    return TenantInfo(
        tenant_id=tenant_id,
        display_name=display_name,
        default_domain=default_domain,
        queried_domain=queried_domain,
        confidence=confidence,
        region=region,
        sources=sources,
        services=tuple(sorted(all_services)),
        slugs=tuple(sorted(all_slugs)),
        auth_type=auth_type,
        dmarc_policy=dmarc_policy,
        domain_count=domain_count,
        tenant_domains=tenant_domains,
        related_domains=tuple(sorted(all_related)),
        insights=tuple(insights),
        degraded_sources=tuple(sorted(all_degraded)),
        cert_summary=cert_summary,
        evidence=evidence_tuple,
        evidence_confidence=evidence_confidence,
        inference_confidence=inference_confidence,
        detection_scores=detection_scores,
        bimi_identity=bimi_identity,
        site_verification_tokens=tuple(sorted(all_site_verification_tokens)),
        mta_sts_mode=mta_sts_mode,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
        merge_conflicts=merge_conflicts,
        primary_email_provider=primary_email_provider,
        email_gateway=email_gateway,
        dmarc_pct=dmarc_pct,
        likely_primary_email_provider=likely_primary_email_provider,
        ct_provider_used=ct_provider_used,
        ct_subdomain_count=ct_subdomain_count,
        ct_cache_age_days=ct_cache_age_days,
        cloud_instance=cloud_instance,
        tenant_region_sub_scope=tenant_region_sub_scope,
        msgraph_host=msgraph_host,
        lexical_observations=lexical_observation_statements,
        surface_attributions=surface_tuple,
    )
