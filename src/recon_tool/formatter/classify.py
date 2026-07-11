"""Service-classification logic shared by every formatter renderer.

Extracted from ``formatter.py`` so the panel, markdown, plain, and json-dict
renderers can be split onto a common base without circular imports. This module
holds the classification *logic*: slug -> category, slug -> cloud vendor,
provider-line detection, the two-pass service categorizer, and the fingerprint
lookups they build on. The data tables live in
``recon_tool.formatter.classify_tables``; this module imports and re-exports
them so ``recon_tool.formatter`` has one import source. It imports nothing from
the formatter facade and does no Rich rendering.

The boundary names are public; the formatter facade re-exports them (and the
tables) under their historical ``_NAME`` aliases so the test/validation import
surface and formatter's own body keep working unchanged.
"""

from __future__ import annotations

from collections.abc import Iterable

from recon_tool.constants import SVC_DKIM_GOOGLE
from recon_tool.fingerprints import load_fingerprints
from recon_tool.formatter.classify_tables import (
    CATEGORY_BY_SLUG,
    CLOUD_SLUG_QUALIFIERS,
    CLOUD_VENDOR_BY_SLUG,
    CLOUD_VENDOR_ROLLUP_EXCLUSIONS,
    EMAIL_SERVICE_PREFIXES,
    FILTERED_SERVICE_PREFIXES,
    FILTERED_SERVICE_SUFFIXES,
    M365_KEYWORDS,
    SERVICE_CATEGORIES_ORDER,
    SLUG_DISPLAY_OVERRIDES,
)
from recon_tool.models import EvidenceRecord, TenantInfo
from recon_tool.source_status import SourceStatus

__all__ = [
    "CATEGORY_BY_SLUG",
    "CLOUD_SLUG_QUALIFIERS",
    "CLOUD_VENDOR_BY_SLUG",
    "CLOUD_VENDOR_ROLLUP_EXCLUSIONS",
    "EMAIL_SERVICE_PREFIXES",
    "FILTERED_SERVICE_PREFIXES",
    "FILTERED_SERVICE_SUFFIXES",
    "M365_KEYWORDS",
    "SERVICE_CATEGORIES_ORDER",
    "SLUG_DISPLAY_OVERRIDES",
    "canonical_cloud_vendor",
    "categorize_service",
    "categorize_services",
    "category_for_slug",
    "count_cloud_vendors",
    "detect_provider",
    "google_workspace_cse_indicators",
    "google_workspace_module_indicators",
    "is_gws_service",
    "is_m365_service",
    "provider_line",
    "role_aware_service_label",
    "slug_to_relationship_metadata",
]

_CAA_ISSUER_DISPLAY_OVERRIDES = {"aws-acm": "Amazon"}
_FALLBACK_ACCOUNT_PROVIDER_NAMES = {
    "microsoft365": "Microsoft 365",
    "google-workspace": "Google Workspace",
    "zoho": "Zoho Mail",
    "protonmail": "ProtonMail",
}


def _get_slug_provider_groups() -> dict[str, str]:
    """Build a slug → provider_group mapping from loaded fingerprints."""
    return {fp.slug: fp.provider_group for fp in load_fingerprints() if fp.provider_group is not None}


def slug_to_relationship_metadata() -> dict[str, dict[str, str | None]]:
    """Return ``{slug: {product_family, parent_vendor, bimi_org}}`` for every
    fingerprint with at least one populated relationship-metadata field.

    Pure data lookup — drives the ``fingerprint_metadata`` block in
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


def is_gws_service(svc: str) -> bool:
    """Check if a service name should be categorized as Google Workspace."""
    pg = _service_provider_group(svc)
    if pg is not None:
        return pg == "google-workspace"
    svc_lower = svc.lower()
    return svc_lower == SVC_DKIM_GOOGLE.lower() or svc_lower.startswith("google workspace")


def is_m365_service(svc: str) -> bool:
    """Check if a service name should be categorized as M365.

    Checks fingerprint provider_group first, then exact source-derived service
    names and the explicit ``Microsoft 365:`` module prefix.
    """
    pg = _service_provider_group(svc)
    if pg is not None:
        return pg == "microsoft365"
    svc_lower = svc.lower()
    if svc_lower in M365_KEYWORDS or svc_lower.startswith("microsoft 365:"):
        return True
    for suffix in (" (role unavailable)", " (public txt account indicator)"):
        if svc_lower.endswith(suffix):
            return svc_lower.removesuffix(suffix) in M365_KEYWORDS
    return False


def google_workspace_module_indicators(info: TenantInfo) -> tuple[str, ...]:
    """Return GWS module names supported by retained CNAME evidence."""
    cname_rules = {
        record.rule_name.casefold() for record in info.evidence if record.source_type.upper().startswith("CNAME")
    }
    modules = {
        service.removeprefix("Google Workspace: ")
        for service in info.services
        if service.startswith("Google Workspace: ") and service.casefold() in cname_rules
    }
    return tuple(sorted(modules))


def google_workspace_cse_indicators(info: TenantInfo) -> tuple[str, ...]:
    """Return CSE fields only when retained HTTP evidence supports them."""
    cse_observed = any(
        record.source_type.upper() == "HTTP"
        and record.slug == "google-cse"
        and record.rule_name == "Google Workspace CSE"
        for record in info.evidence
    )
    if not cse_observed:
        return ()
    return tuple(
        sorted(
            service
            for service in info.services
            if service == "Google Workspace CSE" or service.startswith("CSE Key Manager: ")
        )
    )


def category_for_slug(slug: str) -> str | None:
    """Return the panel category for a fingerprint slug, or ``None``.

    Public accessor over the ``CATEGORY_BY_SLUG`` lookup. The
    corpus-aggregation tooling uses this to estimate the panel's
    categorized-service count from a serialized TenantInfo without
    re-running the full ``categorize_services`` pipeline. Returning
    ``None`` for slugs not in the table is the documented contract.
    """
    return CATEGORY_BY_SLUG.get(slug)


def canonical_cloud_vendor(slug: str) -> str | None:
    """Collapse a fingerprint slug to its cloud-vendor identity.

    Returns the vendor label (``"AWS"``, ``"Azure"``, ``"Cloudflare"``,
    ...) for slugs that map to a recognised cloud vendor, or ``None``
    for slugs that are not cloud-categorized. The mapping is the
    single source of truth used by the multi-cloud rollup; do
    not duplicate it inline at call sites.
    """
    return CLOUD_VENDOR_BY_SLUG.get(slug)


def count_cloud_vendors(
    apex_slugs: Iterable[str],
    surface_slugs: Iterable[str] = (),
    *,
    apex_evidence: Iterable[EvidenceRecord] | None = None,
) -> dict[str, int]:
    """Count distinct cloud-vendor mentions across apex and surface slugs.

    The returned dict maps vendor label to slug-mention count. A vendor
    with multiple slug families (AWS Route 53 + AWS CloudFront) is one
    key with a count of 2. Slugs that do not map to a cloud vendor are
    silently dropped. Apex and surface slug streams are merged before
    counting, so a vendor that fires on the apex and on a subdomain
    counts twice (one mention per slug), but still as one distinct
    vendor key.

    When ``apex_evidence`` is supplied, only apex slugs with retained CNAME,
    A, or PTR endpoint-binding evidence contribute. NS, CAA, and TXT records
    establish DNS hosting, issuer authorization, or account registration, not
    an edge or workload binding. Missing per-slug evidence is excluded rather
    than assigned a role. Omitting ``apex_evidence`` preserves the historical
    pure slug-counter API. Surface slugs already come from CNAME attribution.

    Used by the panel rollup to decide whether to fire (at least 2 distinct
    keys) and what vendor list to render. Sorted-output handling is the
    caller's job because callers differ in tie-break preference.
    """
    if apex_evidence is None:
        filtered_apex_slugs = apex_slugs
    else:
        evidence_types = _evidence_types_by_slug(apex_evidence)
        filtered_apex_slugs = (
            slug
            for slug in apex_slugs
            if evidence_types.get(slug) and _has_cloud_workload_evidence(evidence_types[slug])
        )

    counts: dict[str, int] = {}
    for slug in (*filtered_apex_slugs, *surface_slugs):
        vendor = CLOUD_VENDOR_BY_SLUG.get(slug)
        if vendor is None:
            continue
        counts[vendor] = counts.get(vendor, 0) + 1
    return counts


def _evidence_types_by_slug(evidence: Iterable[EvidenceRecord]) -> dict[str, frozenset[str]]:
    """Return normalized source roles for each detected slug."""
    mutable: dict[str, set[str]] = {}
    for record in evidence:
        mutable.setdefault(record.slug, set()).add(record.source_type.upper())
    return {slug: frozenset(source_types) for slug, source_types in mutable.items()}


def _has_cloud_workload_evidence(source_types: frozenset[str]) -> bool:
    """Whether source roles support an edge, hosting, or workload label.

    NS identifies authoritative DNS, CAA authorizes certificate issuers, and
    TXT commonly records account verification. None establishes a hosted cloud
    workload. CNAME and A/PTR-derived observations do identify a public endpoint
    binding, so they may contribute to the legacy ``Multi-cloud`` summary.
    """
    return any(source_type.startswith("CNAME") or source_type in {"A", "PTR"} for source_type in source_types)


def _split_topology_names(joined: str | None) -> list[str]:
    """Split a deterministic ``" + "`` topology field without ranking it."""
    if not joined:
        return []
    return list(dict.fromkeys(part.strip() for part in joined.split(" + ") if part.strip()))


def _provider_from_topology(
    primary_email_provider: str | None,
    email_gateway: str | None,
    likely_primary_email_provider: str | None,
) -> str:
    """Render observed MX paths and non-MX downstream indicators.

    Joined provider fields are sets encoded for schema compatibility. Their
    order does not establish priority. Every direct provider and gateway is
    therefore an observed MX delivery path, while every non-MX candidate stays
    a possible downstream indicator. No candidate is promoted or demoted.
    """
    direct_paths = _split_topology_names(primary_email_provider)
    gateways = _split_topology_names(email_gateway)
    possible_downstreams = [
        name for name in _split_topology_names(likely_primary_email_provider) if name not in direct_paths
    ]
    segments: list[str] = []
    segments.extend(f"{name} (MX delivery path)" for name in direct_paths)
    for gateway in gateways:
        detail = "MX delivery path"
        if not direct_paths and not possible_downstreams:
            detail += "; downstream unobserved"
        segments.append(f"{gateway} gateway ({detail})")
    segments.extend(f"{name} (possible downstream indicator)" for name in possible_downstreams)

    if segments:
        return " + ".join(segments)
    return "Unknown (no known provider pattern matched)"


def _provider_slug_fallback(
    slugs: tuple[str, ...] | set[str],
    has_mx_records: bool | None,
    evidence_backed_slugs: frozenset[str] | None,
) -> str:
    """Slug-based provider line when no topology data is available.

    Account indicators never become delivery providers. When MX records were
    observed but no catalogued provider matched, the separate
    ``Custom or unclassified MX`` path reports exactly that bounded fact.
    """
    slug_set = set(slugs)
    providers = [(slug, name) for slug, name in _FALLBACK_ACCOUNT_PROVIDER_NAMES.items() if slug in slug_set]
    if not providers and "aws-ses" in slug_set:
        providers.append(("aws-ses", "AWS SES"))
    segments = [
        f"{provider} ({_fallback_account_qualifier(slug, has_mx_records, evidence_backed_slugs)})"
        for slug, provider in providers
    ]
    if "self-hosted-mail" in slug_set or (providers and has_mx_records):
        mx_role = _fallback_observed_role("self-hosted-mail", "MX delivery path", evidence_backed_slugs)
        segments.append(f"Custom or unclassified MX ({mx_role})")
    if "null-mx" in slug_set:
        null_label = "Null MX (domain does not accept email)"
        if _fallback_observed_role("null-mx", "observed", evidence_backed_slugs) == "role unavailable":
            null_label += " (role unavailable)"
        segments.append(null_label)
    if "exchange-onprem" in slug_set:
        endpoint_label = "Exchange-style endpoint indicator"
        if _fallback_observed_role("exchange-onprem", "observed", evidence_backed_slugs) == "role unavailable":
            endpoint_label += " (role unavailable)"
        segments.append(endpoint_label)
    if segments:
        return " + ".join(segments)
    return "Unknown (no known provider pattern matched)"


def _fallback_account_qualifier(
    slug: str,
    has_mx_records: bool | None,
    evidence_backed_slugs: frozenset[str] | None,
) -> str:
    """Describe an account slug without upgrading it into email delivery."""
    if evidence_backed_slugs is not None and slug not in evidence_backed_slugs:
        return "role unavailable"
    if has_mx_records is None:
        return "account indicator; MX collection unavailable"
    if has_mx_records:
        return "account indicator"
    return "account indicator; no MX observed"


def _fallback_observed_role(
    slug: str,
    observed_role: str,
    evidence_backed_slugs: frozenset[str] | None,
) -> str:
    """Return a bounded role only when lineage exists or was not requested."""
    if evidence_backed_slugs is not None and slug not in evidence_backed_slugs:
        return "role unavailable"
    return observed_role


def detect_provider(
    services: tuple[str, ...] | set[str],
    slugs: tuple[str, ...] | set[str] = (),
    primary_email_provider: str | None = None,
    email_gateway: str | None = None,
    likely_primary_email_provider: str | None = None,
    has_mx_records: bool | None = True,
    email_confirmed_slugs: frozenset[str] | None = None,
    evidence_backed_slugs: frozenset[str] | None = None,
) -> str:
    """Detect and format the provider line with email topology awareness.

    Direct MX providers and gateways render as observed MX delivery paths.
    Non-MX candidates behind a gateway render as possible downstream
    indicators. Joined field order never becomes a priority decision.

    Falls back to slug-based detection when topology fields are all
    None (backward compatible).
    """
    if primary_email_provider or email_gateway or likely_primary_email_provider:
        return _provider_from_topology(
            primary_email_provider,
            email_gateway,
            likely_primary_email_provider,
        )

    return _provider_slug_fallback(slugs, has_mx_records, evidence_backed_slugs)


def provider_line(info: TenantInfo) -> str:
    """Return one evidence-aware provider summary for every output surface."""
    from recon_tool.collection_view import collection_observable_evidence, collection_observable_info
    from recon_tool.merger import compute_email_topology

    info = collection_observable_info(info)
    status = SourceStatus.from_degraded_sources(info.degraded_sources)
    observable_evidence = collection_observable_evidence(info)
    primary_email_provider, email_gateway, likely_primary_email_provider = compute_email_topology(observable_evidence)
    has_mx_records = (
        None
        if status.channel_unavailable("mx")
        else any(evidence.source_type.upper() == "MX" for evidence in observable_evidence)
    )
    evidence_backed_slugs = frozenset(evidence.slug for evidence in observable_evidence if evidence.slug)
    return detect_provider(
        info.services,
        info.slugs,
        primary_email_provider=primary_email_provider,
        email_gateway=email_gateway,
        likely_primary_email_provider=likely_primary_email_provider,
        has_mx_records=has_mx_records,
        evidence_backed_slugs=evidence_backed_slugs,
    )


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


def categorize_service(service: str, slug: str | None) -> str:
    """Classify a service into one of SERVICE_CATEGORIES_ORDER.

    Classification rules (first match wins):
        1. Slug lookup via CATEGORY_BY_SLUG
        2. Email prefix match (DMARC, DKIM, SPF, …)
        3. Category-name substring match (for services whose name
           carries a category hint like "DNS: Cloudflare")
        4. Fallback: "Business Apps"
    """
    if slug and slug in CATEGORY_BY_SLUG:
        return CATEGORY_BY_SLUG[slug]
    for prefix in EMAIL_SERVICE_PREFIXES:
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


def _is_service_artifact(name: str) -> bool:
    """Verification tokens and registrar handoffs — filtered from the panel."""
    return any(name.endswith(suf) for suf in FILTERED_SERVICE_SUFFIXES) or any(
        name.startswith(pfx) for pfx in FILTERED_SERVICE_PREFIXES
    )


def _role_aware_slug_display(
    slug: str,
    name: str,
    category: str,
    source_types: frozenset[str],
) -> tuple[str, str]:
    """Return a category and label that state what the evidence proves.

    A fingerprint slug names a vendor, but its source record determines the
    observable role. In particular, account-verification TXT records do not
    establish product deployment, NS records identify DNS hosting rather than
    compute, and CAA records authorize issuers rather than prove certificate
    issuance or a cloud workload.
    """
    if "CAA" in source_types:
        issuer = _CAA_ISSUER_DISPLAY_OVERRIDES.get(slug, name.removeprefix("CAA: "))
        return "Security", f"CAA: {issuer} authorized"

    if not source_types:
        return category, f"{name} (role unavailable)"

    if source_types and source_types <= frozenset({"TXT", "SUBDOMAIN_TXT"}):
        return category, f"{name} (public TXT account indicator)"

    if category != "Cloud":
        return category, name

    has_cname = any(source_type.startswith("CNAME") for source_type in source_types)
    has_ns = "NS" in source_types
    if slug == "cloudflare" and has_cname:
        qualifier = "DNS + CDN/edge" if has_ns else "CDN/edge"
    elif has_ns:
        qualifier = "DNS"
    elif source_types == frozenset({"TXT"}):
        qualifier = "public TXT account indicator"
    else:
        qualifier = CLOUD_SLUG_QUALIFIERS.get(slug)

    return category, f"{name} ({qualifier})" if qualifier else name


def role_aware_service_label(service: str, evidence: Iterable[EvidenceRecord]) -> str:
    """Describe one service using the role of its retained evidence.

    Delta output compares stable raw service names first, then calls this
    helper only for an actual addition or removal. This avoids manufacturing a
    change when an older snapshot lacks lineage while still preventing a TXT
    registration or CNAME module alias from reading as generic deployment.
    """
    supporting = tuple(record for record in evidence if record.rule_name.casefold() == service.casefold())
    if not supporting:
        return service
    source_types = frozenset(record.source_type.upper() for record in supporting)
    if service.startswith("Google Workspace: ") and any(
        source_type.startswith("CNAME") for source_type in source_types
    ):
        module = service.removeprefix("Google Workspace: ")
        return f"Google Workspace module indicator: {module}"
    if service == "Google Workspace CSE" and "HTTP" in source_types:
        return "Google Workspace CSE configuration indicator"
    slugs = {record.slug for record in supporting}
    if len(slugs) != 1:
        return service
    slug = next(iter(slugs))
    _category, label = _role_aware_slug_display(
        slug,
        service,
        categorize_service(service, slug),
        source_types,
    )
    return label


def _categorize_pass1_slugs(
    info: TenantInfo, slug_to_name: dict[str, str], by_cat: dict[str, list[str]]
) -> tuple[set[str], set[str]]:
    """Pass 1: slug-authoritative classification.

    Each detected slug with a known category (``CATEGORY_BY_SLUG``) pulls in
    its canonical fingerprint display name, or an explicit
    ``SLUG_DISPLAY_OVERRIDES`` entry, with the "CAA: " prefix stripped outside
    Security and a cloud type qualifier ("(DNS)", "(CDN)", ...) added so a slug
    like Route 53 does not read as a cloud-compute claim. A category missing
    from ``SERVICE_CATEGORIES_ORDER`` (future-fingerprint drift) is added to
    ``by_cat`` defensively so the append never raises. Mutates ``by_cat``;
    returns the (seen_services, slugs_filed) sets pass 2 needs.
    """
    evidence_types = _evidence_types_by_slug(info.evidence)
    seen_services: set[str] = set()
    slugs_filed: set[str] = set()
    for slug in info.slugs:
        cat = CATEGORY_BY_SLUG.get(slug)
        if not cat:
            continue
        name = SLUG_DISPLAY_OVERRIDES.get(slug) or slug_to_name.get(slug, slug)
        if _is_service_artifact(name):
            continue
        cat, name = _role_aware_slug_display(slug, name, cat, evidence_types.get(slug, frozenset()))
        if cat != "Security" and name.startswith("CAA: "):
            name = name[len("CAA: ") :]
        if name in seen_services:
            continue
        if cat not in by_cat:
            by_cat[cat] = []
        by_cat[cat].append(name)
        seen_services.add(name)
        slugs_filed.add(slug)
    return seen_services, slugs_filed


def _categorize_pass2_names(
    info: TenantInfo,
    name_to_slug: dict[str, str],
    by_cat: dict[str, list[str]],
    seen_services: set[str],
    slugs_filed: set[str],
) -> None:
    """Pass 2: classify service names without a slug match by prefix / name
    pattern, skipping anything already filed in pass 1 (by name, lowercased
    prefix, or slug) so a detection is not double-counted under two display
    names. Mutates ``by_cat`` and the seen sets."""
    seen_lower_prefixes = {s.lower().split(" (")[0] for s in seen_services}
    filed_evidence_aliases = {record.rule_name.casefold() for record in info.evidence if record.slug in slugs_filed}
    for svc in info.services:
        if svc in seen_services:
            continue
        if _is_service_artifact(svc):
            continue
        if svc.casefold() in filed_evidence_aliases:
            continue
        svc_prefix = svc.lower().split(" (")[0]
        if svc_prefix in seen_lower_prefixes:
            continue
        slug = _slug_for_service(svc, name_to_slug)
        if slug and slug in slugs_filed:
            continue
        cat = categorize_service(svc, slug)
        label = role_aware_service_label(svc, info.evidence)
        by_cat.setdefault(cat, []).append(label)
        seen_services.add(label)
        seen_lower_prefixes.add(label.lower().split(" (")[0])


def _dedup_identity_echoes(by_cat: dict[str, list[str]]) -> None:
    """Drop Identity rows that merely echo an Email provider (e.g. "Google
    Workspace (managed identity)" when the Email row already shows Google
    Workspace and the Auth line already says "Managed (Google Workspace)").
    Entries for a distinct identity provider (Okta, Duo, CyberArk, Ping) stay."""
    email_provider_names = {n for n in by_cat.get("Email", []) if n}
    filtered_identity: list[str] = []
    for ident in by_cat.get("Identity", []):
        ident_core = ident
        for suffix in (" (managed identity)", " (federated identity)"):
            if ident.endswith(suffix):
                ident_core = ident[: -len(suffix)]
                break
        if ident_core in email_provider_names:
            continue
        filtered_identity.append(ident)
    by_cat["Identity"] = filtered_identity


def _consolidate_caa_issuers(by_cat: dict[str, list[str]]) -> None:
    """Collapse the per-issuer "CAA: <issuer>" Security entries into one compact
    "CAA: N issuers authorized" line so CAA records do not overwhelm the row or
    read as deployed security tools. The full list stays in --full / --json."""
    security = by_cat.get("Security", [])
    caa_entries = [s for s in security if s.startswith("CAA:")]
    if len(caa_entries) > 1:
        non_caa = [s for s in security if not s.startswith("CAA:")]
        count = len(caa_entries)
        consolidated = f"CAA: {count} issuers authorized"
        by_cat["Security"] = [*non_caa, consolidated]


def categorize_services(info: TenantInfo) -> dict[str, list[str]]:
    """Group TenantInfo services into display categories.

    Two-pass classification:
        1. For each detected slug with a known category, resolve the
           slug to its fingerprint display name and file it under
           that category. This is the authoritative path — a slug's
           category is pinned in ``CATEGORY_BY_SLUG``.
        2. For each remaining service (not yet filed via slug — e.g.
           DNS-derived labels like "DMARC", "DKIM", "SPF: strict"),
           classify by prefix / name pattern via
           ``categorize_service``.

    Preserves input ordering within each category. Categories with
    no services are omitted from the returned dict.
    """
    from recon_tool.collection_view import collection_observable_info

    info = collection_observable_info(info)
    try:
        fps = load_fingerprints()
        slug_to_name: dict[str, str] = {fp.slug: fp.name for fp in fps}
        name_to_slug: dict[str, str] = {fp.name: fp.slug for fp in fps}
    except Exception:
        slug_to_name = {}
        name_to_slug = {}

    # One bucket per declared category. Pass 1 adds any category missing from
    # SERVICE_CATEGORIES_ORDER defensively so a future-fingerprint drift cannot
    # crash the panel; such a category just will not render until added here.
    by_cat: dict[str, list[str]] = {c: [] for c in SERVICE_CATEGORIES_ORDER}

    seen_services, slugs_filed = _categorize_pass1_slugs(info, slug_to_name, by_cat)
    _categorize_pass2_names(info, name_to_slug, by_cat, seen_services, slugs_filed)
    _dedup_identity_echoes(by_cat)
    _consolidate_caa_issuers(by_cat)

    return {c: svcs for c in SERVICE_CATEGORIES_ORDER if (svcs := by_cat.get(c))}
