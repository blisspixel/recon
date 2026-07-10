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
from recon_tool.models import TenantInfo

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
    "is_gws_service",
    "is_m365_service",
    "slug_to_relationship_metadata",
]

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
    # Fallback heuristic for services added with "Google Workspace" prefix
    return svc.lower().startswith("google workspace")
def is_m365_service(svc: str) -> bool:
    """Check if a service name should be categorized as M365.

    Checks fingerprint provider_group first, falls back to M365_KEYWORDS.
    """
    pg = _service_provider_group(svc)
    if pg is not None:
        return pg == "microsoft365"
    svc_lower = svc.lower()
    return any(kw in svc_lower for kw in M365_KEYWORDS)
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
) -> dict[str, int]:
    """Count distinct cloud-vendor mentions across apex and surface slugs.

    The returned dict maps vendor label to slug-mention count. A vendor
    with multiple slug families (AWS Route 53 + AWS CloudFront) is one
    key with a count of 2. Slugs that do not map to a cloud vendor are
    silently dropped. Apex and surface slug streams are merged before
    counting, so a vendor that fires on the apex and on a subdomain
    counts twice (one mention per slug), but still as one distinct
    vendor key.

    Used by the panel rollup to decide whether to fire (≥ 2 distinct
    keys) and what vendor list to render. Sorted-output handling is the
    caller's job because callers differ in tie-break preference.
    """
    counts: dict[str, int] = {}
    for slug in (*apex_slugs, *surface_slugs):
        vendor = CLOUD_VENDOR_BY_SLUG.get(slug)
        if vendor is None:
            continue
        counts[vendor] = counts.get(vendor, 0) + 1
    return counts


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


def _provider_exchange_onprem(
    slug_set_early: set[str], primary_email_provider: str | None, email_gateway: str | None
) -> str | None:
    """Exchange on-prem / hybrid provider line.

    Fires when the exchange-onprem slug is present and there is no MX-backed
    primary provider: a strong signal that email goes to a self-hosted Exchange
    cluster regardless of dormant Google / M365 account registrations the
    identity endpoints report. When an M365 tenant also exists the platform is
    Microsoft 365 (cloud or hybrid) and autodiscover is just an endpoint, so we
    do not lead with "Exchange Server (on-prem)". Returns ``None`` when this
    path does not apply.
    """
    if not ("exchange-onprem" in slug_set_early and not primary_email_provider):
        return None
    if "microsoft365" in slug_set_early:
        primary_segment = "Microsoft 365"
        if email_gateway:
            primary_segment = f"{primary_segment} via {email_gateway} gateway"
        segments = [primary_segment]
        if "google-workspace" in slug_set_early:
            segments.append("Google Workspace (account detected)")
        return " + ".join(segments)
    # Genuinely on-prem Exchange — no M365 tenant found.
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


def _topology_slug_secondaries(
    slug_set: set[str],
    primary_name: str | None,
    inferred_secondaries: list[str],
    email_confirmed_slugs: frozenset[str] | None,
) -> list[str]:
    """Slug-based secondary providers (detected via TXT/DKIM) not already in the
    primary line. Account-only detections (OIDC, TXT tokens) are dropped as
    Provider-line noise unless confirmed via email routing (MX or DKIM)."""
    slug_secondaries: list[str] = []
    for slug, name in (
        ("microsoft365", "Microsoft 365"),
        ("google-workspace", "Google Workspace"),
        ("zoho", "Zoho Mail"),
        ("protonmail", "ProtonMail"),
    ):
        if slug not in slug_set:
            continue
        if primary_name and name == primary_name:
            continue
        if name in inferred_secondaries:
            continue
        if email_confirmed_slugs is not None and slug not in email_confirmed_slugs:
            continue
        slug_secondaries.append(name)
    return slug_secondaries


def _provider_from_topology(
    slugs: tuple[str, ...] | set[str],
    primary_email_provider: str | None,
    email_gateway: str | None,
    likely_primary_email_provider: str | None,
    email_confirmed_slugs: frozenset[str] | None,
) -> str:
    """Provider line from email-topology data: a single promoted primary (see
    ``_pick_single_primary``), an optional gateway, and deduped secondaries
    drawn from the inferred list plus email-confirmed slugs."""
    primary_name: str | None = None
    primary_label: str = ""
    inferred_secondaries: list[str] = []
    if primary_email_provider:
        primary_name, inferred_secondaries = _pick_single_primary(primary_email_provider)
        primary_label = "(primary)"
    elif likely_primary_email_provider:
        primary_name, inferred_secondaries = _pick_single_primary(likely_primary_email_provider)
        primary_label = "(likely primary)"

    slug_secondaries = _topology_slug_secondaries(set(slugs), primary_name, inferred_secondaries, email_confirmed_slugs)

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


def _provider_slug_fallback(slugs: tuple[str, ...] | set[str], has_mx_records: bool) -> str:
    """Slug-based provider line when no topology data is available.

    Distinguishes "account detected, no MX" (the slug came from a non-MX source
    on a domain with zero MX records) from "account detected, custom MX" (MX
    records exist but point to an unrecognized host). Callers that know whether
    MX records exist pass ``has_mx_records``; the conservative default is True.
    """
    slug_set = set(slugs)
    providers: list[str] = []
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
    return "Unknown (no known provider pattern matched)"


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

    Target format:
      - ``Microsoft 365 (primary) via Proofpoint gateway`` — strict primary + gateway
      - ``Microsoft 365 (primary) via Trend Micro gateway + Google Workspace (secondary)``
        — primary + gateway + a separately detected secondary
      - ``Microsoft 365 (primary)`` — strict primary, no gateway
      - ``Microsoft 365 (likely primary) via Trend Micro gateway`` — inferred primary
      - ``Proofpoint gateway (no inferable downstream)`` — gateway only, unknown downstream
      - ``Microsoft 365; Google Workspace`` — slug-only fallback

    The critical change from the old format: when
    ``likely_primary_email_provider`` lists multiple providers (e.g.
    ``"Google Workspace + Microsoft 365"``), one is promoted to the
    single primary and the rest become ``"(secondary)"`` — never
    ``"(dual)"``. The old format implied ambiguous active dual-use
    which is usually wrong on enterprise targets. See
    ``_pick_single_primary`` for the selection rule.

    Falls back to slug-based detection when topology fields are all
    None (backward compatible).
    """
    slug_set_early = set(slugs)
    exchange = _provider_exchange_onprem(slug_set_early, primary_email_provider, email_gateway)
    if exchange is not None:
        return exchange

    if primary_email_provider or email_gateway or likely_primary_email_provider:
        return _provider_from_topology(
            slugs,
            primary_email_provider,
            email_gateway,
            likely_primary_email_provider,
            email_confirmed_slugs,
        )

    return _provider_slug_fallback(slugs, has_mx_records)
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
    seen_services: set[str] = set()
    slugs_filed: set[str] = set()
    for slug in info.slugs:
        cat = CATEGORY_BY_SLUG.get(slug)
        if not cat:
            continue
        name = SLUG_DISPLAY_OVERRIDES.get(slug) or slug_to_name.get(slug, slug)
        if _is_service_artifact(name):
            continue
        if cat != "Security" and name.startswith("CAA: "):
            name = name[len("CAA: ") :]
        if cat == "Cloud":
            qualifier = CLOUD_SLUG_QUALIFIERS.get(slug)
            if qualifier:
                name = f"{name} ({qualifier})"
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
    for svc in info.services:
        if svc in seen_services:
            continue
        if _is_service_artifact(svc):
            continue
        svc_prefix = svc.lower().split(" (")[0]
        if svc_prefix in seen_lower_prefixes:
            continue
        slug = _slug_for_service(svc, name_to_slug)
        if slug and slug in slugs_filed:
            continue
        cat = categorize_service(svc, slug)
        by_cat.setdefault(cat, []).append(svc)
        seen_services.add(svc)
        seen_lower_prefixes.add(svc_prefix)


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
    "CAA: N issuers restricted" line so CAA records do not overwhelm the row or
    read as deployed security tools. The full list stays in --full / --json."""
    security = by_cat.get("Security", [])
    caa_entries = [s for s in security if s.startswith("CAA:")]
    if len(caa_entries) >= 1:
        non_caa = [s for s in security if not s.startswith("CAA:")]
        count = len(caa_entries)
        consolidated = f"CAA: {count} issuer{'s' if count != 1 else ''} restricted"
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
