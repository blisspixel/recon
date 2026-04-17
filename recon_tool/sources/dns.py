"""DNS record lookup source for domain intelligence and tech stack fingerprinting.

Loads patterns from data/fingerprints.yaml — add new services there, no code changes needed.

Detection is split into focused async functions (_detect_txt, _detect_mx, etc.) to keep
each concern isolated and testable. The top-level _detect_services orchestrates them
concurrently via asyncio.gather for maximum throughput.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DMARC,
    SVC_EXCHANGE_AUTODISCOVER,
    SVC_INTUNE_MDM,
    SVC_MICROSOFT_TEAMS,
    SVC_MTA_STS,
    SVC_OFFICE_PROPLUS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.fingerprints import (
    get_caa_patterns,
    get_cname_patterns,
    get_mx_patterns,
    get_ns_patterns,
    get_spf_patterns,
    get_subdomain_txt_patterns,
    get_txt_patterns,
    load_fingerprints,
    match_txt,
)
from recon_tool.fingerprints import (
    get_m365_slugs as _get_m365_slugs,
)
from recon_tool.http import http_client as _http_client
from recon_tool.models import BIMIIdentity, CertSummary, EvidenceRecord, SourceResult
from recon_tool.sources.cert_providers import CertIntelProvider, CertSpotterProvider, CrtshProvider

logger = logging.getLogger("recon")


# Per-query timeout in seconds. Prevents a single slow/hanging DNS server
# from stalling the entire detection chain. Each _safe_resolve call gets
# this as the `lifetime` parameter — total wall-clock time for the query
# including retries across all configured nameservers.
DNS_QUERY_TIMEOUT = 5.0


def _get_resolver() -> dns.asyncresolver.Resolver:
    """Return the async resolver instance. Overridable for testing."""
    return _default_resolver


# Default async resolver instance — reused across queries within a lookup.
# Override via _set_resolver() in tests to inject custom nameservers.
_default_resolver = dns.asyncresolver.Resolver()


def _set_resolver(resolver: dns.asyncresolver.Resolver) -> None:  # pyright: ignore[reportUnusedFunction]
    """Replace the default resolver — for testing or custom nameserver config."""
    global _default_resolver  # noqa: PLW0603
    _default_resolver = resolver


def _parse_rdata(raw: str) -> str:
    """Normalize a single rdata text value.

    For TXT records, dnspython's to_text() returns multi-part strings as
    space-separated quoted chunks (e.g. '"v=DMARC1;" "p=none"'). We join
    these chunks into a single string so downstream parsing sees the full
    record value, not just the first 255-byte fragment.

    For non-TXT records (CNAME, MX, NS), dnspython appends a trailing dot
    to FQDNs. We strip it for cleaner downstream matching.
    """
    if raw.startswith('"'):
        # TXT record — join multi-part chunks, don't strip trailing dots
        # (dots can be meaningful in TXT values like SPF includes)
        parts = raw.split('" "')
        joined = "".join(p.strip('"') for p in parts)
        return joined
    # Non-TXT (CNAME, MX, NS, etc.) — strip trailing FQDN dot
    return raw.strip('"').rstrip(".")


async def _safe_resolve(domain: str, rdtype: str, timeout: float = DNS_QUERY_TIMEOUT) -> list[str]:
    """Resolve DNS records asynchronously, returning empty list on any error.

    Uses dns.asyncresolver for non-blocking DNS queries, allowing multiple
    queries to run concurrently via asyncio.gather.

    Args:
        domain: The domain name to query.
        rdtype: DNS record type (TXT, MX, CNAME, etc.).
        timeout: Max wall-clock seconds for this query (default: DNS_QUERY_TIMEOUT).
    """
    try:
        resolver = _get_resolver()
        answers = await resolver.resolve(domain, rdtype, lifetime=timeout)
        return [_parse_rdata(rdata.to_text()) for rdata in answers]  # pyright: ignore[reportGeneralTypeIssues]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        logger.debug("DNS %s lookup timed out for %s (%.1fs)", rdtype, domain, timeout)
        return []
    except Exception as exc:
        logger.debug("DNS %s lookup failed for %s: %s", rdtype, domain, exc)
        return []


# Keep a synchronous version for tests that mock _safe_resolve at the module level.
# This is the same logic but using the blocking resolver.
def _safe_resolve_sync(domain: str, rdtype: str, timeout: float = DNS_QUERY_TIMEOUT) -> list[str]:  # pyright: ignore[reportUnusedFunction]
    """Synchronous DNS resolution — used only by tests that need blocking behavior."""
    try:
        answers = dns.resolver.resolve(domain, rdtype, lifetime=timeout)
        return [_parse_rdata(rdata.to_text()) for rdata in answers]  # pyright: ignore[reportGeneralTypeIssues]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        logger.debug("DNS %s lookup timed out for %s (%.1fs)", rdtype, domain, timeout)
        return []
    except Exception as exc:
        logger.debug("DNS %s lookup failed for %s: %s", rdtype, domain, exc)
        return []


# ── Detection context ───────────────────────────────────────────────────
# Mutable accumulator passed through all _detect_* functions to avoid
# returning and merging multiple tuples from each sub-detector.
# Thread-safe is NOT required — all sub-detectors run on the event loop,
# not in separate threads.


class _DetectionCtx:
    """Mutable accumulator for service detection results.

    Uses __slots__ for minor memory/speed benefit since we create one per lookup.
    Not a dataclass because we need the custom add() method with the m365 side-effect,
    and the fields are mutated freely by the sub-detectors (frozen=False would work
    but __slots__ is simpler for a private internal class).

    THREAD SAFETY: This class is NOT thread-safe. All sub-detectors MUST run on
    the same event loop (asyncio.gather), not in separate threads. Do NOT wrap
    sub-detectors in asyncio.to_thread() or use thread-based executors — the
    shared mutable state will race. If threading is ever needed, replace this
    with a lock-protected accumulator or per-detector return values.
    """

    __slots__ = (
        "services",
        "slugs",
        "m365",
        "dmarc_policy",
        "spf_include_count",
        "_m365_slugs",
        "related_domains",
        "degraded_sources",
        "cert_summary",
        "evidence",
        "bimi_identity",
        "site_verification_tokens",
        "mta_sts_mode",
        "_matched_fp_detections",
        "dmarc_pct",
        "raw_dns_records",
        "ct_provider_used",
        "ct_subdomain_count",
        "ct_cache_age_days",
    )

    def __init__(self) -> None:
        self.services: set[str] = set()
        self.slugs: set[str] = set()
        self.m365: bool = False
        self.dmarc_policy: str | None = None
        self.spf_include_count: int = 0
        self._m365_slugs: frozenset[str] = _get_m365_slugs()
        self.related_domains: set[str] = set()
        self.degraded_sources: set[str] = set()
        self.cert_summary: CertSummary | None = None
        self.evidence: list[EvidenceRecord] = []
        self.bimi_identity: Any = None  # BIMIIdentity | None
        self.site_verification_tokens: set[str] = set()
        self.mta_sts_mode: str | None = None
        # Tracks (slug, detection_type, pattern) for each matched fingerprint
        # detection rule. Used by enforce_match_mode_all() to verify that
        # fingerprints with match_mode: all had ALL their detections match.
        self._matched_fp_detections: set[tuple[str, str, str]] = set()
        self.dmarc_pct: int | None = None
        self.raw_dns_records: dict[str, list[str]] = {}
        # R4 (v0.9.2): which CT provider actually contributed subdomains,
        # and how many came back. Surfaced in the panel bottom Note so
        # users can distinguish "crt.sh unavailable" from "certspotter
        # pagination returned 87 entries". None until a provider succeeds.
        self.ct_provider_used: str | None = None
        self.ct_subdomain_count: int = 0
        # v0.10: CT cache age in days when cached data used as fallback
        self.ct_cache_age_days: int | None = None

    def add(self, svc_name: str, slug: str | None = None, source_type: str = "", raw_value: str = "") -> None:
        """Register a detected service, optionally with its slug and evidence.

        M365 detection is based on the slug (stable identifier) rather than
        the display name, so renaming a fingerprint won't break detection.
        When source_type and raw_value are provided, an EvidenceRecord is
        created and appended to self.evidence for traceability.
        """
        self.services.add(svc_name)
        if slug:
            self.slugs.add(slug)
            if slug in self._m365_slugs:
                self.m365 = True
            if source_type and raw_value:
                self.evidence.append(
                    EvidenceRecord(
                        source_type=source_type,
                        raw_value=raw_value,
                        rule_name=svc_name,
                        slug=slug,
                    )
                )

    def record_fp_match(self, slug: str, det_type: str, pattern: str) -> None:
        """Record that a specific fingerprint detection rule matched.

        Used by enforce_match_mode_all() to verify that fingerprints with
        match_mode: all had every detection rule produce a match.
        """
        self._matched_fp_detections.add((slug, det_type, pattern))

    def enforce_match_mode_all(self) -> None:
        """Post-process detections: remove partial matches for match_mode: all fingerprints.

        For fingerprints with match_mode: all, every detection rule must have
        produced a match. If any detection rule within such a fingerprint did
        NOT match, we remove the fingerprint's slug and service name from the
        accumulated results.

        Fingerprints with match_mode: any (the default) are unaffected.
        """
        all_fps = [fp for fp in load_fingerprints() if fp.match_mode == "all"]
        if not all_fps:
            return

        for fp in all_fps:
            # Check if ALL detection rules for this fingerprint matched
            all_matched = all((fp.slug, det.type, det.pattern) in self._matched_fp_detections for det in fp.detections)
            if all_matched:
                # All detections matched — keep the fingerprint's results
                continue

            # Partial match — remove this fingerprint's contributions.
            slug = fp.slug
            name = fp.name

            # Remove service name
            self.services.discard(name)

            # Check if another fingerprint shares this slug and was fully matched
            other_has_slug = False
            for other_fp in load_fingerprints():
                if other_fp is fp or other_fp.slug != slug:
                    continue
                if other_fp.match_mode == "any":
                    # match_mode: any — any single detection match is enough
                    if any(
                        (other_fp.slug, det.type, det.pattern) in self._matched_fp_detections
                        for det in other_fp.detections
                    ):
                        other_has_slug = True
                        break
                else:
                    # match_mode: all — all detections must match
                    if all(
                        (other_fp.slug, det.type, det.pattern) in self._matched_fp_detections
                        for det in other_fp.detections
                    ):
                        other_has_slug = True
                        break

            if not other_has_slug:
                self.slugs.discard(slug)
                # Also remove evidence records for this slug
                self.evidence = [e for e in self.evidence if e.slug != slug]
                # Re-check m365 flag if this slug was an m365 slug
                if slug in self._m365_slugs:
                    self.m365 = any(s in self._m365_slugs for s in self.slugs)


# ── Sub-detectors ───────────────────────────────────────────────────────
# Each function handles one DNS record type. All are async and operate
# on the shared _DetectionCtx. They are gathered concurrently in
# _detect_services for maximum throughput.


async def _detect_txt(ctx: _DetectionCtx, domain: str) -> None:
    """Scan TXT records for service fingerprints and SPF analysis."""
    txt_patterns = get_txt_patterns()
    spf_patterns = get_spf_patterns()

    txt_records = await _safe_resolve(domain, "TXT")
    ctx.raw_dns_records.setdefault("TXT", []).extend(txt_records)

    for txt in txt_records:
        txt_lower = txt.lower()

        result = match_txt(txt, txt_patterns)
        if result:
            ctx.add(result.name, result.slug, source_type="TXT", raw_value=txt)
            ctx.record_fp_match(result.slug, "txt", result.pattern)

        # Extract google-site-verification tokens for relationship mapping
        if txt_lower.startswith("google-site-verification="):
            token = txt[len("google-site-verification=") :].strip()
            if token:
                ctx.site_verification_tokens.add(token)

        if txt_lower.startswith("v=spf1"):
            ctx.spf_include_count = txt_lower.count("include:")
            # SPF patterns use substring matching on the include: values.
            # This is intentional — SPF includes are domain names, and we
            # match on the authoritative portion (e.g. "spf.protection.outlook.com").
            # Unlike TXT patterns (which use regex), SPF patterns are plain
            # substrings because the YAML values are literal domain fragments.
            for det in spf_patterns:
                if det.pattern.lower() in txt_lower:
                    ctx.add(det.name, det.slug)
                    ctx.record_fp_match(det.slug, "spf", det.pattern)
            if txt_lower.rstrip().endswith("-all"):
                ctx.services.add(SVC_SPF_STRICT)
            elif txt_lower.rstrip().endswith("~all"):
                ctx.services.add(SVC_SPF_SOFTFAIL)
            # v0.9.3: follow SPF redirect= chains. A record like
            # "v=spf1 redirect=_spf.mail.umich.edu" means "use that
            # domain's SPF as mine" — RFC 7208 §6.1. Higher-ed and
            # enterprise domains commonly use redirect to point at
            # a shared SPF zone they manage separately. Without
            # following the chain, we score the redirected domain
            # as having no SPF strict even when the redirect target
            # does end in -all. Follow up to 3 chain hops to prevent
            # loops, mark each redirect target for SPF fingerprint
            # scanning too.
            if "redirect=" in txt_lower and not txt_lower.rstrip().endswith(("-all", "~all")):
                await _follow_spf_redirect(ctx, txt_lower, depth=0, max_depth=3)

    # SPF complexity summary — runs once per domain after the TXT
    # record scan, regardless of how many SPF variants the loop saw.
    # This block belongs to _detect_txt, not _follow_spf_redirect.
    if ctx.spf_include_count >= 8:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes (large)")
    elif ctx.spf_include_count >= 4:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes")


async def _follow_spf_redirect(
    ctx: _DetectionCtx, spf_text: str, depth: int, max_depth: int
) -> None:
    """Follow SPF redirect= chain up to ``max_depth`` hops.

    When a domain's SPF is ``v=spf1 redirect=<other>``, we need to
    query the redirected domain's SPF to know whether the chain
    ultimately ends in ``-all`` (strict) or ``~all`` (softfail).
    Without following the chain, recon scores 0 on SPF strict for
    every domain that uses the redirect pattern — and that pattern
    is extremely common in higher-ed and enterprise deployments
    where SPF is managed as a single zone across many brand
    domains.

    Any failure (network error, parse error, missing pattern)
    silently no-ops — this is an enrichment path, not a critical
    detection, and it must never break the parent DNS source.
    """
    if depth >= max_depth:
        return
    try:
        import re
        match = re.search(r"redirect=([^\s]+)", spf_text)
        if not match:
            return
        target = match.group(1).strip().rstrip(".")
        if not target or "." not in target:
            return
        target_records = await _safe_resolve(target, "TXT")
        patterns = get_spf_patterns()
        for record in target_records:
            rec_lower = record.strip().lower()
            if not rec_lower.startswith("v=spf1"):
                continue
            # Run the same fingerprint pass on the target's SPF
            for det in patterns:
                if det.pattern.lower() in rec_lower:
                    ctx.add(det.name, det.slug)
                    ctx.record_fp_match(det.slug, "spf", det.pattern)
            # Propagate the policy qualifier from the redirect
            # target up to the origin — if _spf.mail.umich.edu
            # ends in -all, then umich.edu's SPF effectively ends
            # in -all via the redirect, and we credit the origin
            # with SPF strict.
            if rec_lower.rstrip().endswith("-all"):
                ctx.services.add(SVC_SPF_STRICT)
                return
            if rec_lower.rstrip().endswith("~all"):
                ctx.services.add(SVC_SPF_SOFTFAIL)
                return
            # Chain continues: recurse one more hop.
            if "redirect=" in rec_lower:
                await _follow_spf_redirect(ctx, rec_lower, depth + 1, max_depth)
                return
    except Exception as exc:
        logger.debug("SPF redirect chain follow failed: %s", exc)


async def _detect_mx(ctx: _DetectionCtx, domain: str) -> None:
    """Scan MX records for email provider and gateway detection.

    Passes source_type="MX" and the raw record so an EvidenceRecord is
    created — the email topology computation in merger.py filters evidence
    by source_type == "MX" to distinguish true primary providers (direct
    MX) from secondary residue (DKIM/TXT/identity endpoint).

    v0.9.3 refinement: emit a generic EvidenceRecord for EVERY MX host
    found, whether or not a fingerprint pattern matched. This lets
    downstream code distinguish "no MX records at all" (domain has no
    email) from "MX records exist but the host isn't in our fingerprint
    set" (domain has custom / self-hosted email like Apache's own mail
    servers). Previously, apache.org looked identical to
    balcaninnovations.com from the evidence perspective — both had
    zero MX evidence records even though apache.org has three real
    MX hosts. The "generic MX evidence" carries an empty slug so it
    doesn't pollute the detected_slugs set.
    """
    mx_records = await _safe_resolve(domain, "MX")
    ctx.raw_dns_records.setdefault("MX", []).extend(mx_records)

    for mx in mx_records:
        mx_lower = mx.lower()
        matched = False
        for det in get_mx_patterns():
            if det.pattern in mx_lower:
                ctx.add(det.name, det.slug, source_type="MX", raw_value=mx)
                ctx.record_fp_match(det.slug, "mx", det.pattern)
                matched = True
                break
        if not matched:
            # Emit a generic MX evidence record so downstream code can
            # tell that MX records exist, even though this host doesn't
            # match any provider fingerprint. Empty slug keeps it out
            # of the slug set; source_type="MX" is what the email
            # topology + has_mx_records check looks at.
            ctx.evidence.append(
                EvidenceRecord(
                    source_type="MX",
                    raw_value=mx,
                    rule_name="Custom MX host",
                    slug="",
                )
            )


async def _detect_m365_cnames(ctx: _DetectionCtx, domain: str) -> None:
    """Check M365-specific CNAME and SRV records (autodiscover, teams, intune, msoid).

    Also checks _sipfederationtls._tcp SRV for Teams/Skype federation — a strong
    M365 signal that persists even when CNAME records have been cleaned up.

    Sub-queries within this detector are gathered concurrently since they
    are independent of each other.
    """
    # Fire all CNAME/SRV queries concurrently
    autodiscover_task = _safe_resolve(f"autodiscover.{domain}", "CNAME")
    lyncdiscover_task = _safe_resolve(f"lyncdiscover.{domain}", "CNAME")
    sip_task = _safe_resolve(f"sip.{domain}", "CNAME")
    srv_task = _safe_resolve(f"_sipfederationtls._tcp.{domain}", "SRV")
    enterprise_task = _safe_resolve(f"enterpriseregistration.{domain}", "CNAME")
    msoid_task = _safe_resolve(f"msoid.{domain}", "CNAME")

    (
        autodiscover_results,
        lyncdiscover_results,
        sip_results,
        srv_results,
        enterprise_results,
        msoid_results,
    ) = await asyncio.gather(
        autodiscover_task,
        lyncdiscover_task,
        sip_task,
        srv_task,
        enterprise_task,
        msoid_task,
    )

    for cname in autodiscover_results:
        cl = cname.lower()
        if "outlook.com" in cl:
            ctx.add(SVC_EXCHANGE_AUTODISCOVER, "microsoft365")
            ctx.m365 = True
        elif cl and not cl.endswith(domain.lower()):
            redirect_domain = cl.split(".", 1)[1] if "." in cl else None
            # Validate: must have at least one dot (real domain, not single-label)
            if redirect_domain and "." in redirect_domain and redirect_domain != domain.lower():
                ctx.related_domains.add(redirect_domain)

    for cname_list in (lyncdiscover_results, sip_results):
        for cname in cname_list:
            cl = cname.lower()
            if "lync.com" in cl or "teams.microsoft.com" in cl:
                ctx.add(SVC_MICROSOFT_TEAMS, "microsoft365")
                ctx.m365 = True

    for srv in srv_results:
        if "lync.com" in srv.lower() or "teams.microsoft.com" in srv.lower():
            ctx.add(SVC_MICROSOFT_TEAMS, "microsoft365")
            ctx.m365 = True

    for cname in enterprise_results:
        cl = cname.lower()
        if "manage.microsoft.com" in cl or "enterpriseregistration.windows.net" in cl:
            ctx.add(SVC_INTUNE_MDM, "microsoft365")
            ctx.m365 = True

    for cname in msoid_results:
        if "microsoftonline.com" in cname.lower():
            ctx.add(SVC_OFFICE_PROPLUS, "microsoft365")
            ctx.m365 = True


# --- Google Workspace CNAME module probing ---

_GWS_MODULE_PREFIXES = ("mail", "calendar", "docs", "drive", "sites", "groups")
_GWS_CNAME_TARGET = "ghs.googlehosted.com"


async def _detect_gws_cnames(ctx: _DetectionCtx, domain: str) -> None:
    """Check Google Workspace module CNAMEs concurrently.

    Administrators frequently create custom CNAMEs for GWS apps that
    resolve to ghs.googlehosted.com. Detecting these reveals which
    specific Workspace modules are actively deployed and branded.
    """
    tasks = [_safe_resolve(f"{prefix}.{domain}", "CNAME") for prefix in _GWS_MODULE_PREFIXES]
    results = await asyncio.gather(*tasks)

    active_modules: list[str] = []
    for prefix, cname_results in zip(_GWS_MODULE_PREFIXES, results, strict=True):
        for cname in cname_results:
            if _GWS_CNAME_TARGET in cname.lower():
                module_name = prefix.capitalize()
                ctx.add(
                    f"Google Workspace: {module_name}",
                    "google-workspace",
                    source_type="CNAME",
                    raw_value=f"{prefix}.{domain} → {cname}",
                )
                active_modules.append(module_name)
                break

    if active_modules:
        ctx.slugs.add("google-workspace-modules")


async def _detect_dkim(ctx: _DetectionCtx, domain: str) -> None:
    """Check DKIM selectors for Exchange Online, Google, and common providers.

    Exchange uses selector1/selector2, Google uses 'google', and many ESPs
    use 's1'/'s2', 'k1', 'default', 'dkim', 'mail', or 'em' selectors.
    We check all common selectors and record which type of DKIM we found.

    Also extracts the onmicrosoft.com domain from Exchange DKIM CNAMEs —
    this reveals the tenant's internal domain name.
    """
    # Common ESP DKIM selectors beyond Exchange/Google.
    # Each tuple is (selector_prefix, cname_hint, service_name, slug).
    # If the CNAME target contains the hint, we attribute it to that service.
    _ESP_SELECTORS: list[tuple[str, str, str, str]] = [
        ("k1", "domainkey.u", "Mailchimp", "mailchimp"),
        ("s1", "domainkey.u", "Mailchimp", "mailchimp"),
        ("em", "sendgrid.net", "SendGrid", "sendgrid"),
        ("s1", "sendgrid.net", "SendGrid", "sendgrid"),
        ("default", "mailgun.org", "Mailgun", "mailgun"),
        ("pm", "dkim.pstmrk.com", "Postmark", "postmark"),
        ("mxvault", "mimecast", "Mimecast", "mimecast"),
    ]

    # Fire Exchange and Google DKIM queries concurrently
    sel1_task = _safe_resolve(f"selector1._domainkey.{domain}", "CNAME")
    sel2_task = _safe_resolve(f"selector2._domainkey.{domain}", "CNAME")
    google_txt_task = _safe_resolve(f"google._domainkey.{domain}", "TXT")
    google_cname_task = _safe_resolve(f"google._domainkey.{domain}", "CNAME")

    # Also fire ESP selector queries concurrently
    esp_tasks = [_safe_resolve(f"{sel}._domainkey.{domain}", "CNAME") for sel, _, _, _ in _ESP_SELECTORS]

    # v0.10.1: generic enterprise DKIM selectors — large enterprises use
    # non-standard selector names. These TXT probes confirm DKIM exists
    # even when we can't attribute it to a specific provider.
    _GENERIC_DKIM_SELECTORS: tuple[str, ...] = ("s2", "dkim", "mail", "k2")
    generic_dkim_tasks = [_safe_resolve(f"{sel}._domainkey.{domain}", "TXT") for sel in _GENERIC_DKIM_SELECTORS]

    all_results = await asyncio.gather(
        sel1_task,
        sel2_task,
        google_txt_task,
        google_cname_task,
        *esp_tasks,
        *generic_dkim_tasks,
    )

    sel1_results = all_results[0]
    sel2_results = all_results[1]
    google_txt_results = all_results[2]
    google_cname_results = all_results[3]
    esp_end = 4 + len(_ESP_SELECTORS)
    esp_results = all_results[4:esp_end]
    generic_dkim_results = all_results[esp_end:]

    # Exchange DKIM selectors
    for selector_results in (sel1_results, sel2_results):
        for cname in selector_results:
            cl = cname.lower()
            if "protection.outlook.com" in cl or "onmicrosoft.com" in cl:
                ctx.add(SVC_DKIM_EXCHANGE, "microsoft365", source_type="DKIM", raw_value=cname)
                ctx.m365 = True
                if "onmicrosoft.com" in cl:
                    parts = cl.split("._domainkey.")
                    if len(parts) == 2 and parts[1].endswith("onmicrosoft.com") and "." in parts[1]:
                        ctx.related_domains.add(parts[1])
                break

    # Google DKIM selector — proves Google handles email signing.
    # Check TXT first; if no TXT match, fall back to CNAME delegation.
    # When found, add both generic DKIM and Google Workspace attribution
    # so the signal fires even when MX points to a gateway (Proofpoint, etc.).
    # source_type="DKIM" is required for the email topology inference in
    # merger.py to recognize this as downstream-provider evidence when MX
    # points to a gateway.
    google_dkim_found = False
    for record in google_txt_results:
        if "v=dkim1" in record.lower():
            ctx.services.add(SVC_DKIM)
            ctx.add(
                "DKIM (Google Workspace)",
                "google-workspace",
                source_type="DKIM",
                raw_value=record,
            )
            google_dkim_found = True
            break
    if not google_dkim_found:
        for cname in google_cname_results:
            if "google.com" in cname.lower():
                ctx.services.add(SVC_DKIM)
                ctx.add(
                    "DKIM (Google Workspace)",
                    "google-workspace",
                    source_type="DKIM",
                    raw_value=cname,
                )
                break

    # ESP DKIM selectors — attribute to specific services when CNAME matches
    for (_, hint, svc_name, slug), cname_results in zip(_ESP_SELECTORS, esp_results, strict=True):
        for cname in cname_results:
            if hint in cname.lower():
                ctx.add(svc_name, slug, source_type="DKIM", raw_value=cname)
                ctx.services.add(SVC_DKIM)
                break

    # v0.10.1: generic enterprise DKIM — if no provider-specific DKIM was
    # found above, check generic selectors for inline TXT DKIM keys. This
    # only confirms DKIM exists (feeds the email security score) without
    # attributing it to a specific provider.
    if SVC_DKIM not in ctx.services:
        for txt_records in generic_dkim_results:
            for record in txt_records:
                if "v=dkim1" in record.lower():
                    ctx.services.add(SVC_DKIM)
                    break
            if SVC_DKIM in ctx.services:
                break


async def _parse_bimi_vmc(ctx: _DetectionCtx, bimi_txt: str) -> None:
    """Fetch VMC PEM from BIMI 'a=' URL and extract corporate identity.

    BIMI TXT records may contain an 'a=' tag pointing to a .pem VMC
    (Verified Mark Certificate). VMCs require strict legal verification,
    so the Subject fields are high-confidence corporate identity data.
    """

    # Extract a= URL from BIMI TXT record
    a_url: str | None = None
    for part in bimi_txt.split(";"):
        cleaned = part.strip()
        if cleaned.lower().startswith("a="):
            candidate = cleaned[2:].strip()
            if candidate.lower().endswith(".pem"):
                a_url = candidate
                break

    if not a_url:
        return

    try:
        async with _http_client(timeout=5.0) as client:
            resp = await client.get(a_url)
            if resp.status_code != 200:
                return
            pem_data = resp.text

        # Parse X.509 certificate Subject
        org = country = state = locality = trademark = None

        # Try using the cryptography library if available (more reliable)
        try:
            from cryptography import x509

            cert_obj = x509.load_pem_x509_certificate(pem_data.encode())
            subject = cert_obj.subject
            for attr in subject:
                oid_name = attr.oid.dotted_string
                val = str(attr.value)
                if oid_name == "2.5.4.10":  # Organization
                    org = val
                elif oid_name == "2.5.4.6":  # Country
                    country = val
                elif oid_name == "2.5.4.8":  # State
                    state = val
                elif oid_name == "2.5.4.7":  # Locality
                    locality = val
        except ImportError:
            # Fallback: regex parse the PEM for common Subject fields
            import re as _re

            for line in pem_data.splitlines():
                line_stripped = line.strip()
                # Look for Subject line in text representation
                if "O=" in line_stripped or "O =" in line_stripped:
                    m = _re.search(r"O\s*=\s*([^,/]+)", line_stripped)
                    if m:
                        org = m.group(1).strip()
                if "C=" in line_stripped:
                    m = _re.search(r"C\s*=\s*([^,/]+)", line_stripped)
                    if m:
                        country = m.group(1).strip()

        if org:
            ctx.bimi_identity = BIMIIdentity(
                organization=org,
                country=country,
                state=state,
                locality=locality,
                trademark=trademark,
            )
            ctx.slugs.add("bimi-vmc")
            ctx.evidence.append(
                EvidenceRecord(
                    source_type="HTTP",
                    raw_value=f"VMC Organization={org}",
                    rule_name="BIMI VMC",
                    slug="bimi-vmc",
                )
            )

    except Exception as exc:
        logger.debug("BIMI VMC parsing failed: %s", exc)


async def _fetch_mta_sts_policy(domain: str) -> str | None:
    """Fetch MTA-STS policy mode from the well-known endpoint.

    Returns the policy mode ("enforce", "testing", "none") or None
    if the policy file is unreachable or malformed.
    """
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        async with _http_client(timeout=5.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    stripped = line.strip().lower()
                    if stripped.startswith("mode:"):
                        mode = stripped.split(":", 1)[1].strip()
                        if mode in ("enforce", "testing", "none"):
                            return mode
    except Exception as exc:
        logger.debug("MTA-STS policy fetch failed for %s: %s", domain, exc)
    return None


_RUA_MAILTO_RE = re.compile(r"rua\s*=\s*mailto:([^;,\s]+)", re.IGNORECASE)


def _extract_dmarc_rua(ctx: _DetectionCtx, dmarc_record: str) -> None:
    """Extract rua=mailto: addresses and match vendor domains against fingerprints."""
    from recon_tool.fingerprints import get_dmarc_rua_patterns

    matches = _RUA_MAILTO_RE.findall(dmarc_record)
    rua_patterns = get_dmarc_rua_patterns()

    for addr in matches:
        # Extract domain portion from email address
        if "@" not in addr:
            continue
        rua_domain = addr.split("@", 1)[1].lower().rstrip(".")

        # Match against dmarc_rua fingerprint patterns
        for det in rua_patterns:
            if det.pattern.lower() in rua_domain:
                ctx.add(
                    det.name,
                    det.slug,
                    source_type="DMARC_RUA",
                    raw_value=f"rua=mailto:{addr}",
                )
                ctx.record_fp_match(det.slug, "dmarc_rua", det.pattern)
                break  # first match wins per RUA address


async def _detect_email_security(ctx: _DetectionCtx, domain: str) -> None:
    """Check DMARC, BIMI, MTA-STS, and TLS-RPT records concurrently."""
    dmarc_task = _safe_resolve(f"_dmarc.{domain}", "TXT")
    bimi_task = _safe_resolve(f"default._bimi.{domain}", "TXT")
    mta_sts_task = _safe_resolve(f"_mta-sts.{domain}", "TXT")
    tls_rpt_task = _safe_resolve(f"_smtp._tls.{domain}", "TXT")

    dmarc_results, bimi_results, mta_sts_results, tls_rpt_results = await asyncio.gather(
        dmarc_task,
        bimi_task,
        mta_sts_task,
        tls_rpt_task,
    )

    for txt in dmarc_results:
        if txt.lower().startswith("v=dmarc1"):
            ctx.services.add(SVC_DMARC)
            for part in txt.split(";"):
                cleaned = part.strip().lower()
                if cleaned.startswith("p="):
                    ctx.dmarc_policy = cleaned[2:].strip()
                elif cleaned.startswith("pct="):
                    raw_pct = cleaned[4:].strip()
                    try:
                        pct_val = int(raw_pct)
                        if 0 <= pct_val <= 100:
                            ctx.dmarc_pct = pct_val
                        else:
                            logger.warning(
                                "DMARC pct= value %d out of range for %s — ignored",
                                pct_val,
                                domain,
                            )
                    except ValueError:
                        logger.warning(
                            "DMARC pct= value %r is not a valid integer for %s — ignored",
                            raw_pct,
                            domain,
                        )

            # Extract rua= mailto domains and match against fingerprints
            _extract_dmarc_rua(ctx, txt)

    for txt in bimi_results:
        if "v=bimi1" in txt.lower():
            ctx.services.add(SVC_BIMI)
            # Attempt VMC corporate identity extraction
            await _parse_bimi_vmc(ctx, txt)

    mta_sts_detected = False
    for txt in mta_sts_results:
        if "v=stsv1" in txt.lower():
            ctx.services.add(SVC_MTA_STS)
            mta_sts_detected = True

    # Fetch MTA-STS policy file if TXT record found
    if mta_sts_detected:
        policy_mode = await _fetch_mta_sts_policy(domain)
        if policy_mode:
            ctx.mta_sts_mode = policy_mode
            if policy_mode == "enforce":
                ctx.slugs.add("mta-sts-enforce")

    # TLS-RPT detection
    for txt in tls_rpt_results:
        if "v=tlsrptv1" in txt.lower():
            ctx.add("TLS-RPT", "tls-rpt", source_type="TXT", raw_value=txt)
            break


async def _detect_ns(ctx: _DetectionCtx, domain: str) -> None:
    """Scan NS records for DNS provider / infrastructure detection."""
    ns_records = await _safe_resolve(domain, "NS")
    ctx.raw_dns_records.setdefault("NS", []).extend(ns_records)

    for ns in ns_records:
        ns_lower = ns.lower()
        for det in get_ns_patterns():
            if det.pattern in ns_lower:
                ctx.add(det.name, det.slug)
                ctx.record_fp_match(det.slug, "ns", det.pattern)
                break


async def _detect_cname_infra(ctx: _DetectionCtx, domain: str) -> None:
    """Check www/root CNAME for CDN, hosting, and SaaS infrastructure."""
    www_task = _safe_resolve(f"www.{domain}", "CNAME")
    root_task = _safe_resolve(domain, "CNAME")

    www_results, root_results = await asyncio.gather(www_task, root_task)

    all_cnames = www_results + root_results
    if all_cnames:
        ctx.raw_dns_records.setdefault("CNAME", []).extend(all_cnames)

    for cname_list in (www_results, root_results):
        for cname in cname_list:
            cl = cname.lower()
            for det in get_cname_patterns():
                if det.pattern in cl:
                    ctx.add(det.name, det.slug)
                    ctx.record_fp_match(det.slug, "cname", det.pattern)
                    break


async def _detect_domain_connect(ctx: _DetectionCtx, domain: str) -> None:
    """Check _domainconnect CNAME for domain management provider."""
    for cname in await _safe_resolve(f"_domainconnect.{domain}", "CNAME"):
        cl = cname.lower()
        if "azure" in cl:
            ctx.services.add("Domain Connect (Azure)")
        elif "godaddy" in cl or "domaincontrol" in cl:
            ctx.services.add("Domain Connect (GoDaddy)")


# v0.9.3: hosting provider detection from A record → reverse DNS
# (PTR) → hostname pattern match. This fills a major detection gap:
# on web-only domains with minimal DNS signal (a single A record
# and a couple of NS entries), the A record IS the primary signal
# and we were completely ignoring it. Public cloud providers
# publish predictable PTR records for their IP ranges that encode
# both the provider and (for AWS / Azure / GCP) the region.
#
# Pattern table — checked in order, first match wins. Each entry is
# a substring matched against the PTR hostname's lowercased form.
# The region extractor is an optional regex that runs against the
# full PTR hostname to pull a region token; when present and
# matched, the region is appended to the service name.
_HOSTING_PTR_PATTERNS: tuple[tuple[str, str, str, str | None], ...] = (
    # (ptr substring, service name, slug, region regex or None)
    ("compute.amazonaws.com", "AWS EC2", "aws-ec2", r"[a-z]{2}-[a-z]+-\d+"),
    ("ec2.internal", "AWS EC2", "aws-ec2", None),
    ("elb.amazonaws.com", "AWS ELB", "aws-elb", r"[a-z]{2}-[a-z]+-\d+"),
    ("elb.amazonaws.com.cn", "AWS ELB (China)", "aws-elb", None),
    ("amazonaws.com", "AWS", "aws-compute", None),
    ("cloudapp.azure.com", "Azure VM", "azure-vm", r"(?:eastus|westus|centralus|northeurope|westeurope|"
        r"eastasia|southeastasia|japaneast|japanwest|brazilsouth|australiaeast|canadacentral)[a-z0-9]*"),
    ("cloudapp.net", "Azure VM (legacy)", "azure-vm", None),
    ("bc.googleusercontent.com", "GCP Compute Engine", "gcp-compute", None),
    ("googleusercontent.com", "GCP Compute Engine", "gcp-compute", None),
    ("linode.com", "Linode", "linode", None),
    ("linodeusercontent.com", "Linode", "linode", None),
    ("digitalocean.com", "DigitalOcean", "digitalocean", None),
    ("droplets.digitalocean.com", "DigitalOcean", "digitalocean", None),
    ("hetzner.com", "Hetzner", "hetzner", None),
    ("your-server.de", "Hetzner", "hetzner", None),
    ("ovh.net", "OVH", "ovh", None),
    ("ovh.ca", "OVH", "ovh", None),
    ("vultr.com", "Vultr", "vultr", None),
    ("vultrusercontent.com", "Vultr", "vultr", None),
    ("cloudflare.com", "Cloudflare", "cloudflare", None),
    ("fastly.net", "Fastly", "fastly", None),
    ("cdn77.com", "CDN77", "cdn77", None),
    ("bunnycdn.com", "Bunny CDN", "bunnycdn", None),
    ("akamaitechnologies.com", "Akamai", "akamai", None),
    ("akamaiedge.net", "Akamai", "akamai", None),
    ("edgekey.net", "Akamai", "akamai", None),
    ("edgesuite.net", "Akamai", "akamai", None),
)


async def _detect_hosting_from_a_record(ctx: _DetectionCtx, domain: str) -> None:
    """Reverse-resolve the apex A record and match the PTR hostname
    against known cloud-provider patterns.

    On web-only domains this is the primary detection signal — the
    domain may have no MX, no DMARC, no TXT verification tokens,
    but the A record still points somewhere and the hosting
    provider's PTR tells us where. All work is passive DNS:
    resolve A, reverse-lookup the IP, pattern-match the PTR.
    No active probing of the hosting infrastructure.

    The function tolerates every failure mode (no A record,
    PTR missing, PTR matches no known pattern) and simply exits
    without adding a service. Never raises.
    """
    import ipaddress
    import re

    a_records = await _safe_resolve(domain, "A")
    if not a_records:
        return
    ctx.raw_dns_records.setdefault("A", []).extend(a_records)

    # Use the first IP only — multi-A domains are usually
    # load-balanced within the same provider, so one PTR is enough.
    try:
        ip = ipaddress.ip_address(a_records[0])
    except (ValueError, TypeError):
        return

    # Build PTR query: reverse octets + .in-addr.arpa (IPv4) or
    # reverse nibbles + .ip6.arpa (IPv6). dns.reversename handles
    # both, but import locally to keep the hot path clean.
    try:
        import dns.reversename  # pyright: ignore[reportMissingTypeStubs]
        ptr_name = dns.reversename.from_address(str(ip))
        ptr_results = await _safe_resolve(str(ptr_name), "PTR")
    except Exception:
        return
    if not ptr_results:
        return

    ptr_lower = ptr_results[0].rstrip(".").lower()
    for substring, name, slug, region_regex in _HOSTING_PTR_PATTERNS:
        if substring not in ptr_lower:
            continue
        # The display name is always the bare provider. The region
        # (when extractable) goes into the raw_value of the
        # evidence record so --explain and --json still carry it,
        # but the default panel stays compact — it'd get noisy if
        # every Cloud row grew a free-form region parenthetical.
        region_note = ""
        if region_regex:
            match = re.search(region_regex, ptr_lower)
            if match:
                region_note = f" ({match.group(0)})"
        ctx.add(
            name,
            slug,
            source_type="A",
            raw_value=f"{ip} -> {ptr_lower}{region_note}",
        )
        ctx.record_fp_match(slug, "a_ptr", substring)
        break


async def _detect_subdomain_txt(ctx: _DetectionCtx, domain: str) -> None:
    """Query TXT records at specific subdomains for vendor-specific verification.

    Some vendors (Slack Enterprise Grid, GitLab) place their verification
    tokens at a designated subdomain rather than the zone apex. The pattern
    field in fingerprints.yaml uses 'subdomain:regex' format, e.g.
    '_slack-challenge:.' means query _slack-challenge.domain.com for any TXT value.

    All subdomain queries are fired concurrently for throughput.
    """
    patterns = get_subdomain_txt_patterns()
    if not patterns:
        return

    # Parse patterns and build query tasks
    parsed: list[tuple[str, str, str, str, str]] = []  # (subdomain, regex, name, slug, original_pattern)
    for det in patterns:
        if ":" not in det.pattern:
            continue
        subdomain, regex = det.pattern.split(":", 1)
        parsed.append((subdomain, regex, det.name, det.slug, det.pattern))

    if not parsed:
        return

    # Fire all subdomain TXT queries concurrently
    tasks = [_safe_resolve(f"{subdomain}.{domain}", "TXT") for subdomain, _, _, _, _ in parsed]
    results = await asyncio.gather(*tasks)

    for (_, regex, name, slug, original_pattern), txt_records in zip(parsed, results, strict=True):
        for txt in txt_records:
            try:
                if re.search(regex, txt, re.IGNORECASE):
                    ctx.add(name, slug)
                    ctx.record_fp_match(slug, "subdomain_txt", original_pattern)
                    break
            except re.error:
                continue


async def _detect_caa(ctx: _DetectionCtx, domain: str) -> None:
    """Query CAA records to identify certificate authority and PKI strategy."""
    for caa in await _safe_resolve(domain, "CAA"):
        caa_lower = caa.lower()
        for det in get_caa_patterns():
            if det.pattern in caa_lower:
                ctx.add(det.name, det.slug)
                ctx.record_fp_match(det.slug, "caa", det.pattern)
                break


async def _detect_srv(ctx: _DetectionCtx, domain: str) -> None:
    """Check common SRV records for collaboration and identity services.

    SRV records reveal services that don't leave TXT/SPF/MX footprints.
    Only checks a focused set of high-signal SRV names — not brute-forcing.
    """
    # (srv_name, target_hint, service_name, slug)
    # NOTE: _sip._tls and _sipfederationtls._tcp SRV records pointing to
    # lync.com are legacy Skype for Business DNS entries. Microsoft retired
    # Skype for Business Online (July 2021) but recommends keeping these
    # records for Teams interop. We label them as Microsoft Teams since
    # that's what they serve in 2024+. The display name matches the CNAME-
    # based detection in _detect_m365_cnames so they deduplicate naturally.
    _SRV_CHECKS: list[tuple[str, str | None, str, str]] = [
        ("_sip._tls", "lync.com", SVC_MICROSOFT_TEAMS, "microsoft365"),
        ("_sipfederationtls._tcp", "lync.com", SVC_MICROSOFT_TEAMS, "microsoft365"),
        ("_xmpp-server._tcp", None, "XMPP (Jabber)", ""),
        ("_caldavs._tcp", None, "CalDAV", ""),
        ("_carddavs._tcp", None, "CardDAV", ""),
    ]

    tasks = [_safe_resolve(f"{srv}.{domain}", "SRV") for srv, _, _, _ in _SRV_CHECKS]
    results = await asyncio.gather(*tasks)

    for (_, hint, svc_name, slug), srv_records in zip(_SRV_CHECKS, results, strict=True):
        for record in srv_records:
            # SRV records with target "." mean "service not available" — skip
            if record.strip().rstrip(".") == "":
                continue
            if hint is None or hint in record.lower():
                ctx.add(svc_name, slug if slug else None)
                break


# ── Certificate Transparency (fallback chain) ──────────────────────────


async def _detect_cert_intel(ctx: _DetectionCtx, domain: str) -> None:
    """Try CrtshProvider, fall back to CertSpotterProvider, fall back to CT cache.

    On first successful provider, record the provider name and subdomain
    count on the context so the panel can surface which provider actually
    ran ("crt.sh (142 subdomains)" vs "certspotter (8 subdomains)"). This
    makes enrichment asymmetry between runs visible instead of silent.

    When all live providers fail, the per-domain CT cache serves as a
    final fallback — returning the last known subdomain set with an
    explicit cache age annotation so the panel can show "from local
    cache, N days old".
    """
    from recon_tool.ct_cache import ct_cache_get, ct_cache_put

    providers: list[CertIntelProvider] = [CrtshProvider(), CertSpotterProvider()]
    for provider in providers:
        try:
            subdomains, cert_summary = await provider.query(domain)
            ctx.related_domains.update(subdomains)
            if cert_summary is not None:
                ctx.cert_summary = cert_summary
            ctx.ct_provider_used = provider.name
            ctx.ct_subdomain_count = len(subdomains)
            logger.debug("cert intel from %s for %s: %d subdomains", provider.name, domain, len(subdomains))
            # Cache successful result for future fallback
            ct_cache_put(domain, subdomains, cert_summary, provider.name)
            return
        except Exception as exc:
            logger.debug("cert intel provider %s failed for %s: %s", provider.name, domain, exc)
            ctx.degraded_sources.add(provider.name)

    # All live providers failed — try per-domain CT cache as final fallback
    cached = ct_cache_get(domain)
    if cached is not None and cached.subdomains:
        ctx.related_domains.update(cached.subdomains)
        if cached.cert_summary is not None:
            ctx.cert_summary = cached.cert_summary
        ctx.ct_provider_used = f"{cached.provider_used} (cached)"
        ctx.ct_subdomain_count = len(cached.subdomains)
        ctx.ct_cache_age_days = cached.age_days
        logger.debug(
            "cert intel from CT cache for %s: %d subdomains, %d days old",
            domain,
            len(cached.subdomains),
            cached.age_days,
        )


# ── Common subdomain probing ───────────────────────────────────────────

# High-signal subdomain prefixes that commonly CNAME to SaaS providers.
# These are probed directly via DNS — no external service dependency.
# Kept intentionally focused: each prefix has a high probability of
# revealing a SaaS CNAME (auth→Okta, shop→Shopify, status→Statuspage, etc.).
_COMMON_SUBDOMAIN_PREFIXES = (
    # Identity / SSO
    "auth",
    "login",
    "sso",
    "id",
    "identity",
    "secure-auth",
    "accounts",
    # Commerce / customer-facing
    "shop",
    "store",
    "checkout",
    # App / API
    "app",
    "api",
    "portal",
    "dashboard",
    "admin",
    # Support
    "support",
    "help",
    "status",
    "docs",
    "kb",
    # Marketing / email
    "click.em",
    "image.em",
    "view.em",
    "em",
    "email",
    "go",
    "info",
    "pages",
    # Content / CDN
    "cdn",
    "assets",
    "static",
    "media",
    "images",
    # Blog / marketing sites
    "blog",
    "news",
    "events",
    "careers",
    # Dev / staging
    "staging",
    "stage",
    "dev",
    "sandbox",
    "preview",
    "uat",
    "stage-auth",
)


async def _detect_common_subdomains(ctx: _DetectionCtx, domain: str) -> None:
    """Probe common subdomain prefixes for CNAME targets that reveal SaaS usage.

    This is the fallback/complement to crt.sh — works even when crt.sh is
    down, and catches high-signal subdomains that may not appear in CT logs
    (e.g., internal auth endpoints with private certs).

    Only checks CNAME records (not A/AAAA) — we want to discover what service
    the subdomain points to, not just that it exists. Subdomains that resolve
    to a CNAME are added to ctx.related_domains for enrichment.
    """

    async def _probe(prefix: str) -> str | None:
        fqdn = f"{prefix}.{domain}"
        results = await _safe_resolve(fqdn, "CNAME")
        if results:
            return fqdn
        return None

    probes = await asyncio.gather(*(_probe(p) for p in _COMMON_SUBDOMAIN_PREFIXES))

    found = [fqdn for fqdn in probes if fqdn is not None]
    if found:
        logger.debug("Common subdomain probing found %d for %s: %s", len(found), domain, ", ".join(found))
        ctx.related_domains.update(found)


# v0.9.3: identity-hub subdomain prefixes that are strong SSO / IdP
# signals when they exist. These are probed separately from the
# generic common-subdomain list because:
#
#   1. They're specifically about detecting federated identity, a
#      single high-value signal rather than arbitrary SaaS noise.
#   2. They resolve via A records, not CNAMEs (Shibboleth IdPs are
#      often self-hosted on a university's own infrastructure with
#      a direct A record, never a CNAME to a vendor). The generic
#      common-subdomain probe only checks CNAMEs and misses these.
#   3. The detection emits a dedicated insight + slug so downstream
#      code can reason about "this org uses federated SSO" without
#      having to infer it from related_domains.
_IDP_SUBDOMAIN_PREFIXES: tuple[str, ...] = (
    # Shibboleth / SAML family
    "shibboleth",
    "weblogin",
    "idp",
    "wayf",
    "sp",
    "sso",
    "saml",
    "federation",
    # Vendor IdPs
    "okta",
    "adfs",
    # CAS (Central Authentication Service — common in higher ed)
    "cas",
    # University-specific SSO names (Raven=Cambridge, WebAuth=Oxford,
    # HarvardKey=Harvard, Kerberos=MIT-style). These are visible as
    # subdomains on many of their academic customers via
    # CNAME-delegation from the parent university's zone.
    "raven",
    "webauth",
    "harvardkey",
    "kerberos",
)


async def _detect_exchange_onprem(ctx: _DetectionCtx, domain: str) -> None:
    """Detect on-prem / hybrid Microsoft Exchange deployments via
    OWA subdomain probing.

    When ``owa.<domain>``, ``mail.<domain>``, or similar Exchange-
    specific endpoints resolve, it's a strong signal that the org
    runs on-prem / hybrid Exchange (not Exchange Online). These
    orgs often self-host mail while still having an Entra ID /
    Azure AD tenant for identity — a very common higher-ed and
    institutional-nonprofit pattern.

    Without this detection, a domain with custom MX records and an
    OWA endpoint looks sparse to recon even though the actual
    answer ("runs Exchange on-prem") is observable from DNS alone.
    This fills that gap.

    Accepts A or CNAME resolution — on-prem Exchange typically
    resolves via A to an internal-facing IP or via CNAME to a
    load-balanced frontend. Checks a narrow set of strictly-
    Exchange subdomain prefixes to avoid false positives on
    generic `mail.` hostnames that could be anything.
    """
    # Only these prefixes are specifically Exchange-related. We
    # deliberately exclude generic "mail" since many orgs point
    # mail. at a CDN, a web frontend, or a third-party mail
    # provider. The prefixes here only mean Exchange.
    exchange_prefixes = (
        "owa",           # Outlook Web Access
        "outlook",       # Outlook anywhere
        "exchange",      # Named Exchange endpoint
        "mail-ex",       # Less common but unambiguous
        "webmail",       # Often Exchange but could be Horde / Roundcube
        "autodiscover",  # Exchange autodiscover — standard Exchange
                         # protocol, returned as CNAME for M365
                         # (already detected) or as A for on-prem.
    )

    # Two-part probe: (a) A-record only for prefixes that should
    # only match on-prem (autodiscover). On M365 domains
    # autodiscover.<apex> is a CNAME to autodiscover.outlook.com
    # — that's Exchange Online, not on-prem, and is already
    # detected by _detect_m365_cnames. We deliberately skip the
    # CNAME check for autodiscover so M365 domains don't false-
    # positive into the on-prem detector. (b) A-or-CNAME for
    # owa / outlook / exchange / mail-ex / webmail — those
    # prefixes are used by both deployments but any of them
    # existing is a strong Exchange signal regardless.
    a_only_prefixes = {"autodiscover"}

    async def _probe(prefix: str) -> str | None:
        fqdn = f"{prefix}.{domain}"
        a_results = await _safe_resolve(fqdn, "A")
        if a_results:
            return fqdn
        if prefix in a_only_prefixes:
            return None
        cname_results = await _safe_resolve(fqdn, "CNAME")
        if cname_results:
            return fqdn
        return None

    probes = await asyncio.gather(*(_probe(p) for p in exchange_prefixes))
    found = [fqdn for fqdn in probes if fqdn is not None]
    if not found:
        return

    # The strongest signals are owa / outlook / exchange /
    # autodiscover (A-only) — any of them means on-prem or
    # hybrid Exchange. `webmail` alone is too weak (could be
    # Roundcube / Horde / SquirrelMail) — skip when only it
    # is present.
    found_prefixes = {f.split(".", 1)[0] for f in found}
    strong_signals = {"owa", "outlook", "exchange", "mail-ex", "autodiscover"}
    has_strong_signal = bool(found_prefixes & strong_signals)
    if not has_strong_signal:
        return

    ctx.add(
        "Exchange Server (on-prem / hybrid)",
        "exchange-onprem",
        source_type="A",
        raw_value=", ".join(sorted(found)),
    )
    ctx.related_domains.update(found)


async def _detect_idp_hub(ctx: _DetectionCtx, domain: str) -> None:
    """Probe common identity-hub subdomain prefixes.

    Unlike the generic common-subdomain probe, this one accepts A
    records (not just CNAME) because self-hosted Shibboleth / ADFS
    IdPs typically point at an internal server via A, not via a
    CNAME to a SaaS vendor. When any of these subdomains resolves,
    it's a strong passive signal that the org runs federated SSO.

    The result is emitted as a ``federated-sso-hub`` slug and
    surfaces as an insight line via a new generator in
    ``insights.py``.
    """

    async def _probe(prefix: str) -> str | None:
        fqdn = f"{prefix}.{domain}"
        # Try A first (self-hosted IdPs), then CNAME (SaaS vendors)
        a_results = await _safe_resolve(fqdn, "A")
        if a_results:
            return fqdn
        cname_results = await _safe_resolve(fqdn, "CNAME")
        if cname_results:
            return fqdn
        return None

    probes = await asyncio.gather(*(_probe(p) for p in _IDP_SUBDOMAIN_PREFIXES))
    found = [fqdn for fqdn in probes if fqdn is not None]
    if not found:
        return

    ctx.related_domains.update(found)
    # Classify: shibboleth / idp / wayf / sp are Shibboleth / SAML
    # family; okta is the Okta SaaS IdP; adfs is Microsoft.
    # v0.9.3: emit the service name using the same friendly form
    # that _SLUG_DISPLAY_OVERRIDES maps the slug to, so pass 1 and
    # pass 2 of the categorizer agree on the display name and
    # don't produce a duplicate entry in the "Other" row.
    found_prefixes = {f.split(".", 1)[0] for f in found}
    if "okta" in found_prefixes:
        service_name = "Okta SSO hub"
        slug = "okta-sso-hub"
    elif "adfs" in found_prefixes:
        service_name = "ADFS SSO hub"
        slug = "adfs-sso-hub"
    else:
        # Generic SSO hub — could be Entra ID, Okta, Shibboleth, CAS, or
        # anything else. A DNS A record can't distinguish the product.
        service_name = "SSO hub"
        slug = "federated-sso-hub"
    ctx.add(
        service_name,
        slug,
        source_type="A",
        raw_value=", ".join(sorted(found)),
    )


# ── Public lightweight lookup for subdomain enrichment ─────────────────


async def lightweight_subdomain_lookup(subdomain: str) -> SourceResult:
    """Check only CNAME and TXT records for a subdomain — skip MX/NS/DKIM/SRV/crt.sh.

    Public API for the resolver's two-tier enrichment pipeline. Subdomains
    discovered via crt.sh or common-prefix probing don't need full DNS
    fingerprinting — CNAME and TXT are the high-signal record types.
    """
    ctx = _DetectionCtx()
    try:
        await asyncio.gather(
            _detect_cname_infra(ctx, subdomain),
            _detect_txt(ctx, subdomain),
        )
    except Exception as exc:
        return SourceResult(source_name="dns_records", error=str(exc))
    return SourceResult(
        source_name="dns_records",
        detected_services=tuple(sorted(ctx.services)),
        detected_slugs=tuple(sorted(ctx.slugs)),
    )


# ── Main source class ──────────────────────────────────────────────────


class DNSSource:
    """Lookup source: DNS records for domain intelligence and tech stack fingerprinting."""

    @property
    def name(self) -> str:
        return "dns_records"

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        """Query DNS records to detect services and fingerprint tech stack.

        All sub-detectors run concurrently via asyncio.gather for maximum
        throughput. A single domain lookup fires ~15-20 DNS queries in parallel
        instead of sequentially.
        """
        try:
            ctx = await self._detect_services(domain)
        except Exception as exc:
            return SourceResult(
                source_name="dns_records",
                error=f"DNS error for {domain}: {exc}",
            )

        if ctx.services:
            return SourceResult(
                source_name="dns_records",
                m365_detected=ctx.m365,
                detected_services=tuple(sorted(ctx.services)),
                detected_slugs=tuple(sorted(ctx.slugs)),
                dmarc_policy=ctx.dmarc_policy,
                related_domains=tuple(sorted(ctx.related_domains)),
                degraded_sources=tuple(sorted(ctx.degraded_sources)),
                cert_summary=ctx.cert_summary,
                evidence=tuple(ctx.evidence),
                bimi_identity=ctx.bimi_identity,
                site_verification_tokens=tuple(sorted(ctx.site_verification_tokens)),
                mta_sts_mode=ctx.mta_sts_mode,
                dmarc_pct=ctx.dmarc_pct,
                ct_provider_used=ctx.ct_provider_used,
                ct_subdomain_count=ctx.ct_subdomain_count,
                ct_cache_age_days=ctx.ct_cache_age_days,
                raw_dns_records=tuple(
                    (rtype, val) for rtype, vals in sorted(ctx.raw_dns_records.items()) for val in vals
                ),
            )

        return SourceResult(
            source_name="dns_records",
            m365_detected=False,
            dmarc_policy=ctx.dmarc_policy,
            related_domains=tuple(sorted(ctx.related_domains)),
            degraded_sources=tuple(sorted(ctx.degraded_sources)),
            cert_summary=ctx.cert_summary,
            evidence=tuple(ctx.evidence),
            bimi_identity=ctx.bimi_identity,
            site_verification_tokens=tuple(sorted(ctx.site_verification_tokens)),
            mta_sts_mode=ctx.mta_sts_mode,
            dmarc_pct=ctx.dmarc_pct,
            ct_provider_used=ctx.ct_provider_used,
            ct_subdomain_count=ctx.ct_subdomain_count,
            ct_cache_age_days=ctx.ct_cache_age_days,
            raw_dns_records=tuple((rtype, val) for rtype, vals in sorted(ctx.raw_dns_records.items()) for val in vals),
        )

    @staticmethod
    async def _detect_services(domain: str) -> _DetectionCtx:
        """Async service detection — runs all sub-detectors concurrently.

        Each sub-detector handles one DNS record type and writes results
        into the shared _DetectionCtx. Since all coroutines run on the
        same event loop (no threads), there are no race conditions on ctx.
        """
        ctx = _DetectionCtx()

        # Run all independent sub-detectors concurrently.
        # Each one does its own DNS queries internally (also concurrent).
        await asyncio.gather(
            _detect_txt(ctx, domain),
            _detect_mx(ctx, domain),
            _detect_m365_cnames(ctx, domain),
            _detect_gws_cnames(ctx, domain),
            _detect_dkim(ctx, domain),
            _detect_email_security(ctx, domain),
            _detect_ns(ctx, domain),
            _detect_cname_infra(ctx, domain),
            _detect_domain_connect(ctx, domain),
            _detect_subdomain_txt(ctx, domain),
            _detect_caa(ctx, domain),
            _detect_srv(ctx, domain),
            _detect_cert_intel(ctx, domain),
            _detect_common_subdomains(ctx, domain),
            _detect_hosting_from_a_record(ctx, domain),
            _detect_idp_hub(ctx, domain),
            _detect_exchange_onprem(ctx, domain),
        )

        # Remove the queried domain itself from related_domains
        ctx.related_domains.discard(domain.lower())

        # Post-process: enforce match_mode: all — remove partial matches
        ctx.enforce_match_mode_all()

        return ctx
