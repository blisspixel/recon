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

    if ctx.spf_include_count >= 8:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes (large)")
    elif ctx.spf_include_count >= 4:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes")


async def _detect_mx(ctx: _DetectionCtx, domain: str) -> None:
    """Scan MX records for email provider and gateway detection.

    Passes source_type="MX" and the raw record so an EvidenceRecord is
    created — the email topology computation in merger.py filters evidence
    by source_type == "MX" to distinguish true primary providers (direct
    MX) from secondary residue (DKIM/TXT/identity endpoint).
    """
    mx_records = await _safe_resolve(domain, "MX")
    ctx.raw_dns_records.setdefault("MX", []).extend(mx_records)

    for mx in mx_records:
        mx_lower = mx.lower()
        for det in get_mx_patterns():
            if det.pattern in mx_lower:
                ctx.add(det.name, det.slug, source_type="MX", raw_value=mx)
                ctx.record_fp_match(det.slug, "mx", det.pattern)
                break


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

    all_results = await asyncio.gather(
        sel1_task,
        sel2_task,
        google_txt_task,
        google_cname_task,
        *esp_tasks,
    )

    sel1_results = all_results[0]
    sel2_results = all_results[1]
    google_txt_results = all_results[2]
    google_cname_results = all_results[3]
    esp_results = all_results[4:]

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
    """Try CrtshProvider, fall back to CertSpotterProvider, mark degraded if both fail."""
    providers: list[CertIntelProvider] = [CrtshProvider(), CertSpotterProvider()]
    for provider in providers:
        try:
            subdomains, cert_summary = await provider.query(domain)
            ctx.related_domains.update(subdomains)
            if cert_summary is not None:
                ctx.cert_summary = cert_summary
            logger.debug("cert intel from %s for %s: %d subdomains", provider.name, domain, len(subdomains))
            return
        except Exception as exc:
            logger.debug("cert intel provider %s failed for %s: %s", provider.name, domain, exc)
            ctx.degraded_sources.add(provider.name)
    # Both failed — all provider names already in degraded_sources


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
        )

        # Remove the queried domain itself from related_domains
        ctx.related_domains.discard(domain.lower())

        # Post-process: enforce match_mode: all — remove partial matches
        ctx.enforce_match_mode_all()

        return ctx
