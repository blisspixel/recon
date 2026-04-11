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
import httpx

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
    match_txt,
)
from recon_tool.fingerprints import (
    get_m365_slugs as _get_m365_slugs,
)
from recon_tool.models import SourceResult

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
        "services", "slugs", "m365", "dmarc_policy", "spf_include_count",
        "_m365_slugs", "related_domains", "crtsh_degraded",
    )

    def __init__(self) -> None:
        self.services: set[str] = set()
        self.slugs: set[str] = set()
        self.m365: bool = False
        self.dmarc_policy: str | None = None
        self.spf_include_count: int = 0
        self._m365_slugs: frozenset[str] = _get_m365_slugs()
        self.related_domains: set[str] = set()
        self.crtsh_degraded: bool = False

    def add(self, svc_name: str, slug: str | None = None) -> None:
        """Register a detected service, optionally with its slug.

        M365 detection is based on the slug (stable identifier) rather than
        the display name, so renaming a fingerprint won't break detection.
        """
        self.services.add(svc_name)
        if slug:
            self.slugs.add(slug)
            if slug in self._m365_slugs:
                self.m365 = True


# ── Sub-detectors ───────────────────────────────────────────────────────
# Each function handles one DNS record type. All are async and operate
# on the shared _DetectionCtx. They are gathered concurrently in
# _detect_services for maximum throughput.


async def _detect_txt(ctx: _DetectionCtx, domain: str) -> None:
    """Scan TXT records for service fingerprints and SPF analysis."""
    txt_patterns = get_txt_patterns()
    spf_patterns = get_spf_patterns()

    for txt in await _safe_resolve(domain, "TXT"):
        txt_lower = txt.lower()

        result = match_txt(txt, txt_patterns)
        if result:
            ctx.add(result.name, result.slug)

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
            if txt_lower.rstrip().endswith("-all"):
                ctx.services.add(SVC_SPF_STRICT)
            elif txt_lower.rstrip().endswith("~all"):
                ctx.services.add(SVC_SPF_SOFTFAIL)

    if ctx.spf_include_count >= 8:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes (large)")
    elif ctx.spf_include_count >= 4:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes")


async def _detect_mx(ctx: _DetectionCtx, domain: str) -> None:
    """Scan MX records for email provider and gateway detection."""
    for mx in await _safe_resolve(domain, "MX"):
        mx_lower = mx.lower()
        for det in get_mx_patterns():
            if det.pattern in mx_lower:
                ctx.add(det.name, det.slug)
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

    (autodiscover_results, lyncdiscover_results, sip_results,
     srv_results, enterprise_results, msoid_results) = await asyncio.gather(
        autodiscover_task, lyncdiscover_task, sip_task,
        srv_task, enterprise_task, msoid_task,
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
    esp_tasks = [
        _safe_resolve(f"{sel}._domainkey.{domain}", "CNAME")
        for sel, _, _, _ in _ESP_SELECTORS
    ]

    all_results = await asyncio.gather(
        sel1_task, sel2_task, google_txt_task, google_cname_task,
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
                ctx.add(SVC_DKIM_EXCHANGE, "microsoft365")
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
    google_dkim_found = False
    for record in google_txt_results:
        if "v=dkim1" in record.lower():
            ctx.services.add(SVC_DKIM)
            ctx.add("DKIM (Google Workspace)", "google-workspace")
            google_dkim_found = True
            break
    if not google_dkim_found:
        for cname in google_cname_results:
            if "google.com" in cname.lower():
                ctx.services.add(SVC_DKIM)
                ctx.add("DKIM (Google Workspace)", "google-workspace")
                break

    # ESP DKIM selectors — attribute to specific services when CNAME matches
    for (_, hint, svc_name, slug), cname_results in zip(_ESP_SELECTORS, esp_results, strict=True):
        for cname in cname_results:
            if hint in cname.lower():
                ctx.add(svc_name, slug)
                ctx.services.add(SVC_DKIM)
                break


async def _detect_email_security(ctx: _DetectionCtx, domain: str) -> None:
    """Check DMARC, BIMI, and MTA-STS records concurrently."""
    dmarc_task = _safe_resolve(f"_dmarc.{domain}", "TXT")
    bimi_task = _safe_resolve(f"default._bimi.{domain}", "TXT")
    mta_sts_task = _safe_resolve(f"_mta-sts.{domain}", "TXT")

    dmarc_results, bimi_results, mta_sts_results = await asyncio.gather(
        dmarc_task, bimi_task, mta_sts_task,
    )

    for txt in dmarc_results:
        if txt.lower().startswith("v=dmarc1"):
            ctx.services.add(SVC_DMARC)
            for part in txt.split(";"):
                cleaned = part.strip().lower()
                if cleaned.startswith("p="):
                    ctx.dmarc_policy = cleaned[2:].strip()
                    break

    for txt in bimi_results:
        if "v=bimi1" in txt.lower():
            ctx.services.add(SVC_BIMI)

    for txt in mta_sts_results:
        if "v=stsv1" in txt.lower():
            ctx.services.add(SVC_MTA_STS)


async def _detect_ns(ctx: _DetectionCtx, domain: str) -> None:
    """Scan NS records for DNS provider / infrastructure detection."""
    for ns in await _safe_resolve(domain, "NS"):
        ns_lower = ns.lower()
        for det in get_ns_patterns():
            if det.pattern in ns_lower:
                ctx.add(det.name, det.slug)
                break


async def _detect_cname_infra(ctx: _DetectionCtx, domain: str) -> None:
    """Check www/root CNAME for CDN, hosting, and SaaS infrastructure."""
    www_task = _safe_resolve(f"www.{domain}", "CNAME")
    root_task = _safe_resolve(domain, "CNAME")

    www_results, root_results = await asyncio.gather(www_task, root_task)

    for cname_list in (www_results, root_results):
        for cname in cname_list:
            cl = cname.lower()
            for det in get_cname_patterns():
                if det.pattern in cl:
                    ctx.add(det.name, det.slug)
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
    parsed: list[tuple[str, str, str, str]] = []  # (subdomain, regex, name, slug)
    for det in patterns:
        if ":" not in det.pattern:
            continue
        subdomain, regex = det.pattern.split(":", 1)
        parsed.append((subdomain, regex, det.name, det.slug))

    if not parsed:
        return

    # Fire all subdomain TXT queries concurrently
    tasks = [_safe_resolve(f"{subdomain}.{domain}", "TXT") for subdomain, _, _, _ in parsed]
    results = await asyncio.gather(*tasks)

    for (_, regex, name, slug), txt_records in zip(parsed, results, strict=True):
        for txt in txt_records:
            try:
                if re.search(regex, txt, re.IGNORECASE):
                    ctx.add(name, slug)
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


# ── Certificate Transparency (crt.sh) ──────────────────────────────────

# Maximum number of unique subdomains to extract from crt.sh results.
# Prevents unbounded related_domains when a domain has thousands of certs.
_CRTSH_MAX_SUBDOMAINS = 100

# Timeout for the crt.sh HTTP call — separate from DNS query timeout
# because crt.sh can be slow under load.
_CRTSH_TIMEOUT = 8.0

# Patterns to filter out from crt.sh results — wildcards, common noise,
# and subdomains that rarely have interesting TXT/MX records.
_CRTSH_SKIP_PREFIXES = (
    "*.", "cpanel.", "cpcalendars.", "cpcontacts.", "webdisk.", "webmail.",
    "mail.", "ftp.", "localhost.", "www.",
)

# ── Common subdomain probing ───────────────────────────────────────────

# High-signal subdomain prefixes that commonly CNAME to SaaS providers.
# These are probed directly via DNS — no external service dependency.
# Kept intentionally focused: each prefix has a high probability of
# revealing a SaaS CNAME (auth→Okta, shop→Shopify, status→Statuspage, etc.).
_COMMON_SUBDOMAIN_PREFIXES = (
    # Identity / SSO
    "auth", "login", "sso", "id", "identity", "secure-auth", "accounts",
    # Commerce / customer-facing
    "shop", "store", "checkout",
    # App / API
    "app", "api", "portal", "dashboard", "admin",
    # Support
    "support", "help", "status", "docs", "kb",
    # Marketing / email
    "click.em", "image.em", "view.em", "em", "email", "go", "info", "pages",
    # Content / CDN
    "cdn", "assets", "static", "media", "images",
    # Blog / marketing sites
    "blog", "news", "events", "careers",
    # Dev / staging
    "staging", "stage", "dev", "sandbox", "preview", "uat", "stage-auth",
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


async def _detect_crtsh(ctx: _DetectionCtx, domain: str) -> None:
    """Query crt.sh certificate transparency logs for subdomain discovery.

    Adds discovered subdomains to ctx.related_domains so the resolver's
    enrichment pipeline can run DNS fingerprinting on them. This is 100%
    passive — crt.sh is a public, free, unauthenticated JSON API that
    returns certificate transparency log entries.

    Failures are silently ignored — crt.sh is a bonus source, not critical.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=_CRTSH_TIMEOUT) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                logger.debug("crt.sh returned HTTP %d for %s", resp.status_code, domain)
                ctx.crtsh_degraded = True
                return
            data = resp.json()
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError, ValueError) as exc:
        logger.debug("crt.sh lookup failed for %s: %s", domain, exc)
        ctx.crtsh_degraded = True
        return

    if not isinstance(data, list):
        return

    seen: set[str] = set()
    domain_lower = domain.lower()

    for entry in data:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value", "")
        if not isinstance(name_value, str):
            continue
        # crt.sh can return multiple names separated by newlines
        for raw_name in name_value.lower().strip().split("\n"):
            name = raw_name.strip()
            if not name or name == domain_lower:
                continue
            # Skip wildcards and common noise
            if any(name.startswith(prefix) for prefix in _CRTSH_SKIP_PREFIXES):
                continue
            # Must be a subdomain of the queried domain
            if not name.endswith(f".{domain_lower}"):
                continue
            seen.add(name)

    if not seen:
        return

    # Prioritize subdomains likely to have interesting CNAME targets.
    # High-signal prefixes (auth, login, shop, api, etc.) sort first,
    # deep subdomains (3+ levels) sort last (often internal/noise).
    _HIGH_SIGNAL_PREFIXES = (
        "auth", "login", "sso", "secure", "id", "identity",
        "shop", "store", "checkout", "pay",
        "api", "app", "portal", "dashboard",
        "support", "help", "status",
        "track", "click", "image", "view", "email", "em.",
        "cdn", "assets", "static", "media",
        "blog", "docs", "kb",
        "stage", "staging", "dev", "sandbox", "preview", "uat",
    )

    def _sort_key(name: str) -> tuple[int, int, str]:
        """Sort: high-signal prefixes first, then by depth (shallow first), then alpha."""
        prefix = name.split(f".{domain_lower}")[0]
        is_high = 0 if any(prefix.startswith(p) or prefix.endswith(p) for p in _HIGH_SIGNAL_PREFIXES) else 1
        depth = prefix.count(".")
        return (is_high, depth, name)

    prioritized = sorted(seen, key=_sort_key)[:_CRTSH_MAX_SUBDOMAINS]

    logger.debug("crt.sh found %d subdomains for %s (kept %d)", len(seen), domain, len(prioritized))
    ctx.related_domains.update(prioritized)


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
                crtsh_degraded=ctx.crtsh_degraded,
            )

        return SourceResult(
            source_name="dns_records",
            m365_detected=False,
            dmarc_policy=ctx.dmarc_policy,
            related_domains=tuple(sorted(ctx.related_domains)),
            crtsh_degraded=ctx.crtsh_degraded,
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
            _detect_dkim(ctx, domain),
            _detect_email_security(ctx, domain),
            _detect_ns(ctx, domain),
            _detect_cname_infra(ctx, domain),
            _detect_domain_connect(ctx, domain),
            _detect_subdomain_txt(ctx, domain),
            _detect_caa(ctx, domain),
            _detect_srv(ctx, domain),
            _detect_crtsh(ctx, domain),
            _detect_common_subdomains(ctx, domain),
        )

        # Remove the queried domain itself from related_domains
        ctx.related_domains.discard(domain.lower())

        return ctx
