"""Infrastructure, hosting, and certificate-transparency DNS detectors.

Extracted from ``sources/dns.py`` (docs/roadmap.md god-file track): the M365 /
Google-Workspace CNAME probes, NS / CNAME-infra / Domain-Connect / A-record
hosting / subdomain-TXT / CAA / SRV detectors, and the CT fallback chain. The
public ``detect_*`` entry points are orchestrated by ``DNSSource`` and the
surface classifier in ``dns.py`` (re-exported there under their underscore
names). Imports the resolver/context from ``dns_base`` and catalogs/helpers
from ``dns_tables``; never imported by either.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from recon_tool.constants import (
    SVC_EXCHANGE_AUTODISCOVER,
    SVC_INTUNE_MDM,
    SVC_MICROSOFT_TEAMS,
    SVC_OFFICE_PROPLUS,
)
from recon_tool.fingerprints import (
    get_caa_patterns,
    get_cname_patterns,
    get_ns_patterns,
    get_subdomain_txt_patterns,
)
from recon_tool.sources import dns_base
from recon_tool.sources.cert_providers import CertIntelProvider, CertSpotterProvider, CrtshProvider
from recon_tool.sources.dns_tables import (
    HOSTING_PTR_PATTERNS,
    classify_ct_failure,
    ct_failure_outcome,
    is_public_dns_name,
)

if TYPE_CHECKING:
    from recon_tool.ct_cache import CTCacheEntry

logger = logging.getLogger("recon")


# Max length of an attacker-controlled TXT value we will run a user-supplied
# regex against (subdomain_txt detections). Mirrors fingerprints._MAX_TXT_MATCH_LENGTH;
# bounds backtracking amplification from a crafted multi-KB TXT record.
_MAX_SUBDOMAIN_TXT_MATCH_LEN = 4096


# A DNS name is at most 253 characters; a longer CNAME value is malformed.
# Bounds backtracking amplification when a custom / injected cname pattern is
# matched against an attacker-controlled CNAME target. 255 leaves a small margin.
_MAX_CNAME_MATCH_LEN = 255


async def detect_m365_cnames(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Check M365-specific CNAME and SRV records (autodiscover, teams, intune, msoid).

    Also checks _sipfederationtls._tcp SRV for Teams/Skype federation - a strong
    M365 signal that persists even when CNAME records have been cleaned up.

    Sub-queries within this detector are gathered concurrently since they
    are independent of each other.
    """
    # Fire all CNAME/SRV queries concurrently
    autodiscover_task = dns_base.safe_resolve(f"autodiscover.{domain}", "CNAME")
    lyncdiscover_task = dns_base.safe_resolve(f"lyncdiscover.{domain}", "CNAME")
    sip_task = dns_base.safe_resolve(f"sip.{domain}", "CNAME")
    srv_task = dns_base.safe_resolve(f"_sipfederationtls._tcp.{domain}", "SRV")
    enterprise_task = dns_base.safe_resolve(f"enterpriseregistration.{domain}", "CNAME")
    msoid_task = dns_base.safe_resolve(f"msoid.{domain}", "CNAME")

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
            # Validate: must have at least one dot (real domain, not
            # single-label) and must pass the public-suffix check.
            # The latter prevents an attacker-controlled
            # autodiscover CNAME (e.g. autodiscover.attacker.example
            # → something.internal.corp) from planting an
            # internal-looking apex in related_domains.
            if (
                redirect_domain
                and "." in redirect_domain
                and redirect_domain != domain.lower()
                and is_public_dns_name(redirect_domain)
            ):
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


_GWS_MODULE_PREFIXES = ("mail", "calendar", "docs", "drive", "sites", "groups")


_GWS_CNAME_TARGET = "ghs.googlehosted.com"


async def detect_gws_cnames(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Check Google Workspace module CNAMEs concurrently.

    Administrators frequently create custom CNAMEs for GWS apps that
    resolve to ghs.googlehosted.com. Detecting these reveals which
    specific Workspace modules are actively deployed and branded.
    """
    tasks = [dns_base.safe_resolve(f"{prefix}.{domain}", "CNAME") for prefix in _GWS_MODULE_PREFIXES]
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


async def detect_ns(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Scan NS records for DNS provider / infrastructure detection."""
    ns_records = await dns_base.safe_resolve(domain, "NS")
    ctx.raw_dns_records.setdefault("NS", []).extend(ns_records)

    # Sort longest-first so the most specific pattern wins (consistent with
    # MX matcher and cname_target classifier , see filter_shadowed_matches).
    ns_patterns_sorted = sorted(get_ns_patterns(), key=lambda d: -len(d.pattern))

    for ns in ns_records:
        ns_lower = ns.lower()
        for det in ns_patterns_sorted:
            if det.pattern in ns_lower:
                ctx.add(det.name, det.slug)
                ctx.record_fp_match(det.slug, "ns", det.pattern)
                break


async def detect_cname_infra(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Check www/root CNAME for CDN, hosting, and SaaS infrastructure."""
    www_task = dns_base.safe_resolve(f"www.{domain}", "CNAME")
    root_task = dns_base.safe_resolve(domain, "CNAME")

    www_results, root_results = await asyncio.gather(www_task, root_task)

    all_cnames = www_results + root_results
    if all_cnames:
        ctx.raw_dns_records.setdefault("CNAME", []).extend(all_cnames)

    # Sort longest-first so the most specific pattern wins per CNAME
    # (consistent with MX / NS / CAA / dmarc_rua / cname_target , see
    # filter_shadowed_matches).
    #
    # cname patterns are regex-validated at load time (the loader runs
    # them through re.compile to catch ReDoS-shaped expressions), and
    # nine catalog entries today carry real regex syntax (escaped dots,
    # ``$`` anchors, alternation , see slugs langsmith, fastly, flyio,
    # railway, splunk, cyberark, beyond-identity, workspace-one). The
    # original substring matcher (``det.pattern in cl``) silently
    # never-fired on those nine because no real hostname contains
    # backslashes or ``$``. Switching to ``re.search`` lights them up
    # while preserving behavior for the 88 plain-string patterns
    # (regex without metacharacters is equivalent to substring search,
    # modulo ``.`` matching any single character, which on hostname
    # patterns like ``hubspot.net`` is the intended forgiving match).
    cname_patterns_sorted = sorted(get_cname_patterns(), key=lambda d: -len(d.pattern))
    for cname_list in (www_results, root_results):
        for cname in cname_list:
            # Bound adversarial input before the regex match. A DNS name is at
            # most 253 characters, so anything longer is malformed and only
            # amplifies backtracking work for a pathological custom / injected
            # pattern. The validator (fingerprints._validate_regex) rejects the
            # known ReDoS shapes; this length cap is the second layer. The full
            # cname is still used as raw_value below, only the match is bounded.
            cl = cname.lower()[:_MAX_CNAME_MATCH_LEN]
            for det in cname_patterns_sorted:
                try:
                    if re.search(det.pattern, cl, re.IGNORECASE):
                        ctx.add(det.name, det.slug, source_type="CNAME", raw_value=cname)
                        ctx.record_fp_match(det.slug, "cname", det.pattern)
                        break
                except re.error:
                    # Defensive: patterns were validated on load, but
                    # guard against edge cases the loader missed.
                    continue


async def detect_domain_connect(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Check _domainconnect CNAME for domain management provider."""
    for cname in await dns_base.safe_resolve(f"_domainconnect.{domain}", "CNAME"):
        cl = cname.lower()
        if "azure" in cl:
            ctx.services.add("Domain Connect (Azure)")
        elif "godaddy" in cl or "domaincontrol" in cl:
            ctx.services.add("Domain Connect (GoDaddy)")


async def detect_hosting_from_a_record(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Reverse-resolve the apex A record and match the PTR hostname
    against known cloud-provider patterns.

    On web-only domains this is the primary detection signal - the
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

    a_records = await dns_base.safe_resolve(domain, "A")
    if not a_records:
        return
    ctx.raw_dns_records.setdefault("A", []).extend(a_records)

    # Use the first IP only - multi-A domains are usually
    # load-balanced within the same provider, so one PTR is enough.
    try:
        ip = ipaddress.ip_address(a_records[0])
    except (ValueError, TypeError):
        return

    # Only issue PTR lookups for globally-routable unicast addresses.
    # A domain whose A record points to an internal or special-use IP
    # (10.x, 192.168.x, 127.x, 169.254.x, 100.64.x, 0.0.0.0, etc.)
    # would otherwise cause the operator's resolver to answer with
    # internal PTR names that end up in evidence output. When recon is
    # exposed via MCP to an untrusted caller, that's an internal-DNS
    # information-disclosure path.
    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return

    # Build PTR query: reverse octets + .in-addr.arpa (IPv4) or
    # reverse nibbles + .ip6.arpa (IPv6). dns.reversename handles
    # both, but import locally to keep the hot path clean.
    try:
        import dns.reversename  # pyright: ignore[reportMissingTypeStubs]

        ptr_name = dns.reversename.from_address(str(ip))
        ptr_results = await dns_base.safe_resolve(str(ptr_name), "PTR")
    except Exception:
        return
    if not ptr_results:
        return

    ptr_lower = ptr_results[0].rstrip(".").lower()
    for substring, name, slug, region_regex in HOSTING_PTR_PATTERNS:
        if substring not in ptr_lower:
            continue
        # The display name is always the bare provider. The region
        # (when extractable) goes into the raw_value of the
        # evidence record so --explain and --json still carry it,
        # but the default panel stays compact - it'd get noisy if
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


async def detect_subdomain_txt(ctx: dns_base.DetectionCtx, domain: str) -> None:
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
    tasks = [dns_base.safe_resolve(f"{subdomain}.{domain}", "TXT") for subdomain, _, _, _, _ in parsed]
    results = await asyncio.gather(*tasks)

    for (_, regex, name, slug, original_pattern), txt_records in zip(parsed, results, strict=True):
        for txt in txt_records:
            # Bound the attacker-controlled TXT value before running a
            # user-supplied regex against it, mirroring match_txt. Without
            # this cap a crafted multi-KB TXT plus a greedy / catastrophic
            # operator regex would amplify backtracking. This is the only
            # user-regex DNS path that previously lacked the length bound.
            if len(txt) > _MAX_SUBDOMAIN_TXT_MATCH_LEN:
                continue
            try:
                if re.search(regex, txt, re.IGNORECASE):
                    ctx.add(name, slug)
                    ctx.record_fp_match(slug, "subdomain_txt", original_pattern)
                    break
            except re.error:
                continue


async def detect_caa(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Query CAA records to identify certificate authority and PKI strategy."""
    # Sort longest-first so the most specific pattern wins (consistent
    # with MX / NS / cname_target , see filter_shadowed_matches).
    caa_patterns_sorted = sorted(get_caa_patterns(), key=lambda d: -len(d.pattern))
    for caa in await dns_base.safe_resolve(domain, "CAA"):
        caa_lower = caa.lower()
        for det in caa_patterns_sorted:
            if det.pattern in caa_lower:
                ctx.add(det.name, det.slug)
                ctx.record_fp_match(det.slug, "caa", det.pattern)
                break


async def detect_srv(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Check common SRV records for collaboration and identity services.

    SRV records reveal services that don't leave TXT/SPF/MX footprints.
    Only checks a focused set of high-signal SRV names - not brute-forcing.
    """
    # (srv_name, target_hint, service_name, slug)
    # NOTE: _sip._tls and _sipfederationtls._tcp SRV records pointing to
    # lync.com are legacy Skype for Business DNS entries. Microsoft retired
    # Skype for Business Online (July 2021) but recommends keeping these
    # records for Teams interop. We label them as Microsoft Teams since
    # that's what they serve in 2024+. The display name matches the CNAME-
    # based detection in detect_m365_cnames so they deduplicate naturally.
    _SRV_CHECKS: list[tuple[str, str | None, str, str]] = [
        ("_sip._tls", "lync.com", SVC_MICROSOFT_TEAMS, "microsoft365"),
        ("_sipfederationtls._tcp", "lync.com", SVC_MICROSOFT_TEAMS, "microsoft365"),
        ("_xmpp-server._tcp", None, "XMPP (Jabber)", ""),
        ("_caldavs._tcp", None, "CalDAV", ""),
        ("_carddavs._tcp", None, "CardDAV", ""),
    ]

    tasks = [dns_base.safe_resolve(f"{srv}.{domain}", "SRV") for srv, _, _, _ in _SRV_CHECKS]
    results = await asyncio.gather(*tasks)

    for (_, hint, svc_name, slug), srv_records in zip(_SRV_CHECKS, results, strict=True):
        for record in srv_records:
            # SRV records with target "." mean "service not available" - skip
            if record.strip().rstrip(".") == "":
                continue
            if hint is None or hint in record.lower():
                ctx.add(svc_name, slug if slug else None)
                break


def _apply_cached_cert_intel(ctx: dns_base.DetectionCtx, cached: CTCacheEntry, attribution: str) -> None:
    """Apply a CT cache entry to the context (shared by cache-first and fallback)."""
    ctx.related_domains.update(cached.subdomains)
    if cached.cert_summary is not None:
        ctx.cert_summary = cached.cert_summary
    ctx.ct_provider_used = attribution
    ctx.ct_subdomain_count = len(cached.subdomains)
    ctx.ct_cache_age_days = cached.age_days
    ctx.ct_attempt_outcome = "cache_hit"


async def _query_cert_providers(ctx: dns_base.DetectionCtx, domain: str) -> tuple[bool, str | None, dict[str, int]]:
    """Try each live CT provider in turn. Apply the first real success to ctx.

    Returns (success, soft_provider, failure-tallies). An empty-but-not-error
    response (``([], None, None)``, e.g. a CertSpotter rate-limit) is a soft
    failure: the first such provider name is remembered so the cache fallback
    can still attribute the panel correctly.
    """
    from recon_tool.ct_cache import ct_cache_put

    providers: list[CertIntelProvider] = [CrtshProvider(), CertSpotterProvider()]
    failures = {"breaker": 0, "rate_limit": 0, "other": 0}
    soft_provider: str | None = None
    for provider in providers:
        try:
            subdomains, cert_summary, infrastructure_clusters = await provider.query(domain)
        except Exception as exc:
            failures[classify_ct_failure(exc)] += 1
            logger.debug("cert intel provider %s failed for %s: %s", provider.name, domain, exc)
            ctx.degraded_sources.add(provider.name)
            continue

        if not subdomains and cert_summary is None and infrastructure_clusters is None:
            logger.debug(
                "cert intel provider %s returned empty for %s - treating as soft failure",
                provider.name,
                domain,
            )
            if soft_provider is None:
                soft_provider = provider.name
            continue

        ctx.related_domains.update(subdomains)
        if cert_summary is not None:
            ctx.cert_summary = cert_summary
        if infrastructure_clusters is not None:
            ctx.infrastructure_clusters = infrastructure_clusters
        ctx.ct_provider_used = provider.name
        ctx.ct_subdomain_count = len(subdomains)
        ctx.ct_attempt_outcome = "live_success"
        logger.debug("cert intel from %s for %s: %d subdomains", provider.name, domain, len(subdomains))
        ct_cache_put(domain, subdomains, cert_summary, provider.name)
        return True, None, failures

    return False, soft_provider, failures


async def detect_cert_intel(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Try CrtshProvider, fall back to CertSpotterProvider, fall back to CT cache.

    On the first successful provider, record the provider name and subdomain
    count on the context so the panel can surface which provider actually ran
    ("crt.sh (142 subdomains)" vs "certspotter (8 subdomains)"), making
    enrichment asymmetry between runs visible instead of silent.

    A fresh CT cache entry short-circuits the live providers entirely.
    When all live providers fail (hard error or empty-but-not-error),
    the per-domain CT cache is the final fallback, annotated with its
    age so the panel can show "from local cache, N days old". With no cache and
    no success, the attempt outcome reflects the most precise failure observed.
    """
    from recon_tool.ct_cache import ct_cache_get

    cached_first = ct_cache_get(domain)
    if cached_first is not None and cached_first.subdomains:
        _apply_cached_cert_intel(ctx, cached_first, f"{cached_first.provider_used} (cached)")
        logger.debug(
            "cert intel cache-first hit for %s: %d subdomains, %d days old",
            domain,
            len(cached_first.subdomains),
            cached_first.age_days,
        )
        return

    success, soft_provider, failures = await _query_cert_providers(ctx, domain)
    if success:
        return

    cached = ct_cache_get(domain)
    if cached is not None and cached.subdomains:
        # Attribution: if a live provider returned empty (soft failure), name
        # it explicitly so the panel reflects what actually ran.
        _apply_cached_cert_intel(ctx, cached, f"{soft_provider or cached.provider_used} (cached)")
        logger.debug(
            "cert intel from CT cache for %s: %d subdomains, %d days old",
            domain,
            len(cached.subdomains),
            cached.age_days,
        )
    elif soft_provider is not None:
        # No cache, but a provider returned empty - surface it rather than
        # leaving ct_provider_used unset.
        ctx.ct_provider_used = soft_provider
        ctx.ct_attempt_outcome = "cache_miss"
    else:
        ctx.ct_attempt_outcome = ct_failure_outcome(failures)
        ctx.ct_subdomain_count = 0
