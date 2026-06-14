"""DNS record lookup source for domain intelligence and tech stack fingerprinting.

Loads patterns from data/fingerprints.yaml - add new services there, no code changes needed.

Detection is split into focused async functions (_detect_txt, _detect_mx, etc.) to keep
each concern isolated and testable. The top-level _detect_services orchestrates them
concurrently via asyncio.gather for maximum throughput.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from recon_tool.ct_cache import CTCacheEntry


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
    filter_shadowed_matches,
    get_caa_patterns,
    get_cname_patterns,
    get_cname_target_rules,
    get_mx_patterns,
    get_ns_patterns,
    get_spf_patterns,
    get_subdomain_txt_patterns,
    get_txt_patterns,
    match_txt,
)
from recon_tool.http import http_client as _http_client
from recon_tool.models import (
    BIMIIdentity,
    ChainMotifObservation,
    EvidenceRecord,
    SourceResult,
    SurfaceAttribution,
    UnclassifiedCnameChain,
)
from recon_tool.motifs import load_motifs, match_chain_motifs
from recon_tool.sources import dns_base
from recon_tool.sources.cert_providers import CertIntelProvider, CertSpotterProvider, CrtshProvider
from recon_tool.sources.dns_base import (  # re-exported: stable import path after the split
    DetectionCtx as _DetectionCtx,
)
from recon_tool.sources.dns_tables import (
    COMMON_SUBDOMAIN_PREFIXES as _COMMON_SUBDOMAIN_PREFIXES,
)
from recon_tool.sources.dns_tables import (
    ESP_DKIM_SELECTORS as _ESP_DKIM_SELECTORS,
)
from recon_tool.sources.dns_tables import (
    GENERIC_DKIM_SELECTORS as _GENERIC_DKIM_SELECTORS,
)
from recon_tool.sources.dns_tables import (
    HOSTING_PTR_PATTERNS as _HOSTING_PTR_PATTERNS,
)
from recon_tool.sources.dns_tables import (
    IDP_SUBDOMAIN_PREFIXES as _IDP_SUBDOMAIN_PREFIXES,
)
from recon_tool.sources.dns_tables import (
    bimi_vmc_url_is_safe as _bimi_vmc_url_is_safe,
)
from recon_tool.sources.dns_tables import (
    classify_chain as _classify_chain,
)
from recon_tool.sources.dns_tables import (
    classify_ct_failure as _classify_ct_failure,
)
from recon_tool.sources.dns_tables import (
    ct_failure_outcome as _ct_failure_outcome,
)
from recon_tool.sources.dns_tables import (
    extract_bimi_vmc_url as _extract_bimi_vmc_url,
)
from recon_tool.sources.dns_tables import (
    is_public_dns_name as _is_public_dns_name,
)
from recon_tool.sources.dns_tables import (
    parse_vmc_subject as _parse_vmc_subject,
)
from recon_tool.validator import strip_control_chars

logger = logging.getLogger("recon")


# Max length of an attacker-controlled TXT value we will run a user-supplied
# regex against (subdomain_txt detections). Mirrors fingerprints._MAX_TXT_MATCH_LENGTH;
# bounds backtracking amplification from a crafted multi-KB TXT record.
_MAX_SUBDOMAIN_TXT_MATCH_LEN = 4096

# A DNS name is at most 253 characters; a longer CNAME value is malformed.
# Bounds backtracking amplification when a custom / injected cname pattern is
# matched against an attacker-controlled CNAME target. 255 leaves a small margin.
_MAX_CNAME_MATCH_LEN = 255


# ── Detection context ───────────────────────────────────────────────────
# Mutable accumulator passed through all _detect_* functions to avoid
# returning and merging multiple tuples from each sub-detector.
# Thread-safe is NOT required - all sub-detectors run on the event loop,
# not in separate threads.


# ── Sub-detectors ───────────────────────────────────────────────────────
# Each function handles one DNS record type. All are async and operate
# on the shared _DetectionCtx. They are gathered concurrently in
# _detect_services for maximum throughput.


async def _detect_txt(ctx: _DetectionCtx, domain: str) -> None:
    """Scan TXT records for service fingerprints and SPF analysis."""
    txt_patterns = get_txt_patterns()
    spf_patterns = get_spf_patterns()

    txt_records = await dns_base.safe_resolve(domain, "TXT")
    ctx.raw_dns_records.setdefault("TXT", []).extend(txt_records)

    for txt in txt_records:
        txt_lower = txt.lower()

        result = match_txt(txt, txt_patterns)
        if result:
            ctx.add(result.name, result.slug, source_type="TXT", raw_value=txt)
            ctx.record_fp_match(result.slug, "txt", result.pattern)

        # Extract google-site-verification tokens for relationship mapping.
        # Strip control bytes: the token is attacker-controlled and is
        # serialized into JSON / MCP output and clustering. JSON escaping
        # contains it today, but stripping at ingestion keeps any future
        # non-JSON renderer safe by construction (tokens are base64/hex, so
        # this is lossless for legitimate values).
        if txt_lower.startswith("google-site-verification="):
            token = strip_control_chars(txt[len("google-site-verification=") :].strip())
            if token:
                ctx.site_verification_tokens.add(token)

        if txt_lower.startswith("v=spf1"):
            ctx.spf_include_count = txt_lower.count("include:")
            # SPF patterns use substring matching on the include: values.
            # This is intentional - SPF includes are domain names, and we
            # match on the authoritative portion (e.g. "spf.protection.outlook.com").
            # Unlike TXT patterns (which use regex), SPF patterns are plain
            # substrings because the YAML values are literal domain fragments.
            #
            # Multiple distinct vendors can legitimately fire on one SPF
            # record (e.g. M365 + Salesforce includes), so we accumulate
            # rather than break-on-first-match. We then apply
            # ``filter_shadowed_matches`` so that when a broad pattern
            # (e.g. ``cisco.com``) and a narrow one
            # (e.g. ``ess.cisco.com``) both match, only the narrow one's
            # slug fires , preventing double-counting of the same vendor.
            spf_matches = [det for det in spf_patterns if det.pattern.lower() in txt_lower]
            for det in filter_shadowed_matches(spf_matches):
                ctx.add(det.name, det.slug)
                ctx.record_fp_match(det.slug, "spf", det.pattern)
            if txt_lower.rstrip().endswith("-all"):
                ctx.services.add(SVC_SPF_STRICT)
            elif txt_lower.rstrip().endswith("~all"):
                ctx.services.add(SVC_SPF_SOFTFAIL)
            # Follow SPF redirect= chains. A record like
            # "v=spf1 redirect=_spf.mail.umich.edu" means "use that
            # domain's SPF as mine" - RFC 7208 §6.1. Higher-ed and
            # enterprise domains commonly use redirect to point at
            # a shared SPF zone they manage separately. Without
            # following the chain, we score the redirected domain
            # as having no SPF strict even when the redirect target
            # does end in -all. Follow up to 3 chain hops to prevent
            # loops, mark each redirect target for SPF fingerprint
            # scanning too.
            if "redirect=" in txt_lower and not txt_lower.rstrip().endswith(("-all", "~all")):
                await _follow_spf_redirect(ctx, txt_lower, depth=0, max_depth=3)

    # SPF complexity summary - runs once per domain after the TXT
    # record scan, regardless of how many SPF variants the loop saw.
    # This block belongs to _detect_txt, not _follow_spf_redirect.
    if ctx.spf_include_count >= 8:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes (large)")
    elif ctx.spf_include_count >= 4:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes")


async def _follow_spf_redirect(ctx: _DetectionCtx, spf_text: str, depth: int, max_depth: int) -> None:
    """Follow SPF redirect= chain up to ``max_depth`` hops.

    When a domain's SPF is ``v=spf1 redirect=<other>``, we need to
    query the redirected domain's SPF to know whether the chain
    ultimately ends in ``-all`` (strict) or ``~all`` (softfail).
    Without following the chain, recon scores 0 on SPF strict for
    every domain that uses the redirect pattern - and that pattern
    is extremely common in higher-ed and enterprise deployments
    where SPF is managed as a single zone across many brand
    domains.

    Any failure (network error, parse error, missing pattern)
    silently no-ops - this is an enrichment path, not a critical
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
        # Security: the redirect= target is attacker-controlled. The owner
        # of the queried domain authors their own SPF record, so a record
        # like "v=spf1 redirect=secret.internal.corp" would otherwise make
        # the operator's resolver query an internal/split-horizon name and
        # turn recon into an internal-DNS oracle. This is the same class as
        # the CNAME chain-walker leak; we reuse the same suffix denylist
        # (_is_public_dns_name) and refuse the hop before any query. The
        # check covers the recursive hop below too, since each recursion
        # re-enters here with the next target. Legitimate public targets
        # such as "_spf.mail.example.edu" pass unchanged. See
        # docs/security-audit-resolutions.md.
        if not _is_public_dns_name(target):
            logger.debug(
                "SPF redirect chain: refusing non-public-suffix target %s",
                target,
            )
            return
        target_records = await dns_base.safe_resolve(target, "TXT")
        patterns = get_spf_patterns()
        for record in target_records:
            rec_lower = record.strip().lower()
            if not rec_lower.startswith("v=spf1"):
                continue
            # Run the same fingerprint pass on the target's SPF, with
            # specificity suppression for shadow patterns (see the
            # comment in _detect_txt above).
            spf_matches = [det for det in patterns if det.pattern.lower() in rec_lower]
            for det in filter_shadowed_matches(spf_matches):
                ctx.add(det.name, det.slug)
                ctx.record_fp_match(det.slug, "spf", det.pattern)
            # Propagate the policy qualifier from the redirect
            # target up to the origin - if _spf.mail.umich.edu
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
    created - the email topology computation in merger.py filters evidence
    by source_type == "MX" to distinguish true primary providers (direct
    MX) from secondary residue (DKIM/TXT/identity endpoint).

    Emit a generic EvidenceRecord for EVERY MX host
    found, whether or not a fingerprint pattern matched. This lets
    downstream code distinguish "no MX records at all" (domain has no
    email) from "MX records exist but the host isn't in our fingerprint
    set" (domain has custom / self-hosted email like Apache's own mail
    servers). Previously, apache.org looked identical to
    balcaninnovations.com from the evidence perspective - both had
    zero MX evidence records even though apache.org has three real
    MX hosts. The "generic MX evidence" carries an empty slug so it
    doesn't pollute the detected_slugs set.
    """
    mx_records = await dns_base.safe_resolve(domain, "MX")
    ctx.raw_dns_records.setdefault("MX", []).extend(mx_records)

    # Sort MX patterns longest-first so the most specific pattern wins per
    # MX record (the loop below stops at the first match). Without this,
    # a broader pattern listed earlier in the catalog could shadow a
    # narrower one (e.g. `cisco.com` shadowing `ess.cisco.com`).
    mx_patterns_sorted = sorted(get_mx_patterns(), key=lambda d: -len(d.pattern))

    unmatched_hosts: list[str] = []
    any_matched = False
    for mx in mx_records:
        mx_lower = mx.lower()
        matched = False
        for det in mx_patterns_sorted:
            if det.pattern in mx_lower:
                ctx.add(det.name, det.slug, source_type="MX", raw_value=mx)
                ctx.record_fp_match(det.slug, "mx", det.pattern)
                matched = True
                any_matched = True
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
            # Track unmatched MX hosts for self-hosted-mail inference.
            # MX record format is ``<priority> <host>`` - extract host.
            parts = mx.strip().split()
            if len(parts) >= 2:
                unmatched_hosts.append(parts[-1].rstrip(".").lower())

    # Self-hosted-mail inference. When MX records exist and none of
    # them match a known cloud provider or gateway, attribute the
    # primary provider as "Self-hosted mail". This rescues orgs whose
    # MX targets live under the queried apex or under an operator-owned
    # sibling domain - they otherwise fall through to the weaker
    # ``exchange-onprem`` attribution driven by ``owa.`` / ``autodiscover.``
    # probes. ``Self-hosted`` is a conservative label that may in rare
    # cases cover obscure cloud providers we don't yet fingerprint - in
    # both cases the MX hosts are surfaced in the evidence so the user
    # can see what's actually being used.
    if unmatched_hosts and not any_matched:
        ctx.add(
            "Self-hosted mail",
            "self-hosted-mail",
            source_type="MX",
            raw_value=", ".join(sorted(set(unmatched_hosts))),
        )


async def _detect_m365_cnames(ctx: _DetectionCtx, domain: str) -> None:
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
                and _is_public_dns_name(redirect_domain)
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


# --- Google Workspace CNAME module probing ---

_GWS_MODULE_PREFIXES = ("mail", "calendar", "docs", "drive", "sites", "groups")
_GWS_CNAME_TARGET = "ghs.googlehosted.com"


async def _detect_gws_cnames(ctx: _DetectionCtx, domain: str) -> None:
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


def _apply_exchange_dkim(ctx: _DetectionCtx, selector_groups: tuple[list[str], list[str]]) -> None:
    """Attribute Exchange Online DKIM and capture the onmicrosoft.com tenant domain."""
    for selector_results in selector_groups:
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


def _apply_google_dkim(ctx: _DetectionCtx, txt_results: list[str], cname_results: list[str]) -> None:
    """Attribute Google Workspace DKIM. TXT first, then CNAME delegation.

    source_type="DKIM" is required for the email-topology inference in
    merger.py to recognise this as downstream-provider evidence when MX
    points to a gateway (Proofpoint, etc.).
    """
    for record in txt_results:
        if "v=dkim1" in record.lower():
            ctx.services.add(SVC_DKIM)
            ctx.add("DKIM (Google Workspace)", "google-workspace", source_type="DKIM", raw_value=record)
            return
    for cname in cname_results:
        if "google.com" in cname.lower():
            ctx.services.add(SVC_DKIM)
            ctx.add("DKIM (Google Workspace)", "google-workspace", source_type="DKIM", raw_value=cname)
            return


def _apply_esp_dkim(
    ctx: _DetectionCtx,
    esp_selectors: list[tuple[str, str, str, str]],
    esp_results: list[list[str]],
) -> None:
    """Attribute ESP DKIM (Mailchimp, SendGrid, ...) when a selector CNAME matches its hint."""
    for (_, hint, svc_name, slug), cname_results in zip(esp_selectors, esp_results, strict=True):
        for cname in cname_results:
            if hint in cname.lower():
                ctx.add(svc_name, slug, source_type="DKIM", raw_value=cname)
                ctx.services.add(SVC_DKIM)
                break


def _apply_generic_dkim(ctx: _DetectionCtx, generic_results: list[list[str]]) -> None:
    """Confirm DKIM exists via generic selectors when no provider-specific DKIM fired.

    Only feeds the email-security score; does not attribute a provider.
    """
    if SVC_DKIM in ctx.services:
        return
    for txt_records in generic_results:
        for record in txt_records:
            if "v=dkim1" in record.lower():
                ctx.services.add(SVC_DKIM)
                return


async def _detect_dkim(ctx: _DetectionCtx, domain: str) -> None:
    """Check DKIM selectors for Exchange Online, Google, and common providers.

    Exchange uses selector1/selector2, Google uses 'google', and many ESPs
    use 's1'/'s2', 'k1', 'default', 'dkim', 'mail', or 'em' selectors. Fires
    all the common selector probes concurrently, then applies each provider's
    attribution. Also extracts the onmicrosoft.com domain from Exchange DKIM
    CNAMEs, which reveals the tenant's internal domain name.
    """
    sel1_task = dns_base.safe_resolve(f"selector1._domainkey.{domain}", "CNAME")
    sel2_task = dns_base.safe_resolve(f"selector2._domainkey.{domain}", "CNAME")
    google_txt_task = dns_base.safe_resolve(f"google._domainkey.{domain}", "TXT")
    google_cname_task = dns_base.safe_resolve(f"google._domainkey.{domain}", "CNAME")
    esp_tasks = [dns_base.safe_resolve(f"{sel}._domainkey.{domain}", "CNAME") for sel, _, _, _ in _ESP_DKIM_SELECTORS]
    generic_dkim_tasks = [dns_base.safe_resolve(f"{sel}._domainkey.{domain}", "TXT") for sel in _GENERIC_DKIM_SELECTORS]

    all_results = await asyncio.gather(
        sel1_task,
        sel2_task,
        google_txt_task,
        google_cname_task,
        *esp_tasks,
        *generic_dkim_tasks,
    )

    esp_end = 4 + len(_ESP_DKIM_SELECTORS)
    sel1_results, sel2_results, google_txt_results, google_cname_results = all_results[:4]
    esp_results = all_results[4:esp_end]
    generic_dkim_results = all_results[esp_end:]

    _apply_exchange_dkim(ctx, (sel1_results, sel2_results))
    _apply_google_dkim(ctx, google_txt_results, google_cname_results)
    _apply_esp_dkim(ctx, _ESP_DKIM_SELECTORS, esp_results)
    _apply_generic_dkim(ctx, generic_dkim_results)


async def _parse_bimi_vmc(ctx: _DetectionCtx, bimi_txt: str) -> None:
    """Fetch the VMC PEM from a BIMI ``a=`` URL and extract corporate identity.

    BIMI TXT records may carry an ``a=`` tag pointing to a ``.pem`` VMC
    (Verified Mark Certificate). VMCs require strict legal verification, so the
    Subject fields are high-confidence corporate identity data. The fetch is
    SSRF-guarded and the parsed fields are control-stripped before they reach
    any sink.
    """
    a_url = _extract_bimi_vmc_url(bimi_txt)
    if a_url is None or not _bimi_vmc_url_is_safe(a_url):
        return

    try:
        async with _http_client(timeout=5.0) as client:
            resp = await client.get(a_url, follow_redirects=False)
            if resp.status_code != 200:
                return
            pem_data = resp.text

        org, country, state, locality = _parse_vmc_subject(pem_data)
        if not org:
            return
        # The VMC subject fields come from a PEM served at the attacker-
        # influenced a= URL. Strip control bytes before any panel / markdown /
        # MCP sink.
        org = strip_control_chars(org)
        ctx.bimi_identity = BIMIIdentity(
            organization=org,
            country=strip_control_chars(country) if country else None,
            state=strip_control_chars(state) if state else None,
            locality=strip_control_chars(locality) if locality else None,
            trademark=None,
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
    # Sort longest-first so the most specific pattern wins per rua address
    # (consistent with MX / NS / CAA / cname_target , see
    # filter_shadowed_matches).
    rua_patterns = sorted(get_dmarc_rua_patterns(), key=lambda d: -len(d.pattern))

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


def _apply_dmarc_pct(ctx: _DetectionCtx, raw_pct: str, domain: str) -> None:
    """Validate and record a DMARC ``pct=`` value (0-100), warning on bad input."""
    try:
        pct_val = int(raw_pct)
    except ValueError:
        logger.warning("DMARC pct= value %r is not a valid integer for %s - ignored", raw_pct, domain)
        return
    if 0 <= pct_val <= 100:
        ctx.dmarc_pct = pct_val
    else:
        logger.warning("DMARC pct= value %d out of range for %s - ignored", pct_val, domain)


def _apply_dmarc(ctx: _DetectionCtx, dmarc_results: list[str], domain: str) -> None:
    """Record DMARC presence, policy, pct, and rua mailto fingerprints."""
    for txt in dmarc_results:
        if not txt.lower().startswith("v=dmarc1"):
            continue
        ctx.services.add(SVC_DMARC)
        for part in txt.split(";"):
            cleaned = part.strip().lower()
            if cleaned.startswith("p="):
                ctx.dmarc_policy = cleaned[2:].strip()
            elif cleaned.startswith("pct="):
                _apply_dmarc_pct(ctx, cleaned[4:].strip(), domain)
        _extract_dmarc_rua(ctx, txt)


async def _apply_bimi(ctx: _DetectionCtx, bimi_results: list[str], domain: str) -> None:
    """Record BIMI presence and attempt best-effort VMC identity enrichment.

    BIMI presence is read from the DNS TXT record (passive). The VMC enrichment
    fetches the ``a=`` certificate URL, a direct request to a host the looked-up
    party influences, so it is gated behind ``ctx.active_probes`` (--direct-probes)
    and skipped by default. When it does run it must never abort the DNS source:
    anything it raises is caught and the BIMI detection plus the rest of the DNS
    intelligence is kept.
    """
    for txt in bimi_results:
        if "v=bimi1" in txt.lower():
            ctx.services.add(SVC_BIMI)
            if not ctx.active_probes:
                continue
            try:
                await _parse_bimi_vmc(ctx, txt)
            except Exception as exc:
                logger.debug("BIMI VMC enrichment failed for %s: %s", domain, exc)


async def _apply_mta_sts(ctx: _DetectionCtx, mta_sts_results: list[str], domain: str) -> None:
    """Record MTA-STS presence and, when the TXT fires, fetch the policy mode."""
    mta_sts_detected = any("v=stsv1" in txt.lower() for txt in mta_sts_results)
    if not mta_sts_detected:
        return
    ctx.services.add(SVC_MTA_STS)
    policy_mode = await _fetch_mta_sts_policy(domain)
    if policy_mode:
        ctx.mta_sts_mode = policy_mode
        if policy_mode == "enforce":
            ctx.slugs.add("mta-sts-enforce")


def _apply_tls_rpt(ctx: _DetectionCtx, tls_rpt_results: list[str]) -> None:
    """Record TLS-RPT presence."""
    for txt in tls_rpt_results:
        if "v=tlsrptv1" in txt.lower():
            ctx.add("TLS-RPT", "tls-rpt", source_type="TXT", raw_value=txt)
            break


async def _detect_email_security(ctx: _DetectionCtx, domain: str) -> None:
    """Check DMARC, BIMI, MTA-STS, and TLS-RPT records concurrently."""
    dmarc_results, bimi_results, mta_sts_results, tls_rpt_results = await asyncio.gather(
        dns_base.safe_resolve(f"_dmarc.{domain}", "TXT"),
        dns_base.safe_resolve(f"default._bimi.{domain}", "TXT"),
        dns_base.safe_resolve(f"_mta-sts.{domain}", "TXT"),
        dns_base.safe_resolve(f"_smtp._tls.{domain}", "TXT"),
    )
    _apply_dmarc(ctx, dmarc_results, domain)
    await _apply_bimi(ctx, bimi_results, domain)
    await _apply_mta_sts(ctx, mta_sts_results, domain)
    _apply_tls_rpt(ctx, tls_rpt_results)


async def _detect_ns(ctx: _DetectionCtx, domain: str) -> None:
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


async def _detect_cname_infra(ctx: _DetectionCtx, domain: str) -> None:
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


async def _detect_domain_connect(ctx: _DetectionCtx, domain: str) -> None:
    """Check _domainconnect CNAME for domain management provider."""
    for cname in await dns_base.safe_resolve(f"_domainconnect.{domain}", "CNAME"):
        cl = cname.lower()
        if "azure" in cl:
            ctx.services.add("Domain Connect (Azure)")
        elif "godaddy" in cl or "domaincontrol" in cl:
            ctx.services.add("Domain Connect (GoDaddy)")


async def _detect_hosting_from_a_record(ctx: _DetectionCtx, domain: str) -> None:
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
    for substring, name, slug, region_regex in _HOSTING_PTR_PATTERNS:
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


async def _detect_caa(ctx: _DetectionCtx, domain: str) -> None:
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


async def _detect_srv(ctx: _DetectionCtx, domain: str) -> None:
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
    # based detection in _detect_m365_cnames so they deduplicate naturally.
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


# ── Certificate Transparency (fallback chain) ──────────────────────────


def _apply_cached_cert_intel(ctx: _DetectionCtx, cached: CTCacheEntry, attribution: str) -> None:
    """Apply a CT cache entry to the context (shared by cache-first and fallback)."""
    ctx.related_domains.update(cached.subdomains)
    if cached.cert_summary is not None:
        ctx.cert_summary = cached.cert_summary
    ctx.ct_provider_used = attribution
    ctx.ct_subdomain_count = len(cached.subdomains)
    ctx.ct_cache_age_days = cached.age_days
    ctx.ct_attempt_outcome = "cache_hit"


async def _query_cert_providers(ctx: _DetectionCtx, domain: str) -> tuple[bool, str | None, dict[str, int]]:
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
            failures[_classify_ct_failure(exc)] += 1
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


async def _detect_cert_intel(ctx: _DetectionCtx, domain: str) -> None:
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
        ctx.ct_attempt_outcome = _ct_failure_outcome(failures)
        ctx.ct_subdomain_count = 0


# ── Common subdomain probing ───────────────────────────────────────────


async def _detect_common_subdomains(ctx: _DetectionCtx, domain: str) -> None:
    """Probe common subdomain prefixes for CNAME targets that reveal SaaS usage.

    This is the fallback/complement to crt.sh - works even when crt.sh is
    down, and catches high-signal subdomains that may not appear in CT logs
    (e.g., internal auth endpoints with private certs).

    Only checks CNAME records (not A/AAAA) - we want to discover what service
    the subdomain points to, not just that it exists. Subdomains that resolve
    to a CNAME are added to ctx.related_domains for enrichment.
    """

    async def _probe(prefix: str) -> str | None:
        fqdn = f"{prefix}.{domain}"
        results = await dns_base.safe_resolve(fqdn, "CNAME")
        if results:
            return fqdn
        return None

    probes = await asyncio.gather(*(_probe(p) for p in _COMMON_SUBDOMAIN_PREFIXES))

    found = [fqdn for fqdn in probes if fqdn is not None]
    if found:
        logger.debug("Common subdomain probing found %d for %s: %s", len(found), domain, ", ".join(found))
        ctx.related_domains.update(found)


async def _detect_exchange_onprem(ctx: _DetectionCtx, domain: str) -> None:
    """Detect on-prem / hybrid Microsoft Exchange deployments via
    OWA subdomain probing.

    When ``owa.<domain>``, ``mail.<domain>``, or similar Exchange-
    specific endpoints resolve, it's a strong signal that the org
    runs on-prem / hybrid Exchange (not Exchange Online). These
    orgs often self-host mail while still having an Entra ID /
    Azure AD tenant for identity - a very common higher-ed and
    institutional-nonprofit pattern.

    Without this detection, a domain with custom MX records and an
    OWA endpoint looks sparse to recon even though the actual
    answer ("runs Exchange on-prem") is observable from DNS alone.
    This fills that gap.

    Accepts A or CNAME resolution - on-prem Exchange typically
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
        "owa",  # Outlook Web Access
        "outlook",  # Outlook anywhere
        "exchange",  # Named Exchange endpoint
        "mail-ex",  # Less common but unambiguous
        "webmail",  # Often Exchange but could be Horde / Roundcube
        "autodiscover",  # Exchange autodiscover - standard Exchange
        # protocol, returned as CNAME for M365
        # (already detected) or as A for on-prem.
    )

    # Probe strategy:
    # - For `autodiscover`: query CNAME first. If the immediate CNAME
    #   target points to the M365 cloud (autodiscover.outlook.com or an
    #   outlook.com / office.com / cloud.microsoft suffix), suppress -
    #   that's Exchange Online, not on-prem. Only fall through to A when
    #   there's no CNAME (self-hosted autodiscover responder). Note that
    #   a plain A query chases CNAMEs through dnspython, so an A query
    #   alone returns IPs even for M365 cloud endpoints - that's why the
    #   CNAME check has to come first.
    # - For other prefixes (owa / outlook / exchange / mail-ex / webmail):
    #   A-or-CNAME. Those names are typically on-prem-only when they
    #   resolve at all.
    _M365_CLOUD_SUFFIXES = (
        "autodiscover.outlook.com",
        "outlook.com",
        "mail.protection.outlook.com",
        "office.com",
        "office365.com",
        "cloud.microsoft",
    )

    def _is_m365_cloud_target(target: str) -> bool:
        t = target.lower().rstrip(".")
        return any(t == s or t.endswith("." + s) for s in _M365_CLOUD_SUFFIXES)

    async def _probe(prefix: str) -> str | None:
        fqdn = f"{prefix}.{domain}"
        if prefix == "autodiscover":
            # autodiscover keeps its CNAME-first M365-cloud suppression.
            cname_results = await dns_base.safe_resolve(fqdn, "CNAME")
            if cname_results:
                target = cname_results[0].strip().lower().rstrip(".")
                if _is_m365_cloud_target(target):
                    return None  # M365 cloud autodiscover, not on-prem
                # Non-Microsoft CNAME: count it only when the target is a
                # public name. An internal-suffix target is a leak, not a
                # self-operated endpoint.
                return fqdn if _is_public_dns_name(target) else None
            # No CNAME: direct-A self-operated autodiscover. The A query
            # runs through _safe_resolve's canonical-name guard.
            return fqdn if await dns_base.safe_resolve(fqdn, "A") else None
        # owa / outlook / exchange / mail-ex / webmail: CNAME-first safe
        # resolution so an attacker-pointed prefix cannot drive an
        # A-query CNAME chase to an internal name.
        return fqdn if await _resolves_to_public_endpoint(fqdn) else None

    probes = await asyncio.gather(*(_probe(p) for p in exchange_prefixes))
    found = [fqdn for fqdn in probes if fqdn is not None]
    if not found:
        return

    # The strongest signals are owa / outlook / exchange /
    # autodiscover (A-only) - any of them means on-prem or
    # hybrid Exchange. `webmail` alone is too weak (could be
    # Roundcube / Horde / SquirrelMail) - skip when only it
    # is present.
    found_prefixes = {f.split(".", 1)[0] for f in found}
    strong_signals = {"owa", "outlook", "exchange", "mail-ex", "autodiscover"}
    has_strong_signal = bool(found_prefixes & strong_signals)
    if not has_strong_signal:
        return

    # Wildcard-DNS guard. Some apexes point ``*.<apex>`` at a single IP,
    # which causes every Exchange prefix above to resolve to the same
    # address. That's not Exchange - it's wildcard DNS, and firing on
    # it mislabels a web-only domain as running Exchange Server. Probe
    # a nonsense prefix: if it also
    # resolves, assume wildcard and suppress the detection.
    nonsense = f"this-is-not-a-real-host-xyz123.{domain}"
    if await _resolves_to_public_endpoint(nonsense):
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
        # CNAME-first via the safe helper. Self-hosted IdPs (direct A)
        # and SaaS-vendor IdPs (public CNAME) both count as resolving,
        # but a prefix the domain owner has delegated to an internal
        # name is not followed and does not leak. See
        # _resolves_to_public_endpoint.
        return fqdn if await _resolves_to_public_endpoint(fqdn) else None

    probes = await asyncio.gather(*(_probe(p) for p in _IDP_SUBDOMAIN_PREFIXES))
    found = [fqdn for fqdn in probes if fqdn is not None]
    if not found:
        return

    ctx.related_domains.update(found)
    # Classify: shibboleth / idp / wayf / sp are Shibboleth / SAML
    # family; okta is the Okta SaaS IdP; adfs is Microsoft.
    # Emit the service name using the same friendly form
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
        # Generic SSO hub - could be Entra ID, Okta, Shibboleth, CAS, or
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
    """Check only CNAME and TXT records for a subdomain - skip MX/NS/DKIM/SRV/crt.sh.

    Public API for the resolver's two-tier enrichment pipeline. Subdomains
    discovered via crt.sh or common-prefix probing don't need full DNS
    fingerprinting - CNAME and TXT are the high-signal record types.
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
        evidence=tuple(ctx.evidence),
    )


async def medium_subdomain_lookup(subdomain: str) -> SourceResult:
    """Extended subdomain probe for top-signal prefixes.

    Adds MX + DKIM probing on top of the lightweight CNAME + TXT. Used for
    the handful of subdomains that are most likely to publish their own
    email / SaaS verification records distinct from the apex: `auth.*`,
    `sso.*`, `login.*`, `idp.*`, `api.*`, `mail.*`. A tier between
    lightweight (everything else) and full lookup (separate domains).

    Still passive, still zero-creds - just probes more record types on a
    small cap of subdomains that reliably publish verification data.
    """
    ctx = _DetectionCtx()
    try:
        await asyncio.gather(
            _detect_cname_infra(ctx, subdomain),
            _detect_txt(ctx, subdomain),
            _detect_mx(ctx, subdomain),
            _detect_dkim(ctx, subdomain),
        )
    except Exception as exc:
        return SourceResult(source_name="dns_records", error=str(exc))
    return SourceResult(
        source_name="dns_records",
        detected_services=tuple(sorted(ctx.services)),
        detected_slugs=tuple(sorted(ctx.slugs)),
        evidence=tuple(ctx.evidence),
    )


# ── CNAME chain classifier (surface-attribution pipeline) ──────────────

# Hard caps for surface-attribution work. The DNS classifier is cheap (one
# CNAME query per related domain, 1-3 hops typical) but unbounded inputs
# warrant ceilings:
#   _SURFACE_MAX_HOSTS - most lookups stay under this; pathological CT
#     responses with thousands of subdomains get truncated rather than
#     paying full DNS cost.
#   _SURFACE_MAX_HOPS  - defends against CNAME chains that loop or stall
#     by giving up after a small number of hops.
#   _SURFACE_CONCURRENCY - bounds simultaneous DNS in flight so a large
#     related-domain set does not exhaust file descriptors or trip
#     resolver rate limits.
_SURFACE_MAX_HOSTS = 100
_SURFACE_MAX_HOPS = 5
_SURFACE_CONCURRENCY = 30


async def _resolves_to_public_endpoint(host: str) -> bool:
    """Return True when *host* resolves to a public endpoint, without
    turning an attacker-controlled subdomain into an internal-DNS oracle.

    Safe replacement for the A-first subdomain probes (IdP hub, on-prem
    Exchange, the wildcard guard). Those probes only need a yes/no
    "does this name resolve" signal, but an ``A`` / ``AAAA`` query makes
    the recursive resolver chase a CNAME server-side, so probing
    ``owa.<looked-up-domain>`` when the domain owner has pointed it at an
    internal name would query that internal name. Resolution discipline,
    mirroring the CNAME walker:

      1. Reject a non-public entry name before any query.
      2. CNAME query first (a CNAME query does not chase). A private
         CNAME target is rejected here, before any A/AAAA query fires,
         so the obvious attack costs zero internal queries. A public
         CNAME target means the name resolves publicly.
      3. Only when there is no CNAME do we issue A/AAAA, and that runs
         through ``_safe_resolve``'s canonical-name guard, so a
         type-dependent CNAME chase to a private name returns empty and
         is not reported.

    The boolean answer never carries the resolved name or address, so a
    rejected hop produces the same ``False`` as a name that does not
    resolve: no disclosure, no observable oracle.
    """
    if not _is_public_dns_name(host):
        return False
    cname = await dns_base.safe_resolve(host, "CNAME")
    if cname:
        target = cname[0].strip().lower().rstrip(".")
        return _is_public_dns_name(target)
    for rdtype in ("A", "AAAA"):
        if await dns_base.safe_resolve(host, rdtype):
            return True
    return False


async def _resolve_cname_chain(host: str, max_hops: int = _SURFACE_MAX_HOPS) -> list[str]:
    """Walk the CNAME chain for *host*, returning the list of targets.

    Returns an empty list when the host has no CNAME (typical for hosts
    with direct A records, or for stale CT entries that no longer
    resolve). Stops at *max_hops* to defend against pathological loops.

    **Attacker-controlled-target defenses (two layers).**

    1. **Entry-point validation.** ``host`` is checked
       against ``_is_public_dns_name`` before any query is issued.
       Names with private suffixes, IP literals, or single-label
       form are rejected without touching the resolver. The walker
       is invoked on entries from ``ctx.related_domains``, which is
       populated by several detectors; not every populator validates
       names before adding (see ``_detect_m365_cnames``
       redirect_domain extraction). Rejecting at the entry point
       removes the dependency on every populator getting it right.

    2. **Per-hop suffix denylist.** Every CNAME target
       returned by the resolver is validated against
       ``_is_public_dns_name`` before the walker continues. When the
       check fails, the walker stops at that hop without recording
       the rejected target.

    **Why this walker issues only CNAME queries.**
    The v1.9.4 audit established that calling A or AAAA on an
    attacker-influenced name causes the recursive resolver to chase
    deeper CNAMEs while answering, potentially querying
    private/internal names before the walker's suffix denylist has
    seen them. The v1.9.13 hardening pass added a terminus-only
    A/AAAA check, on the assumption that a prior CNAME query
    returning no results proved the terminus had no CNAME to chase.
    A 2026-05-17 scanner pass showed the assumption is wrong:
    authoritative DNS servers can return type-dependent answers, so
    a malicious server can answer the CNAME query for the terminus
    with NoAnswer while returning a CNAME to an internal name on
    the A or AAAA query. v1.9.14 reverts the terminus check and
    restores the v1.9.4 invariant: the walker issues CNAME queries
    only. CNAME queries do not cause recursive resolvers to chase
    further records; they return the immediate CNAME or nothing.

    The tradeoff is the same one v1.9.4 disclosed: dropping the
    A/AAAA check trades zero internal-DNS leakage during the walk
    against the loss of split-horizon detection on hops with
    public-looking suffixes that resolve to private addresses. The
    project errs on the side of zero leakage.
    """
    # Normalize the entry-point name before any further
    # use. Subsequent iterations work with lowercased targets
    # (the resolver's response is lowercased by ``_safe_resolve``),
    # so an unnormalized mixed-case host would slip through the
    # ``target == cur`` self-loop check on the first iteration.
    host = host.strip().lower().rstrip(".")
    # Entry-point validation. Reject the walk before issuing
    # any DNS query when ``host`` itself fails the public-suffix check.
    if not _is_public_dns_name(host):
        logger.debug(
            "CNAME chain walker: refusing non-public-suffix entry point %s",
            host,
        )
        return []

    chain: list[str] = []
    cur = host
    for _ in range(max_hops):
        results = await dns_base.safe_resolve(cur, "CNAME")
        if not results:
            break
        target = results[0].lower().rstrip(".")
        if not target or target == cur:
            break
        if not _is_public_dns_name(target):
            logger.debug(
                "CNAME chain walker: refusing non-public-suffix hop from %s -> %s",
                cur,
                target,
            )
            break
        chain.append(target)
        cur = target

    return chain


# Cap on total motif observations per lookup. Prevents a domain
# with hundreds of related subdomains from flooding the chain_motifs
# field. Per-chain motif count is bounded implicitly by the catalog size.
_MAX_CHAIN_MOTIF_OBSERVATIONS = 50


async def _classify_related_surface(ctx: _DetectionCtx, queried_domain: str) -> None:
    """Resolve CNAME chains for related domains and attribute services.

    Runs after the main detector gather populates ``ctx.related_domains``.
    For each related host (capped at ``_SURFACE_MAX_HOSTS``), walks the
    CNAME chain and matches every hop against the cname_target fingerprint
    catalog. Each successful classification:

      * appends a SurfaceAttribution (subdomain → primary service, plus
        the fronting infrastructure when both tiers matched);
      * unions the primary slug into ctx.slugs and the primary service
        name into ctx.services so the default panel surfaces the
        attribution without a new section;
      * emits an EvidenceRecord with the full chain for --explain.

    Application-tier matches always beat infrastructure-tier matches when
    a chain produces both - the primary attribution is the meaningful
    layer, and CDNs / load balancers fall to the supplementary slot.
    """
    rules = get_cname_target_rules()
    motifs_catalog = load_motifs()
    if not rules and not motifs_catalog:
        return

    # Sort longest-pattern-first so specific matches (e.g. ``cname.vercel-dns.com``)
    # win over substrings (``vercel.com``) when both would match the same hop.
    sorted_rules: tuple[Any, ...] = tuple(sorted(rules, key=lambda r: -len(r.pattern)))

    # Wildcard-DNS guard. Some apexes (kayak.com, certain higher-ed orgs)
    # answer every ``*.<apex>`` query with the same CNAME - typically a
    # CDN. Without this guard the common-subdomain and IDP-hub probes
    # generate dozens of fake "subdomains" that all CNAME to the same
    # target, and we mis-attribute every probed prefix as if the
    # subdomain genuinely existed and were intentionally pointed at a
    # SaaS. Probe a deliberately-bogus prefix; if it resolves and any
    # target's chain matches its terminal, that target is a wildcard
    # echo, not real evidence.
    wildcard_terminal: str | None = None
    nonsense_host = f"nonsense-classifier-guard-{int(time.time()) % 100000}.{queried_domain.lower()}"
    wildcard_chain = await _resolve_cname_chain(nonsense_host)
    if wildcard_chain:
        wildcard_terminal = wildcard_chain[-1]
        logger.debug(
            "Surface classifier: wildcard DNS detected on %s (terminal=%s) - filtering",
            queried_domain,
            wildcard_terminal,
        )

    targets = sorted(h for h in ctx.related_domains if h and "*" not in h and h != queried_domain.lower())
    if len(targets) > _SURFACE_MAX_HOSTS:
        logger.debug(
            "Surface classifier: %d related domains exceeds cap %d - truncating",
            len(targets),
            _SURFACE_MAX_HOSTS,
        )
        targets = targets[:_SURFACE_MAX_HOSTS]

    sem = asyncio.Semaphore(_SURFACE_CONCURRENCY)

    async def _process(host: str) -> tuple[str, list[str]] | None:
        # Isolate per-host failures: this gather runs after the main
        # detector gather and is awaited by _detect_services, so an
        # unhandled raise here would still abort the whole DNS source.
        # A failed host returns None and is skipped, like a no-chain host.
        try:
            async with sem:
                chain = await _resolve_cname_chain(host)
                if not chain:
                    return None
                # Filter wildcard echoes: when a host's terminal matches
                # the wildcard probe's terminal, the host is not genuinely
                # delegated - it just got the wildcard answer. Skip.
                if wildcard_terminal is not None and chain[-1] == wildcard_terminal:
                    return None
                return host, chain
        except Exception as exc:
            logger.debug("surface classifier failed for %s: %s", host, exc)
            return None

    results = await asyncio.gather(*(_process(h) for h in targets))

    for item in results:
        if item is None:
            continue
        host, chain = item

        # Motif matching runs alongside the rule-based classifier.
        # Motifs describe chain-shape (Cloudflare → AWS origin, etc.) and
        # complement single-hop application detection - they never
        # override it.
        if motifs_catalog and len(ctx.chain_motifs) < _MAX_CHAIN_MOTIF_OBSERVATIONS:
            for match in match_chain_motifs(chain, motifs_catalog, subdomain=host):
                ctx.chain_motifs.append(
                    ChainMotifObservation(
                        motif_name=match.motif_name,
                        display_name=match.display_name,
                        confidence=match.confidence,
                        subdomain=match.subdomain,
                        chain=match.chain,
                    )
                )
                if len(ctx.chain_motifs) >= _MAX_CHAIN_MOTIF_OBSERVATIONS:
                    break

        application, infrastructure = _classify_chain(chain, sorted_rules)
        if application is None and infrastructure is None:
            # Genuinely unclassified - preserve for the fingerprint-discovery
            # loop. The chain is real (wildcard echoes were filtered upstream)
            # and didn't match any cname_target rule, so it is a candidate
            # for a new fingerprint.
            ctx.unclassified_cname_chains.append(UnclassifiedCnameChain(subdomain=host, chain=tuple(chain)))
            continue

        primary = application if application is not None else infrastructure
        if primary is None:
            # Defensive: control flow above guarantees at least one match,
            # but the type checker can't prove it. Skip rather than crash.
            continue
        infra = infrastructure if (application is not None and infrastructure is not None) else None

        ctx.surface_attributions.append(
            SurfaceAttribution(
                subdomain=host,
                primary_slug=primary.slug,
                primary_name=primary.name,
                primary_tier=primary.tier,
                infra_slug=infra.slug if infra is not None else None,
                infra_name=infra.name if infra is not None else None,
            )
        )

        # Emit an EvidenceRecord so --explain and JSON consumers can trace
        # the resolution path. We deliberately do NOT union the slug or
        # service name into ctx.services / ctx.slugs: apex DNS evidence
        # and subdomain CNAME-chain evidence answer different questions
        # ("what does the org use" vs "what is each subdomain hosting"),
        # and conflating them in the apex Services block makes the default
        # panel double-count items that already show up under the
        # Subdomain summary line.
        chain_repr = f"{host}: " + " -> ".join(chain)
        ctx.evidence.append(
            EvidenceRecord(
                source_type="CNAME",
                raw_value=chain_repr,
                rule_name=primary.name,
                slug=primary.slug,
            )
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

        Recognized kwargs:
          * ``skip_ct`` - when True, skip the cert-transparency providers
            (crt.sh, CertSpotter). Discovery still runs the common-subdomain
            probe and apex CNAME walks. Useful for high-volume validation
            runs where users want zero CT load.
          * ``active_probes`` - when True, opt in to the BIMI VMC certificate
            fetch (a direct request to a target-influenced host). Off by
            default keeps the DNS source passive; BIMI presence is still
            detected from the TXT record either way.
        """
        skip_ct = bool(kwargs.get("skip_ct", False))
        active_probes = bool(kwargs.get("active_probes", False))
        try:
            ctx = await self._detect_services(domain, skip_ct=skip_ct, active_probes=active_probes)
        except Exception as exc:
            return SourceResult(
                source_name="dns_records",
                error=f"DNS error for {domain}: {exc}",
            )

        surface_tuple = tuple(sorted(ctx.surface_attributions, key=lambda s: s.subdomain))
        unclassified_tuple = tuple(sorted(ctx.unclassified_cname_chains, key=lambda u: u.subdomain))
        chain_motifs_tuple = tuple(sorted(ctx.chain_motifs, key=lambda m: (m.subdomain, m.motif_name)))

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
                ct_attempt_outcome=ctx.ct_attempt_outcome,
                raw_dns_records=tuple(
                    (rtype, val) for rtype, vals in sorted(ctx.raw_dns_records.items()) for val in vals
                ),
                surface_attributions=surface_tuple,
                unclassified_cname_chains=unclassified_tuple,
                chain_motifs=chain_motifs_tuple,
                infrastructure_clusters=ctx.infrastructure_clusters,
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
            ct_attempt_outcome=ctx.ct_attempt_outcome,
            raw_dns_records=tuple((rtype, val) for rtype, vals in sorted(ctx.raw_dns_records.items()) for val in vals),
            surface_attributions=surface_tuple,
            unclassified_cname_chains=unclassified_tuple,
            chain_motifs=chain_motifs_tuple,
            infrastructure_clusters=ctx.infrastructure_clusters,
        )

    @staticmethod
    async def _detect_services(domain: str, skip_ct: bool = False, active_probes: bool = False) -> _DetectionCtx:
        """Async service detection - runs all sub-detectors concurrently.

        Each sub-detector handles one DNS record type and writes results
        into the shared _DetectionCtx. Since all coroutines run on the
        same event loop (no threads), there are no race conditions on ctx.

        When ``skip_ct`` is True, the cert-transparency probe is omitted.
        Surface attribution still runs against the common-subdomain probe
        and any other CNAME-discovered hosts; only the CT-fed contributions
        are absent from related_domains.

        ``active_probes`` is recorded on the context so the BIMI VMC fetch
        (the one direct-to-target HTTP call in this source) runs only when the
        operator opted in; the default stays passive.
        """
        ctx = _DetectionCtx()
        ctx.active_probes = active_probes

        # Build the detector list as (name, coroutine) pairs. The name is a
        # stable label used for logging and degraded-source reporting (it
        # replaces fragile coroutine introspection). _detect_cert_intel is
        # skipped when skip_ct is True; the other sub-detectors run unchanged.
        detectors: list[tuple[str, Any]] = [
            ("txt", _detect_txt(ctx, domain)),
            ("mx", _detect_mx(ctx, domain)),
            ("m365_cnames", _detect_m365_cnames(ctx, domain)),
            ("gws_cnames", _detect_gws_cnames(ctx, domain)),
            ("dkim", _detect_dkim(ctx, domain)),
            ("email_security", _detect_email_security(ctx, domain)),
            ("ns", _detect_ns(ctx, domain)),
            ("cname_infra", _detect_cname_infra(ctx, domain)),
            ("domain_connect", _detect_domain_connect(ctx, domain)),
            ("subdomain_txt", _detect_subdomain_txt(ctx, domain)),
            ("caa", _detect_caa(ctx, domain)),
            ("srv", _detect_srv(ctx, domain)),
            ("common_subdomains", _detect_common_subdomains(ctx, domain)),
            ("hosting_a_record", _detect_hosting_from_a_record(ctx, domain)),
            ("idp_hub", _detect_idp_hub(ctx, domain)),
            ("exchange_onprem", _detect_exchange_onprem(ctx, domain)),
        ]
        if not skip_ct:
            detectors.append(("cert_intel", _detect_cert_intel(ctx, domain)))

        # Isolate each detector so one failure on crafted input degrades
        # gracefully instead of aborting the whole DNS source. A bare
        # asyncio.gather propagates the first exception up to
        # DNSSource.lookup, which converts it into a whole-source error and
        # discards every other detector's intelligence (this is the
        # v1.9.18 BIMI-port bug generalized: any detector raise nukes the
        # source). Each detector mutates the shared ctx in place, so a
        # partial contribution from a failing detector still survives.
        # BaseException (cancellation / KeyboardInterrupt) still propagates.
        #
        # A failed detector is recorded in degraded_sources (surfaced in
        # JSON / --explain output) and logged at warning level, so a real
        # regression that breaks a detector for every input is visible
        # rather than silently dropping that detector's intelligence.
        async def _isolate(name: str, coro: Any) -> None:
            try:
                await coro
            except Exception as exc:
                logger.warning("DNS detector %r failed for %s: %s", name, domain, exc)
                ctx.degraded_sources.add(f"detector:{name}")

        await asyncio.gather(*(_isolate(name, coro) for name, coro in detectors))

        # Remove the queried domain itself from related_domains
        ctx.related_domains.discard(domain.lower())

        # Surface-attribution pass. Runs after the main gather because it
        # depends on related_domains being fully populated by CT and the
        # common-subdomain probe.
        await _classify_related_surface(ctx, domain)

        # Post-process: enforce match_mode: all - remove partial matches
        ctx.enforce_match_mode_all()

        return ctx
