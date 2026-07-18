"""Email-channel DNS detectors: SPF/TXT, MX, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT.

Extracted from ``sources/dns.py`` (docs/roadmap.md god-file track). The
public ``detect_*`` entry points are orchestrated by ``DNSSource`` and the
surface classifier in ``dns.py`` (re-exported there under their original
underscore names). Imports the shared resolver/context from ``dns_base`` and
the static catalogs/parsers from ``dns_tables``; never imported by either.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import logging
import re
from urllib.parse import SplitResult, urlsplit

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DKIM_GOOGLE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.fingerprints import (
    Detection,
    filter_shadowed_matches,
    get_dmarc_rua_patterns,
    get_mx_patterns,
    get_spf_patterns,
    get_txt_patterns,
    match_txt_all,
)
from recon_tool.http import http_client as _http_client
from recon_tool.models import EvidenceRecord
from recon_tool.sources import dns_base
from recon_tool.sources.dns_tables import (
    ESP_DKIM_SELECTORS,
    GENERIC_DKIM_SELECTORS,
    bimi_vmc_url_is_safe,
    extract_bimi_vmc_url,
    is_public_dns_name,
)
from recon_tool.validator import host_has_suffix, strip_control_chars

logger = logging.getLogger("recon")

_REPORTING_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_SPF_TARGET_RE = re.compile(
    r"(?:^|\s)(?:[+?~-]?include:|redirect=)([^\s]+)",
    re.IGNORECASE,
)


def _record_spf_targets(
    ctx: dns_base.DetectionCtx,
    spf_text: str,
    patterns: tuple[Detection, ...],
) -> tuple[str, ...]:
    """Record and return normalized include and redirect targets."""
    targets: list[str] = []
    for match in _SPF_TARGET_RE.finditer(spf_text):
        target = match.group(1).strip().lower().rstrip(".")
        if not target:
            continue
        targets.append(target)
        classified = any(host_has_suffix(target, det.pattern.lower()) for det in patterns)
        ctx.record_catalog_observation("spf", "@", target, classified=classified)
    return tuple(targets)


def _matching_spf_patterns(
    targets: tuple[str, ...],
    patterns: tuple[Detection, ...],
) -> list[Detection]:
    """Return provider patterns that match a parsed SPF target by DNS labels."""
    return [det for det in patterns if any(host_has_suffix(target, det.pattern.lower()) for target in targets)]


async def detect_txt(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Scan TXT records for service fingerprints and SPF analysis."""
    txt_patterns = get_txt_patterns()
    spf_patterns = get_spf_patterns()

    ctx.record_catalog_query("txt")
    ctx.record_catalog_query("spf")
    txt_records = await dns_base.safe_resolve(
        domain,
        "TXT",
        degraded_sources=ctx.degraded_sources,
        degraded_name="dns:apex_txt",
    )
    ctx.raw_dns_records.setdefault("TXT", []).extend(txt_records)

    for txt in txt_records:
        txt_lower = txt.lower()

        txt_matches = match_txt_all(txt, txt_patterns)
        if not txt_lower.startswith("v=spf1"):
            ctx.record_catalog_observation("txt", "@", txt, classified=bool(txt_matches))
        if txt_matches:
            result = txt_matches[0]
            ctx.add(result.name, result.slug, source_type="TXT", raw_value=txt)
            for match in txt_matches:
                if match.slug == result.slug:
                    ctx.record_fp_match(match.slug, "txt", match.pattern)

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
            spf_targets = _record_spf_targets(ctx, txt_lower, spf_patterns)
            ctx.spf_include_count = max(ctx.spf_include_count, txt_lower.count("include:"))
            # SPF patterns match parsed include: and redirect= domains on DNS
            # label boundaries. A raw substring match would misattribute a
            # lookalike such as ``vendor.example.evil.test``.
            #
            # Multiple distinct vendors can legitimately fire on one SPF
            # record (e.g. M365 + Salesforce includes), so we accumulate
            # rather than break-on-first-match. We then apply
            # ``filter_shadowed_matches`` so that when a broad pattern
            # (e.g. ``cisco.com``) and a narrow one
            # (e.g. ``ess.cisco.com``) both match, only the narrow one's
            # slug fires , preventing double-counting of the same vendor.
            spf_matches = _matching_spf_patterns(spf_targets, spf_patterns)
            for det in filter_shadowed_matches(spf_matches):
                ctx.add(det.name, det.slug, source_type="SPF", raw_value=txt)
                ctx.record_fp_match(det.slug, "spf", det.pattern)
            if txt_lower.rstrip().endswith("-all"):
                ctx.services.add(SVC_SPF_STRICT)
                ctx.evidence.append(EvidenceRecord("SPF", txt, SVC_SPF_STRICT, "spf-strict"))
            elif txt_lower.rstrip().endswith("~all"):
                ctx.services.add(SVC_SPF_SOFTFAIL)
                ctx.evidence.append(EvidenceRecord("SPF", txt, SVC_SPF_SOFTFAIL, "spf-softfail"))
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
    # This block belongs to detect_txt, not _follow_spf_redirect.
    if ctx.spf_include_count >= 8:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes (large)")
    elif ctx.spf_include_count >= 4:
        ctx.services.add(f"SPF complexity: {ctx.spf_include_count} includes")


async def _follow_spf_redirect(ctx: dns_base.DetectionCtx, spf_text: str, depth: int, max_depth: int) -> None:
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
        # (is_public_dns_name) and refuse the hop before any query. The
        # check covers the recursive hop below too, since each recursion
        # re-enters here with the next target. Legitimate public targets
        # such as "_spf.mail.example.edu" pass unchanged. See
        # docs/security-audit-resolutions.md.
        if not is_public_dns_name(target):
            logger.debug(
                "SPF redirect chain: refusing non-public-suffix target %s",
                target,
            )
            return
        ctx.record_catalog_query("spf")
        target_records = await dns_base.safe_resolve(
            target,
            "TXT",
            degraded_sources=ctx.degraded_sources,
            degraded_name="dns:apex_txt",
        )
        patterns = get_spf_patterns()
        for record in target_records:
            rec_lower = record.strip().lower()
            if not rec_lower.startswith("v=spf1"):
                continue
            spf_targets = _record_spf_targets(ctx, rec_lower, patterns)
            # Run the same fingerprint pass on the target's SPF, with
            # specificity suppression for shadow patterns (see the
            # comment in detect_txt above).
            spf_matches = _matching_spf_patterns(spf_targets, patterns)
            for det in filter_shadowed_matches(spf_matches):
                ctx.add(det.name, det.slug, source_type="SPF", raw_value=record)
                ctx.record_fp_match(det.slug, "spf", det.pattern)
            # Propagate the policy qualifier from the redirect
            # target up to the origin - if _spf.mail.umich.edu
            # ends in -all, then umich.edu's SPF effectively ends
            # in -all via the redirect, and we credit the origin
            # with SPF strict.
            if rec_lower.rstrip().endswith("-all"):
                ctx.services.add(SVC_SPF_STRICT)
                ctx.evidence.append(EvidenceRecord("SPF", record, SVC_SPF_STRICT, "spf-strict"))
                return
            if rec_lower.rstrip().endswith("~all"):
                ctx.services.add(SVC_SPF_SOFTFAIL)
                ctx.evidence.append(EvidenceRecord("SPF", record, SVC_SPF_SOFTFAIL, "spf-softfail"))
                return
            # Chain continues: recurse one more hop.
            if "redirect=" in rec_lower:
                await _follow_spf_redirect(ctx, rec_lower, depth + 1, max_depth)
                return
    except Exception as exc:
        logger.debug("SPF redirect chain follow failed: %s", exc)


async def detect_mx(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Scan MX records for email provider and gateway detection.

    Passes source_type="MX" and the raw record so an EvidenceRecord is
    created - the email topology computation in merger.py filters evidence
    by source_type == "MX" to distinguish true primary providers (direct
    MX) from secondary residue (DKIM/TXT/identity endpoint).

    Emit a generic EvidenceRecord for EVERY MX host
    found, whether or not a fingerprint pattern matched. This lets
    downstream code distinguish "no MX records at all" (domain has no
    email) from "MX records exist but the host isn't in our fingerprint
    set" (the domain has custom or self-hosted email). Previously, a
    namespace with unclassified MX records looked identical to one with
    no MX records from the evidence perspective. The "generic MX evidence"
    carries an empty slug so it
    doesn't pollute the detected_slugs set.
    """
    ctx.record_catalog_query("mx")
    mx_records = await dns_base.safe_resolve(
        domain,
        "MX",
        degraded_sources=ctx.degraded_sources,
        degraded_name="dns:mx",
    )
    ctx.raw_dns_records.setdefault("MX", []).extend(mx_records)

    # Sort MX patterns longest-first so the most specific pattern wins per
    # MX record (the loop below stops at the first match). Without this,
    # a broader pattern listed earlier in the catalog could shadow a
    # narrower one (e.g. `cisco.com` shadowing `ess.cisco.com`).
    mx_patterns_sorted = sorted(get_mx_patterns(), key=lambda d: -len(d.pattern))

    unmatched_hosts: list[str] = []
    any_matched = False
    null_mx_observed = False
    for mx in mx_records:
        parts = mx.strip().split()
        if len(parts) >= 2 and parts[0] == "0" and parts[-1].rstrip(".") == "":
            ctx.record_catalog_observation("mx", "@", ".", classified=True)
            ctx.add(
                "Null MX (domain does not accept email)",
                "null-mx",
                source_type="MX",
                raw_value=mx,
            )
            null_mx_observed = True
            continue
        host = parts[-1].rstrip(".").lower() if parts else mx.lower().strip().rstrip(".")
        matched = False
        for det in mx_patterns_sorted:
            if host_has_suffix(host, det.pattern.lower()):
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
                    rule_name="Custom or unclassified MX host",
                    slug="",
                )
            )
            # Track unmatched MX hosts for the bounded unclassified-MX label.
            # MX record format is ``<priority> <host>`` - extract host.
            if len(parts) >= 2:
                unmatched_hosts.append(parts[-1].rstrip(".").lower())
        ctx.record_catalog_observation("mx", "@", host, classified=matched)

    # The compatibility slug is retained for serialized-cache stability, but
    # the observation does not infer who operates an unmatched MX host. It may
    # be self-managed, hosted by an uncatalogued provider, or delegated through
    # another public namespace. A Null MX is an explicit no-mail declaration,
    # not an unclassified delivery path.
    if unmatched_hosts and not any_matched and not null_mx_observed:
        ctx.add(
            "Custom or unclassified MX",
            "self-hosted-mail",
            source_type="MX",
            raw_value=", ".join(sorted(set(unmatched_hosts))),
        )


def _apply_exchange_dkim(ctx: dns_base.DetectionCtx, selector_groups: tuple[list[str], list[str]]) -> None:
    """Attribute Exchange Online DKIM and capture the onmicrosoft.com tenant domain."""
    for selector_results in selector_groups:
        for cname in selector_results:
            cl = cname.lower()
            host = cl.rstrip(".")
            if host_has_suffix(host, "protection.outlook.com") or host_has_suffix(host, "onmicrosoft.com"):
                ctx.add(SVC_DKIM_EXCHANGE, "microsoft365", source_type="DKIM", raw_value=cname)
                ctx.m365 = True
                if host_has_suffix(host, "onmicrosoft.com"):
                    parts = host.split("._domainkey.")
                    if len(parts) == 2 and host_has_suffix(parts[1], "onmicrosoft.com") and "." in parts[1]:
                        ctx.related_domains.add(parts[1])
                break


def _apply_google_dkim(ctx: dns_base.DetectionCtx, txt_results: list[str], cname_results: list[str]) -> None:
    """Attribute Google Workspace DKIM. TXT first, then CNAME delegation.

    source_type="DKIM" is required for the email-topology inference in
    merger.py to recognise this as downstream-provider evidence when MX
    points to a gateway (Proofpoint, etc.).
    """
    for record in txt_results:
        if "v=dkim1" in record.lower():
            ctx.services.add(SVC_DKIM)
            ctx.add(SVC_DKIM_GOOGLE, "google-workspace", source_type="DKIM", raw_value=record)
            return
    for cname in cname_results:
        host = cname.lower().rstrip(".")
        if host_has_suffix(host, "google.com"):
            ctx.services.add(SVC_DKIM)
            ctx.add(SVC_DKIM_GOOGLE, "google-workspace", source_type="DKIM", raw_value=cname)
            return


def _apply_esp_dkim(
    ctx: dns_base.DetectionCtx,
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


def _apply_generic_dkim(ctx: dns_base.DetectionCtx, generic_results: list[list[str]]) -> None:
    """Confirm DKIM exists via generic selectors when no provider-specific DKIM fired.

    Only feeds the email-security score; does not attribute a provider.
    """
    if SVC_DKIM in ctx.services:
        return
    for txt_records in generic_results:
        for record in txt_records:
            if "v=dkim1" in record.lower():
                ctx.services.add(SVC_DKIM)
                ctx.evidence.append(EvidenceRecord("DKIM", record, SVC_DKIM, "dkim"))
                return


async def detect_dkim(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Check DKIM selectors for Exchange Online, Google, and common providers.

    Exchange uses selector1/selector2, Google uses 'google', and many ESPs
    use 's1'/'s2', 'k1', 'default', 'dkim', 'mail', or 'em' selectors. Fires
    all the common selector probes concurrently, then applies each provider's
    attribution. Also extracts the onmicrosoft.com domain from Exchange DKIM
    CNAMEs, which reveals the tenant's internal domain name.
    """

    def resolve_selector(selector: str, rdtype: str):
        return dns_base.safe_resolve(
            f"{selector}._domainkey.{domain}",
            rdtype,
            degraded_sources=ctx.degraded_sources,
            degraded_name="dns:dkim",
        )

    sel1_task = resolve_selector("selector1", "CNAME")
    sel2_task = resolve_selector("selector2", "CNAME")
    google_txt_task = resolve_selector("google", "TXT")
    google_cname_task = resolve_selector("google", "CNAME")
    esp_tasks = [resolve_selector(sel, "CNAME") for sel, _, _, _ in ESP_DKIM_SELECTORS]
    generic_dkim_tasks = [resolve_selector(sel, "TXT") for sel in GENERIC_DKIM_SELECTORS]

    all_results = await asyncio.gather(
        sel1_task,
        sel2_task,
        google_txt_task,
        google_cname_task,
        *esp_tasks,
        *generic_dkim_tasks,
    )

    esp_end = 4 + len(ESP_DKIM_SELECTORS)
    sel1_results, sel2_results, google_txt_results, google_cname_results = all_results[:4]
    esp_results = all_results[4:esp_end]
    generic_dkim_results = all_results[esp_end:]

    _apply_exchange_dkim(ctx, (sel1_results, sel2_results))
    _apply_google_dkim(ctx, google_txt_results, google_cname_results)
    _apply_esp_dkim(ctx, ESP_DKIM_SELECTORS, esp_results)
    _apply_generic_dkim(ctx, generic_dkim_results)


async def _parse_bimi_vmc(ctx: dns_base.DetectionCtx, bimi_txt: str) -> None:
    """Fetch and parse the certificate document named by BIMI ``a=``.

    Certificate syntax alone does not establish a trusted chain or the VMC
    profile. Record the document as an observation, but never promote its
    attacker-supplied subject fields to corporate identity.
    """
    a_url = extract_bimi_vmc_url(bimi_txt)
    if a_url is None or not bimi_vmc_url_is_safe(a_url):
        return

    try:
        async with _http_client(timeout=5.0) as client:
            resp = await client.get(a_url, follow_redirects=False)
            if resp.status_code != 200:
                return
            pem_data = resp.text

        if not _has_certificate_pem_shape(pem_data):
            return
        ctx.slugs.add("bimi-vmc")
        ctx.evidence.append(
            EvidenceRecord(
                source_type="HTTP",
                raw_value="BIMI certificate document observed",
                rule_name="BIMI certificate document",
                slug="bimi-vmc",
            )
        )
    except Exception as exc:
        logger.debug("BIMI VMC parsing failed: %s", exc)


def _has_certificate_pem_shape(pem_data: str) -> bool:
    """Return whether text has one bounded PEM certificate envelope."""
    lines = pem_data.strip().splitlines()
    if len(lines) < 3:
        return False
    if lines[0] != "-----BEGIN CERTIFICATE-----" or lines[-1] != "-----END CERTIFICATE-----":
        return False
    encoded = "".join(line.strip() for line in lines[1:-1])
    try:
        der = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(der) >= 2 and der[0] == 0x30


async def _fetch_mta_sts_policy(domain: str, degraded_sources: set[str] | None = None) -> str | None:
    """Fetch MTA-STS policy mode from the well-known endpoint.

    Returns the policy mode ("enforce", "testing", "none") or None
    if the policy file is unavailable or malformed. Transport failures and
    transient HTTP responses are recorded as degraded collection. Stable HTTP
    responses such as 404 remain observed invalid policy states, so callers can
    distinguish an unavailable channel from observed non-enforcement.
    """
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        async with _http_client(timeout=5.0) as client:
            resp = await client.get(url)
            if resp.status_code in (408, 429) or 500 <= resp.status_code <= 599:
                if degraded_sources is not None:
                    degraded_sources.add("http:mta_sts_policy")
                logger.debug("MTA-STS policy fetch returned transient HTTP %d for %s", resp.status_code, domain)
                return None
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    stripped = line.strip().lower()
                    if stripped.startswith("mode:"):
                        mode = stripped.split(":", 1)[1].strip()
                        if mode in ("enforce", "testing", "none"):
                            return mode
    except Exception as exc:
        if degraded_sources is not None:
            degraded_sources.add("http:mta_sts_policy")
        logger.debug("MTA-STS policy fetch failed for %s: %s", domain, exc)
    return None


# The rua tag value is a comma-separated list of DMARC aggregate report URIs,
# as specified by RFC 9990. Each parsed item is URI-validated before a mailto
# path can contribute vendor evidence.
_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_INVALID_URI_CHAR_RE = re.compile(r"[\x00-\x20\x7f]")
_INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_URI_PATH_RE = re.compile(r"^[A-Za-z0-9._~$&'()*+,;=:@%/-]*$")
_URI_QUERY_FRAGMENT_RE = re.compile(r"^[A-Za-z0-9._~$&'()*+,;=:@%/?-]*$")
_URI_USERINFO_RE = re.compile(r"^[A-Za-z0-9._~$&'()*+,;=:%-]*$")
_URI_REG_NAME_RE = re.compile(r"^[A-Za-z0-9._~$&'()*+,;=%-]*$")
_IPV_FUTURE_RE = re.compile(r"^[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~$&'()*+,;=:-]+$")
_UPPER_IPV_FUTURE_RE = re.compile(r"(://(?:[^/?#]*@)?\[)V(?=[0-9A-Fa-f]+\.)")
_ASCII_PORT_RE = re.compile(r"^[0-9]*$")
_OBSOLETE_REPORT_SIZE_RE = re.compile(r"![0-9]+[kmgt]?$", re.IGNORECASE)

_DMARC_POLICY_VALUES = frozenset({"none", "quarantine", "reject"})
_DMARC_TESTING_VALUES = frozenset({"n", "y"})


def extract_dmarc_rua(
    ctx: dns_base.DetectionCtx,
    dmarc_record: str,
    *,
    tags: dict[str, str] | None = None,
) -> None:
    """Extract rua=mailto: addresses and match vendor domains against fingerprints."""

    parsed_tags = tags if tags is not None else parse_dmarc_tags(dmarc_record, "unknown")
    rua_value = parsed_tags.get("rua") if parsed_tags is not None else None
    matches = [
        addr
        for uri in (_dmarc_uri_items(rua_value) if rua_value is not None else ())
        if (addr := _reporting_mailto_address(uri)) is not None
    ]
    # Sort longest-first so the most specific pattern wins per rua address
    # (consistent with MX / NS / CAA / cname_target , see
    # filter_shadowed_matches).
    rua_patterns = sorted(get_dmarc_rua_patterns(), key=lambda d: -len(d.pattern))

    for addr in matches:
        # Extract domain portion from email address
        local, separator, rua_domain = addr.rpartition("@")
        if not separator or not local or "@" in local or not rua_domain:
            continue
        rua_domain = rua_domain.lower()
        labels = rua_domain.split(".")
        if (
            len(rua_domain) > 253
            or len(labels) < 2
            or any(_REPORTING_DOMAIN_LABEL_RE.fullmatch(label) is None for label in labels)
        ):
            continue

        # Match against dmarc_rua fingerprint patterns
        classified = False
        for det in rua_patterns:
            if host_has_suffix(rua_domain, det.pattern.lower()):
                ctx.add(
                    det.name,
                    det.slug,
                    source_type="DMARC_RUA",
                    raw_value=f"rua=mailto:{addr}",
                )
                ctx.record_fp_match(det.slug, "dmarc_rua", det.pattern)
                classified = True
                break  # first match wins per RUA address
        ctx.record_catalog_observation("dmarc_rua", "_dmarc", rua_domain, classified=classified)


def _parse_dmarc_pct(raw_pct: str, domain: str) -> int | None:
    """Validate a DMARC ``pct=`` value (0-100), warning on bad input."""
    if re.fullmatch(r"-[0-9]{1,3}", raw_pct):
        logger.warning("DMARC pct= value %d out of range for %s - ignored", int(raw_pct), domain)
        return None
    if not re.fullmatch(r"[0-9]{1,3}", raw_pct):
        logger.warning("DMARC pct= value %r is not a valid integer for %s - ignored", raw_pct, domain)
        return None
    pct_val = int(raw_pct)
    if 0 <= pct_val <= 100:
        return pct_val
    logger.warning("DMARC pct= value %d out of range for %s - ignored", pct_val, domain)
    return None


def parse_dmarc_policy(raw_policy: str, domain: str) -> str | None:
    """Validate a DMARC ``p=`` policy."""
    return _parse_dmarc_request(raw_policy, domain, tag="p")


def _parse_dmarc_request(raw_policy: str, domain: str, *, tag: str) -> str | None:
    """Validate one DMARC request value and name the source tag in diagnostics."""
    policy = raw_policy.lower()
    if policy in _DMARC_POLICY_VALUES:
        return policy
    logger.warning("DMARC %s= value %r is not a valid policy for %s - ignored", tag, raw_policy, domain)
    return None


def _parse_dmarc_np(raw_np: str, domain: str) -> str | None:
    """Validate RFC 9989 ``np=`` for non-existent subdomain policy."""
    return _parse_dmarc_request(raw_np, domain, tag="np")


def _parse_dmarc_testing(raw_testing: str, domain: str) -> bool | None:
    """Validate RFC 9989 ``t=`` testing mode."""
    testing = raw_testing.lower()
    if testing not in _DMARC_TESTING_VALUES:
        logger.warning("DMARC t= value %r is not valid for %s - ignored", raw_testing, domain)
        return None
    return testing == "y"


def parse_dmarc_tags(dmarc_record: str, domain: str) -> dict[str, str] | None:
    """Parse a DMARC tag list, rejecting duplicate tag names."""
    tags: dict[str, str] = {}
    parts = dmarc_record.split(";")
    for index, part in enumerate(parts):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        key = key.strip(" \t").lower()
        if key in tags:
            logger.warning("DMARC record for %s contains duplicate %s= tag - ignored", domain, key)
            return None
        value = value.lstrip(" \t")
        tags[key] = value.rstrip(" \t") if index < len(parts) - 1 else value
    return tags


def leading_dmarc_version_value(dmarc_record: str) -> str | None:
    """Return the leading DMARC version value using RFC 9989 ASCII WSP."""
    first_tag = dmarc_record.split(";", 1)[0]
    if first_tag.startswith((" ", "\t")):
        if "=" in first_tag and first_tag.lstrip(" \t").lower().startswith("v"):
            return first_tag
        return None
    key, separator, value = first_tag.partition("=")
    if not separator:
        return None
    if key.rstrip(" \t").lower() != "v":
        return first_tag if key.strip().lower().startswith("v") else None
    value = value.lstrip(" \t")
    return value.rstrip(" \t") if ";" in dmarc_record else value


def _valid_uri_ip_literal(literal: str) -> bool:
    if "%" in literal:
        return False
    try:
        ipaddress.IPv6Address(literal)
        return True
    except ValueError:
        return bool(_IPV_FUTURE_RE.fullmatch(literal))


def _valid_uri_authority(netloc: str) -> bool:
    userinfo, separator, host_port = netloc.rpartition("@")
    if separator and not _URI_USERINFO_RE.fullmatch(userinfo):
        return False
    if host_port.startswith("["):
        close = host_port.find("]")
        suffix = host_port[close + 1 :] if close >= 0 else "invalid"
        valid_suffix = not suffix or (suffix.startswith(":") and bool(_ASCII_PORT_RE.fullmatch(suffix[1:])))
        if close < 0 or not valid_suffix:
            return False
        return _valid_uri_ip_literal(host_port[1:close])
    if "[" in host_port or "]" in host_port:
        return False
    host, separator, port = host_port.rpartition(":")
    if not separator:
        host = host_port
    return (
        ":" not in host
        and (not separator or bool(_ASCII_PORT_RE.fullmatch(port)))
        and bool(_URI_REG_NAME_RE.fullmatch(host))
    )


def _parse_reporting_uri(raw_uri: str) -> SplitResult | None:
    """Return one syntax-checked RFC 3986 URI with legacy size removed."""
    candidate = _OBSOLETE_REPORT_SIZE_RE.sub("", raw_uri.lstrip(" \t"))
    if (
        not candidate
        or not candidate.isascii()
        or "!" in candidate
        or _INVALID_URI_CHAR_RE.search(candidate)
        or _INVALID_PERCENT_ESCAPE_RE.search(candidate)
        or not _URI_SCHEME_RE.match(candidate)
    ):
        return None
    try:
        parsed = urlsplit(_UPPER_IPV_FUTURE_RE.sub(r"\1v", candidate, count=1))
    except ValueError:
        return None
    components_valid = (
        bool(parsed.scheme)
        and bool(_URI_PATH_RE.fullmatch(parsed.path))
        and bool(_URI_QUERY_FRAGMENT_RE.fullmatch(parsed.query))
        and bool(_URI_QUERY_FRAGMENT_RE.fullmatch(parsed.fragment))
    )
    if not components_valid or (parsed.netloc and not _valid_uri_authority(parsed.netloc)):
        return None
    return parsed


def _valid_reporting_uri(raw_uri: str) -> bool:
    """Conservatively recognize one syntactically usable RFC 3986 URI."""
    return _parse_reporting_uri(raw_uri) is not None


def _reporting_mailto_address(raw_uri: str) -> str | None:
    """Return only a validated mailto URI path, excluding query and fragment."""
    parsed = _parse_reporting_uri(raw_uri)
    if parsed is None:
        return None
    return parsed.path if parsed.scheme.lower() == "mailto" else None


def _dmarc_uri_items(raw_value: str) -> tuple[str, ...]:
    """Normalize only URI-list WSP around commas, preserving final-value WSP."""
    parts = raw_value.split(",")
    return tuple(
        part.lstrip(" \t").rstrip(" \t") if index < len(parts) - 1 else part.lstrip(" \t")
        for index, part in enumerate(parts)
    )


def _has_valid_dmarc_rua(tags: dict[str, str]) -> bool:
    raw_rua = tags.get("rua")
    return bool(raw_rua and any(_valid_reporting_uri(value) for value in _dmarc_uri_items(raw_rua)))


def _resolve_dmarc_policy(tags: dict[str, str], domain: str) -> tuple[str | None, bool]:
    """Return the applicable policy and whether it came from valid explicit ``p``."""
    raw_policy = tags.get("p")
    policy = parse_dmarc_policy(raw_policy, domain) if raw_policy is not None else None
    invalid_subdomain_policy = any(
        tag in tags and _parse_dmarc_request(tags[tag], domain, tag=tag) is None for tag in ("sp", "np")
    )
    if policy is not None and not invalid_subdomain_policy:
        return policy, True
    if _has_valid_dmarc_rua(tags):
        return "none", False
    logger.warning(
        "DMARC record for %s has no applicable policy and no valid rua= fallback - ignored",
        domain,
    )
    return None, False


def parse_explicit_dmarc_policy_record(dmarc_record: str, domain: str) -> str | None:
    """Return an explicit policy only when the whole record is applicable."""
    if leading_dmarc_version_value(dmarc_record) != "DMARC1":
        return None
    tags = parse_dmarc_tags(dmarc_record, domain)
    if tags is None or "p" not in tags:
        return None
    explicit = parse_dmarc_policy(tags["p"], domain)
    effective, explicitly_applicable = _resolve_dmarc_policy(tags, domain)
    return explicit if explicitly_applicable and explicit == effective else None


def _record_non_policy_dmarc_evidence(
    ctx: dns_base.DetectionCtx,
    records: list[tuple[str, dict[str, str] | None]],
) -> None:
    """Retain observed DMARC-shaped records without awarding policy credit."""
    for record, _ in records:
        ctx.evidence.append(
            EvidenceRecord(
                "DMARC",
                record,
                "DMARC record observed without one valid policy",
                "dmarc-invalid",
            )
        )


def _apply_dmarc(ctx: dns_base.DetectionCtx, dmarc_results: list[str], domain: str) -> None:
    """Record DMARC presence, policy tags, and rua mailto fingerprints."""
    records: list[tuple[str, dict[str, str] | None]] = []
    for txt in dmarc_results:
        version = leading_dmarc_version_value(txt)
        if version == "DMARC1":
            records.append((txt, parse_dmarc_tags(txt, domain)))
        elif version is not None:
            logger.warning("DMARC v= value %r is not valid for %s - ignored", version, domain)

    if len(records) > 1:
        logger.warning("Multiple DMARC records found for %s - ignored", domain)
        _record_non_policy_dmarc_evidence(ctx, records)
        return
    for txt, tags in records:
        if tags is None:
            _record_non_policy_dmarc_evidence(ctx, records)
            continue
        applicable_policy, explicitly_applicable = _resolve_dmarc_policy(tags, domain)
        if applicable_policy is None:
            _record_non_policy_dmarc_evidence(ctx, records)
            continue
        ctx.services.add(SVC_DMARC)
        ctx.evidence.append(EvidenceRecord("DMARC", txt, SVC_DMARC, "dmarc"))
        explicit_policy = parse_dmarc_policy(tags["p"], domain) if "p" in tags else None
        ctx.dmarc_policy = explicit_policy if explicitly_applicable else None
        if (value := tags.get("pct")) is not None and (pct := _parse_dmarc_pct(value, domain)) is not None:
            ctx.dmarc_pct = pct
        if (value := tags.get("np")) is not None and (dmarc_np := _parse_dmarc_np(value, domain)) is not None:
            ctx.dmarc_np = dmarc_np
        if (value := tags.get("t")) is not None and (testing := _parse_dmarc_testing(value, domain)) is not None:
            ctx.dmarc_testing = testing
        extract_dmarc_rua(ctx, txt, tags=tags)


async def _apply_bimi(ctx: dns_base.DetectionCtx, bimi_results: list[str], domain: str) -> None:
    """Record BIMI presence and optionally observe its certificate document.

    BIMI presence is read from the DNS TXT record (passive). The document fetch
    fetches the ``a=`` certificate URL, a direct request to a host the looked-up
    party influences, so it is gated behind ``ctx.active_probes`` (--direct-probes)
    and skipped by default. Subject identity is not trusted without chain and
    VMC-profile validation. When the fetch runs it must never abort the DNS source:
    anything it raises is caught and the BIMI detection plus the rest of the DNS
    intelligence is kept.
    """
    for txt in bimi_results:
        if "v=bimi1" in txt.lower():
            ctx.services.add(SVC_BIMI)
            ctx.evidence.append(EvidenceRecord("BIMI", txt, SVC_BIMI, "bimi"))
            if not ctx.active_probes:
                continue
            try:
                await _parse_bimi_vmc(ctx, txt)
            except Exception as exc:
                logger.debug("BIMI VMC enrichment failed for %s: %s", domain, exc)


async def _apply_mta_sts(ctx: dns_base.DetectionCtx, mta_sts_results: list[str], domain: str) -> None:
    """Record MTA-STS presence and, when the TXT fires, fetch the policy mode."""
    mta_sts_detected = any("v=stsv1" in txt.lower() for txt in mta_sts_results)
    if not mta_sts_detected:
        return
    ctx.services.add(SVC_MTA_STS)
    mta_sts_txt = next(txt for txt in mta_sts_results if "v=stsv1" in txt.lower())
    ctx.evidence.append(EvidenceRecord("MTA_STS", mta_sts_txt, SVC_MTA_STS, "mta-sts"))
    policy_mode = await _fetch_mta_sts_policy(domain, ctx.degraded_sources)
    if policy_mode:
        ctx.mta_sts_mode = policy_mode
        policy_slug = "mta-sts-enforce" if policy_mode == "enforce" else "mta-sts"
        ctx.evidence.append(EvidenceRecord("MTA_STS_POLICY", f"mode: {policy_mode}", SVC_MTA_STS, policy_slug))
        if policy_mode == "enforce":
            ctx.slugs.add("mta-sts-enforce")


def _apply_tls_rpt(ctx: dns_base.DetectionCtx, tls_rpt_results: list[str]) -> None:
    """Record TLS-RPT presence."""
    for txt in tls_rpt_results:
        if "v=tlsrptv1" in txt.lower():
            ctx.add("TLS-RPT", "tls-rpt", source_type="TXT", raw_value=txt)
            break


async def detect_email_security(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Check DMARC, BIMI, MTA-STS, and TLS-RPT records concurrently."""
    ctx.record_catalog_query("dmarc_rua")
    dmarc_results, bimi_results, mta_sts_results, tls_rpt_results = await asyncio.gather(
        dns_base.safe_resolve(
            f"_dmarc.{domain}",
            "TXT",
            degraded_sources=ctx.degraded_sources,
            degraded_name="dns:dmarc",
        ),
        dns_base.safe_resolve(
            f"default._bimi.{domain}",
            "TXT",
            degraded_sources=ctx.degraded_sources,
            degraded_name="dns:bimi",
        ),
        dns_base.safe_resolve(
            f"_mta-sts.{domain}",
            "TXT",
            degraded_sources=ctx.degraded_sources,
            degraded_name="dns:mta_sts",
        ),
        dns_base.safe_resolve(
            f"_smtp._tls.{domain}",
            "TXT",
            degraded_sources=ctx.degraded_sources,
            degraded_name="dns:tls_rpt",
        ),
    )
    _apply_dmarc(ctx, dmarc_results, domain)
    await _apply_bimi(ctx, bimi_results, domain)
    await _apply_mta_sts(ctx, mta_sts_results, domain)
    _apply_tls_rpt(ctx, tls_rpt_results)
