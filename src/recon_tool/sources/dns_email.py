"""Email-channel DNS detectors: SPF/TXT, MX, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT.

Extracted from ``sources/dns.py`` (docs/roadmap.md god-file track). The
public ``detect_*`` entry points are orchestrated by ``DNSSource`` and the
surface classifier in ``dns.py`` (re-exported there under their original
underscore names). Imports the shared resolver/context from ``dns_base`` and
the static catalogs/parsers from ``dns_tables``; never imported by either.
"""

from __future__ import annotations

import asyncio
import logging
import re

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.fingerprints import (
    filter_shadowed_matches,
    get_dmarc_rua_patterns,
    get_mx_patterns,
    get_spf_patterns,
    get_txt_patterns,
    match_txt_all,
)
from recon_tool.http import http_client as _http_client
from recon_tool.models import BIMIIdentity, EvidenceRecord
from recon_tool.sources import dns_base
from recon_tool.sources.dns_tables import (
    ESP_DKIM_SELECTORS,
    GENERIC_DKIM_SELECTORS,
    bimi_vmc_url_is_safe,
    extract_bimi_vmc_url,
    is_public_dns_name,
    parse_vmc_subject,
)
from recon_tool.validator import host_has_suffix, strip_control_chars

logger = logging.getLogger("recon")


async def detect_txt(ctx: dns_base.DetectionCtx, domain: str) -> None:
    """Scan TXT records for service fingerprints and SPF analysis."""
    txt_patterns = get_txt_patterns()
    spf_patterns = get_spf_patterns()

    txt_records = await dns_base.safe_resolve(domain, "TXT")
    ctx.raw_dns_records.setdefault("TXT", []).extend(txt_records)

    for txt in txt_records:
        txt_lower = txt.lower()

        txt_matches = match_txt_all(txt, txt_patterns)
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
            ctx.spf_include_count = max(ctx.spf_include_count, txt_lower.count("include:"))
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
        target_records = await dns_base.safe_resolve(target, "TXT")
        patterns = get_spf_patterns()
        for record in target_records:
            rec_lower = record.strip().lower()
            if not rec_lower.startswith("v=spf1"):
                continue
            # Run the same fingerprint pass on the target's SPF, with
            # specificity suppression for shadow patterns (see the
            # comment in detect_txt above).
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
            ctx.add("DKIM (Google Workspace)", "google-workspace", source_type="DKIM", raw_value=record)
            return
    for cname in cname_results:
        host = cname.lower().rstrip(".")
        if host_has_suffix(host, "google.com"):
            ctx.services.add(SVC_DKIM)
            ctx.add("DKIM (Google Workspace)", "google-workspace", source_type="DKIM", raw_value=cname)
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
                return


async def detect_dkim(ctx: dns_base.DetectionCtx, domain: str) -> None:
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
    esp_tasks = [dns_base.safe_resolve(f"{sel}._domainkey.{domain}", "CNAME") for sel, _, _, _ in ESP_DKIM_SELECTORS]
    generic_dkim_tasks = [dns_base.safe_resolve(f"{sel}._domainkey.{domain}", "TXT") for sel in GENERIC_DKIM_SELECTORS]

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
    """Fetch the VMC PEM from a BIMI ``a=`` URL and extract corporate identity.

    BIMI TXT records may carry an ``a=`` tag pointing to a ``.pem`` VMC
    (Verified Mark Certificate). VMCs require strict legal verification, so the
    Subject fields are high-confidence corporate identity data. The fetch is
    SSRF-guarded and the parsed fields are control-stripped before they reach
    any sink.
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

        org, country, state, locality = parse_vmc_subject(pem_data)
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


# The rua tag value is a comma-separated list of DMARC aggregate report URIs,
# as specified by RFC 9990,
# e.g. ``rua=mailto:a@x.com,mailto:b@y.com``. Capture the whole tag value (up to
# the next tag separator), then pull each mailto address out of it, so the
# second and later addresses are not dropped. Scoping to the ``rua=`` tag keeps
# ``ruf=`` (forensic) addresses out.
_RUA_TAG_RE = re.compile(r"rua\s*=\s*([^;]+)", re.IGNORECASE)
# Stop the address capture at ``!``: RFC 9990 preserves the optional
# ``!<size>`` report-size suffix (e.g. ``mailto:a@x.com!10m``), and a literal
# ``!`` inside the address itself is percent-encoded, so an unescaped ``!``
# always delimits the size.
_RUA_MAILTO_RE = re.compile(r"(?:^|,)\s*mailto:([^,;\s!]+)", re.IGNORECASE)

_DMARC_POLICY_VALUES = frozenset({"none", "quarantine", "reject"})
_DMARC_TESTING_VALUES = frozenset({"n", "y"})


def extract_dmarc_rua(ctx: dns_base.DetectionCtx, dmarc_record: str) -> None:
    """Extract rua=mailto: addresses and match vendor domains against fingerprints."""

    matches = [addr for value in _RUA_TAG_RE.findall(dmarc_record) for addr in _RUA_MAILTO_RE.findall(value)]
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


def _parse_dmarc_pct(raw_pct: str, domain: str) -> int | None:
    """Validate a DMARC ``pct=`` value (0-100), warning on bad input."""
    try:
        pct_val = int(raw_pct)
    except ValueError:
        logger.warning("DMARC pct= value %r is not a valid integer for %s - ignored", raw_pct, domain)
        return None
    if 0 <= pct_val <= 100:
        return pct_val
    logger.warning("DMARC pct= value %d out of range for %s - ignored", pct_val, domain)
    return None


def _parse_dmarc_policy(raw_policy: str, domain: str) -> str | None:
    """Validate the required DMARC ``p=`` policy."""
    policy = raw_policy.strip().lower()
    if policy in _DMARC_POLICY_VALUES:
        return policy
    logger.warning("DMARC p= value %r is not a valid policy for %s - ignored", raw_policy, domain)
    return None


def _parse_dmarc_np(raw_np: str, domain: str) -> str | None:
    """Validate RFC 9989 ``np=`` for non-existent subdomain policy."""
    policy = raw_np.strip().lower()
    if policy in _DMARC_POLICY_VALUES:
        return policy
    logger.warning("DMARC np= value %r is not a valid policy for %s - ignored", raw_np, domain)
    return None


def _parse_dmarc_testing(raw_testing: str, domain: str) -> bool | None:
    """Validate RFC 9989 ``t=`` testing mode."""
    testing = raw_testing.strip().lower()
    if testing not in _DMARC_TESTING_VALUES:
        logger.warning("DMARC t= value %r is not valid for %s - ignored", raw_testing, domain)
        return None
    return testing == "y"


def _parse_dmarc_tags(dmarc_record: str, domain: str) -> dict[str, str] | None:
    """Parse a DMARC tag list, rejecting duplicate tag names."""
    tags: dict[str, str] = {}
    for part in dmarc_record.split(";"):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        if key in tags:
            logger.warning("DMARC record for %s contains duplicate %s= tag - ignored", domain, key)
            return None
        tags[key] = value.strip()
    return tags


def _leading_dmarc_version_value(dmarc_record: str) -> str | None:
    """Return the leading DMARC version value when the first tag is ``v=``."""
    first_tag = dmarc_record.split(";", 1)[0]
    if not first_tag.startswith("v="):
        normalized = first_tag.strip().lower()
        if normalized.startswith("v") and "=" in normalized:
            return first_tag
        return None
    return first_tag.removeprefix("v=")


def _dmarc_rua_address_domain(addr: str) -> str | None:
    """Return a usable public reporting-address domain, if the RUA is valid."""
    local, sep, domain = addr.partition("@")
    domain = domain.lower().rstrip(".")
    if not sep or not local or not domain or "." not in domain or not is_public_dns_name(domain):
        return None
    return domain


def _has_valid_dmarc_rua(tags: dict[str, str]) -> bool:
    """Return whether the record carries at least one usable aggregate-report URI."""
    return any(_dmarc_rua_address_domain(addr) is not None for addr in _RUA_MAILTO_RE.findall(tags.get("rua", "")))


def _dmarc_policy_or_rua_fallback(tags: dict[str, str], domain: str) -> str | None:
    """Return a valid DMARC policy, including RUA-backed monitoring fallback."""
    raw_policy = tags.get("p")
    if raw_policy is not None:
        policy = _parse_dmarc_policy(raw_policy, domain)
        if policy is not None:
            return policy
    if _has_valid_dmarc_rua(tags):
        logger.warning(
            "DMARC policy for %s is missing or invalid; valid rua= present, treating as p=none",
            domain,
        )
        return "none"
    if raw_policy is None:
        logger.warning(
            "DMARC p= tag missing for %s and no valid rua= fallback is present - ignored",
            domain,
        )
    return None


def _apply_dmarc(ctx: dns_base.DetectionCtx, dmarc_results: list[str], domain: str) -> None:
    """Record DMARC presence, policy tags, and rua mailto fingerprints."""
    records: list[tuple[str, dict[str, str] | None]] = []
    for txt in dmarc_results:
        version = _leading_dmarc_version_value(txt)
        if version == "DMARC1":
            records.append((txt, _parse_dmarc_tags(txt, domain)))
        elif version is not None:
            logger.warning("DMARC v= value %r is not valid for %s - ignored", version, domain)

    if len(records) > 1:
        logger.warning("Multiple DMARC records found for %s - ignored", domain)
        return
    for txt, tags in records:
        if tags is None:
            continue
        policy = _dmarc_policy_or_rua_fallback(tags, domain)
        if policy is None:
            continue
        ctx.services.add(SVC_DMARC)
        ctx.dmarc_policy = policy
        if (value := tags.get("pct")) is not None and (pct := _parse_dmarc_pct(value, domain)) is not None:
            ctx.dmarc_pct = pct
        if (value := tags.get("np")) is not None and (dmarc_np := _parse_dmarc_np(value, domain)) is not None:
            ctx.dmarc_np = dmarc_np
        if (value := tags.get("t")) is not None and (testing := _parse_dmarc_testing(value, domain)) is not None:
            ctx.dmarc_testing = testing
        extract_dmarc_rua(ctx, txt)


async def _apply_bimi(ctx: dns_base.DetectionCtx, bimi_results: list[str], domain: str) -> None:
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


async def _apply_mta_sts(ctx: dns_base.DetectionCtx, mta_sts_results: list[str], domain: str) -> None:
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


def _apply_tls_rpt(ctx: dns_base.DetectionCtx, tls_rpt_results: list[str]) -> None:
    """Record TLS-RPT presence."""
    for txt in tls_rpt_results:
        if "v=tlsrptv1" in txt.lower():
            ctx.add("TLS-RPT", "tls-rpt", source_type="TXT", raw_value=txt)
            break


async def detect_email_security(ctx: dns_base.DetectionCtx, domain: str) -> None:
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
