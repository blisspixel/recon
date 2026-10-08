"""Static catalogs and pure, stateless DNS parsers/validators.

Extracted from ``sources/dns.py`` as the first step of its decomposition
(docs/roadmap.md god-file track). These symbols have no I/O, no detection
context, and no dependency on the live-resolution helpers, so they form a
true leaf: ``dns.py`` imports from here, never the reverse. Names keep their
original (underscore) spelling and are re-exported from ``dns.py`` so the
``recon_tool.sources.dns`` import path and the test surface are unchanged.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from recon_tool.rate_limit import RateLimited
from recon_tool.regex_safety import compile_regex
from recon_tool.sources.email_uri import parse_email_policy_uri
from recon_tool.validator import host_has_suffix, is_domain_shaped

logger = logging.getLogger("recon")

if TYPE_CHECKING:
    from recon_tool.fingerprints import Detection

_CNAME_TARGET_FRAGMENT_RE = re.compile(r"^[a-z0-9_-]+$", re.ASCII)
_DKIM_TAG_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*", re.ASCII)
_TLS_RPT_FIELD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", re.ASCII)
_TLS_RPT_EXTENSION_RE = re.compile(r"[\x21-\x3a\x3c\x3e-\x7e]+", re.ASCII)
_BIMI_LOCAL_PART_PREFIX_RE = re.compile(r"[A-Za-z0-9-]{1,63}", re.ASCII)


def parse_rdata(raw: str) -> str:
    """Normalize a single rdata text value.

    For TXT records, dnspython's to_text() returns multi-part strings as
    space-separated quoted chunks (e.g. '"v=DMARC1;" "p=none"'). We join
    these chunks into a single string so downstream parsing sees the full
    record value, not just the first 255-byte fragment.

    For non-TXT records (CNAME, MX, NS), dnspython appends a trailing dot
    to FQDNs. We strip it for cleaner downstream matching, except when the
    target is the bare root label. A lone "." is a deliberate declaration,
    not a hostname: RFC 7505 Null MX ("0 .") says the domain accepts no
    mail, and RFC 2782 ("0 0 0 .") says the service is not available.
    Stripping it there would turn an explicit negative declaration into an
    ordinary unclassified host.
    """
    if raw.startswith('"'):
        # TXT record - join multi-part chunks, don't strip trailing dots
        # (dots can be meaningful in TXT values like SPF includes)
        parts = raw.split('" "')
        return "".join(p.strip('"') for p in parts)
    # Non-TXT (CNAME, MX, NS, SRV, etc.) - strip trailing FQDN dot
    value = raw.strip('"')
    stripped = value.rstrip(".")
    if not stripped or stripped.endswith(" "):
        # The whole target was the root label; keep it verbatim.
        return value
    return stripped


def _parse_dkim_tag_list(record: str) -> dict[str, str] | None:
    """Parse RFC 6376 tag-list syntax, also used by BIMI assertion records."""
    # DNS RDATA has a 16-bit length. Reject oversized caller-supplied input
    # before allocating tag lists, and unfold only RFC 6376-permitted FWS.
    if len(record) > 65_535 or not record.isascii():
        return None
    unfolded = re.sub(r"\r\n(?=[ \t])", "", record)
    if any(char != "\t" and not 0x20 <= ord(char) <= 0x7E for char in unfolded):
        return None
    parts = unfolded.strip(" \t").split(";")
    if parts[-1].strip(" \t") == "":
        parts.pop()
    tags: dict[str, str] = {}
    for part in parts:
        name, separator, value = part.strip(" \t").partition("=")
        name = name.rstrip(" \t")
        if not separator or _DKIM_TAG_NAME_RE.fullmatch(name) is None or name in tags:
            return None
        tags[name] = value.strip(" \t")
    return tags


def is_dkim_key_record(record: str) -> bool:
    """Recognize a DKIM TXT key declaration with nonempty base64 key material.

    RFC 6376 sections 3.2 and 3.6.1 make ``v`` optional, case-sensitive and
    first when supplied. Empty ``p`` revokes a key. This is record-shape
    admission only: no signature, algorithm, key strength or ASN.1 validation.
    Unknown tags retain their specified ignore semantics.
    """
    tags = _parse_dkim_tag_list(record)
    if not tags or ("v" in tags and (next(iter(tags)) != "v" or tags["v"] != "DKIM1")):
        return False
    encoded = tags.get("p", "").replace(" ", "").replace("\t", "")
    # validate=True checks the alphabet, but some Python versions still accept
    # surplus padding after a complete quartet. Enforce its position as well.
    if not encoded or len(encoded) % 4 or "=" in encoded[:-2]:
        return False
    try:
        return bool(base64.b64decode(encoded, validate=True))
    except binascii.Error:
        return False


def is_spf_record(value: str) -> bool:
    """Recognize the complete version token (RFC 7208 section 4.5)."""
    lowered = value.lower()
    return lowered == "v=spf1" or lowered.startswith("v=spf1 ")


def select_spf_record(records: Iterable[str]) -> str | None:
    """Select one SPF TXT record before policy credit or redirects.

    RFC 7208 section 4.5 treats competing records as permerror. Distinct wire
    records may concatenate to identical text, so retain their multiplicity.
    dnspython's RRset already removes byte-identical duplicate DNS records.
    """
    candidates = [record for record in records if is_spf_record(record)]
    return candidates[0] if len(candidates) == 1 else None


def _spf_terms(record: str) -> tuple[str, ...]:
    """Keep SPF's ASCII-space term boundaries without interpreting macros."""
    if not is_spf_record(record):
        return ()
    return tuple(term for term in record.lower().split(" ")[1:] if term)


def spf_all_qualifier(record: str) -> str | None:
    """Return the first exact all mechanism's qualifier, wherever it occurs."""
    for term in _spf_terms(record):
        if term == "all":
            return "+"
        if len(term) == 4 and term[0] in "+-~?" and term[1:] == "all":
            return term[0]
    return None


def spf_redirect_target(record: str) -> str | None:
    """Return one effective redirect, never modifier text or an ignored hop.

    RFC 7208 sections 6 and 6.1 forbid repeated redirect modifiers and ignore
    redirect whenever any all mechanism is present, including on later hops.
    """
    if spf_all_qualifier(record) is not None:
        return None
    targets = [
        term.removeprefix("redirect=").rstrip(".") for term in _spf_terms(record) if term.startswith("redirect=")
    ]
    return targets[0] if len(targets) == 1 and targets[0] else None


def spf_targets(spf_text: str) -> tuple[str, ...]:
    """Return reachable include references and the effective redirect target.

    Provider attribution must compare a parsed target, not the raw record text.
    Searching the whole string lets a lookalike such as
    ``_spf.vendor.com.attacker-controlled.test`` match ``vendor.com``, because
    the vendor name appears as an interior label rather than the target's
    suffix. Every include qualifier can supply a policy reference, but no
    include after all is reachable. Both live collection and cached replay
    use this projection. It does not establish sender authorization, evaluate
    sender IPs or expand SPF macros.
    """
    targets: list[str] = []
    for term in _spf_terms(spf_text):
        mechanism = term[1:] if term[0] in "+-~?" else term
        if mechanism == "all":
            break
        if mechanism.startswith("include:") and (target := mechanism.removeprefix("include:").rstrip(".")):
            targets.append(target)
    if redirect := spf_redirect_target(spf_text):
        targets.append(redirect)
    return tuple(targets)


def match_spf_targets(targets: tuple[str, ...], patterns: tuple[Detection, ...]) -> list[Detection]:
    """Apply specificity per target, then preserve independently matched rules.

    A narrow rule shadows its parent only on the same target. A separate
    include for the parent's own domain still supplies evidence for that rule.
    Repeated targets do not duplicate the resulting rule occurrences.
    """
    from recon_tool.fingerprints import filter_shadowed_matches

    matched: set[Detection] = set()
    for target in targets:
        candidates = [det for det in patterns if host_has_suffix(target, det.pattern)]
        matched.update(filter_shadowed_matches(candidates))
    return list(dict.fromkeys(det for det in patterns if det in matched))


def _valid_bimi_uri(value: str, *, authority_evidence: bool) -> bool:
    if "," in value:
        return False
    parsed = parse_email_policy_uri(value)
    if parsed is None or parsed.scheme != "https" or not parsed.hostname:
        return False
    # BIMI's authority document specifically requires an FQDN. This is
    # declaration syntax only, not permission to fetch a destination.
    host = parsed.hostname.lower().rstrip(".")
    return not authority_evidence or (
        is_domain_shaped(host) and len(host) <= 253 and all(len(label) <= 63 for label in host.split("."))
    )


def _bimi_assertion_tags(record: str) -> dict[str, str] | None:
    """Admit a participating default-selector declaration, not logo validity.

    BIMI draft -14 sections 4.3 and 7.2 require an exact leading version,
    a location tag, and one assertion. Both locations empty is an opt-out.
    Unknown tags and unknown avatar preferences retain ignore semantics.
    """
    tags = _parse_dkim_tag_list(record)
    if not tags or next(iter(tags)) != "v" or tags["v"] != "BIMI1" or "l" not in tags:
        return None
    if not tags["l"] and not tags.get("a"):
        return None
    for name in ("l", "a"):
        value = tags.get(name, "")
        if value and not _valid_bimi_uri(value, authority_evidence=name == "a"):
            return None
    prefixes = tags.get("lps", "")
    if prefixes and any(
        _BIMI_LOCAL_PART_PREFIX_RE.fullmatch(prefix.strip(" \t")) is None for prefix in prefixes.split(",")
    ):
        return None
    return tags


def select_bimi_record(records: Iterable[str]) -> str | None:
    """Select before validating so a malformed competing assertion still blocks."""
    candidates = [record for record in records if _parse_dkim_tag_list(record.split(";", 1)[0]) == {"v": "BIMI1"}]
    if len(candidates) != 1 or _bimi_assertion_tags(candidates[0]) is None:
        return None
    return candidates[0]


def extract_bimi_vmc_url(bimi_txt: str) -> str | None:
    """Use the admitted, case-sensitive authority tag for opt-in enrichment."""
    tags = _bimi_assertion_tags(bimi_txt)
    candidate = tags.get("a", "") if tags else ""
    return candidate if candidate.lower().endswith(".pem") else None


def _valid_tls_rpt_record(record: str) -> bool:
    if len(record) > 65_535 or not record.isascii():
        return False
    parts = record.split(";")
    if parts[0].rstrip(" \t") != "v=TLSRPTv1":
        return False
    has_rua = False
    for index, part in enumerate(parts[1:], start=1):
        # WSP belongs to a semicolon delimiter or a URI-list comma, never
        # around '=' or after the final URI without a trailing semicolon.
        field = part.lstrip(" \t")
        if index < len(parts) - 1:
            field = field.rstrip(" \t")
        elif not field:
            continue
        name, separator, value = field.partition("=")
        if not separator or _TLS_RPT_FIELD_RE.fullmatch(name) is None:
            return False
        if name == "rua":
            has_rua = True
            uris = value.split(",")
            for uri_index, uri in enumerate(uris):
                candidate = uri.lstrip(" \t") if uri_index else uri
                if uri_index < len(uris) - 1:
                    candidate = candidate.rstrip(" \t")
                if "!" in candidate or parse_email_policy_uri(candidate) is None:
                    return False
        elif _TLS_RPT_EXTENSION_RE.fullmatch(value) is None:
            return False
    return has_rua


def select_tls_rpt_record(records: Iterable[str]) -> str | None:
    """Apply RFC 8460 section 3 selection and declaration grammar.

    Repeated rua fields and unknown extensions are allowed. URI syntax does
    not establish endpoint reachability, scheme support or report delivery.
    """
    candidates = list(records)
    # The ABNF permits WSP before ';' for a lone record. The RFC specifies
    # a literal-prefix filter specifically when multiple TXT RRs arrive.
    if len(candidates) > 1:
        candidates = [record for record in candidates if record.startswith("v=TLSRPTv1;")]
    if len(candidates) != 1 or not _valid_tls_rpt_record(candidates[0]):
        return None
    return candidates[0]


def bimi_vmc_url_is_safe(a_url: str) -> bool:
    """SSRF guard for the attacker-authored BIMI ``a=`` URL.

    The looked-up domain owner authors their own BIMI TXT record, so the URL
    could name any server, an internal/split-horizon name, or an IP literal.
    Require https, a public-DNS host, no embedded credentials, and the default
    port. The shared client's transport additionally blocks private-IP
    destinations. See docs/security-audit-resolutions.md.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(a_url)
        host = (parsed.hostname or "").lower()
        # ``.port`` raises ValueError on a malformed/out-of-range port
        # (e.g. ":bad", ":99999"); read it inside the guard so a crafted
        # record is refused cleanly rather than aborting the DNS source.
        port = parsed.port
    except ValueError:
        logger.debug("BIMI VMC a= URL refused (unparseable URL/port): %s", a_url)
        return False
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or not is_public_dns_name(host)
    ):
        logger.debug("BIMI VMC a= URL refused (requires https + public host): %s", a_url)
        return False
    return True


def is_public_dns_name(name: str) -> bool:
    """Return True when *name* looks like a name on the public DNS.

    Rejects single-label names, IP literals, RFC 6761 special-use
    suffixes, reverse-DNS arpa zones, common private-network
    conventions (.local/.corp/.lan/etc.), the Tor namespace, and
    names containing characters outside the DNS letter-digit-hyphen
    alphabet (plus dot as separator and underscore for DKIM/SRV).
    The check is suffix-based and case-insensitive.

    The CNAME chain walker uses this to refuse to follow attacker-
    controlled CNAME hops that target internal/split-horizon DNS,
    which would otherwise let a public domain owner force the
    operator's resolver to query arbitrary internal hostnames and
    leak internal topology in evidence output.
    """
    if not name:
        return False
    n = name.strip().lower().rstrip(".")
    if not n or "." not in n:
        # Single-label names are either internal hostnames or root-
        # zone TLDs; neither is a sensible CNAME target.
        return False
    # Character-class restriction. DNS names use a limited
    # alphabet (RFC 1035: ASCII alphanumeric, hyphen, dot) plus
    # underscore for DKIM and SRV selectors. Reject anything outside
    # this set - adversarial DNS responses or lax resolver parsing
    # could otherwise smuggle HTML / shell / control characters
    # through to evidence output where downstream renderers
    # (terminal escape codes, markdown, HTML-aware JSON viewers)
    # might interpret them. dnspython's strict parser usually
    # rejects such names before we see them; this check is
    # defense-in-depth in case the parser ever relaxes or a future
    # caller passes a name from a non-DNS source.
    if not all(c.isascii() and (c.isalnum() or c in "-._") for c in n):
        return False
    # IP literals (IPv4 dotted-quad or IPv6 with hex+colons). CNAMEs
    # cannot legally target IPs in DNS, but defensive resolvers may
    # still see something interpretable as one. The IPv6 ``:`` is
    # already covered by the character-class check above, but we
    # keep the explicit IPv4 (all-digit-labels) check for clarity.
    if all(part.isdigit() for part in n.split(".")):
        return False
    return all(not n.endswith(suffix) for suffix in PRIVATE_DNS_SUFFIXES)


def classify_ct_failure(exc: Exception) -> str:
    """Bucket a CT-provider exception as breaker / rate_limit / other.

    RateLimited from the adaptive limiter wraps either a local breaker-open
    decline or a max-wait-exceeded decline; both surface as "rate-limited".
    """
    current: BaseException | None = exc
    saw_rate_limited = False
    while current is not None:
        saw_rate_limited = saw_rate_limited or isinstance(current, RateLimited)
        current = current.__cause__ or (None if current.__suppress_context__ else current.__context__)

    err_str = str(exc).lower()
    if "circuit breaker open" in err_str:
        return "breaker"
    status_code = getattr(getattr(exc, "response", None), "status_code", None)
    if saw_rate_limited or status_code == 429 or "rate-limited" in err_str or "rate limited" in err_str:
        return "rate_limit"
    return "other"


def ct_failure_outcome(failures: dict[str, int]) -> str:
    """Pick the most precise outcome label from the failure tallies.

    Live-attempt failures carry more operational signal than a separate
    provider's already-open breaker. Reserve ``breaker_open`` for the case
    where every failed provider was stopped by its local breaker before any
    useful live attempt happened.
    """
    if failures["rate_limit"] > 0:
        return "live_rate_limited"
    if failures["other"] > 0:
        return "live_other_failure"
    if failures["breaker"] > 0:
        return "breaker_open"
    return "cache_miss"


def cname_target_pattern_matches(hostname: str, pattern: str) -> bool:
    """Match a CNAME-chain hop against a suffix, fragment, or safe regex."""
    host = hostname.lower().strip().rstrip(".")
    raw_pattern = pattern.lower().strip()
    domain_pattern = raw_pattern.lstrip(".").rstrip(".")
    if not host or not domain_pattern:
        return False
    if is_domain_shaped(domain_pattern):
        return host_has_suffix(host, domain_pattern)
    if _CNAME_TARGET_FRAGMENT_RE.fullmatch(domain_pattern):
        return re.search(rf"(?:^|[.-]){re.escape(domain_pattern)}", host) is not None
    compiled = compile_regex(raw_pattern, re.IGNORECASE)
    return compiled is not None and compiled.search(host) is not None


def classify_chain(
    chain: list[str],
    rules: tuple[Any, ...],
) -> tuple[Any | None, Any | None]:
    """Pick the primary application match and the fronting infrastructure match.

    Walks every hop in *chain* and matches each against every rule (rules
    are pre-sorted longest-pattern-first by the caller). Returns
    ``(application_match, infrastructure_match)`` where each is the most
    specific matched rule of its tier, or None when no rule of that tier
    matched. The pair lets downstream code render
    "sso.example.com  Auth0" while still recording that Cloudflare
    fronted it for --explain consumers.
    """
    application: Any | None = None
    infrastructure: Any | None = None
    for hop in chain:
        for rule in rules:
            if cname_target_pattern_matches(hop, rule.pattern):
                if rule.tier == "application" and application is None:
                    application = rule
                elif rule.tier == "infrastructure" and infrastructure is None:
                    infrastructure = rule
        if application is not None and infrastructure is not None:
            break
    return application, infrastructure


# Common ESP DKIM selectors beyond Exchange/Google.
# Each tuple is (selector_prefix, cname_hint, service_name, slug).
# If the CNAME target contains the hint, we attribute it to that service.
ESP_DKIM_SELECTORS: list[tuple[str, str, str, str]] = [
    ("k1", "domainkey.u", "Mailchimp", "mailchimp"),
    ("s1", "domainkey.u", "Mailchimp", "mailchimp"),
    ("em", "sendgrid.net", "SendGrid", "sendgrid"),
    ("s1", "sendgrid.net", "SendGrid", "sendgrid"),
    ("default", "mailgun.org", "Mailgun", "mailgun"),
    ("pm", "dkim.pstmrk.com", "Postmark", "postmark"),
    ("mxvault", "mimecast", "Mimecast", "mimecast"),
]


# Generic enterprise DKIM selectors - large enterprises use
# non-standard selector names. These TXT probes confirm DKIM exists even when
# we can't attribute it to a specific provider.
GENERIC_DKIM_SELECTORS: tuple[str, ...] = ("s2", "dkim", "mail", "k2")


# Hosting provider detection from A record → reverse DNS
# (PTR) → hostname pattern match. This fills a major detection gap:
# on web-only domains with minimal DNS signal (a single A record
# and a couple of NS entries), the A record IS the primary signal
# and we were completely ignoring it. Public cloud providers
# publish predictable PTR records for their IP ranges that encode
# both the provider and (for AWS / Azure / GCP) the region.
#
# Pattern table - checked in order, first match wins. Each entry is
# a substring matched against the PTR hostname's lowercased form.
# The region extractor is an optional regex that runs against the
# full PTR hostname to pull a region token; when present and
# matched, the region is appended to the service name.
HOSTING_PTR_PATTERNS: tuple[tuple[str, str, str, str | None], ...] = (
    # (ptr substring, service name, slug, region regex or None)
    ("compute.amazonaws.com", "AWS EC2", "aws-ec2", r"[a-z]{2}-[a-z]+-\d+"),
    ("ec2.internal", "AWS EC2", "aws-ec2", None),
    ("elb.amazonaws.com", "AWS ELB", "aws-elb", r"[a-z]{2}-[a-z]+-\d+"),
    ("elb.amazonaws.com.cn", "AWS ELB (China)", "aws-elb", None),
    ("amazonaws.com", "AWS", "aws-compute", None),
    (
        "cloudapp.azure.com",
        "Azure VM",
        "azure-vm",
        r"(?:eastus|westus|centralus|northeurope|westeurope|"
        r"eastasia|southeastasia|japaneast|japanwest|brazilsouth|australiaeast|canadacentral)[a-z0-9]*",
    ),
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


# High-signal subdomain prefixes that commonly CNAME to SaaS providers.
# These are probed directly via DNS - no external service dependency.
# Kept intentionally focused: each prefix has a high probability of
# revealing a SaaS CNAME (auth→Okta, shop→Shopify, status→Statuspage, etc.).
COMMON_SUBDOMAIN_PREFIXES = (
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
    # Data / analytics platform subdomains. Vendors like
    # Snowflake, Databricks, Looker, Tableau, Mode, ThoughtSpot, and
    # PowerBI commonly resolve under host-level prefixes. Adding these
    # widens the probe to the analytics tier, which the prior set
    # missed entirely.
    "data",
    "analytics",
    # AI / ML platform subdomains. Organizations that publish
    # internal ML tooling or vendor-hosted AI services (Hugging Face
    # spaces, Vertex AI endpoints, OpenAI proxies, AzureML workspaces)
    # often expose them under these prefixes. Adds coverage for an
    # increasingly common stack tier the prior set ignored.
    "ml",
    "ai",
    # Operations / internal-tooling subdomains. When an org
    # publishes operations dashboards, internal-only services with
    # public DNS entries, or platform tooling, these prefixes are the
    # idiomatic landing zones. Surfacing them in passive enumeration
    # gives defenders visibility into the operations tier that the
    # original commerce/identity-skewed wordlist missed.
    "internal",
    "ops",
    "tools",
    # Security-team subdomains. Vendors and internal SOCs
    # often surface incident-response portals, vuln-disclosure
    # endpoints, or SIEM consoles under this prefix. Low false-positive
    # rate because the prefix is rarely used for non-security purposes.
    "security",
)


# Identity-hub subdomain prefixes that are strong SSO / IdP
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
IDP_SUBDOMAIN_PREFIXES: tuple[str, ...] = (
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
    # CAS (Central Authentication Service - common in higher ed)
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


# Suffixes that identify private/internal/special-use DNS names. A
# CNAME hop pointing at one of these should be dropped: continuing to
# resolve it would turn an attacker-controlled public CNAME into an
# oracle for the operator's internal/split-horizon DNS, and including
# it in evidence would leak internal topology to the caller. RFC 6761
# special-use suffixes plus the common private-network conventions
# (.local, .internal, .corp, .lan, .home, .home.arpa) plus reverse-
# DNS arpa zones plus the Tor namespace (.onion). The list is
# deliberately permissive on the public-DNS side: anything not in
# this set is treated as resolvable public DNS.
PRIVATE_DNS_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".intranet",
    ".private",
    ".corp",
    ".lan",
    ".home",
    ".home.arpa",
    ".test",
    ".example",
    ".invalid",
    ".onion",
    ".in-addr.arpa",
    ".ip6.arpa",
    ".arpa",
)
