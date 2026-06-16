"""Static catalogs and pure, stateless DNS parsers/validators.

Extracted from ``sources/dns.py`` as the first step of its decomposition
(docs/roadmap.md god-file track). These symbols have no I/O, no detection
context, and no dependency on the live-resolution helpers, so they form a
true leaf: ``dns.py`` imports from here, never the reverse. Names keep their
original (underscore) spelling and are re-exported from ``dns.py`` so the
``recon_tool.sources.dns`` import path and the test surface are unchanged.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("recon")


def parse_rdata(raw: str) -> str:
    """Normalize a single rdata text value.

    For TXT records, dnspython's to_text() returns multi-part strings as
    space-separated quoted chunks (e.g. '"v=DMARC1;" "p=none"'). We join
    these chunks into a single string so downstream parsing sees the full
    record value, not just the first 255-byte fragment.

    For non-TXT records (CNAME, MX, NS), dnspython appends a trailing dot
    to FQDNs. We strip it for cleaner downstream matching.
    """
    if raw.startswith('"'):
        # TXT record - join multi-part chunks, don't strip trailing dots
        # (dots can be meaningful in TXT values like SPF includes)
        parts = raw.split('" "')
        return "".join(p.strip('"') for p in parts)
    # Non-TXT (CNAME, MX, NS, etc.) - strip trailing FQDN dot
    return raw.strip('"').rstrip(".")


def extract_bimi_vmc_url(bimi_txt: str) -> str | None:
    """Return the ``a=`` VMC ``.pem`` URL from a BIMI TXT record, or None."""
    for part in bimi_txt.split(";"):
        cleaned = part.strip()
        if cleaned.lower().startswith("a="):
            candidate = cleaned[2:].strip()
            if candidate.lower().endswith(".pem"):
                return candidate
    return None


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


def parse_vmc_subject(pem_data: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Extract (organization, country, state, locality) from a VMC PEM.

    Prefers the cryptography library; falls back to a regex over the PEM text
    when it is unavailable.
    """
    org = country = state = locality = None
    try:
        from cryptography import x509

        cert_obj = x509.load_pem_x509_certificate(pem_data.encode())
        for attr in cert_obj.subject:
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
        import re as _re

        for line in pem_data.splitlines():
            line_stripped = line.strip()
            if "O=" in line_stripped or "O =" in line_stripped:
                m = _re.search(r"O\s*=\s*([^,/]+)", line_stripped)
                if m:
                    org = m.group(1).strip()
            if "C=" in line_stripped:
                m = _re.search(r"C\s*=\s*([^,/]+)", line_stripped)
                if m:
                    country = m.group(1).strip()
    return org, country, state, locality


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
    err_str = str(exc).lower()
    if "circuit breaker open" in err_str:
        return "breaker"
    if "rate-limited" in err_str or "429" in err_str:
        return "rate_limit"
    return "other"


def ct_failure_outcome(failures: dict[str, int]) -> str:
    """Pick the most precise outcome label from the failure tallies."""
    if failures["breaker"] > 0:
        return "breaker_open"
    if failures["rate_limit"] > 0:
        return "live_rate_limited"
    if failures["other"] > 0:
        return "live_other_failure"
    return "cache_miss"


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
            # Label-aware match for domain patterns: the hop must equal the vendor
            # domain or be a proper subdomain, so an attacker-controlled target like
            # ``manageengine.com.attacker.tld`` no longer matches ``manageengine.com``.
            # A leading-dot pattern (``.desk.com``) is the same suffix idiom; a
            # dot-less fragment (``s3-website``) is a mid-hostname infra marker and
            # keeps substring semantics.
            pat = rule.pattern.lstrip(".")
            matched = (hop == pat or hop.endswith("." + pat)) if "." in pat else (pat in hop)
            if matched:
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
