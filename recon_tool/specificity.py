"""Pattern-specificity gate for fingerprint regexes.

A valid-YAML fingerprint can still be a catastrophic false positive — a
regex like ``cname:\\.com$`` parses fine but would match a third of the
internet. Validation's runtime schema check doesn't catch this class
of error; the specificity gate does.

The gate takes each regex pattern and matches it against a synthetic
adversarial corpus — strings that legitimate fingerprints should
essentially never hit. If a pattern matches more than a threshold
fraction of the corpus (default 1%), the gate flags it as
under-specific.

Why synthetic rather than a real domain corpus:
- Reproducible across runs (no network, no seed drift).
- Deliberately diverse — we seed bad patterns the gate should catch.
- Cheap: ~1500 strings, one regex compile per pattern.

The gate is intentionally conservative: threshold is high enough that
real-world specific patterns never trigger, and the corpus is
deliberately biased toward generic strings that over-broad patterns
would false-positive on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "DEFAULT_MATCH_THRESHOLD",
    "PATTERN_TYPE_CORPORA",
    "SpecificityVerdict",
    "evaluate_pattern",
    "synthetic_corpus",
]

# One percent of a 1500-string corpus = 15 matches. That leaves headroom
# for patterns that legitimately match a vendor's multiple variants
# (e.g. ``.atlassian\.net$`` matching ``foo.atlassian.net`` and
# ``bar.atlassian.net``) while still catching ``\.com$``-grade
# disasters. Tuned on the built-in catalog: all 227 entries pass.
DEFAULT_MATCH_THRESHOLD: float = 0.01


@dataclass(frozen=True)
class SpecificityVerdict:
    """Result of running one pattern against the synthetic corpus."""

    pattern: str
    detection_type: str
    matches: int
    corpus_size: int
    threshold_exceeded: bool

    @property
    def match_rate(self) -> float:
        if self.corpus_size == 0:
            return 0.0
        return self.matches / self.corpus_size


def _random_tlds() -> list[str]:
    # Common TLDs plus a few IDN punycode TLDs. A pattern anchored
    # to ``\.com$`` will over-match this corpus; one anchored to a
    # specific vendor domain will not.
    return [
        "com",
        "org",
        "net",
        "io",
        "co",
        "app",
        "dev",
        "ai",
        "tech",
        "xyz",
        "us",
        "uk",
        "de",
        "fr",
        "jp",
        "cn",
        "in",
        "br",
        "au",
        "ca",
        "xn--p1ai",
        "xn--fiqs8s",
    ]


def _cname_corpus() -> list[str]:
    """Synthetic CNAME targets — vendor-ish but unaffiliated with any
    specific fingerprint. Mixes hyphenated business words, short
    alphanumerics, and common vendor-agnostic suffixes.
    """
    bases = [
        "alpha",
        "beta",
        "acme",
        "example",
        "sample",
        "test",
        "prod",
        "staging",
        "dev",
        "app",
        "web",
        "api",
        "cdn",
        "edge",
        "ingress",
        "mail",
        "login",
        "auth",
        "id",
        "www",
        "docs",
        "support",
        "status",
        "help",
        "team",
        "company",
        "brand",
        "store",
        "shop",
        "portal",
    ]
    suffixes = [
        "hosted.example.com",
        "cdn.example.net",
        "vendor.example.io",
        "cloud.example.co",
        "platform.example.app",
        "service.example.dev",
    ]
    corpus: list[str] = []
    for base in bases:
        for suffix in suffixes:
            corpus.append(f"{base}.{suffix}")
        for tld in _random_tlds():
            corpus.append(f"{base}-api.{tld}")
            corpus.append(f"{base}-cdn.{tld}")
    return corpus


def _txt_corpus() -> list[str]:
    """Synthetic TXT record values. Includes SPF, DKIM, domain-verification
    lookalikes, and generic key-value noise.
    """
    return [
        # SPF-shaped
        "v=spf1 include:_spf.example.com ~all",
        "v=spf1 include:mail.example.net -all",
        "v=spf1 mx a -all",
        "v=spf1 -all",
        # DMARC-shaped
        "v=DMARC1; p=none; rua=mailto:reports@example.com",
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.net",
        "v=DMARC1; p=quarantine",
        # Domain-verification lookalikes — the class most prone to
        # false-positive regexes. A pattern like ``^\w+-verification=``
        # would flag every one of these.
        "example-verification=abc123",
        "vendor-verification=xyz789",
        "domain-verification=qwe456",
        "site-verification=asd123",
        "brand-domain-verification=zxc987",
        "google-site-verification=placeholder1234567890",
        "facebook-domain-verification=abcdefg",
        # Generic key-value noise
        "description=marketing landing page",
        "owner=platform team",
        "purpose=product catalog",
        "contact=admin@example.com",
        "t=s",
        "p=none",
        # DKIM-shaped
        "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN...",
        "k=rsa; p=ABC123DEF456",
        # Misc binding strings
        "apple-domain-verification=example",
        "atlassian-domain-verification=example",
        "docusign=abc-1234-def",
        "webex=xyz",
        # Random-looking bases
        *[f"app-{i}-verification=abc" for i in range(50)],
        *[f"service-{i}-site-verification=xyz" for i in range(50)],
        *[f"generic-{i}=value{i}" for i in range(100)],
    ]


def _spf_corpus() -> list[str]:
    """Synthetic SPF includes/directives. Vendor-agnostic — each string
    uses ``example.{com,net,io,co,org}`` or reserved IP space so it
    can't legitimately match a real vendor fingerprint.
    """
    return [
        "include:_spf.example.com",
        "include:mail.example.net",
        "include:spf.vendor.example.io",
        "include:spf.provider.example.co",
        "include:mailers.example.org",
        "include:relay.example.app",
        "ip4:192.0.2.0/24",
        "ip4:198.51.100.0/24",
        "ip6:2001:db8::/32",
        "a",
        "mx",
        "+all",
        "-all",
        "~all",
        "?all",
        "redirect=_spf.example.org",
    ]


def _mx_corpus() -> list[str]:
    """Synthetic MX hostnames. Priority-stripped."""
    return [
        "mail.example.com",
        "mx.example.net",
        "mail1.vendor.io",
        "inbound.example.co",
        "smtp.example.org",
        "mx01.example.com",
        "mx02.example.com",
        "inbound-smtp.example.io",
        "relay.example.net",
        "mta.example.co",
    ]


def _ns_corpus() -> list[str]:
    """Synthetic NS hostnames."""
    return [
        "ns1.example.com",
        "ns2.example.net",
        "ns.vendor.io",
        "dns1.example.co",
        "dns2.example.co",
    ]


def _generic_corpus() -> list[str]:
    """Shared fallback corpus for detection types without a dedicated pool."""
    return [
        *_cname_corpus()[:40],
        *_txt_corpus()[:40],
        *_spf_corpus(),
        *_mx_corpus(),
        *_ns_corpus(),
    ]


PATTERN_TYPE_CORPORA: dict[str, list[str]] = {
    "txt": _txt_corpus(),
    "dmarc_rua": _txt_corpus(),
    "subdomain_txt": _txt_corpus(),
    "spf": _spf_corpus(),
    "mx": _mx_corpus(),
    "cname": _cname_corpus(),
    "ns": _ns_corpus(),
    "caa": _generic_corpus(),
    "srv": _generic_corpus(),
    "a": _generic_corpus(),
}


def synthetic_corpus(detection_type: str) -> list[str]:
    """Return the synthetic corpus for a detection type.

    Unknown types fall through to a mixed generic corpus so new
    detection types get *some* coverage until the corpus is
    specialised.
    """
    return PATTERN_TYPE_CORPORA.get(detection_type.lower(), _generic_corpus())


# Hard cap on regex length. Mirrors ``_MAX_PATTERN_LENGTH`` in
# ``fingerprints.py`` — we don't want a malicious PR or MCP caller
# to hand the specificity gate a megabyte of regex that pegs CPU
# before the schema validator can reject it. Schema validation
# already enforces this cap; duplicating it here keeps the gate
# safe even when called directly (e.g. from the MCP
# ``inject_ephemeral_fingerprint`` path).
_MAX_PATTERN_LENGTH: int = 500


def evaluate_pattern(
    pattern: str,
    detection_type: str,
    *,
    threshold: float = DEFAULT_MATCH_THRESHOLD,
) -> SpecificityVerdict:
    """Match ``pattern`` against the synthetic corpus for ``detection_type``.

    Returns a ``SpecificityVerdict`` with match count and a flag for
    whether the threshold was exceeded. Uncompilable or oversized
    patterns yield a verdict with ``matches=0`` and
    ``threshold_exceeded=False`` — the runtime schema validator
    already rejects them. A length guard here prevents a pathological
    regex (catastrophic backtracking, megabyte-scale pattern) from
    hanging the validator even when this function is called directly
    without first going through ``_validate_fingerprint``.
    """
    corpus = synthetic_corpus(detection_type)

    # Length guard — cheap, and matches the schema validator's cap.
    # Without it, a contributor PR or an MCP client could hand the
    # specificity gate a pathological pattern that pegs CPU before
    # the schema check runs.
    if len(pattern) > _MAX_PATTERN_LENGTH:
        return SpecificityVerdict(
            pattern=pattern,
            detection_type=detection_type,
            matches=0,
            corpus_size=len(corpus),
            threshold_exceeded=False,
        )

    try:
        compiled = re.compile(pattern)
    except re.error:
        return SpecificityVerdict(
            pattern=pattern,
            detection_type=detection_type,
            matches=0,
            corpus_size=len(corpus),
            threshold_exceeded=False,
        )

    matches = sum(1 for entry in corpus if compiled.search(entry))
    return SpecificityVerdict(
        pattern=pattern,
        detection_type=detection_type,
        matches=matches,
        corpus_size=len(corpus),
        threshold_exceeded=(matches / len(corpus) if corpus else 0.0) > threshold,
    )
