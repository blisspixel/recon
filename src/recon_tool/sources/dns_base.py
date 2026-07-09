"""DNS resolution primitives and the detection-context accumulator.

Extracted from ``sources/dns.py`` (docs/roadmap.md god-file track). Holds the
shared async resolver, the leak-guarded ``safe_resolve``, and the mutable
``DetectionCtx`` every sub-detector threads through. A leaf below the detectors:
it imports the static helpers from ``dns_tables`` and is imported by ``dns.py``
and the per-channel detector modules, never the reverse. ``safe_resolve`` /
``get_resolver`` are the seams tests monkeypatch (on this module).
"""

from __future__ import annotations

import logging
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from recon_tool.fingerprints import get_m365_slugs as _get_m365_slugs
from recon_tool.fingerprints import load_fingerprints
from recon_tool.models import (
    CertSummary,
    ChainMotifObservation,
    EvidenceRecord,
    InfrastructureClusterReport,
    SurfaceAttribution,
    UnclassifiedCnameChain,
)
from recon_tool.sources.dns_tables import is_public_dns_name, parse_rdata

logger = logging.getLogger("recon")


# Per-query timeout in seconds. Prevents a single slow/hanging DNS server
# from stalling the entire detection chain. Each safe_resolve call gets
# this as the `lifetime` parameter - total wall-clock time for the query
# including retries across all configured nameservers.
DNS_QUERY_TIMEOUT = 5.0


def get_resolver() -> dns.asyncresolver.Resolver:
    """Return the async resolver instance. Overridable for testing."""
    return _default_resolver


# Default async resolver instance - reused across queries within a lookup
# and across concurrent lookups. This is safe to share: the resolver is
# constructed with no answer cache (dnspython defaults cache=None), so
# concurrent resolve() calls from many asyncio tasks share no mutable
# answer state. The only shared mutable field is the nameserver-rotation
# index, whose races are benign (they only affect which configured
# nameserver a query picks). A per-lookup resolver would add construction
# cost on the hot path without a correctness benefit.
_default_resolver = dns.asyncresolver.Resolver()


# Query types that are exempt from the canonical-name leak guard below.
# A CNAME query returns the immediate record without the recursive
# resolver chasing further (the CNAME walker validates that target
# itself), and PTR records legitimately CNAME within the .arpa tree
# (RFC 2317 classless reverse delegation), so a private-looking .arpa
# canonical there is normal, not a leak. Every other query type (A,
# AAAA, TXT, MX, SRV, NS, CAA) makes a recursive resolver chase a CNAME
# on the queried name before answering, which is the leak vector.
_CANONICAL_GUARD_SKIP_RDTYPES = frozenset({"CNAME", "PTR"})


async def safe_resolve(domain: str, rdtype: str, timeout: float = DNS_QUERY_TIMEOUT) -> list[str]:
    """Resolve DNS records asynchronously, returning empty list on any error.

    Uses dns.asyncresolver for non-blocking DNS queries, allowing multiple
    queries to run concurrently via asyncio.gather.

    **Internal-DNS leak guard.** For every query type other than CNAME
    and PTR, the answer is discarded when the recursive resolver chased
    a CNAME to a non-public canonical name (a ``.corp`` / ``.internal``
    / ``.local`` / IP-literal / other private-suffix target). recon
    queries many subdomains of a domain whose DNS the looked-up party
    controls (DKIM selectors, SRV records, IdP and Exchange probe
    prefixes), and any non-CNAME query on such a name makes the
    operator's resolver chase a CNAME server-side before recon sees
    anything. Discarding private-canonical answers means an internal
    name is never returned in records (no disclosure) and a query that
    chased to a private name yields the same empty result as a name
    that does not resolve (no observable oracle). This generalizes the
    CNAME walker's per-hop suffix denylist to every other query path.
    The residual is a single blind query in the type-dependent-answer
    case, which returns nothing observable. See
    docs/security-audit-resolutions.md.

    Args:
        domain: The domain name to query.
        rdtype: DNS record type (TXT, MX, CNAME, etc.).
        timeout: Max wall-clock seconds for this query (default: DNS_QUERY_TIMEOUT).
    """
    try:
        resolver = get_resolver()
        answers = await resolver.resolve(domain, rdtype, lifetime=timeout)
        if rdtype not in _CANONICAL_GUARD_SKIP_RDTYPES:
            queried = domain.strip().rstrip(".").lower()
            canonical = str(answers.canonical_name).rstrip(".").lower()  # pyright: ignore[reportGeneralTypeIssues]
            if canonical != queried and not is_public_dns_name(canonical):
                logger.debug(
                    "DNS %s answer for %s discarded: resolver chased CNAME to non-public canonical %s",
                    rdtype,
                    domain,
                    canonical,
                )
                return []
        return [parse_rdata(rdata.to_text()) for rdata in answers]  # pyright: ignore[reportGeneralTypeIssues]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        logger.debug("DNS %s lookup timed out for %s (%.1fs)", rdtype, domain, timeout)
        return []
    except Exception as exc:
        logger.debug("DNS %s lookup failed for %s: %s", rdtype, domain, exc)
        return []


class DetectionCtx:
    """Mutable accumulator for service detection results.

    Uses __slots__ for minor memory/speed benefit since we create one per lookup.
    Not a dataclass because we need the custom add() method with the m365 side-effect,
    and the fields are mutated freely by the sub-detectors (frozen=False would work
    but __slots__ is simpler for a private internal class).

    THREAD SAFETY: This class is NOT thread-safe. All sub-detectors MUST run on
    the same event loop (asyncio.gather), not in separate threads. Do NOT wrap
    sub-detectors in asyncio.to_thread() or use thread-based executors - the
    shared mutable state will race. If threading is ever needed, replace this
    with a lock-protected accumulator or per-detector return values.
    """

    __slots__ = (
        "_m365_slugs",
        "_matched_fp_detections",
        "active_probes",
        "bimi_identity",
        "cert_summary",
        "chain_motifs",
        "ct_attempt_outcome",
        "ct_cache_age_days",
        "ct_provider_used",
        "ct_subdomain_count",
        "degraded_sources",
        "dmarc_np",
        "dmarc_pct",
        "dmarc_policy",
        "dmarc_testing",
        "evidence",
        "infrastructure_clusters",
        "m365",
        "mta_sts_mode",
        "raw_dns_records",
        "related_domains",
        "services",
        "site_verification_tokens",
        "slugs",
        "spf_include_count",
        "surface_attributions",
        "unclassified_cname_chains",
    )

    def __init__(self) -> None:
        self.services: set[str] = set()
        self.slugs: set[str] = set()
        self.m365: bool = False
        # Opt-in direct probes to target-controlled hosts (here: the BIMI VMC
        # fetch). False keeps the DNS source passive; set by DNSSource.lookup
        # from the active_probes kwarg.
        self.active_probes: bool = False
        self.dmarc_policy: str | None = None
        self.dmarc_testing: bool = False
        self.dmarc_np: str | None = None
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
        # R4: which CT provider actually contributed subdomains,
        # and how many came back. Surfaced in the panel bottom Note so
        # users can distinguish "crt.sh unavailable" from "certspotter
        # pagination returned 87 entries". None until a provider succeeds.
        self.ct_provider_used: str | None = None
        self.ct_subdomain_count: int = 0
        # CT cache age in days when cached data used as fallback
        self.ct_cache_age_days: int | None = None
        # Per-record CT attempt outcome. See ``TenantInfo.ct_attempt_outcome``
        # for the enum values. None when CT enumeration was not attempted
        # for this lookup (e.g. ``--no-ct``); set by ``_detect_cert_intel``.
        self.ct_attempt_outcome: str | None = None
        # Per-subdomain attributions from CNAME-chain classification.
        # Populated after the main detector gather, since classification
        # depends on related_domains being collected first.
        self.surface_attributions: list[SurfaceAttribution] = []
        # CNAME chains resolved during surface classification that
        # didn't match any cname_target rule. Always captured; surfaced
        # only when --include-unclassified is set. Feeds fingerprint-
        # discovery tooling. Wildcard echoes are filtered before this list
        # is populated.
        self.unclassified_cname_chains: list[UnclassifiedCnameChain] = []
        # Motif observations from data/motifs.yaml. Each entry
        # records a CDN/origin shape that fired on a related subdomain's
        # CNAME chain - never an ownership claim.
        self.chain_motifs: list[ChainMotifObservation] = []
        # CT co-occurrence community detection report. Built from
        # the same cert entries that produce cert_summary; surfaced as
        # the top-level ``infrastructure_clusters`` JSON field. None
        # until a CT provider returns data.
        self.infrastructure_clusters: InfrastructureClusterReport | None = None

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
                # All detections matched - keep the fingerprint's results
                continue

            # Partial match - remove this fingerprint's contributions.
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
                    # match_mode: any - any single detection match is enough
                    if any(
                        (other_fp.slug, det.type, det.pattern) in self._matched_fp_detections
                        for det in other_fp.detections
                    ):
                        other_has_slug = True
                        break
                else:
                    # match_mode: all - all detections must match
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
