"""Certificate transparency intelligence providers.

Abstracts CT querying behind a CertIntelProvider protocol with shared
filtering helpers. Providers: CrtshProvider (primary), CertSpotterProvider (fallback).

All HTTP goes through the SSRF-safe client from recon_tool/http.py.
Zero credentials, zero API keys.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

import httpx

from recon_tool.http import http_client
from recon_tool.infra_graph import build_infrastructure_clusters
from recon_tool.models import CertBurst, CertSummary, InfrastructureClusterReport

# ── v1.7 caps for derived cert intelligence ──────────────────────────────
# Wildcard SAN sibling clusters: each cert that contains ≥1 wildcard SAN
# can produce one cluster of its non-wildcard SANs. We bound both how
# many clusters surface and how big each cluster can be — a single cert
# with hundreds of SANs would otherwise dominate the field.
_MAX_WILDCARD_CLUSTERS = 10
_MAX_NAMES_PER_CLUSTER = 20

# Temporal CT burst detection: certificates whose not_before timestamps
# fall within ``_BURST_WINDOW_SECONDS`` of each other are treated as a
# co-issuance cohort. The minimum cohort size keeps single renewals out
# of the burst output. ``_MAX_BURSTS`` and ``_MAX_NAMES_PER_BURST`` cap
# the surface so a long history with constant renewals does not flood
# the JSON.
_BURST_WINDOW_SECONDS = 60
_MIN_BURST_NAMES = 3
_MAX_BURSTS = 8
_MAX_NAMES_PER_BURST = 25


def _parse_iso_datetime(value: str) -> datetime:
    """Parse an ISO-8601 timestamp tolerating a trailing ``Z``.

    Python 3.10's ``datetime.fromisoformat`` rejects the ``Z`` UTC
    suffix that CertSpotter and many CT log emitters use; only 3.11+
    accepts it natively. We normalise here so both providers behave
    the same on every supported Python. Raises ValueError on
    unparseable input — callers handle that.
    """
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(normalized)


logger = logging.getLogger("recon")

__all__ = [
    "CertIntelProvider",
    "CertSpotterProvider",
    "CrtshProvider",
    "build_cert_summary",
    "filter_subdomains",
]

# ── Shared constants ────────────────────────────────────────────────────

# Patterns to filter out from CT results — wildcards, common noise,
# and subdomains that rarely have interesting TXT/MX records.
SKIP_PREFIXES = (
    "*.",
    "cpanel.",
    "cpcalendars.",
    "cpcontacts.",
    "webdisk.",
    "webmail.",
    "mail.",
    "ftp.",
    "localhost.",
    "www.",
)

# Maximum number of unique subdomains to extract from CT results.
MAX_SUBDOMAINS = 100

# Bound local processing of CT provider responses. The HTTP client still
# receives a provider response as a whole, but parsing every certificate
# entry and every name from a very large crt.sh JSON payload can create
# avoidable CPU/memory spikes before the public ``MAX_SUBDOMAINS`` cap is
# applied. These limits keep extraction proportional to the output cap.
_MAX_CRTSH_ENTRIES = MAX_SUBDOMAINS * 20
_MAX_CRTSH_RAW_NAMES = MAX_SUBDOMAINS * 10
_MAX_CRTSH_CERT_SUMMARY_ENTRIES = MAX_SUBDOMAINS * 10

# Hostnames cap out at 253 chars. A pathological crt.sh ``name_value``
# field could in principle list millions of newline-delimited names,
# and parsing the whole field before any later cap is what made
# CrtshProvider memory-unbounded under hostile/malformed CT responses.
# Cap the per-cert SAN parse to a generous-but-bounded number; sane
# certs are well below this (web PKI BR limits push real certs to a
# few thousand SANs at the outside).
_MAX_SANS_PER_CERT = 2000

# High-signal subdomain prefixes that commonly CNAME to SaaS providers.
HIGH_SIGNAL_PREFIXES = (
    "auth",
    "login",
    "sso",
    "secure",
    "id",
    "identity",
    "shop",
    "store",
    "checkout",
    "pay",
    "api",
    "app",
    "portal",
    "dashboard",
    "support",
    "help",
    "status",
    "track",
    "click",
    "image",
    "view",
    "email",
    "em.",
    "cdn",
    "assets",
    "static",
    "media",
    "blog",
    "docs",
    "kb",
    "stage",
    "staging",
    "dev",
    "sandbox",
    "preview",
    "uat",
    # v1.9.9: keep prioritization in parity with the dns.py probe
    # wordlist. CT SAN sets that include these prefixes should sort to
    # the top of the returned subdomain list so the operator sees the
    # data, AI, ops, and security tiers when CT happens to surface them.
    "data",
    "analytics",
    "ml",
    "ai",
    "internal",
    "ops",
    "tools",
    "security",
)

# Timeout for CT HTTP calls — separate from DNS query timeout
# because CT services can be slow under load. Kept tight so a slow
# provider fails fast and the fallback chain proceeds.
_CT_TIMEOUT = 6.0


# ── Protocol ────────────────────────────────────────────────────────────


@runtime_checkable
class CertIntelProvider(Protocol):
    """Protocol for certificate transparency intelligence providers."""

    @property
    def name(self) -> str:
        """Unique identifier for this provider (e.g. 'crt.sh', 'certspotter')."""
        ...

    async def query(
        self,
        domain: str,
    ) -> tuple[list[str], CertSummary | None, InfrastructureClusterReport | None]:
        """Query CT data for a domain.

        Returns:
            Tuple of ``(discovered_subdomains, cert_summary,
            infrastructure_clusters)``. ``cert_summary`` is None when no
            cert metadata could be parsed; ``infrastructure_clusters``
            is None on the same condition (the report is built from the
            same entries).

        Raises:
            Exception on failure (timeout, HTTP error, etc.) so the
            fallback chain can proceed to the next provider.
        """
        ...


# ── Shared filtering helpers ────────────────────────────────────────────


def filter_subdomains(
    raw_names: list[str],
    domain: str,
    skip_prefixes: tuple[str, ...] = SKIP_PREFIXES,
    max_count: int = MAX_SUBDOMAINS,
) -> list[str]:
    """Filter and prioritize subdomain names from CT results.

    Applies: wildcard removal, noise-prefix skip, subdomain-of-domain
    validation, priority sort (high-signal first, shallow first), max cap.

    Args:
        raw_names: Raw subdomain strings (may include wildcards, noise, etc.)
        domain: The queried domain (e.g. "example.com")
        skip_prefixes: Prefixes to filter out
        max_count: Maximum number of subdomains to return

    Returns:
        Filtered, prioritized list of subdomain strings.
    """
    domain_lower = domain.lower()
    seen: set[str] = set()

    # Hard ceiling on accumulation to bound worst-case memory and sort
    # cost. A domain with an enormous CT history (tens of thousands of
    # distinct subdomains) would otherwise force the whole set into
    # memory and sort it — when recon is exposed via MCP to an untrusted
    # caller, that's an easy CPU-spike vector. Capping at ``max_count *
    # 10`` keeps enough headroom to still prioritize high-signal
    # subdomains correctly while bounding the work.
    hard_cap = max_count * 10

    for raw_name in raw_names:
        name = raw_name.lower().strip()
        if not name or name == domain_lower:
            continue
        if any(name.startswith(prefix) for prefix in skip_prefixes):
            continue
        if not name.endswith(f".{domain_lower}"):
            continue
        seen.add(name)
        if len(seen) >= hard_cap:
            break

    if not seen:
        return []

    def _sort_key(name: str) -> tuple[int, int, str]:
        """Sort: high-signal prefixes first, then by depth (shallow first), then alpha."""
        prefix = name.split(f".{domain_lower}")[0]
        is_high = 0 if any(prefix.startswith(p) or prefix.endswith(p) for p in HIGH_SIGNAL_PREFIXES) else 1
        depth = prefix.count(".")
        return (is_high, depth, name)

    return sorted(seen, key=_sort_key)[:max_count]


def _extract_wildcard_sibling_clusters(
    entries: list[dict[str, str | int | list[str] | None]],
) -> tuple[tuple[str, ...], ...]:
    """Walk cert entries, harvesting non-wildcard SANs from any cert that
    also covered a wildcard SAN.

    Each cert that contains ``*.something`` produces one cluster: the
    sorted, deduplicated, non-wildcard SAN set from that same cert.
    Wildcards in the cluster itself are dropped (the wildcard fact is
    already implicit in the cluster's existence).

    Bounded by ``_MAX_WILDCARD_CLUSTERS`` and ``_MAX_NAMES_PER_CLUSTER``
    to keep one massive cert from dominating the field. Identical
    clusters across renewals are deduplicated.
    """
    seen_clusters: set[tuple[str, ...]] = set()
    out: list[tuple[str, ...]] = []
    for entry in entries:
        names = entry.get("dns_names")
        if not isinstance(names, list) or not names:
            continue
        # Need at least one wildcard SAN for this cert to be a "wildcard
        # cert" for our purposes.
        has_wildcard = any(n.startswith("*.") for n in names)
        if not has_wildcard:
            continue
        siblings: set[str] = set()
        for n in names:
            normalized = n.strip().lower()
            if not normalized or normalized.startswith("*."):
                continue
            siblings.add(normalized)
        if not siblings:
            continue
        cluster = tuple(sorted(siblings)[:_MAX_NAMES_PER_CLUSTER])
        if cluster in seen_clusters:
            continue
        seen_clusters.add(cluster)
        out.append(cluster)
        if len(out) >= _MAX_WILDCARD_CLUSTERS:
            break
    return tuple(out)


def _detect_deployment_bursts(
    entries: list[dict[str, str | int | list[str] | None]],
) -> tuple[CertBurst, ...]:
    """Cluster cert entries by ``not_before`` proximity.

    Sort entries by parseable ``not_before``; each contiguous group whose
    span fits inside ``_BURST_WINDOW_SECONDS`` becomes a candidate burst.
    A burst is emitted only when the cohort has at least
    ``_MIN_BURST_NAMES`` distinct non-wildcard SANs across the group.

    Output is intentionally relative — span_seconds + name list — and
    never claims ownership. Co-issuance is observable; "same owner" is
    not.
    """
    parsed: list[tuple[datetime, list[str]]] = []
    for entry in entries:
        not_before_raw = entry.get("not_before")
        if not isinstance(not_before_raw, str):
            continue
        try:
            dt = _parse_iso_datetime(not_before_raw)
        except (ValueError, TypeError):
            continue
        dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        names = entry.get("dns_names")
        names_list: list[str] = []
        if isinstance(names, list):
            for n in names:
                nm = n.strip().lower()
                if nm and not nm.startswith("*."):
                    names_list.append(nm)
        parsed.append((dt, names_list))

    if not parsed:
        return ()
    parsed.sort(key=lambda t: t[0])

    bursts: list[CertBurst] = []
    i = 0
    while i < len(parsed):
        window_start = parsed[i][0]
        cluster: list[tuple[datetime, list[str]]] = [parsed[i]]
        j = i + 1
        while j < len(parsed):
            if (parsed[j][0] - window_start).total_seconds() <= _BURST_WINDOW_SECONDS:
                cluster.append(parsed[j])
                j += 1
            else:
                break
        # Collect distinct non-wildcard SANs across the cohort.
        names_set: set[str] = set()
        for _, ns in cluster:
            names_set.update(ns)
        if len(names_set) >= _MIN_BURST_NAMES:
            window_end = cluster[-1][0]
            span = max(int((window_end - window_start).total_seconds()), 0)
            sorted_names = tuple(sorted(names_set)[:_MAX_NAMES_PER_BURST])
            bursts.append(
                CertBurst(
                    window_start=window_start.isoformat(),
                    window_end=window_end.isoformat(),
                    span_seconds=span,
                    names=sorted_names,
                )
            )
            if len(bursts) >= _MAX_BURSTS:
                break
        i = j if j > i else i + 1
    return tuple(bursts)


def build_cert_summary(
    entries: list[dict[str, str | int | list[str] | None]],
    now: datetime,
) -> CertSummary | None:
    """Build a CertSummary from certificate metadata entries.

    Each entry should have keys: issuer_id (or issuer_ca_id), issuer_name,
    not_before, not_after. Entries missing required fields are skipped.
    When an entry also carries a ``dns_names`` list (CertSpotter, or
    crt.sh after the v1.7 SAN-attached payload change), wildcard sibling
    clustering and temporal burst detection both run.

    Args:
        entries: List of cert metadata dicts.
        now: Current UTC datetime for age calculations.

    Returns:
        CertSummary if any valid entries found, None otherwise.
    """
    issuer_ids: set[str] = set()
    issuer_name_counter: Counter[str] = Counter()
    not_before_dates: list[datetime] = []
    cert_meta_count = 0

    for entry in entries:
        issuer_id = entry.get("issuer_id") or entry.get("issuer_ca_id")
        issuer_name = entry.get("issuer_name")
        not_before_raw = entry.get("not_before")
        not_after_raw = entry.get("not_after")

        if issuer_id is None or issuer_name is None or not_before_raw is None or not_after_raw is None:
            continue
        if not isinstance(not_before_raw, str) or not isinstance(not_after_raw, str):
            continue

        try:
            not_before_dt = _parse_iso_datetime(not_before_raw)
            # Validate not_after is also parseable
            _parse_iso_datetime(not_after_raw)
        except (ValueError, TypeError):
            continue

        cert_meta_count += 1
        issuer_ids.add(str(issuer_id))
        issuer_name_counter[str(issuer_name)] += 1
        not_before_dates.append(not_before_dt)

    if cert_meta_count == 0 or not not_before_dates:
        return None

    # Make all dates offset-aware for comparison with `now`
    aware_dates = []
    for dt in not_before_dates:
        aware_dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        aware_dates.append(aware_dt)

    newest_dt = max(aware_dates)
    oldest_dt = min(aware_dates)
    ninety_days_ago = now - timedelta(days=90)

    wildcard_clusters = _extract_wildcard_sibling_clusters(entries)
    bursts = _detect_deployment_bursts(entries)

    return CertSummary(
        cert_count=cert_meta_count,
        issuer_diversity=len(issuer_ids),
        issuance_velocity=sum(1 for dt in aware_dates if dt >= ninety_days_ago),
        newest_cert_age_days=max((now - newest_dt).days, 0),
        oldest_cert_age_days=max((now - oldest_dt).days, 0),
        top_issuers=tuple(name for name, _ in issuer_name_counter.most_common(3)),
        wildcard_sibling_clusters=wildcard_clusters,
        deployment_bursts=bursts,
    )


# ── CrtshProvider ───────────────────────────────────────────────────────


class CrtshProvider:
    """CertIntelProvider backed by crt.sh certificate transparency logs."""

    @property
    def name(self) -> str:
        return "crt.sh"

    async def query(
        self,
        domain: str,
    ) -> tuple[list[str], CertSummary | None, InfrastructureClusterReport | None]:
        """Query crt.sh for subdomain discovery and cert metadata.

        Raises on any failure so the fallback chain can proceed.
        """
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with http_client(timeout=_CT_TIMEOUT, retry_transient=False) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                msg = f"crt.sh returned HTTP {resp.status_code} for {domain}"
                raise httpx.HTTPStatusError(msg, request=resp.request, response=resp)
            try:
                data = resp.json()
            except ValueError as exc:
                msg = f"crt.sh returned invalid JSON for {domain}"
                raise httpx.HTTPError(msg) from exc

        if not isinstance(data, list):
            return [], None, None

        # Extract a bounded candidate set from name_value fields. Do
        # not build raw/cert lists from the entire crt.sh payload:
        # large CT histories can contain tens of thousands of names,
        # and only MAX_SUBDOMAINS are ever returned.
        raw_names: list[str] = []
        cert_entries: list[dict[str, str | int | list[str] | None]] = []
        for entry in data[:_MAX_CRTSH_ENTRIES]:
            if not isinstance(entry, dict):
                continue

            # v1.7: parse SANs once so they can both feed the
            # ``raw_names`` discovery list AND attach to the per-cert
            # entry for wildcard-sibling and burst analysis. Bounded
            # by ``_MAX_SANS_PER_CERT`` so a hostile/malformed
            # ``name_value`` cannot exhaust memory during the split.
            name_value = entry.get("name_value", "")
            cert_sans: list[str] = []
            if isinstance(name_value, str):
                for raw_name in name_value.split("\n", _MAX_SANS_PER_CERT):
                    if len(cert_sans) >= _MAX_SANS_PER_CERT:
                        break
                    n = raw_name.strip()
                    if n:
                        cert_sans.append(n)

            if len(cert_entries) < _MAX_CRTSH_CERT_SUMMARY_ENTRIES:
                cert_entries.append(
                    {
                        "issuer_ca_id": entry.get("issuer_ca_id"),
                        "issuer_id": entry.get("issuer_ca_id"),
                        "issuer_name": entry.get("issuer_name"),
                        "not_before": entry.get("not_before"),
                        "not_after": entry.get("not_after"),
                        "dns_names": cert_sans,
                    }
                )

            if len(raw_names) >= _MAX_CRTSH_RAW_NAMES:
                continue
            for n in cert_sans:
                raw_names.append(n)
                if len(raw_names) >= _MAX_CRTSH_RAW_NAMES:
                    break

        subdomains = filter_subdomains(raw_names, domain)

        now = datetime.now(timezone.utc)
        cert_summary = build_cert_summary(cert_entries, now)
        cluster_report = build_infrastructure_clusters(list(cert_entries)) if cert_entries else None

        return subdomains, cert_summary, cluster_report


# ── CertSpotterProvider ─────────────────────────────────────────────────


class CertSpotterProvider:
    """CertIntelProvider backed by the CertSpotter free API.

    Zero API keys, zero credentials. Uses the public unauthenticated endpoint.

    Pagination (v0.9.2): CertSpotter returns issuances in pages. Without
    pagination a single request returns ~100 entries for small domains but
    silently truncates on large targets — producing the enrichment
    asymmetry observed on bank-scale domains (one run returned 5 related
    subdomains, another returned 100+). This provider now follows the
    ``after=`` cursor up to ``_MAX_PAGES`` pages, stopping early when
    enough subdomains have been collected or when the API returns an
    empty page.

    Rate limits: CertSpotter's free tier has weekly IP quotas. When the
    API returns a 429 or an empty first page, we stop and return what
    we have. The caller sees a smaller but non-zero result rather than
    a failure.
    """

    _BASE_URL = "https://api.certspotter.com/v1/issuances"
    # Maximum number of pages to fetch. At 8s timeout per page + ~2s of retry
    # backoff, each page can cost up to ~10s, and we hit this cost 5× in
    # parallel under batch concurrency. Dropped from 4 to 2 after validation
    # on a 100-domain corpus showed 10-14% of big-enterprise lookups hitting
    # the 120s aggregate ceiling, usually during CertSpotter pagination.
    # Two pages still cover ~500 certs, which is enough for the subdomain-
    # discovery use case on all but the very largest cert portfolios.
    _MAX_PAGES = 2

    @property
    def name(self) -> str:
        return "certspotter"

    async def _fetch_page(
        self,
        client: httpx.AsyncClient,
        domain: str,
        after_cursor: str | None,
    ) -> httpx.Response:
        """Fetch a single CertSpotter page. No retry decorator — when CertSpotter
        is consistently slow, three 8s ReadTimeouts per page accumulated >25s of
        pure delay and blew the aggregate resolve budget on big enterprises
        (observed during 150-domain validation: 12% timeout rate). Failing
        fast on the first timeout is better than waiting 25s to discover the
        provider is unhealthy — the caller still gets whatever pages
        succeeded. Returns the raw httpx Response so the caller can inspect
        status_code (429 vs 200 vs other)."""
        params: dict[str, str | list[str]] = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": ["dns_names", "issuer"],
        }
        if after_cursor is not None:
            params["after"] = after_cursor
        return await client.get(self._BASE_URL, params=params)

    async def query(
        self,
        domain: str,
    ) -> tuple[list[str], CertSummary | None, InfrastructureClusterReport | None]:
        """Query CertSpotter for subdomain discovery and cert metadata.

        Iterates through up to ``_MAX_PAGES`` paginated responses using
        CertSpotter's ``after=<issuance_id>`` cursor. Each page's results
        are accumulated into a single raw-names list before filtering.
        Stops early when a page is empty, when a 429 is returned, or when
        the filtered subdomain count already exceeds ``MAX_SUBDOMAINS``.

        Each page fetch is wrapped in ``retry_on_transient`` so a single
        transient connection error doesn't break the entire pagination —
        the retry decorator gives each page two retries before giving up.

        Raises on unrecoverable failures (e.g. an HTTP 5xx that survives
        retry, or a 4xx other than 429) so the fallback chain can proceed.
        A 429 response is NOT raised — the provider returns the data
        collected so far (which may be partial) and the caller can decide
        whether that's enough.
        """
        all_raw_names: list[str] = []
        all_cert_entries: list[dict[str, str | int | list[str] | None]] = []
        after_cursor: str | None = None

        async with http_client(timeout=_CT_TIMEOUT, retry_transient=False) as client:
            for _ in range(self._MAX_PAGES):
                resp = await self._fetch_page(client, domain, after_cursor)
                if resp.status_code == 429:
                    # Rate-limited — stop and return what we have so far.
                    # The caller will see partial but usable data, and the
                    # result is still better than a cascade failure.
                    break
                if resp.status_code != 200:
                    msg = f"CertSpotter returned HTTP {resp.status_code} for {domain}"
                    raise httpx.HTTPStatusError(msg, request=resp.request, response=resp)

                try:
                    data = resp.json()
                except ValueError as exc:
                    msg = f"CertSpotter returned invalid JSON for {domain}"
                    raise httpx.HTTPError(msg) from exc
                if not isinstance(data, list) or not data:
                    # Empty page — we've reached the end of the issuance list.
                    break

                # Extract dns_names and cert metadata from each issuance
                last_id: str | None = None
                for issuance in data:
                    if not isinstance(issuance, dict):
                        continue

                    issuance_id = issuance.get("id")
                    if isinstance(issuance_id, str | int):
                        last_id = str(issuance_id)

                    dns_names = issuance.get("dns_names", [])
                    cert_sans: list[str] = []
                    if isinstance(dns_names, list):
                        for name in dns_names:
                            if len(cert_sans) >= _MAX_SANS_PER_CERT:
                                break
                            if isinstance(name, str):
                                stripped = name.strip()
                                all_raw_names.append(stripped)
                                if stripped:
                                    cert_sans.append(stripped)

                    issuer = issuance.get("issuer")
                    issuer_name = None
                    if isinstance(issuer, dict):
                        issuer_name = issuer.get("friendly_name") or issuer.get("name")
                    not_before = issuance.get("not_before")
                    not_after = issuance.get("not_after")
                    all_cert_entries.append(
                        {
                            "issuer_id": issuer_name,
                            "issuer_name": issuer_name,
                            "not_before": not_before,
                            "not_after": not_after,
                            "dns_names": cert_sans,
                        }
                    )

                # If we already have enough unique candidate names to fill
                # MAX_SUBDOMAINS after filtering, stop early — no point
                # paying for more pages.
                if len(set(all_raw_names)) >= MAX_SUBDOMAINS * 2:
                    break

                # Advance the cursor. If the response didn't include ids
                # we can't paginate any further.
                if last_id is None:
                    break
                after_cursor = last_id

        if not all_raw_names and not all_cert_entries:
            return [], None, None

        subdomains = filter_subdomains(all_raw_names, domain)
        now = datetime.now(timezone.utc)
        cert_summary = build_cert_summary(all_cert_entries, now)
        cluster_report = build_infrastructure_clusters(list(all_cert_entries)) if all_cert_entries else None
        return subdomains, cert_summary, cluster_report
