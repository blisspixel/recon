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
from recon_tool.models import CertSummary

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
)

# Timeout for CT HTTP calls — separate from DNS query timeout
# because CT services can be slow under load.
_CT_TIMEOUT = 8.0


# ── Protocol ────────────────────────────────────────────────────────────


@runtime_checkable
class CertIntelProvider(Protocol):
    """Protocol for certificate transparency intelligence providers."""

    @property
    def name(self) -> str:
        """Unique identifier for this provider (e.g. 'crt.sh', 'certspotter')."""
        ...

    async def query(self, domain: str) -> tuple[list[str], CertSummary | None]:
        """Query CT data for a domain.

        Returns:
            Tuple of (discovered_subdomains, optional CertSummary).

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

    for raw_name in raw_names:
        name = raw_name.lower().strip()
        if not name or name == domain_lower:
            continue
        if any(name.startswith(prefix) for prefix in skip_prefixes):
            continue
        if not name.endswith(f".{domain_lower}"):
            continue
        seen.add(name)

    if not seen:
        return []

    def _sort_key(name: str) -> tuple[int, int, str]:
        """Sort: high-signal prefixes first, then by depth (shallow first), then alpha."""
        prefix = name.split(f".{domain_lower}")[0]
        is_high = 0 if any(prefix.startswith(p) or prefix.endswith(p) for p in HIGH_SIGNAL_PREFIXES) else 1
        depth = prefix.count(".")
        return (is_high, depth, name)

    return sorted(seen, key=_sort_key)[:max_count]


def build_cert_summary(
    entries: list[dict[str, str | int | None]],
    now: datetime,
) -> CertSummary | None:
    """Build a CertSummary from certificate metadata entries.

    Each entry should have keys: issuer_id (or issuer_ca_id), issuer_name,
    not_before, not_after. Entries missing required fields are skipped.

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
            not_before_dt = datetime.fromisoformat(not_before_raw)
            # Validate not_after is also parseable
            datetime.fromisoformat(not_after_raw)
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

    return CertSummary(
        cert_count=cert_meta_count,
        issuer_diversity=len(issuer_ids),
        issuance_velocity=sum(1 for dt in aware_dates if dt >= ninety_days_ago),
        newest_cert_age_days=max((now - newest_dt).days, 0),
        oldest_cert_age_days=max((now - oldest_dt).days, 0),
        top_issuers=tuple(name for name, _ in issuer_name_counter.most_common(3)),
    )


# ── CrtshProvider ───────────────────────────────────────────────────────


class CrtshProvider:
    """CertIntelProvider backed by crt.sh certificate transparency logs."""

    @property
    def name(self) -> str:
        return "crt.sh"

    async def query(self, domain: str) -> tuple[list[str], CertSummary | None]:
        """Query crt.sh for subdomain discovery and cert metadata.

        Raises on any failure so the fallback chain can proceed.
        """
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with http_client(timeout=_CT_TIMEOUT) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                msg = f"crt.sh returned HTTP {resp.status_code} for {domain}"
                raise httpx.HTTPStatusError(msg, request=resp.request, response=resp)
            data = resp.json()

        if not isinstance(data, list):
            return [], None

        # Extract subdomain names from name_value fields
        raw_names: list[str] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            name_value = entry.get("name_value", "")
            if not isinstance(name_value, str):
                continue
            for raw_name in name_value.strip().split("\n"):
                raw_names.append(raw_name.strip())

        subdomains = filter_subdomains(raw_names, domain)

        # Build cert metadata entries for CertSummary
        cert_entries: list[dict[str, str | int | None]] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            cert_entries.append(
                {
                    "issuer_ca_id": entry.get("issuer_ca_id"),
                    "issuer_id": entry.get("issuer_ca_id"),
                    "issuer_name": entry.get("issuer_name"),
                    "not_before": entry.get("not_before"),
                    "not_after": entry.get("not_after"),
                }
            )

        now = datetime.now(timezone.utc)
        cert_summary = build_cert_summary(cert_entries, now)

        return subdomains, cert_summary


# ── CertSpotterProvider ─────────────────────────────────────────────────


class CertSpotterProvider:
    """CertIntelProvider backed by the CertSpotter free API.

    Zero API keys, zero credentials. Uses the public unauthenticated endpoint.
    """

    _BASE_URL = "https://api.certspotter.com/v1/issuances"

    @property
    def name(self) -> str:
        return "certspotter"

    async def query(self, domain: str) -> tuple[list[str], CertSummary | None]:
        """Query CertSpotter for subdomain discovery and cert metadata.

        Raises on any failure so the fallback chain can proceed.
        """
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": ["dns_names", "issuer"],
        }
        async with http_client(timeout=_CT_TIMEOUT) as client:
            resp = await client.get(self._BASE_URL, params=params)
            if resp.status_code != 200:
                msg = f"CertSpotter returned HTTP {resp.status_code} for {domain}"
                raise httpx.HTTPStatusError(msg, request=resp.request, response=resp)
            data = resp.json()

        if not isinstance(data, list):
            return [], None

        # Extract subdomain names from dns_names arrays
        raw_names: list[str] = []
        cert_entries: list[dict[str, str | int | None]] = []

        for issuance in data:
            if not isinstance(issuance, dict):
                continue

            # Subdomain extraction from dns_names
            dns_names = issuance.get("dns_names", [])
            if isinstance(dns_names, list):
                for name in dns_names:
                    if isinstance(name, str):
                        raw_names.append(name.strip())

            # Cert metadata extraction
            issuer = issuance.get("issuer")
            issuer_name = None
            if isinstance(issuer, dict):
                issuer_name = issuer.get("friendly_name") or issuer.get("name")

            not_before = issuance.get("not_before")
            not_after = issuance.get("not_after")

            # Use a hash of issuer_name as issuer_id for diversity counting
            cert_entries.append(
                {
                    "issuer_id": issuer_name,
                    "issuer_name": issuer_name,
                    "not_before": not_before,
                    "not_after": not_after,
                }
            )

        subdomains = filter_subdomains(raw_names, domain)

        now = datetime.now(timezone.utc)
        cert_summary = build_cert_summary(cert_entries, now)

        return subdomains, cert_summary
