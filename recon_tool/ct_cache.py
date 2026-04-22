"""Per-domain CT subdomain cache.

Stores CT provider results as JSON files in {Config_Dir}/ct-cache/.
One file per domain, seven-day default TTL, lazy eviction via mtime.
All I/O wrapped in try/except — never raises to caller.

Separate from the main TenantInfo cache (cache.py): the CT cache stores
only the raw provider output (subdomains + cert summary) so it can serve
as a fallback when all live CT providers are degraded without needing a
full TenantInfo round-trip.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from recon_tool.models import CertSummary

__all__ = [
    "CT_CACHE_TTL",
    "CTCacheEntry",
    "CTCacheInfo",
    "ct_cache_clear",
    "ct_cache_clear_all",
    "ct_cache_dir",
    "ct_cache_get",
    "ct_cache_list",
    "ct_cache_put",
    "ct_cache_show",
]

logger = logging.getLogger("recon")

CT_CACHE_TTL: int = 604800  # 7 days in seconds


@dataclass(frozen=True)
class CTCacheEntry:
    """Data returned from a CT cache hit."""

    subdomains: tuple[str, ...]
    cert_summary: CertSummary | None
    provider_used: str
    cached_at: str  # ISO timestamp
    age_days: int


@dataclass(frozen=True)
class CTCacheInfo:
    """Metadata about a cached CT entry (for `recon cache show`)."""

    domain: str
    provider_used: str
    subdomain_count: int
    cached_at: str
    age_days: int
    file_size_bytes: int


def ct_cache_dir() -> Path:
    """Return the CT cache directory, respecting RECON_CONFIG_DIR."""
    config = os.environ.get("RECON_CONFIG_DIR")
    base = Path(config) if config else Path.home() / ".recon"
    return base / "ct-cache"


def _safe_path(domain: str) -> Path:
    """Resolve a cache file path, rejecting path traversal attempts.

    The prior ``str(path).startswith(str(d.resolve()))`` check was
    path-prefix rather than path-aware: a crafted domain like
    ``../ct-cache-malice/evil`` could resolve to a sibling directory
    whose path string still started with the ``ct-cache`` prefix and
    slip through. ``Path.is_relative_to`` is the correct containment
    check — it compares path components, so siblings don't pass.
    A light-weight input guard also rejects the most common traversal
    characters before resolution, giving defense in depth.
    """
    if not domain or "/" in domain or "\\" in domain or ".." in domain:
        msg = f"Invalid domain for cache path: {domain}"
        raise ValueError(msg)
    d = ct_cache_dir().resolve()
    path = (d / f"{domain}.json").resolve()
    try:
        if not path.is_relative_to(d):
            msg = f"Invalid domain for cache path: {domain}"
            raise ValueError(msg)
    except (ValueError, OSError) as exc:
        msg = f"Invalid domain for cache path: {domain}"
        raise ValueError(msg) from exc
    return path


def ct_cache_get(domain: str, ttl: int = CT_CACHE_TTL) -> CTCacheEntry | None:
    """Read cached CT data for domain. Returns None if missing/stale/corrupt."""
    try:
        path = _safe_path(domain)
        if not path.exists():
            return None
        mtime = path.stat().st_mtime
        age_seconds = time.time() - mtime
        if age_seconds > ttl:
            logger.debug("CT cache stale for %s (age %.0f s > %d s)", domain, age_seconds, ttl)
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("CT cache payload must be a JSON object")
        return _entry_from_dict(data, age_seconds)
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        logger.debug("CT cache read failed for %s", domain, exc_info=True)
        return None


def ct_cache_put(
    domain: str,
    subdomains: list[str],
    cert_summary: CertSummary | None,
    provider_used: str,
) -> None:
    """Write CT results to cache. Creates dir if needed. Logs on failure."""
    try:
        d = ct_cache_dir()
        d.mkdir(parents=True, exist_ok=True)
        path = _safe_path(domain)
        data = _entry_to_dict(subdomains, cert_summary, provider_used)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.debug("CT cache written for %s (%d subdomains)", domain, len(subdomains))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        logger.debug("CT cache write failed for %s", domain, exc_info=True)


def ct_cache_clear(domain: str) -> bool:
    """Remove cached CT data for a domain. Returns True if file existed."""
    try:
        path = _safe_path(domain)
        if path.exists():
            path.unlink()
            return True
        return False
    except (OSError, ValueError):
        logger.debug("CT cache clear failed for %s", domain, exc_info=True)
        return False


def ct_cache_clear_all() -> int:
    """Remove all cached CT data. Returns count of files removed."""
    count = 0
    try:
        d = ct_cache_dir()
        if not d.exists():
            return 0
        for f in d.glob("*.json"):
            try:
                f.unlink()
                count += 1
            except OSError:
                logger.debug("Failed to remove %s", f, exc_info=True)
    except OSError:
        logger.debug("CT cache clear-all failed", exc_info=True)
    return count


def ct_cache_show(domain: str) -> CTCacheInfo | None:
    """Return metadata about a cached CT entry, or None if not cached."""
    try:
        path = _safe_path(domain)
        if not path.exists():
            return None
        stat = path.stat()
        age_seconds = time.time() - stat.st_mtime
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("CT cache payload must be a JSON object")
        return CTCacheInfo(
            domain=domain,
            provider_used=data.get("provider_used", "unknown"),
            subdomain_count=len(data.get("subdomains", [])),
            cached_at=data.get("cached_at", "unknown"),
            age_days=int(age_seconds / 86400),
            file_size_bytes=stat.st_size,
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        logger.debug("CT cache show failed for %s", domain, exc_info=True)
        return None


def ct_cache_list() -> list[CTCacheInfo]:
    """List all cached CT entries with metadata."""
    entries: list[CTCacheInfo] = []
    try:
        d = ct_cache_dir()
        if not d.exists():
            return entries
        for f in sorted(d.glob("*.json")):
            domain = f.stem
            info = ct_cache_show(domain)
            if info is not None:
                entries.append(info)
    except OSError:
        logger.debug("CT cache list failed", exc_info=True)
    return entries


# ── Serialization ─────────────────────────────────────────────────────


def _entry_to_dict(
    subdomains: list[str],
    cert_summary: CertSummary | None,
    provider_used: str,
) -> dict[str, Any]:
    d: dict[str, Any] = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "provider_used": provider_used,
        "subdomains": subdomains,
    }
    if cert_summary is not None:
        d["cert_summary"] = {
            "cert_count": cert_summary.cert_count,
            "issuer_diversity": cert_summary.issuer_diversity,
            "issuance_velocity": cert_summary.issuance_velocity,
            "newest_cert_age_days": cert_summary.newest_cert_age_days,
            "oldest_cert_age_days": cert_summary.oldest_cert_age_days,
            "top_issuers": list(cert_summary.top_issuers),
        }
    else:
        d["cert_summary"] = None
    return d


def _entry_from_dict(data: dict[str, Any], age_seconds: float) -> CTCacheEntry:
    cs_data = data.get("cert_summary")
    cert_summary: CertSummary | None = None
    if isinstance(cs_data, dict):
        cert_summary = CertSummary(
            cert_count=int(cs_data.get("cert_count", 0)),
            issuer_diversity=int(cs_data.get("issuer_diversity", 0)),
            issuance_velocity=int(cs_data.get("issuance_velocity", 0)),
            newest_cert_age_days=int(cs_data.get("newest_cert_age_days", 0)),
            oldest_cert_age_days=int(cs_data.get("oldest_cert_age_days", 0)),
            top_issuers=tuple(cs_data.get("top_issuers", [])),
        )
    return CTCacheEntry(
        subdomains=tuple(data.get("subdomains", [])),
        cert_summary=cert_summary,
        provider_used=data.get("provider_used", "unknown"),
        cached_at=data.get("cached_at", "unknown"),
        age_days=int(age_seconds / 86400),
    )
