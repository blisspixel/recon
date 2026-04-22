"""Lightweight JSON disk cache for TenantInfo.

Stores serialized TenantInfo as JSON files in {Config_Dir}/cache/.
Lazy eviction via mtime check — no background process, no directory scanning.
All I/O wrapped in try/except with debug logging, never raises to caller.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from recon_tool.models import (
    BIMIIdentity,
    CertSummary,
    ConfidenceLevel,
    EvidenceRecord,
    TenantInfo,
)

__all__ = [
    "DEFAULT_TTL",
    "cache_clear",
    "cache_clear_all",
    "cache_dir",
    "cache_get",
    "cache_put",
    "tenant_info_from_dict",
    "tenant_info_to_dict",
]

logger = logging.getLogger("recon")

DEFAULT_TTL: int = 86400  # 24 hours

_CACHE_VERSION = 1


def cache_dir() -> Path:
    """Return the cache directory path, respecting RECON_CONFIG_DIR."""
    config = os.environ.get("RECON_CONFIG_DIR")
    base = Path(config) if config else Path.home() / ".recon"
    return base / "cache"


def cache_get(domain: str, ttl: int = DEFAULT_TTL) -> TenantInfo | None:
    """Read cached TenantInfo for domain. Returns None if missing/stale/corrupt.

    The returned ``TenantInfo`` carries ``cached_at`` set from the
    on-disk ``_cached_at`` field so downstream can distinguish a
    cache-served result from a freshly-resolved one. ``resolved_at``
    is preserved from the time the result was first produced.
    """
    try:
        path = _safe_cache_path(domain)
        if path is None:
            logger.debug("Cache read rejected invalid domain: %r", domain)
            return None
        if not path.exists():
            return None
        # Lazy eviction: check mtime against TTL
        mtime = path.stat().st_mtime
        if time.time() - mtime > ttl:
            logger.debug("Cache stale for %s (age > %d s)", domain, ttl)
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        info = tenant_info_from_dict(data)
        cached_at = data.get("_cached_at")
        if isinstance(cached_at, str) and cached_at:
            info = dataclasses.replace(info, cached_at=cached_at)
        return info
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        logger.debug("Cache read failed for %s", domain, exc_info=True)
        return None


def cache_put(domain: str, info: TenantInfo) -> None:
    """Write TenantInfo to cache as JSON. Creates dir if needed. Logs on failure."""
    try:
        d = cache_dir()
        d.mkdir(parents=True, exist_ok=True)
        path = _safe_cache_path(domain)
        if path is None:
            logger.debug("Cache write rejected invalid domain: %r", domain)
            return
        data = tenant_info_to_dict(info)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        logger.debug("Cache write failed for %s", domain, exc_info=True)


def _safe_cache_path(domain: str) -> Path | None:
    """Resolve a cache file path for ``domain``, rejecting traversal.

    Returns None (rather than raising) when the domain is malformed or
    would escape the cache directory. Callers treat None as "no entry
    to operate on" — this keeps ``cache_clear("../../etc/passwd")``
    from deleting files outside ``~/.recon/cache/``. Uses
    ``Path.is_relative_to`` instead of string-prefix matching so
    sibling directories sharing the cache-dir prefix cannot be
    reached via a crafted traversal string.
    """
    if not domain or "/" in domain or "\\" in domain or ".." in domain:
        return None
    d = cache_dir().resolve()
    path = (d / f"{domain}.json").resolve()
    try:
        if not path.is_relative_to(d):
            return None
    except (ValueError, OSError):
        return None
    return path


def cache_clear(domain: str) -> bool:
    """Remove the cached TenantInfo for domain. Returns True if a file was deleted.

    Input is sanitised via ``_safe_cache_path`` — crafted traversal
    strings like ``../settings`` are rejected and the function
    returns ``False`` rather than deleting a file outside the cache
    directory.
    """
    try:
        path = _safe_cache_path(domain)
        if path is None:
            logger.debug("Cache clear rejected invalid domain: %r", domain)
            return False
        if path.exists():
            path.unlink()
            return True
        return False
    except OSError:
        logger.debug("Cache clear failed for %s", domain, exc_info=True)
        return False


def cache_clear_all() -> int:
    """Remove all cached TenantInfo files. Returns the count deleted."""
    try:
        d = cache_dir()
        if not d.exists():
            return 0
        count = 0
        for path in d.glob("*.json"):
            try:
                path.unlink()
                count += 1
            except OSError:
                logger.debug("Cache entry unlink failed: %s", path, exc_info=True)
        return count
    except OSError:
        logger.debug("Cache clear-all failed", exc_info=True)
        return 0


def tenant_info_to_dict(info: TenantInfo) -> dict[str, Any]:
    """Serialize TenantInfo to a JSON-serializable dict with cache metadata.

    Handles: ConfidenceLevel → string, CertSummary/BIMIIdentity → nested dict,
    EvidenceRecord tuple → list of dicts, detection_scores tuple-of-tuples → dict,
    all tuple fields → lists.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    d: dict[str, Any] = {
        "_cached_at": now_iso,
        "_cache_version": _CACHE_VERSION,
        # resolved_at is the original resolution timestamp. Preserve it
        # across cache round-trips so agents can tell when the data was
        # first produced, not just when it was last written to disk.
        "resolved_at": info.resolved_at or now_iso,
        "tenant_id": info.tenant_id,
        "display_name": info.display_name,
        "default_domain": info.default_domain,
        "queried_domain": info.queried_domain,
        "confidence": info.confidence.value,
        "region": info.region,
        "sources": list(info.sources),
        "services": list(info.services),
        "slugs": list(info.slugs),
        "auth_type": info.auth_type,
        "dmarc_policy": info.dmarc_policy,
        "domain_count": info.domain_count,
        "tenant_domains": list(info.tenant_domains),
        "related_domains": list(info.related_domains),
        "insights": list(info.insights),
        "crtsh_degraded": info.crtsh_degraded,
        "degraded_sources": list(info.degraded_sources),
        "evidence_confidence": info.evidence_confidence.value,
        "inference_confidence": info.inference_confidence.value,
        "site_verification_tokens": list(info.site_verification_tokens),
        "mta_sts_mode": info.mta_sts_mode,
        "google_auth_type": info.google_auth_type,
        "google_idp_name": info.google_idp_name,
        "primary_email_provider": info.primary_email_provider,
        "email_gateway": info.email_gateway,
        "dmarc_pct": info.dmarc_pct,
        "likely_primary_email_provider": info.likely_primary_email_provider,
        "ct_provider_used": info.ct_provider_used,
        "ct_subdomain_count": info.ct_subdomain_count,
        "ct_cache_age_days": info.ct_cache_age_days,
        "slug_confidences": [[slug, score] for slug, score in info.slug_confidences],
        "cloud_instance": info.cloud_instance,
        "tenant_region_sub_scope": info.tenant_region_sub_scope,
        "msgraph_host": info.msgraph_host,
        "lexical_observations": list(info.lexical_observations),
        # shared_verification_tokens is intentionally NOT cached — it is
        # batch-scope only and a per-domain lookup should never inherit
        # peers from a previous batch run.
    }

    # CertSummary → nested dict or None
    if info.cert_summary is not None:
        cs = info.cert_summary
        d["cert_summary"] = {
            "cert_count": cs.cert_count,
            "issuer_diversity": cs.issuer_diversity,
            "issuance_velocity": cs.issuance_velocity,
            "newest_cert_age_days": cs.newest_cert_age_days,
            "oldest_cert_age_days": cs.oldest_cert_age_days,
            "top_issuers": list(cs.top_issuers),
        }
    else:
        d["cert_summary"] = None

    # BIMIIdentity → nested dict or None
    if info.bimi_identity is not None:
        bi = info.bimi_identity
        d["bimi_identity"] = {
            "organization": bi.organization,
            "country": bi.country,
            "state": bi.state,
            "locality": bi.locality,
            "trademark": bi.trademark,
        }
    else:
        d["bimi_identity"] = None

    # EvidenceRecord tuple → list of dicts
    d["evidence"] = [
        {
            "source_type": ev.source_type,
            "raw_value": ev.raw_value,
            "rule_name": ev.rule_name,
            "slug": ev.slug,
        }
        for ev in info.evidence
    ]

    # detection_scores tuple-of-tuples → dict
    d["detection_scores"] = dict(info.detection_scores)

    return d


def _parse_confidence(value: Any, fallback: ConfidenceLevel = ConfidenceLevel.MEDIUM) -> ConfidenceLevel:
    """Parse a confidence level string, falling back to MEDIUM on invalid input."""
    if isinstance(value, str):
        try:
            return ConfidenceLevel(value.lower())
        except ValueError:
            return fallback
    return fallback


def _parse_degraded_sources(data: dict[str, Any]) -> tuple[str, ...]:
    """Parse degraded_sources from cache data, with backward compat for crtsh_degraded."""
    # New format: degraded_sources list
    ds = data.get("degraded_sources")
    if isinstance(ds, list):
        return tuple(str(s) for s in ds)
    # Old format: crtsh_degraded bool
    if bool(data.get("crtsh_degraded", False)):
        return ("crt.sh",)
    return ()


def tenant_info_from_dict(data: dict[str, Any]) -> TenantInfo:
    """Deserialize a dict back to TenantInfo. Raises ValueError on invalid data.

    Handles: string → ConfidenceLevel (fallback MEDIUM), nested dicts → frozen
    dataclasses, lists → tuples, dict → tuple-of-tuples for detection_scores.
    """
    if not isinstance(data, dict):  # pyright: ignore[reportUnnecessaryIsInstance, reportUnreachable]
        msg = "Cache data must be a dict"  # pyright: ignore[reportUnreachable]
        raise ValueError(msg)

    # Required string fields
    display_name = data.get("display_name")
    default_domain = data.get("default_domain")
    queried_domain = data.get("queried_domain")
    if display_name is None or not default_domain or not queried_domain:
        msg = "Missing required fields: display_name, default_domain, queried_domain"
        raise ValueError(msg)

    # CertSummary
    cert_summary: CertSummary | None = None
    cs_data = data.get("cert_summary")
    if isinstance(cs_data, dict):
        cert_summary = CertSummary(
            cert_count=int(cs_data.get("cert_count", 0)),
            issuer_diversity=int(cs_data.get("issuer_diversity", 0)),
            issuance_velocity=int(cs_data.get("issuance_velocity", 0)),
            newest_cert_age_days=int(cs_data.get("newest_cert_age_days", 0)),
            oldest_cert_age_days=int(cs_data.get("oldest_cert_age_days", 0)),
            top_issuers=tuple(cs_data.get("top_issuers", [])),
        )

    # BIMIIdentity
    bimi_identity: BIMIIdentity | None = None
    bi_data = data.get("bimi_identity")
    if isinstance(bi_data, dict):
        bimi_identity = BIMIIdentity(
            organization=bi_data.get("organization", ""),
            country=bi_data.get("country"),
            state=bi_data.get("state"),
            locality=bi_data.get("locality"),
            trademark=bi_data.get("trademark"),
        )

    # EvidenceRecord list
    evidence_list = data.get("evidence", [])
    evidence: tuple[EvidenceRecord, ...] = ()
    if isinstance(evidence_list, list):
        records = []
        for ev in evidence_list:
            if isinstance(ev, dict):
                records.append(
                    EvidenceRecord(
                        source_type=ev.get("source_type", ""),
                        raw_value=ev.get("raw_value", ""),
                        rule_name=ev.get("rule_name", ""),
                        slug=ev.get("slug", ""),
                    )
                )
        evidence = tuple(records)

    # detection_scores dict → tuple of tuples
    ds_data = data.get("detection_scores", {})
    detection_scores: tuple[tuple[str, str], ...] = ()
    if isinstance(ds_data, dict):
        detection_scores = tuple((str(k), str(v)) for k, v in ds_data.items())

    return TenantInfo(
        tenant_id=data.get("tenant_id"),
        display_name=display_name,
        default_domain=default_domain,
        queried_domain=queried_domain,
        confidence=_parse_confidence(data.get("confidence")),
        region=data.get("region"),
        sources=tuple(data.get("sources", [])),
        services=tuple(data.get("services", [])),
        slugs=tuple(data.get("slugs", [])),
        auth_type=data.get("auth_type"),
        dmarc_policy=data.get("dmarc_policy"),
        domain_count=int(data.get("domain_count", 0)),
        tenant_domains=tuple(data.get("tenant_domains", [])),
        related_domains=tuple(data.get("related_domains", [])),
        insights=tuple(data.get("insights", [])),
        degraded_sources=_parse_degraded_sources(data),
        cert_summary=cert_summary,
        evidence=evidence,
        evidence_confidence=_parse_confidence(data.get("evidence_confidence")),
        inference_confidence=_parse_confidence(data.get("inference_confidence")),
        detection_scores=detection_scores,
        bimi_identity=bimi_identity,
        site_verification_tokens=tuple(data.get("site_verification_tokens", [])),
        mta_sts_mode=data.get("mta_sts_mode"),
        google_auth_type=data.get("google_auth_type"),
        google_idp_name=data.get("google_idp_name"),
        primary_email_provider=data.get("primary_email_provider"),
        email_gateway=data.get("email_gateway"),
        dmarc_pct=data.get("dmarc_pct"),
        likely_primary_email_provider=data.get("likely_primary_email_provider"),
        ct_provider_used=data.get("ct_provider_used"),
        ct_subdomain_count=int(data.get("ct_subdomain_count", 0) or 0),
        ct_cache_age_days=data.get("ct_cache_age_days"),
        slug_confidences=tuple(
            (str(entry[0]), float(entry[1]))
            for entry in data.get("slug_confidences", [])
            if isinstance(entry, (list, tuple)) and len(entry) == 2
        ),
        cloud_instance=data.get("cloud_instance"),
        tenant_region_sub_scope=data.get("tenant_region_sub_scope"),
        msgraph_host=data.get("msgraph_host"),
        lexical_observations=tuple(data.get("lexical_observations", [])),
        resolved_at=data.get("resolved_at"),
        # cached_at is stamped by cache_get from _cached_at; not populated
        # from arbitrary dict input so round-tripping an uncached dict
        # does not spuriously mark the result as cache-served.
    )
