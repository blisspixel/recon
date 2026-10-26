"""Optional per-source progress events from the collection pipeline.

The resolver and the DNS source report when each collection unit starts and
settles. A human interface (the CLI source ladder) can listen; everything else
(MCP, batch, library callers) never installs a listener, so emitting is a
no-op. The listener is held in a context variable, so it follows asyncio tasks
created inside the listening scope and never leaks across concurrent lookups.

This module is part of the collection core: it imports no renderer and no
terminal library. Units are collection facts, not presentation:

- ``oidc_discovery``, ``user_realm``, ``google_identity``, ``google_workspace``
  and ``dns_records`` are the top-level sources in ``resolver.default_pool``.
  Their ``done`` event carries the ``SourceResult``.
- ``mta_sts`` and ``ct`` run inside the DNS source. Their ``done`` event
  carries a ``UnitOutcome`` computed by the classifiers below, which the CLI
  summary also applies to a finished DNS result, so both agree.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Collection, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

from recon_tool.models import CertSummary, InfrastructureClusterReport, SourceResult
from recon_tool.source_status import CT_PROVIDER_MARKERS

__all__ = [
    "CT_UNIT",
    "MTA_STS_UNIT",
    "ProgressCallback",
    "ProgressEvent",
    "UnitOutcome",
    "UnitState",
    "ct_has_observations",
    "ct_outcome",
    "ct_outcome_from_result",
    "emit",
    "listening",
    "mta_sts_outcome",
    "mta_sts_outcome_from_result",
    "progress_listener",
    "suppressed",
]

logger = logging.getLogger("recon")

UnitState = Literal["match", "no_match", "unavailable"]
Phase = Literal["start", "done"]

CT_UNIT = "ct"
MTA_STS_UNIT = "mta_sts"


@dataclass(frozen=True, slots=True)
class UnitOutcome:
    """How one collection unit settled, with a short reason when unavailable."""

    state: UnitState
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """One unit starting or settling. ``done`` carries a result or an outcome."""

    unit: str
    phase: Phase
    result: SourceResult | None = None
    outcome: UnitOutcome | None = None


ProgressCallback = Callable[[ProgressEvent], None]

_LISTENER: ContextVar[ProgressCallback | None] = ContextVar("recon_progress_listener", default=None)


@contextmanager
def progress_listener(callback: ProgressCallback) -> Generator[None]:
    """Deliver progress events from collection started inside this scope."""
    token = _LISTENER.set(callback)
    try:
        yield
    finally:
        _LISTENER.reset(token)


@contextmanager
def suppressed() -> Generator[None]:
    """Silence events for nested work, such as related-domain enrichment.

    Enrichment reuses the DNS source on other names; its events must not
    settle the queried domain's rows.
    """
    token = _LISTENER.set(None)
    try:
        yield
    finally:
        _LISTENER.reset(token)


def listening() -> bool:
    """Return whether a listener would receive events emitted here."""
    return _LISTENER.get() is not None


def emit(
    unit: str,
    phase: Phase,
    *,
    result: SourceResult | None = None,
    outcome: UnitOutcome | None = None,
) -> None:
    """Send one event to the active listener, if any.

    A listener failure is logged at debug level and never reaches collection:
    progress display must not change what recon observes.
    """
    callback = _LISTENER.get()
    if callback is None:
        return
    try:
        callback(ProgressEvent(unit=unit, phase=phase, result=result, outcome=outcome))
    except Exception as exc:  # pragma: no cover - defensive; listeners are tested directly
        logger.debug("progress listener failed for %s/%s: %s", unit, phase, exc)


# ── Derived unit classification ─────────────────────────────────────────────

_CT_OUTCOME_REASONS = {
    "live_rate_limited": "rate limited",
    "live_other_failure": "provider error",
    "breaker_open": "paused after repeated failures",
    "cache_miss": "empty response, no local cache",
}

_MTA_STS_DNS_MARKERS = frozenset({"dns:mta_sts", "detector:email_security"})
_MTA_STS_HTTP_MARKER = "http:mta_sts_policy"


def ct_has_observations(
    subdomains: Collection[str],
    summary: CertSummary | None,
    clusters: InfrastructureClusterReport | None,
) -> bool:
    """Require retained CT data, rather than an empty metadata container."""
    return bool(
        subdomains
        or (summary is not None and summary.cert_count > 0)
        or (clusters is not None and (clusters.node_count > 0 or clusters.clusters or clusters.edges))
    )


def ct_outcome(
    *,
    subdomain_count: int,
    has_summary: bool,
    degraded: Collection[str],
    attempt_outcome: str | None,
) -> UnitOutcome:
    """Classify the certificate-transparency unit from its collection fields.

    Names or a certificate summary from any path (a live provider, a partial
    page, the local CT cache) are a match. A provider failure with nothing
    recovered is unavailable, never an observed empty CT history.
    """
    if subdomain_count > 0 or has_summary:
        return UnitOutcome("match")
    failed = sorted(marker for marker in degraded if marker in CT_PROVIDER_MARKERS)
    detector_failed = "detector:cert_intel" in degraded
    detail = _CT_OUTCOME_REASONS.get(attempt_outcome or "")
    if not failed and not detector_failed and detail is None:
        return UnitOutcome("no_match")
    if detail is None:
        detail = "failed" if failed else "collector error"
    return UnitOutcome("unavailable", f"{', '.join(failed)} {detail}" if failed else detail)


def mta_sts_outcome(*, mode: str | None, record_observed: bool, degraded: Collection[str]) -> UnitOutcome:
    """Classify the MTA-STS unit (the DNS record plus the policy fetch)."""
    if mode is not None:
        return UnitOutcome("match")
    if not _MTA_STS_DNS_MARKERS.isdisjoint(degraded):
        return UnitOutcome("unavailable", "DNS query failed")
    if _MTA_STS_HTTP_MARKER in degraded:
        return UnitOutcome("unavailable", "policy fetch failed")
    if record_observed:
        return UnitOutcome("match")
    return UnitOutcome("no_match")


def _dns_unavailable(result: SourceResult) -> UnitOutcome | None:
    if result.source_unavailable:
        return UnitOutcome("unavailable", "DNS unavailable")
    return None


def ct_outcome_from_result(dns_result: SourceResult) -> UnitOutcome:
    """Apply ``ct_outcome`` to a finished DNS source result."""
    whole = _dns_unavailable(dns_result)
    if whole is not None:
        return whole
    ct_cached = dns_result.ct_cache_age_days is not None or dns_result.ct_attempt_outcome == "cache_hit"
    has_summary = (
        False
        if ct_cached and dns_result.ct_subdomain_count == 0
        else ct_has_observations((), dns_result.cert_summary, dns_result.infrastructure_clusters)
    )
    return ct_outcome(
        subdomain_count=dns_result.ct_subdomain_count,
        has_summary=has_summary,
        degraded=dns_result.degraded_sources,
        attempt_outcome=dns_result.ct_attempt_outcome,
    )


def mta_sts_outcome_from_result(dns_result: SourceResult) -> UnitOutcome:
    """Apply ``mta_sts_outcome`` to a finished DNS source result."""
    whole = _dns_unavailable(dns_result)
    if whole is not None:
        return whole
    return mta_sts_outcome(
        mode=dns_result.mta_sts_mode,
        record_observed=any(record.source_type == "MTA_STS" for record in dns_result.evidence),
        degraded=dns_result.degraded_sources,
    )
