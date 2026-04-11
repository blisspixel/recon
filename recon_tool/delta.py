"""Delta engine — compares two domain intelligence snapshots.

Computes structured diffs between a previous JSON export and a live
TenantInfo, surfacing what changed over time. Uses set operations for
ordering-independent comparison of services, slugs, and signals.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_STRICT,
)
from recon_tool.models import DeltaReport, TenantInfo

logger = logging.getLogger("recon")

__all__ = [
    "compute_delta",
    "load_previous",
]


def load_previous(path: Path) -> dict[str, Any]:
    """Load and validate a previous JSON export file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file contains invalid JSON.
    """
    if not path.exists():
        raise FileNotFoundError(f"Previous export not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}, got {type(data).__name__}")
    return data


def _extract_signal_names(insights: list[str] | tuple[str, ...]) -> set[str]:
    """Extract signal names from insight strings.

    Signal insights follow the format "SignalName: slug1, slug2".
    Non-signal insights (from generate_insights) don't contain ": " with
    comma-separated slugs, so this heuristic works for the current format.
    """
    names: set[str] = set()
    for insight in insights:
        if ": " in insight:
            name, _, rest = insight.partition(": ")
            # Signal matches have comma-separated lowercase slugs
            parts = [p.strip() for p in rest.split(",")]
            if all(p.replace("-", "").replace("_", "").isalnum() for p in parts if p):
                names.add(name)
    return names


def _compute_email_security_score(services: tuple[str, ...] | list[str]) -> int:
    """Compute email security score (0-5) from service list."""
    score_services = {SVC_DMARC, SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_SPF_STRICT, SVC_MTA_STS, SVC_BIMI}
    return min(sum(1 for svc in services if svc in score_services), 5)


def compute_delta(previous_json: dict[str, Any], current: TenantInfo) -> DeltaReport:
    """Compare a deserialized JSON export against a live TenantInfo.

    Uses set operations for services, slugs, and signals to correctly
    identify additions and removals regardless of ordering.
    Missing fields in older JSON exports are treated as absent.
    """
    # Services comparison
    prev_services = set(previous_json.get("services", []))
    curr_services = set(current.services)
    added_services = tuple(sorted(curr_services - prev_services))
    removed_services = tuple(sorted(prev_services - curr_services))

    # Slugs comparison (may not be in standard JSON output)
    prev_slugs = set(previous_json.get("slugs", []))
    curr_slugs = set(current.slugs)
    added_slugs = tuple(sorted(curr_slugs - prev_slugs))
    removed_slugs = tuple(sorted(prev_slugs - curr_slugs))

    # Signals comparison (extracted from insights)
    prev_insights = previous_json.get("insights", [])
    curr_insights = list(current.insights)
    prev_signals = _extract_signal_names(prev_insights)
    curr_signals = _extract_signal_names(curr_insights)
    added_signals = tuple(sorted(curr_signals - prev_signals))
    removed_signals = tuple(sorted(prev_signals - curr_signals))

    # Scalar field comparisons
    changed_auth_type: tuple[str | None, str | None] | None = None
    prev_auth = previous_json.get("auth_type")
    curr_auth = current.auth_type
    if prev_auth != curr_auth:
        changed_auth_type = (prev_auth, curr_auth)

    changed_dmarc_policy: tuple[str | None, str | None] | None = None
    prev_dmarc = previous_json.get("dmarc_policy")
    curr_dmarc = current.dmarc_policy
    if prev_dmarc != curr_dmarc:
        changed_dmarc_policy = (prev_dmarc, curr_dmarc)

    changed_confidence: tuple[str, str] | None = None
    prev_confidence = previous_json.get("confidence")
    curr_confidence = current.confidence.value
    if prev_confidence is not None and prev_confidence != curr_confidence:
        changed_confidence = (prev_confidence, curr_confidence)

    changed_domain_count: tuple[int, int] | None = None
    prev_domain_count = previous_json.get("domain_count")
    curr_domain_count = current.domain_count
    if prev_domain_count is not None and prev_domain_count != curr_domain_count:
        changed_domain_count = (prev_domain_count, curr_domain_count)

    # Email security score comparison
    changed_email_security_score: tuple[int | None, int | None] | None = None
    prev_score = previous_json.get("email_security_score")
    curr_score = _compute_email_security_score(current.services)
    if prev_score is not None and prev_score != curr_score:
        changed_email_security_score = (prev_score, curr_score)

    return DeltaReport(
        domain=current.queried_domain,
        added_services=added_services,
        removed_services=removed_services,
        added_slugs=added_slugs,
        removed_slugs=removed_slugs,
        added_signals=added_signals,
        removed_signals=removed_signals,
        changed_auth_type=changed_auth_type,
        changed_dmarc_policy=changed_dmarc_policy,
        changed_email_security_score=changed_email_security_score,
        changed_confidence=changed_confidence,
        changed_domain_count=changed_domain_count,
    )
