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

from recon_tool.email_security import compute_email_security_score
from recon_tool.json_limits import exceeds_json_nesting_limit
from recon_tool.models import DeltaReport, TenantInfo

logger = logging.getLogger("recon")

_MAX_PREVIOUS_EXPORT_BYTES = 5 * 1024 * 1024

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
    with path.open("rb") as handle:
        raw = handle.read(_MAX_PREVIOUS_EXPORT_BYTES + 1)
    if len(raw) > _MAX_PREVIOUS_EXPORT_BYTES:
        raise ValueError(
            f"Previous export exceeds maximum size of {_MAX_PREVIOUS_EXPORT_BYTES // (1024 * 1024)} MiB: {path}"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Invalid UTF-8 in {path} at byte {exc.start}") from exc
    if exceeds_json_nesting_limit(text):
        raise ValueError(f"Invalid JSON in {path}: document is too deeply nested")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    except RecursionError as exc:
        raise ValueError(f"Invalid JSON in {path}: document is too deeply nested") from exc
    except ValueError as exc:
        raise ValueError(f"Invalid JSON in {path}: value exceeds supported limits") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}, got {type(data).__name__}")
    _validate_previous_snapshot(data)
    return data


def _string_list_field(previous_json: dict[str, Any], field: str) -> list[str]:
    value = previous_json.get(field, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Previous snapshot field '{field}' must be a list of strings")
    return value


def _optional_str_field(previous_json: dict[str, Any], field: str) -> str | None:
    value = previous_json.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Previous snapshot field '{field}' must be a string or null")
    return value


def _optional_int_field(previous_json: dict[str, Any], field: str) -> int | None:
    value = previous_json.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Previous snapshot field '{field}' must be an integer or null")
    return value


def _validate_previous_snapshot(previous_json: dict[str, Any]) -> None:
    for field in ("services", "slugs", "insights"):
        _string_list_field(previous_json, field)
    for field in ("auth_type", "dmarc_policy", "confidence"):
        _optional_str_field(previous_json, field)
    for field in ("domain_count", "email_security_score"):
        _optional_int_field(previous_json, field)


def _extract_signal_names(insights: list[str] | tuple[str, ...]) -> set[str]:
    """Extract fired-signal names from rendered insight strings.

    A signal insight renders as ``"{signal name}: {matched products}"`` or, when
    the signal fires with no matched slugs, as the bare ``"{signal name}"``. The
    matched-products list is humanized (``"Google Workspace"``, with spaces and
    qualifiers), so it can no longer be told apart from prose by character set.
    The reliable discriminator is the prefix itself: match it against the known
    signal names. The legacy comma-separated-slug check is kept as a fallback so
    older JSON exports whose insight values were still raw slugs keep diffing.
    """
    from recon_tool.signals import load_signals

    known_signal_names = {sig.name for sig in load_signals()}
    names: set[str] = set()
    for insight in insights:
        name = insight.partition(": ")[0] if ": " in insight else insight
        if name in known_signal_names:
            names.add(name)
            continue
        if ": " in insight:
            rest = insight.partition(": ")[2]
            parts = [p.strip() for p in rest.split(",") if p.strip()]
            if parts and all(p.replace("-", "").replace("_", "").isalnum() for p in parts):
                names.add(name)
    return names


def compute_delta(previous_json: dict[str, Any], current: TenantInfo) -> DeltaReport:
    """Compare a deserialized JSON export against a live TenantInfo.

    Uses set operations for services, slugs, and signals to correctly
    identify additions and removals regardless of ordering.
    Missing fields in older JSON exports are treated as absent.
    """
    _validate_previous_snapshot(previous_json)

    # Services comparison
    prev_services = set(_string_list_field(previous_json, "services"))
    curr_services = set(current.services)
    added_services = tuple(sorted(curr_services - prev_services))
    removed_services = tuple(sorted(prev_services - curr_services))

    # Slugs comparison (may not be in standard JSON output)
    prev_slugs = set(_string_list_field(previous_json, "slugs"))
    curr_slugs = set(current.slugs)
    added_slugs = tuple(sorted(curr_slugs - prev_slugs))
    removed_slugs = tuple(sorted(prev_slugs - curr_slugs))

    # Signals comparison (extracted from insights)
    prev_insights = _string_list_field(previous_json, "insights")
    curr_insights = list(current.insights)
    prev_signals = _extract_signal_names(prev_insights)
    curr_signals = _extract_signal_names(curr_insights)
    added_signals = tuple(sorted(curr_signals - prev_signals))
    removed_signals = tuple(sorted(prev_signals - curr_signals))

    # Scalar field comparisons
    changed_auth_type: tuple[str | None, str | None] | None = None
    prev_auth = _optional_str_field(previous_json, "auth_type")
    curr_auth = current.auth_type
    if prev_auth != curr_auth:
        changed_auth_type = (prev_auth, curr_auth)

    changed_dmarc_policy: tuple[str | None, str | None] | None = None
    prev_dmarc = _optional_str_field(previous_json, "dmarc_policy")
    curr_dmarc = current.dmarc_policy
    if prev_dmarc != curr_dmarc:
        changed_dmarc_policy = (prev_dmarc, curr_dmarc)

    changed_confidence: tuple[str, str] | None = None
    prev_confidence = _optional_str_field(previous_json, "confidence")
    curr_confidence = current.confidence.value
    if prev_confidence is not None and prev_confidence != curr_confidence:
        changed_confidence = (prev_confidence, curr_confidence)

    changed_domain_count: tuple[int, int] | None = None
    prev_domain_count = _optional_int_field(previous_json, "domain_count")
    curr_domain_count = current.domain_count
    if prev_domain_count is not None and prev_domain_count != curr_domain_count:
        changed_domain_count = (prev_domain_count, curr_domain_count)

    # Email security score comparison
    changed_email_security_score: tuple[int | None, int | None] | None = None
    prev_score = _optional_int_field(previous_json, "email_security_score")
    curr_score = compute_email_security_score(current)
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
