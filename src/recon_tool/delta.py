"""Delta engine — compares two domain intelligence snapshots.

Computes structured diffs between a previous JSON export and a live
TenantInfo, surfacing what changed over time. Uses set operations for
ordering-independent comparison of services, slugs, and signals.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from recon_tool.collection_view import claim_contract_insights, collection_observable_info
from recon_tool.email_security import compute_email_security_score
from recon_tool.json_limits import exceeds_json_nesting_limit
from recon_tool.models import DeltaComparisonIncomplete, DeltaReport, TenantInfo
from recon_tool.source_status import ObservationChannel, SourceStatus

logger = logging.getLogger("recon")

_MAX_PREVIOUS_EXPORT_BYTES = 5 * 1024 * 1024
_EMAIL_SCORE_CHANNELS: tuple[ObservationChannel, ...] = ("dmarc", "dkim", "apex_txt", "mta_sts", "bimi")
_CT_DEGRADATION_MARKERS = frozenset({"crt.sh", "certspotter"})

__all__ = [
    "compute_delta",
    "load_previous",
]


@dataclass(frozen=True, slots=True)
class _CollectionDeltas:
    """Set-valued deltas that share endpoint observability rules."""

    added_services: tuple[str, ...]
    removed_services: tuple[str, ...]
    added_slugs: tuple[str, ...]
    removed_slugs: tuple[str, ...]
    added_signals: tuple[str, ...]
    removed_signals: tuple[str, ...]


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
    for field in ("services", "slugs", "insights", "degraded_sources"):
        _string_list_field(previous_json, field)
    for field in ("auth_type", "dmarc_policy", "confidence", "ct_provider_used"):
        _optional_str_field(previous_json, field)
    for field in ("domain_count", "email_security_score"):
        _optional_int_field(previous_json, field)


def _extract_signal_labels(insights: list[str] | tuple[str, ...]) -> set[str]:
    """Extract claim-safe public signal labels from rendered insights.

    A signal insight renders as ``"{signal name}: {matched products}"`` or, when
    the signal fires with no matched slugs, as the bare ``"{signal name}"``. The
    matched-products list is humanized (``"Google Workspace"``, with spaces and
    qualifiers), so it cannot be distinguished from prose by RHS syntax. The
    only safe discriminator is an exact name in the declarative signal catalog.
    Unknown historical prose is ignored instead of being promoted into a signal.
    """
    from recon_tool.signals import signal_observation_label, signal_rule_names_from_observation

    labels: set[str] = set()
    for insight in claim_contract_insights(insights):
        for rule_name in signal_rule_names_from_observation(insight):
            if (label := signal_observation_label(rule_name)) is not None:
                labels.add(label)
    return labels


def _previous_collection_view(
    previous_json: dict[str, Any],
    status: SourceStatus,
) -> tuple[dict[str, Any], bool, TenantInfo | None]:
    """Project a prior snapshot through the same collection contract as live data.

    Current cache exports contain enough provenance to mask stale values retained
    after a failed subchannel. Very old minimal exports may not. In that case the
    boolean is false so removals are withheld instead of treating retained raw
    values as confirmed prior observations.
    """
    visible = dict(previous_json)
    visible["insights"] = list(claim_contract_insights(_string_list_field(previous_json, "insights")))
    if not status.unavailable_channels:
        from recon_tool.cache import tenant_info_from_dict

        try:
            return visible, True, tenant_info_from_dict(previous_json)
        except (TypeError, ValueError):
            return visible, True, None

    from recon_tool.cache import tenant_info_from_dict

    try:
        observable = collection_observable_info(tenant_info_from_dict(previous_json))
    except (TypeError, ValueError):
        return visible, False, None
    visible.update(
        services=list(observable.services),
        slugs=list(observable.slugs),
        insights=list(observable.insights),
    )
    return visible, True, observable


def _set_delta(
    previous: set[str],
    current: set[str],
    *,
    allow_additions: bool,
    allow_removals: bool,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return sorted changes only when both endpoints support each direction."""
    added = tuple(sorted(current - previous)) if allow_additions else ()
    removed = tuple(sorted(previous - current)) if allow_removals else ()
    return added, removed


def _initial_suppressed_fields(
    previous_degraded_sources: tuple[str, ...],
    current_degraded_sources: tuple[str, ...],
    *,
    auth_comparison_available: bool,
    domain_count_comparison_available: bool,
    confidence_comparison_available: bool,
) -> set[str]:
    """Name comparisons whose required endpoint had no observation opportunity."""
    suppressed: set[str] = set()
    if previous_degraded_sources:
        suppressed.update({"added_services", "added_slugs", "added_signals"})
    if current_degraded_sources:
        suppressed.update({"removed_services", "removed_slugs", "removed_signals"})
    if not auth_comparison_available:
        suppressed.add("changed_auth_type")
    if not domain_count_comparison_available:
        suppressed.add("changed_domain_count")
    if not confidence_comparison_available:
        suppressed.add("changed_confidence")
    return suppressed


def _confidence_endpoint_available(
    degraded_sources: frozenset[str],
    ct_provider_used: str | None,
) -> bool:
    """Whether one endpoint's confidence is comparable across collection state.

    Non-CT degradation can change confidence directly. CT-only degradation is
    comparable only when the snapshot explicitly records that a live provider
    or cached CT result recovered the collection, matching the merger's
    confidence-downgrade rule.
    """
    if not degraded_sources:
        return True
    return degraded_sources <= _CT_DEGRADATION_MARKERS and bool(ct_provider_used)


def _collection_deltas(
    previous_json: dict[str, Any],
    current: TenantInfo,
    previous_info: TenantInfo | None,
    *,
    allow_additions: bool,
    allow_removals: bool,
) -> _CollectionDeltas:
    """Compare observable collection fields under directional opportunity rules."""
    added_services_raw, removed_services_raw = _set_delta(
        set(_string_list_field(previous_json, "services")),
        set(current.services),
        allow_additions=allow_additions,
        allow_removals=allow_removals,
    )
    from recon_tool.formatter.classify import role_aware_service_label

    added_services = tuple(
        sorted(role_aware_service_label(service, current.evidence) for service in added_services_raw)
    )
    removed_services = tuple(sorted(_removed_service_label(service, previous_info) for service in removed_services_raw))
    added_slugs, removed_slugs = _set_delta(
        set(_string_list_field(previous_json, "slugs")),
        set(current.slugs),
        allow_additions=allow_additions,
        allow_removals=allow_removals,
    )
    added_signals, removed_signals = _set_delta(
        _extract_signal_labels(_string_list_field(previous_json, "insights")),
        _extract_signal_labels(current.insights),
        allow_additions=allow_additions,
        allow_removals=allow_removals,
    )
    return _CollectionDeltas(
        added_services=added_services,
        removed_services=removed_services,
        added_slugs=added_slugs,
        removed_slugs=removed_slugs,
        added_signals=added_signals,
        removed_signals=removed_signals,
    )


def _removed_service_label(
    service: str,
    previous_info: TenantInfo | None,
) -> str:
    """Render a prior service without inventing a role absent prior lineage."""
    from recon_tool.formatter.classify import role_aware_service_label

    if previous_info is None:
        return f"{service} (prior evidence role unavailable)"
    supporting = tuple(record for record in previous_info.evidence if record.rule_name.casefold() == service.casefold())
    if not supporting:
        return f"{service} (prior evidence role unavailable)"
    return role_aware_service_label(service, supporting)


def compute_delta(previous_json: dict[str, Any], current: TenantInfo) -> DeltaReport:
    """Compare a deserialized JSON export against a live TenantInfo.

    Uses set operations for services, slugs, and signals to correctly
    identify additions and removals regardless of ordering.
    Missing fields in older JSON exports are treated as absent.
    """
    _validate_previous_snapshot(previous_json)
    previous_source_status = SourceStatus.from_degraded_sources(_string_list_field(previous_json, "degraded_sources"))
    current_source_status = SourceStatus.from_degraded_sources(current.degraded_sources)
    previous_degraded_sources = tuple(sorted(previous_source_status.degraded_sources))
    current_degraded_sources = tuple(sorted(current_source_status.degraded_sources))
    degraded_sources = tuple(sorted(previous_source_status.degraded_sources | current_source_status.degraded_sources))
    combined_degradation = previous_source_status.degraded_sources | current_source_status.degraded_sources
    auth_comparison_available = combined_degradation.isdisjoint(
        {"identity:user_realm", "source:user_realm", "user_realm"}
    )
    domain_count_comparison_available = combined_degradation.isdisjoint(
        {"identity:autodiscover", "source:user_realm", "user_realm"}
    )
    confidence_comparison_available = _confidence_endpoint_available(
        previous_source_status.degraded_sources,
        _optional_str_field(previous_json, "ct_provider_used"),
    ) and _confidence_endpoint_available(
        current_source_status.degraded_sources,
        current.ct_provider_used,
    )
    suppressed_fields = _initial_suppressed_fields(
        previous_degraded_sources,
        current_degraded_sources,
        auth_comparison_available=auth_comparison_available,
        domain_count_comparison_available=domain_count_comparison_available,
        confidence_comparison_available=confidence_comparison_available,
    )
    observable_previous, previous_projection_complete, previous_info = _previous_collection_view(
        previous_json,
        previous_source_status,
    )
    if not previous_projection_complete:
        suppressed_fields.update({"removed_services", "removed_slugs", "removed_signals"})
    observable_current = collection_observable_info(current)
    collection_deltas = _collection_deltas(
        observable_previous,
        observable_current,
        previous_info,
        allow_additions=not previous_degraded_sources,
        allow_removals=not current_degraded_sources and previous_projection_complete,
    )

    # Scalar field comparisons
    changed_auth_type: tuple[str | None, str | None] | None = None
    prev_auth = _optional_str_field(previous_json, "auth_type")
    curr_auth = observable_current.auth_type
    if auth_comparison_available and prev_auth != curr_auth:
        changed_auth_type = (prev_auth, curr_auth)

    changed_dmarc_policy: tuple[str | None, str | None] | None = None
    prev_dmarc = _optional_str_field(previous_json, "dmarc_policy")
    curr_dmarc = observable_current.dmarc_policy
    if previous_source_status.channel_unavailable("dmarc") or current_source_status.channel_unavailable("dmarc"):
        suppressed_fields.add("changed_dmarc_policy")
    elif prev_dmarc != curr_dmarc:
        changed_dmarc_policy = (prev_dmarc, curr_dmarc)

    changed_confidence: tuple[str, str] | None = None
    prev_confidence = _optional_str_field(previous_json, "confidence")
    curr_confidence = observable_current.confidence.value
    if confidence_comparison_available and prev_confidence is not None and prev_confidence != curr_confidence:
        changed_confidence = (prev_confidence, curr_confidence)

    changed_domain_count: tuple[int, int] | None = None
    prev_domain_count = _optional_int_field(previous_json, "domain_count")
    curr_domain_count = observable_current.domain_count
    if domain_count_comparison_available and prev_domain_count is not None and prev_domain_count != curr_domain_count:
        changed_domain_count = (prev_domain_count, curr_domain_count)

    # Email security score comparison
    changed_email_security_score: tuple[int | None, int | None] | None = None
    prev_score = _optional_int_field(previous_json, "email_security_score")
    curr_score = compute_email_security_score(observable_current)
    if any(
        previous_source_status.channel_unavailable(channel) or current_source_status.channel_unavailable(channel)
        for channel in _EMAIL_SCORE_CHANNELS
    ):
        suppressed_fields.add("changed_email_security_score")
    elif prev_score is not None and prev_score != curr_score:
        changed_email_security_score = (prev_score, curr_score)

    incomplete_comparison = None
    if suppressed_fields:
        incomplete_comparison = DeltaComparisonIncomplete(
            degraded_sources=degraded_sources,
            suppressed_fields=tuple(sorted(suppressed_fields)),
            previous_degraded_sources=previous_degraded_sources,
            current_degraded_sources=current_degraded_sources,
        )

    return DeltaReport(
        domain=current.queried_domain,
        added_services=collection_deltas.added_services,
        removed_services=collection_deltas.removed_services,
        added_slugs=collection_deltas.added_slugs,
        removed_slugs=collection_deltas.removed_slugs,
        added_signals=collection_deltas.added_signals,
        removed_signals=collection_deltas.removed_signals,
        changed_auth_type=changed_auth_type,
        changed_dmarc_policy=changed_dmarc_policy,
        changed_email_security_score=changed_email_security_score,
        changed_confidence=changed_confidence,
        changed_domain_count=changed_domain_count,
        incomplete_comparison=incomplete_comparison,
    )
