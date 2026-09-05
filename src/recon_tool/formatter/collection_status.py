"""Shared collection-status meaning for human lookup renderers.

The panel and Markdown surfaces keep their own layout and wording, but they
must agree on what a degraded marker means. This projection separates core
source failures from certificate-transparency fallback and cache states without
creating a new public output contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from recon_tool.confidence import is_confidence_contributor
from recon_tool.models import ConfidenceLevel, SourceResult, TenantInfo

_CT_SOURCES = frozenset({"crt.sh", "certspotter"})
CTCollectionState = Literal["none", "fallback_recovered", "cache_recovered", "unavailable"]
SourceDisplayState = Literal["match", "no_match", "unavailable"]

# Legacy collectors retain expected negative responses in the error field.
# Explicit unavailability takes precedence over these compatibility markers.
_SOFT_MISS_MARKERS = (
    "No Google Workspace",
    "No federated IdP redirect",
    "Not a Google Workspace",
    "No M365 tenant",
    "Not a registered M365",
    "HTTP 400 from OIDC discovery",
    "No information could be resolved",
    "no data returned",
)


def source_display_state(result: SourceResult) -> SourceDisplayState:
    """Use one match, clean non-match, or unavailable state in source views."""
    if result.source_unavailable:
        return "unavailable"
    if is_confidence_contributor(result):
        return "match"
    if not result.error or any(marker in result.error for marker in _SOFT_MISS_MARKERS):
        return "no_match"
    return "unavailable"


def low_confidence_guidance(info: TenantInfo, *, detailed: bool) -> str | None:
    """Point a sparse CLI briefing at diagnostics, unless already requested."""
    if info.confidence != ConfidenceLevel.LOW or detailed:
        return None
    return "Use --explain to inspect evidence or --verbose to review source status."


@dataclass(frozen=True)
class CollectionStatusProjection:
    """Renderer-neutral interpretation of lookup collection degradation."""

    unavailable_sources: tuple[str, ...]
    ct_sources: tuple[str, ...]
    ct_state: CTCollectionState
    ct_cache_age_days: int | None
    ct_subdomain_count: int

    @property
    def is_warning(self) -> bool:
        """Return whether the projected state includes incomplete collection."""
        return bool(self.unavailable_sources) or self.ct_state == "unavailable"


def project_collection_status(info: TenantInfo) -> CollectionStatusProjection:
    """Classify degraded markers without assigning renderer-specific prose."""
    unavailable_sources = tuple(source for source in info.degraded_sources if source not in _CT_SOURCES)
    ct_sources = tuple(source for source in info.degraded_sources if source in _CT_SOURCES)

    ct_state: CTCollectionState = "none"
    if ct_sources:
        if info.ct_provider_used is None:
            ct_state = "unavailable"
        elif info.ct_cache_age_days is not None and info.ct_subdomain_count > 0:
            ct_state = "cache_recovered"
        else:
            ct_state = "fallback_recovered"

    return CollectionStatusProjection(
        unavailable_sources=unavailable_sources,
        ct_sources=ct_sources,
        ct_state=ct_state,
        ct_cache_age_days=info.ct_cache_age_days,
        ct_subdomain_count=info.ct_subdomain_count,
    )


def collection_note_parts(status: CollectionStatusProjection) -> tuple[str, ...]:
    """Compact material caveats shared by the panel and its linear view."""
    parts: list[str] = []
    if status.unavailable_sources:
        parts.append(f"Some sources unavailable ({', '.join(status.unavailable_sources)})")
    if status.ct_state == "unavailable":
        parts.append(f"All CT providers unavailable ({', '.join(status.ct_sources)})")
    elif status.ct_state == "cache_recovered":
        age = status.ct_cache_age_days
        age_str = "today" if age == 0 else f"{age} day{'s' if age != 1 else ''} old"
        parts.append(f"CT: from local cache, {age_str} ({status.ct_subdomain_count} subdomains)")
    return tuple(parts)
