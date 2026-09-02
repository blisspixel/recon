"""Shared collection-status meaning for human lookup renderers.

The panel and Markdown surfaces keep their own layout and wording, but they
must agree on what a degraded marker means. This projection separates core
source failures from certificate-transparency fallback and cache states without
creating a new public output contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from recon_tool.models import TenantInfo

_CT_SOURCES = frozenset({"crt.sh", "certspotter"})
CTCollectionState = Literal["none", "fallback_recovered", "cache_recovered", "unavailable"]


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
