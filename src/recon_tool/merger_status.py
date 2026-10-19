"""Merge helpers for lookup collection status.

Decides when a lookup failed as a whole (``all_sources_failed``) and which
degraded markers the merged result carries. Kept apart from ``merger`` so the
collection-status rules have one home.
"""

from __future__ import annotations

from recon_tool.models import ReconLookupError, SourceResult


def raise_if_all_sources_failed(results: list[SourceResult], queried_domain: str, tenant_id: str | None) -> None:
    """Raise ``all_sources_failed`` only when EVERY attempted source returned an error.

    If any source produced a clean result (even with empty services/slugs), the
    successful lookup is honored downstream as a sparse TenantInfo: "we looked
    and found nothing" is a valid, hedged answer, not an error. A source that
    deliberately made no attempt (an opt-in probe left disabled) is neither,
    so it is excluded from the decision rather than counted as a clean result.
    """
    attempted = [r for r in results if not r.not_attempted] or results
    if tenant_id is not None or not all(r.error is not None for r in attempted):
        return
    source_errors: tuple[tuple[str, str], ...] = tuple(
        (r.source_name, r.error) for r in attempted if r.error is not None
    )
    reasons = "; ".join(f"{n}: {e}" for n, e in source_errors)
    raise ReconLookupError(
        domain=queried_domain,
        message=(f"No information could be resolved for {queried_domain}. All sources returned errors: {reasons}"),
        error_type="all_sources_failed",
        source_errors=source_errors,
    )


def collect_degraded(results: list[SourceResult]) -> set[str]:
    """Deduplicate granular markers and preserve whole DNS failure status."""
    degraded = {source for result in results for source in result.degraded_sources}
    degraded.update(f"source:{result.source_name}" for result in results if result.source_unavailable)
    if any(result.source_name == "dns_records" and result.error is not None for result in results):
        degraded.add("dns_records")
    return degraded
