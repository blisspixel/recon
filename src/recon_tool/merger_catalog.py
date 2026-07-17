"""Merge helpers for opt-in DNS catalog diagnostics."""

from __future__ import annotations

from recon_tool.models import (
    ChainMotifObservation,
    DnsCatalogSummary,
    SourceResult,
    SurfaceAttribution,
    UnclassifiedCnameChain,
    UnclassifiedDnsObservation,
)


def dedupe_surface(results: list[SourceResult]) -> tuple[SurfaceAttribution, ...]:
    """Deduplicate surface attributions by subdomain using first observation."""
    merged = {item.subdomain: item for result in reversed(results) for item in reversed(result.surface_attributions)}
    return tuple(sorted(merged.values(), key=lambda item: item.subdomain))


def dedupe_unclassified(results: list[SourceResult]) -> tuple[UnclassifiedCnameChain, ...]:
    """Deduplicate unclassified CNAME chains by subdomain using first observation."""
    merged = {
        item.subdomain: item for result in reversed(results) for item in reversed(result.unclassified_cname_chains)
    }
    return tuple(sorted(merged.values(), key=lambda item: item.subdomain))


def dedupe_motifs(results: list[SourceResult]) -> tuple[ChainMotifObservation, ...]:
    """Deduplicate motifs by subdomain and motif name using first observation."""
    merged = {
        (item.subdomain, item.motif_name): item
        for result in reversed(results)
        for item in reversed(result.chain_motifs)
    }
    return tuple(sorted(merged.values(), key=lambda item: (item.subdomain, item.motif_name)))


def merge_dns_catalog_diagnostics(
    results: list[SourceResult],
) -> tuple[tuple[DnsCatalogSummary, ...], tuple[UnclassifiedDnsObservation, ...]]:
    """Merge count summaries and deduplicate unmatched values."""
    totals: dict[str, list[int | bool]] = {}
    observations: dict[tuple[str, str, str], UnclassifiedDnsObservation] = {}
    for result in results:
        for summary in result.dns_catalog_summaries:
            current = totals.setdefault(summary.record_type, [0, 0, 0, False])
            current[0] = int(current[0]) + summary.opportunity_count
            current[1] = int(current[1]) + summary.observed_count
            current[2] = int(current[2]) + summary.classified_count
            current[3] = bool(current[3]) or summary.truncated
        for observation in result.unclassified_dns_observations:
            key = (observation.record_type, observation.owner, observation.value)
            observations.setdefault(key, observation)
    summaries = tuple(
        DnsCatalogSummary(
            record_type=record_type,
            opportunity_count=int(values[0]),
            observed_count=int(values[1]),
            classified_count=int(values[2]),
            truncated=bool(values[3]),
        )
        for record_type, values in sorted(totals.items())
    )
    return summaries, tuple(observations[key] for key in sorted(observations))
