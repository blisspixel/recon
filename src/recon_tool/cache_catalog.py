"""Cache serialization for the opt-in catalog-discovery payload.

``--include-unclassified`` produces three related collections: the unclassified
CNAME chains, the bounded per-record-type accounting, and the individual
unmatched values. They are cached so a later run of the discovery loop can read
them without re-resolving DNS, and they move together because a cache entry
holding only some of them reports "nothing unclassified" rather than "not
measured".

Split out of ``cache.py`` to keep that module under the size guard in
``docs/engineering-practices.md``. Every reader tolerates a malformed or absent
field by returning an empty tuple, matching the cache contract that a corrupt
entry degrades to a miss instead of raising.
"""

from __future__ import annotations

from typing import Any

from recon_tool.models import (
    DnsCatalogSummary,
    TenantInfo,
    UnclassifiedCnameChain,
    UnclassifiedDnsObservation,
)

__all__ = [
    "catalog_discovery_to_cache_dict",
    "dns_catalog_summaries_from_dict",
    "unclassified_chains_from_dict",
    "unclassified_dns_observations_from_dict",
]


def catalog_discovery_to_cache_dict(info: TenantInfo) -> dict[str, Any]:
    """Serialize every catalog-discovery collection on ``info``."""
    return {
        "unclassified_cname_chains": [
            {"subdomain": chain.subdomain, "chain": list(chain.chain)} for chain in info.unclassified_cname_chains
        ],
        "dns_catalog_summaries": [
            {
                "record_type": summary.record_type,
                "opportunity_count": summary.opportunity_count,
                "observed_count": summary.observed_count,
                "classified_count": summary.classified_count,
                "truncated": summary.truncated,
            }
            for summary in info.dns_catalog_summaries
        ],
        "unclassified_dns_observations": [
            {"record_type": observation.record_type, "owner": observation.owner, "value": observation.value}
            for observation in info.unclassified_dns_observations
        ],
    }


def _dict_items(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return the list of object entries stored under ``key``."""
    raw = data.get(key, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def unclassified_chains_from_dict(data: dict[str, Any]) -> tuple[UnclassifiedCnameChain, ...]:
    """Deserialize the ``unclassified_cname_chains`` list."""
    records: list[UnclassifiedCnameChain] = []
    for item in _dict_items(data, "unclassified_cname_chains"):
        subdomain = item.get("subdomain")
        chain = item.get("chain", [])
        if not subdomain or not isinstance(chain, list):
            continue
        records.append(UnclassifiedCnameChain(subdomain=str(subdomain), chain=tuple(str(hop) for hop in chain)))
    return tuple(records)


def dns_catalog_summaries_from_dict(data: dict[str, Any]) -> tuple[DnsCatalogSummary, ...]:
    """Deserialize the ``dns_catalog_summaries`` list."""
    summaries: list[DnsCatalogSummary] = []
    for item in _dict_items(data, "dns_catalog_summaries"):
        record_type = item.get("record_type")
        if not record_type:
            continue
        try:
            summaries.append(
                DnsCatalogSummary(
                    record_type=str(record_type),
                    opportunity_count=int(item.get("opportunity_count", 0)),
                    observed_count=int(item.get("observed_count", 0)),
                    classified_count=int(item.get("classified_count", 0)),
                    truncated=bool(item.get("truncated", False)),
                )
            )
        except (TypeError, ValueError):
            continue
    return tuple(summaries)


def unclassified_dns_observations_from_dict(data: dict[str, Any]) -> tuple[UnclassifiedDnsObservation, ...]:
    """Deserialize the ``unclassified_dns_observations`` list."""
    observations: list[UnclassifiedDnsObservation] = []
    for item in _dict_items(data, "unclassified_dns_observations"):
        record_type = item.get("record_type")
        owner = item.get("owner")
        value = item.get("value")
        if not record_type or owner is None or value is None:
            continue
        observations.append(
            UnclassifiedDnsObservation(record_type=str(record_type), owner=str(owner), value=str(value))
        )
    return tuple(observations)
