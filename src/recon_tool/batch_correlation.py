"""Bound batch peer materialization and retain explicit comparison limits.

This is the owner of batch-only per-domain correlation projections, separate
from CLI scheduling and presentation. Clustering remains in clustering.py.
Inputs are supplied namespaces; none of these overlaps establish ownership.
"""

from __future__ import annotations

from collections.abc import Mapping
from itertools import islice
from typing import Any

from recon_tool.clustering import (
    compute_display_name_clusters,
    compute_shared_token_report,
    compute_tenant_clusters,
)
from recon_tool.models import TenantInfo

MAX_PEERS_PER_DOMAIN = 10
MAX_TOKEN_PEER_ENTRIES = 50_000
MAX_TOKEN_ENCODED_BYTES = 8 * 1024 * 1024


def _bounded_peers(domains: tuple[str, ...], subject: str) -> tuple[list[str], int, int]:
    """Inspect at most eleven sorted members, rather than every other member."""
    peers: list[str] = []
    examined = 0
    for peer in islice(domains, MAX_PEERS_PER_DOMAIN + 1):
        examined += 1
        if peer != subject:
            peers.append(peer)
            if len(peers) == MAX_PEERS_PER_DOMAIN:
                break
    return peers, len(domains) - 1 - len(peers), examined


def _attach_identity_peers(fields: dict[str, dict[str, Any]], infos: Mapping[str, TenantInfo]) -> None:
    """Reuse shared groups and bound both identity and display-name projections."""
    tenants = {
        domain: None if info.merge_conflicts is not None and info.merge_conflicts.tenant_id else info.tenant_id
        for domain, info in infos.items()
    }
    for group in compute_tenant_clusters(tenants):
        for domain in group.domains:
            peers, omitted, examined = _bounded_peers(group.domains, domain)
            fields[domain]["shared_tenant"] = [{"tenant_id": group.tenant_id, "peers": peers}]
            diagnostic = fields[domain]["correlation_completeness"]
            diagnostic["omitted_tenant_peers"] = omitted
            diagnostic["peer_candidates_examined"] += examined
    names = {domain: info.display_name for domain, info in infos.items()}
    for group in compute_display_name_clusters(names):
        for domain, raw in zip(group.domains, group.raw_names, strict=True):
            peers, omitted, examined = _bounded_peers(group.domains, domain)
            fields[domain]["shared_display_name"] = [
                {"display_name": raw, "normalized_name": group.normalized_name, "peers": peers}
            ]
            diagnostic = fields[domain]["correlation_completeness"]
            diagnostic["omitted_display_name_peers"] = omitted
            diagnostic["peer_candidates_examined"] += examined


def attach_batch_correlations(records: list[dict[str, Any]], infos: Mapping[str, TenantInfo]) -> None:
    """Attach bounded peer observations and diagnostics without changing arrays.

    Each success record receives a completeness diagnostic, even when no
    overlap was observed. Failed and degraded supplied namespaces are counted
    separately from omissions, so absent peers cannot stand in for unavailable
    comparison opportunities. Streaming NDJSON does not invoke this pass.
    """
    from recon_tool.collection_view import collection_observable_info

    observable = {domain: collection_observable_info(info) for domain, info in infos.items()}
    failed = max(0, len(records) - len(infos))
    unavailable = sum(bool(info.degraded_sources) for info in infos.values())
    fields: dict[str, dict[str, Any]] = {
        domain: {
            "correlation_completeness": {
                "enumeration_complete": True,
                "failed_namespaces": failed,
                "source_unavailable_namespaces": unavailable,
                "omitted_tenant_peers": 0,
                "omitted_display_name_peers": 0,
                "omitted_token_peers": 0,
                "high_cardinality_token_peers": 0,
                "token_output_limited": False,
                "peer_candidates_examined": 0,
                "peer_limit": MAX_PEERS_PER_DOMAIN,
                "token_entry_limit": MAX_TOKEN_PEER_ENTRIES,
                "token_encoded_byte_limit": MAX_TOKEN_ENCODED_BYTES,
            }
        }
        for domain in observable
    }
    _attach_identity_peers(fields, observable)
    tokens = compute_shared_token_report(
        {domain: info.site_verification_tokens for domain, info in observable.items()},
        max_entries=MAX_TOKEN_PEER_ENTRIES,
        max_encoded_bytes=MAX_TOKEN_ENCODED_BYTES,
    )
    for domain, extensions in fields.items():
        diagnostic = extensions["correlation_completeness"]
        diagnostic["omitted_token_peers"] = tokens.omitted_peers.get(domain, 0)
        diagnostic["high_cardinality_token_peers"] = tokens.high_cardinality_peers.get(domain, 0)
        diagnostic["token_output_limited"] = bool(tokens.omitted_peers.get(domain, 0))
        diagnostic["enumeration_complete"] = not any(
            diagnostic[key]
            for key in (
                "failed_namespaces",
                "source_unavailable_namespaces",
                "omitted_tenant_peers",
                "omitted_display_name_peers",
                "omitted_token_peers",
                "high_cardinality_token_peers",
            )
        )
        if domain in tokens.clusters:
            extensions["shared_verification_tokens"] = [
                {"token": entry.token, "peer": entry.peer} for entry in tokens.clusters[domain]
            ]
    for record in records:
        domain = record.get("queried_domain")
        if isinstance(domain, str) and domain in fields:
            record.update(fields[domain])
