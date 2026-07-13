"""Graph MCP tools: chain lookup, token clustering, infrastructure clusters, export.

Extracted from server.py (docs/roadmap.md god-file track, app-sharing variant).
Registers its tools on the shared ``mcp`` instance imported from
``recon_tool.server.app``; the server facade imports this module to trigger
registration and re-exports the tool functions for the test surface. Imports
``recon_tool.server.app`` and ``recon_tool.server.runtime``; never the reverse.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, cast

from typing_extensions import TypedDict

from recon_tool.mcp_client.sdk_compat import ToolAnnotations, ToolError
from recon_tool.models import ChainReport, InfrastructureEdge
from recon_tool.server import app as server_app
from recon_tool.server.app import mcp
from recon_tool.server.runtime import (
    log_structured,
    rate_limit_try_acquire,
)
from recon_tool.validator import validate_domain

logger = logging.getLogger("recon")

GRAPH_EXPORT_DISCLAIMER = (
    "Graph describes observable certificate SAN co-occurrence. Edges are co-issuance evidence, not ownership claims."
)


class SharedVerificationPeer(TypedDict):
    token: str
    peer: str


class DomainToolError(TypedDict):
    domain: str
    error: str


class VerificationTokenClusterResult(TypedDict):
    clusters: dict[str, list[SharedVerificationPeer]]
    errors: list[DomainToolError]
    peer_limit_per_domain: int
    peers_omitted: dict[str, int]
    selection_rule: str
    raw_request: str
    disclaimer: str


class InfrastructureClusterSummary(TypedDict):
    cluster_id: int
    size: int
    members: list[str]
    members_omitted: int
    shared_cert_count: int
    dominant_issuer: str | None


class InfrastructureClusterEnvelope(TypedDict):
    domain: str
    algorithm: str
    modularity: float
    partition_stability: float | None
    stability_runs: int
    node_count: int
    edge_count: int
    member_limit_per_cluster: int
    selection_rule: str
    raw_request: str
    clusters: list[InfrastructureClusterSummary]


class GraphEdgeSummary(TypedDict):
    source: str
    target: str
    shared_cert_count: int


class GraphExportEnvelope(TypedDict):
    domain: str
    algorithm: str
    node_count: int
    edge_count: int
    node_limit: int
    edge_limit: int
    nodes_omitted: int
    edges_omitted: int
    cluster_assignment_omitted: int
    selection_rule: str
    raw_request: str
    nodes: list[str]
    edges: list[GraphEdgeSummary]
    cluster_assignment: dict[str, int]
    disclaimer: str


def _verification_peer(token: str, peer: str) -> SharedVerificationPeer:
    return {"token": token, "peer": peer}


def _normalize_limit(value: int, name: str) -> int:
    """Validate an optional compact-output cap. Zero means full raw output."""
    if value < 0:
        raise ToolError(f"{name} must be zero or a positive integer")
    return value


def _surface_cluster_members(members: tuple[str, ...], limit: int) -> tuple[list[str], int]:
    """Return deterministic cluster members and an omitted count."""
    surfaced = list(members if limit == 0 else members[:limit])
    return surfaced, len(members) - len(surfaced)


def _surface_verification_peers(
    entries: tuple[SharedVerificationPeer, ...],
    limit: int,
) -> tuple[list[SharedVerificationPeer], int]:
    """Return deterministic token peers and an omitted count."""
    surfaced = list(entries if limit == 0 else entries[:limit])
    return surfaced, len(entries) - len(surfaced)


def _top_graph_nodes(
    edges: tuple[InfrastructureEdge, ...],
    nodes: set[str],
    limit: int,
) -> set[str]:
    """Select graph nodes by weighted degree, then hostname, for compact output."""
    if limit == 0 or len(nodes) <= limit:
        return set(nodes)
    weighted_degree = dict.fromkeys(nodes, 0)
    for edge in edges:
        source = edge.source
        target = edge.target
        weight = edge.shared_cert_count
        weighted_degree[source] = weighted_degree.get(source, 0) + weight
        weighted_degree[target] = weighted_degree.get(target, 0) + weight
    ranked = sorted(nodes, key=lambda node: (-weighted_degree.get(node, 0), node))
    return set(ranked[:limit])


def _format_compact_chain_json(report: ChainReport, result_limit: int) -> str:
    from recon_tool.formatter import format_chain_dict

    payload = format_chain_dict(report)
    domains = cast(list[dict[str, Any]], payload["domains"])
    surfaced = domains[:result_limit]
    payload["domains"] = surfaced
    payload["result_limit"] = result_limit
    payload["domains_omitted"] = len(domains) - len(surfaced)
    payload["selection_rule"] = (
        "raw BFS chain order when result_limit is zero; otherwise domains are truncated by chain depth "
        "then discovery order"
    )
    payload["raw_request"] = "Call chain_lookup with result_limit=0 for the raw domain list."
    return json.dumps(payload, indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def chain_lookup(domain: str, depth: int = 1, result_limit: int = 0) -> str:
    """Recursively resolve a domain and its related domains.

    Follows CNAME breadcrumbs and certificate transparency discoveries
    up to the specified depth. Returns intelligence for all discovered domains.

    Args:
        domain: Starting domain (e.g., "northwindtraders.com")
        depth: Maximum recursion depth (1-3, default 1)
        result_limit: Optional compact-output cap. ``0`` returns the raw chain
            JSON. A positive value returns the first N domains in BFS chain
            order plus ``domains_omitted`` metadata.

    Returns:
        JSON object with total_domains, max_depth_reached, truncated flag,
        and an array of domain intelligence objects with chain_depth.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    # Clamp depth
    depth = max(1, min(depth, 3))
    result_limit = _normalize_limit(result_limit, "result_limit")

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        log_structured(
            logging.WARNING,
            "validation_failed",
            request_id=request_id,
            domain=domain,
            error=str(exc),
        )
        return f"Error: {exc}"

    # Rate limit: chain_lookup is the most expensive tool (up to
    # MAX_CHAIN_DOMAINS resolves per call), so an untrusted MCP caller
    # could otherwise use it to amplify outbound DNS/HTTP. Gate it on the
    # same per-domain limiter the single-domain tools use. Retain the cooldown
    # after every started attempt, including failures and cancellation.
    if not rate_limit_try_acquire(validated):
        return f"Rate limited: {domain} was looked up recently. Try again in a few seconds."

    try:
        from recon_tool.chain import chain_resolve
        from recon_tool.formatter import format_chain_json

        report = await chain_resolve(validated, depth=depth)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.exception(
            "Unexpected error in chain lookup for %s (request_id=%s)",
            domain,
            request_id,
        )
        return server_app.internal_lookup_error(domain, request_id, exc)

    elapsed = time.monotonic() - start_time
    log_structured(
        logging.INFO,
        "chain_resolved",
        request_id=request_id,
        domain=domain,
        total_domains=len(report.results),
        max_depth=report.max_depth_reached,
        truncated=report.truncated,
        elapsed_s=round(elapsed, 2),
    )

    if result_limit == 0:
        return format_chain_json(report)
    return _format_compact_chain_json(report, result_limit)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def cluster_verification_tokens(
    domains: list[str],
    peer_limit_per_domain: int = 0,
) -> VerificationTokenClusterResult:
    """Cluster a list of domains by shared site-verification tokens.

    For defensive OSINT and vendor due-diligence only.

    Looks up each domain (using the TTL cache when available) and
    computes a map of shared TXT verification tokens across the input
    set. When two domains share a ``google-site-verification=``,
    ``MS=``, Atlassian, Zoom, or similar token, it reports the exact
    administrative token reuse and does not infer a relationship.

    Exact token reuse is consistent with shared administration, copied
    configuration, a managed-services provider, or stale residue. The public
    record does not establish a shared account, operator, ownership, or current
    product use. The tool reports the observation and leaves synthesis to the
    caller.

    Zero additional network calls beyond whatever initial resolves are
    required to populate the cache. Every result is computed from
    cached TenantInfo.

    Args:
        domains: List of domain names to cluster. Must contain at
            least two distinct domains to be useful. Invalid domains
            are skipped with an error entry in the response.
        peer_limit_per_domain: Optional compact-output cap. ``0`` returns
            every observed peer entry. A positive value returns the first N
            entries per domain after deterministic ``(token, peer)`` sorting,
            plus ``peers_omitted`` counts.

    Returns:
        JSON object with ``clusters`` (a map from each domain to its
        peers via shared tokens) and ``errors`` (a list of domains
        that could not be resolved). Empty ``clusters`` means no
        shared tokens were observed — not an error.
    """
    from recon_tool.clustering import compute_shared_tokens

    peer_limit_per_domain = _normalize_limit(peer_limit_per_domain, "peer_limit_per_domain")
    if not domains:
        raise ToolError("At least one domain is required")

    # Cap and dedup the input, matching the CLI batch path. Without this
    # the MCP tool lets a caller drive unbounded sequential resolves (each
    # distinct domain gets its own rate-limit slot, so the per-domain
    # limiter does not throttle a many-distinct-domain flood) and build a
    # proportionally large response.
    _MAX_CLUSTER_DOMAINS = 100
    seen_keys: set[str] = set()
    deduped: list[str] = []
    for raw in domains:
        key = raw.strip().lower()
        if key and key not in seen_keys:
            seen_keys.add(key)
            deduped.append(raw)
    if len(deduped) > _MAX_CLUSTER_DOMAINS:
        raise ToolError(f"Too many domains: {len(deduped)} distinct (max {_MAX_CLUSTER_DOMAINS})")
    domains = deduped

    domain_tokens: dict[str, tuple[str, ...]] = {}
    errors: list[DomainToolError] = []

    for raw in domains:
        resolved = await server_app.resolve_or_cache(raw)
        if isinstance(resolved, str):
            errors.append({"domain": raw, "error": resolved})
            continue
        info, _results = resolved
        from recon_tool.collection_view import collection_observable_info

        info = collection_observable_info(info)
        domain_tokens[info.queried_domain] = info.site_verification_tokens

    clusters = compute_shared_tokens(domain_tokens)

    # Serialize: domain → list of {token, peer}
    serialized: dict[str, list[SharedVerificationPeer]] = {}
    peers_omitted: dict[str, int] = {}
    for d in sorted(clusters):
        entries = tuple(_verification_peer(e.token, e.peer) for e in clusters[d])
        surfaced, omitted = _surface_verification_peers(entries, peer_limit_per_domain)
        serialized[d] = surfaced
        peers_omitted[d] = omitted

    payload: VerificationTokenClusterResult = {
        "clusters": serialized,
        "errors": errors,
        "peer_limit_per_domain": peer_limit_per_domain,
        "peers_omitted": peers_omitted,
        "selection_rule": (
            "raw peer lists when peer_limit_per_domain is zero; otherwise entries are sorted by token then peer"
        ),
        "raw_request": "Call cluster_verification_tokens with peer_limit_per_domain=0 for raw peer lists.",
        "disclaimer": (
            "Exact administrative token reuse was observed. It is consistent "
            "with shared administration, copied configuration, a managed "
            "service, or stale residue, but does not establish a shared "
            "account, operator, ownership, or current product use."
        ),
    }
    return payload


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def get_infrastructure_clusters(domain: str, member_limit_per_cluster: int = 0) -> InfrastructureClusterEnvelope:
    """Return the CT co-occurrence community-detection report for a domain.

    Surfaces the same ``infrastructure_clusters`` envelope that ships in
    the default ``--json`` output: cluster membership, modularity score,
    algorithm path, and underlying graph metrics. The report describes
    observable structure — names that co-occur on the same certificates,
    grouped by the Louvain co-occurrence heuristic, never an ownership claim.

    No new network surface: the report was already computed during the
    last ``lookup_tenant`` (or implicit resolve). This tool just exposes
    what the deterministic graph pass produced.

    Args:
        domain: Domain to look up. Will use the existing TTL cache when
            available; otherwise resolves via the standard pipeline.
        member_limit_per_cluster: Optional compact-output cap. ``0`` returns
            every surfaced member from the already bounded raw report. A
            positive value returns the first N sorted members from each cluster
            plus ``members_omitted`` counts.

    Returns:
        JSON object matching the ``InfrastructureClusterReport`` schema
        in ``docs/recon-schema.json``. The ``algorithm`` field reflects
        which path produced the partition (``louvain`` |
        ``connected_components`` | ``skipped``); ``skipped`` means the
        graph was empty or had no edges. ``partition_stability`` (2.2.0+)
        is the Louvain seed-sweep consensus (mean pairwise adjusted Rand
        index over ``stability_runs`` seeds; null outside the Louvain path).
        A value of 1.0 means every seed produced the identical partition;
        lower values show optimizer seed sensitivity on the same fixed graph.
        The field does not measure CT data stability, model stability,
        significance, or partition correctness.
    """
    member_limit_per_cluster = _normalize_limit(member_limit_per_cluster, "member_limit_per_cluster")
    resolved = await server_app.resolve_or_cache(domain)
    if isinstance(resolved, str):
        raise ToolError(resolved)
    info, _results = resolved
    ic = info.infrastructure_clusters
    if ic is None:
        return {
            "domain": info.queried_domain,
            "algorithm": "skipped",
            "modularity": 0.0,
            "partition_stability": None,
            "stability_runs": 0,
            "node_count": 0,
            "edge_count": 0,
            "member_limit_per_cluster": member_limit_per_cluster,
            "selection_rule": "raw cluster members when limit is zero; otherwise sorted cluster members are truncated",
            "raw_request": "Call get_infrastructure_clusters with member_limit_per_cluster=0 for raw members.",
            "clusters": [],
        }
    clusters: list[InfrastructureClusterSummary] = []
    for cluster in ic.clusters:
        members, omitted = _surface_cluster_members(cluster.members, member_limit_per_cluster)
        clusters.append(
            {
                "cluster_id": cluster.cluster_id,
                "size": cluster.size,
                "members": members,
                "members_omitted": omitted,
                "shared_cert_count": cluster.shared_cert_count,
                "dominant_issuer": cluster.dominant_issuer,
            }
        )
    return {
        "domain": info.queried_domain,
        "algorithm": ic.algorithm,
        "modularity": ic.modularity,
        # 2.2.0 (additive): Louvain seed-sweep consensus (mean pairwise
        # ARI; CAL11). null outside the Louvain path.
        "partition_stability": ic.partition_stability,
        "stability_runs": ic.stability_runs,
        "node_count": ic.node_count,
        "edge_count": ic.edge_count,
        "member_limit_per_cluster": member_limit_per_cluster,
        "selection_rule": "raw cluster members when limit is zero; otherwise sorted cluster members are truncated",
        "raw_request": "Call get_infrastructure_clusters with member_limit_per_cluster=0 for raw members.",
        "clusters": clusters,
    }


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def export_graph(domain: str, node_limit: int = 0, edge_limit: int = 0) -> GraphExportEnvelope:
    """Return the raw CT co-occurrence graph (nodes + weighted edges).

    Companion to ``get_infrastructure_clusters``: surfaces the underlying
    graph that the Louvain pass partitioned. Nodes are SAN hostnames;
    edges carry the shared-cert count between each pair. Useful for
    Mermaid / GraphViz / CSV rendering pipelines that want to draw the
    structure directly.

    Edges are sorted by weight descending; both nodes and edges are
    capped — see ``recon_tool/infra_graph.MAX_GRAPH_NODES`` and
    ``MAX_EDGES_RETAINED`` for the bounds. ``cluster_assignment`` maps
    every surfaced node to the cluster id from the same report so
    downstream tools can colour the graph by community without re-
    running detection.

    No new network surface — the graph was already built during the
    last ``lookup_tenant``. Read-only exposure of computed state.

    Args:
        domain: Domain whose graph to export. Uses the TTL cache when
            available; otherwise resolves via the standard pipeline.
        node_limit: Optional compact-output cap. ``0`` returns every bounded
            node. A positive value selects top nodes by weighted degree
            descending, then hostname.
        edge_limit: Optional compact-output cap after node filtering. ``0``
            returns every retained edge among surfaced nodes.

    Returns:
        JSON object with ``domain``, ``algorithm`` (mirroring the
        cluster report), ``node_count``, ``edge_count``, ``nodes`` (a
        sorted array of hostnames), ``edges`` (array of {source,
        target, shared_cert_count} records), and ``cluster_assignment``
        (object mapping each surfaced node to its cluster_id).
    """
    node_limit = _normalize_limit(node_limit, "node_limit")
    edge_limit = _normalize_limit(edge_limit, "edge_limit")
    resolved = await server_app.resolve_or_cache(domain)
    if isinstance(resolved, str):
        raise ToolError(resolved)
    info, _results = resolved
    ic = info.infrastructure_clusters
    if ic is None:
        return {
            "domain": info.queried_domain,
            "algorithm": "skipped",
            "node_count": 0,
            "edge_count": 0,
            "node_limit": node_limit,
            "edge_limit": edge_limit,
            "nodes_omitted": 0,
            "edges_omitted": 0,
            "cluster_assignment_omitted": 0,
            "selection_rule": (
                "raw bounded graph when limits are zero; compact nodes use weighted degree descending then hostname"
            ),
            "raw_request": "Call export_graph with node_limit=0 and edge_limit=0 for the raw bounded graph.",
            "nodes": [],
            "edges": [],
            "cluster_assignment": {},
            "disclaimer": GRAPH_EXPORT_DISCLAIMER,
        }

    cluster_assignment: dict[str, int] = {}
    for cluster in ic.clusters:
        for member in cluster.members:
            cluster_assignment[member] = cluster.cluster_id

    nodes_set: set[str] = set(cluster_assignment)
    for edge in ic.edges:
        nodes_set.add(edge.source)
        nodes_set.add(edge.target)
    selected_nodes = _top_graph_nodes(ic.edges, nodes_set, node_limit)
    nodes_sorted = sorted(selected_nodes)
    filtered_edges = [edge for edge in ic.edges if edge.source in selected_nodes and edge.target in selected_nodes]
    surfaced_edges = filtered_edges if edge_limit == 0 else filtered_edges[:edge_limit]
    surfaced_assignment = {node: cluster_assignment[node] for node in nodes_sorted if node in cluster_assignment}

    return {
        "domain": info.queried_domain,
        "algorithm": ic.algorithm,
        "node_count": ic.node_count,
        "edge_count": ic.edge_count,
        "node_limit": node_limit,
        "edge_limit": edge_limit,
        "nodes_omitted": len(nodes_set) - len(nodes_sorted),
        "edges_omitted": len(ic.edges) - len(surfaced_edges),
        "cluster_assignment_omitted": len(cluster_assignment) - len(surfaced_assignment),
        "selection_rule": (
            "raw bounded graph when limits are zero; compact nodes use weighted degree descending then hostname"
        ),
        "raw_request": "Call export_graph with node_limit=0 and edge_limit=0 for the raw bounded graph.",
        "nodes": nodes_sorted,
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "shared_cert_count": e.shared_cert_count,
            }
            for e in surfaced_edges
        ],
        "cluster_assignment": surfaced_assignment,
        "disclaimer": GRAPH_EXPORT_DISCLAIMER,
    }
