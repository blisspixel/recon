"""Graph MCP tools: chain lookup, token clustering, infrastructure clusters, export.

Extracted from server.py (docs/roadmap.md god-file track, app-sharing variant).
Registers its tools on the shared ``mcp`` instance imported from server_app;
server.py imports this module to trigger registration and re-exports the tool
functions for the test surface. Imports server_app / server_runtime; never the
reverse.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid

from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from typing_extensions import TypedDict

from recon_tool import server_app
from recon_tool.server_app import mcp
from recon_tool.server_runtime import (
    log_structured,
    rate_limit_release,
    rate_limit_try_acquire,
)
from recon_tool.validator import validate_domain

logger = logging.getLogger("recon")

GRAPH_EXPORT_DISCLAIMER = (
    "Graph describes observable certificate SAN co-occurrence. "
    "Edges are co-issuance evidence, not ownership claims."
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
    disclaimer: str


class InfrastructureClusterSummary(TypedDict):
    cluster_id: int
    size: int
    members: list[str]
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
    nodes: list[str]
    edges: list[GraphEdgeSummary]
    cluster_assignment: dict[str, int]
    disclaimer: str


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def chain_lookup(domain: str, depth: int = 1) -> str:
    """Recursively resolve a domain and its related domains.

    Follows CNAME breadcrumbs and certificate transparency discoveries
    up to the specified depth. Returns intelligence for all discovered domains.

    Args:
        domain: Starting domain (e.g., "northwindtraders.com")
        depth: Maximum recursion depth (1-3, default 1)

    Returns:
        JSON object with total_domains, max_depth_reached, truncated flag,
        and an array of domain intelligence objects with chain_depth.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    # Clamp depth
    depth = max(1, min(depth, 3))

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
    # same per-domain limiter the single-domain tools use; release the
    # slot on error so a transient failure does not block a legitimate
    # retry.
    if not rate_limit_try_acquire(validated):
        return f"Rate limited: {domain} was looked up recently. Try again in a few seconds."

    try:
        from recon_tool.chain import chain_resolve
        from recon_tool.formatter import format_chain_json

        report = await chain_resolve(validated, depth=depth)
    except asyncio.CancelledError:
        rate_limit_release(validated)
        raise
    except Exception as exc:
        rate_limit_release(validated)
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

    return format_chain_json(report)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def cluster_verification_tokens(domains: list[str]) -> VerificationTokenClusterResult:
    """Cluster a list of domains by shared site-verification tokens.

    For defensive OSINT and vendor due-diligence only.

    Looks up each domain (using the TTL cache when available) and
    computes a map of shared TXT verification tokens across the input
    set. When two domains share a ``google-site-verification=``,
    ``MS=``, Atlassian, Zoom, or similar token, it surfaces a hedged
    "possible relationship" observation — not a verdict.

    A reused token implies a shared operator scope: the same SaaS
    account provisioned the verification on both domains. Common
    interpretations include shared infrastructure, acquisition history,
    subsidiary relationships, managed-services providers, or
    historical residue. The tool does NOT commit to any of these —
    it reports the observation and leaves synthesis to the caller.

    Zero additional network calls beyond whatever initial resolves are
    required to populate the cache. Every result is computed from
    cached TenantInfo.

    Args:
        domains: List of domain names to cluster. Must contain at
            least two distinct domains to be useful. Invalid domains
            are skipped with an error entry in the response.

    Returns:
        JSON object with ``clusters`` (a map from each domain to its
        peers via shared tokens) and ``errors`` (a list of domains
        that could not be resolved). Empty ``clusters`` means no
        shared tokens were observed — not an error.
    """
    from recon_tool.clustering import compute_shared_tokens

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
        domain_tokens[info.queried_domain] = info.site_verification_tokens

    clusters = compute_shared_tokens(domain_tokens)

    # Serialize: domain → list of {token, peer}
    serialized: dict[str, list[SharedVerificationPeer]] = {}
    for d, entries in clusters.items():
        serialized[d] = [{"token": e.token, "peer": e.peer} for e in entries]

    payload: VerificationTokenClusterResult = {
        "clusters": serialized,
        "errors": errors,
        "disclaimer": (
            "Shared verification tokens imply operator-scoped credential "
            "reuse across domains. This is consistent with shared "
            "infrastructure, subsidiary relationships, or managed-services "
            "providers — it is not a corporate-identity verdict. Observation, "
            "not a verdict."
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
async def get_infrastructure_clusters(domain: str) -> InfrastructureClusterEnvelope:
    """Return the CT co-occurrence community-detection report for a domain.

    Surfaces the same ``infrastructure_clusters`` envelope that ships in
    the default ``--json`` output: cluster membership, modularity score,
    algorithm path, and underlying graph metrics. The report describes
    observable structure — names that co-occur on the same certificates,
    grouped by Louvain community detection — never an ownership claim.

    No new network surface: the report was already computed during the
    last ``lookup_tenant`` (or implicit resolve). This tool just exposes
    what the deterministic graph pass produced.

    Args:
        domain: Domain to look up. Will use the existing TTL cache when
            available; otherwise resolves via the standard pipeline.

    Returns:
        JSON object matching the ``InfrastructureClusterReport`` schema
        in ``docs/recon-schema.json``. The ``algorithm`` field reflects
        which path produced the partition (``louvain`` |
        ``connected_components`` | ``skipped``); ``skipped`` means the
        graph was empty or had no edges. ``partition_stability`` (2.2.0+)
        is the Louvain seed-sweep consensus (mean pairwise adjusted Rand
        index over ``stability_runs`` seeds; null outside the Louvain
        path) — 1.0 means every seed produced the identical partition,
        lower values flag partition degeneracy a single modularity score
        cannot see.
    """
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
            "clusters": [],
        }
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
        "clusters": [
            {
                "cluster_id": c.cluster_id,
                "size": c.size,
                "members": list(c.members),
                "shared_cert_count": c.shared_cert_count,
                "dominant_issuer": c.dominant_issuer,
            }
            for c in ic.clusters
        ],
    }


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def export_graph(domain: str) -> GraphExportEnvelope:
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

    Returns:
        JSON object with ``domain``, ``algorithm`` (mirroring the
        cluster report), ``node_count``, ``edge_count``, ``nodes`` (a
        sorted array of hostnames), ``edges`` (array of {source,
        target, shared_cert_count} records), and ``cluster_assignment``
        (object mapping each surfaced node to its cluster_id).
    """
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
    nodes_sorted = sorted(nodes_set)

    return {
        "domain": info.queried_domain,
        "algorithm": ic.algorithm,
        "node_count": ic.node_count,
        "edge_count": ic.edge_count,
        "nodes": nodes_sorted,
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "shared_cert_count": e.shared_cert_count,
            }
            for e in ic.edges
        ],
        "cluster_assignment": cluster_assignment,
        "disclaimer": GRAPH_EXPORT_DISCLAIMER,
    }
