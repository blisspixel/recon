"""CT co-occurrence graph + community detection (v1.8+).

Build an in-memory undirected graph from a domain's certificate
transparency entries, then run Louvain community detection (via
pure-Python ``networkx``) to expose substructure that single-cert
fingerprinting misses.

Graph shape
-----------
Nodes are non-wildcard SAN hostnames. For every certificate entry,
the SANs in that cert form a clique: each pair of SANs gets one
edge whose weight aggregates:

  * ``shared_certs``: number of certs both SANs appeared on together.
  * ``issuers``: set of issuer names contributing to the edge.

The aggregate edge weight passed to Louvain is ``shared_certs``
itself (the count is the natural "how strongly do these names go
together" signal). Issuer overlap is preserved in the edge
attributes for downstream attribution but does not double-count.

Algorithm choice
----------------
Louvain (``networkx.algorithms.community.louvain_communities``) over
Leiden — see ``docs/correlation.md §4.5`` for the rationale. Briefly:
Leiden's well-connectedness guarantee only matters on dense graphs;
our caps keep us well below that threshold, and Louvain ships pure-
Python in networkx while ``leidenalg`` would pull in C extensions.

Determinism
-----------
Louvain is randomized. The module passes a fixed seed
(``_LOUVAIN_SEED``) so repeated runs over identical inputs return
identical partitions. Modularity is also computed via networkx for
the same partition.

Caps
----
``MAX_GRAPH_NODES`` bounds the Louvain pass to keep runtime
predictable. Beyond the cap, the module falls back to connected-
components clustering (deterministic, fast, no modularity score).
``MAX_CLUSTERS`` and ``MAX_MEMBERS_PER_CLUSTER`` cap the surfaced
output so a pathologically connected component cannot dominate the
field.
"""

from __future__ import annotations

import logging
from collections import Counter
from itertools import combinations
from typing import Any

import networkx as nx

from recon_tool.models import (
    InfrastructureCluster,
    InfrastructureClusterReport,
    InfrastructureEdge,
)

logger = logging.getLogger(__name__)

__all__ = [
    "MAX_CLUSTERS",
    "MAX_EDGES_RETAINED",
    "MAX_GRAPH_NODES",
    "MAX_MEMBERS_PER_CLUSTER",
    "MIN_CLUSTER_SIZE",
    "build_infrastructure_clusters",
]

# Hard caps. The graph layer ships under the same hedge as the cert
# summary itself: bounded surface, no claims of ownership.
MAX_GRAPH_NODES = 500
MAX_CLUSTERS = 20
MAX_MEMBERS_PER_CLUSTER = 50
MIN_CLUSTER_SIZE = 2  # singletons are not interesting

# Edges retained on the report for ``export_graph`` MCP consumption.
# A 500-node graph could in principle have ~125k complete-graph edges;
# we keep only the strongest co-occurrence relationships to bound
# memory and JSON payload sizes.
MAX_EDGES_RETAINED = 2000

# Bounds applied during graph construction so a single huge cert with
# hundreds of SANs cannot blow up the edge count quadratically.
_MAX_SANS_PER_CERT_FOR_EDGES = 60

# Seed for Louvain — keeps partitions stable across runs.
_LOUVAIN_SEED = 1729


def _clean_sans(raw: Any) -> list[str]:
    """Filter a cert entry's ``dns_names`` to non-wildcard, lowercased SANs."""
    if not isinstance(raw, list):
        return []
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            continue
        n = item.strip().lower()
        if not n or n.startswith("*."):
            continue
        if n in seen:
            continue
        seen.add(n)
        cleaned.append(n)
    return cleaned


def _build_graph(
    entries: list[dict[str, Any]],
) -> tuple[nx.Graph[str], dict[tuple[str, str], list[str]], bool]:
    """Build the SAN co-occurrence graph from cert entries.

    Returns ``(graph, edge_issuers, truncated)``. ``edge_issuers`` maps
    each (sorted) edge tuple to the issuer names that contributed to
    that edge — used afterward to compute ``dominant_issuer`` per
    cluster without re-reading entries. ``truncated`` is True when
    construction stopped early because the node cap was reached, so
    callers can route to the connected-components fallback without
    attempting Louvain on the partial graph.

    Construction is bounded twice: once per cert by
    ``_MAX_SANS_PER_CERT_FOR_EDGES`` (so a single huge cert cannot
    blow up edge count quadratically), and globally by
    ``MAX_GRAPH_NODES`` (so a hostile/pathological CT response with
    many large certs cannot materialize millions of edges before the
    later cap is checked).
    """
    g: nx.Graph[str] = nx.Graph()
    edge_issuers: dict[tuple[str, str], list[str]] = {}
    truncated = False

    for entry in entries:
        if g.number_of_nodes() >= MAX_GRAPH_NODES:
            # Stop adding new certs once the node cap is reached.
            # Existing edges still aggregate their issuer lists for
            # accuracy on the bounded partition; new SAN names are
            # rejected. The caller routes to connected-components
            # fallback rather than running Louvain on this partial
            # graph.
            truncated = True
            break
        sans = _clean_sans(entry.get("dns_names"))
        if len(sans) < 2:
            continue
        if len(sans) > _MAX_SANS_PER_CERT_FOR_EDGES:
            sans = sorted(sans)[:_MAX_SANS_PER_CERT_FOR_EDGES]
        issuer_raw = entry.get("issuer_name")
        issuer = str(issuer_raw) if isinstance(issuer_raw, str) else ""

        for a, b in combinations(sorted(sans), 2):
            if g.has_edge(a, b):
                data = g[a][b]
                data["shared_certs"] = int(data.get("shared_certs", 0)) + 1
                data["weight"] = float(data["shared_certs"])
            else:
                g.add_edge(a, b, shared_certs=1, weight=1.0)
            if issuer:
                edge_issuers.setdefault((a, b), []).append(issuer)
    return g, edge_issuers, truncated


def _louvain_partition(g: nx.Graph[str]) -> tuple[list[set[str]], float, str]:
    """Run Louvain. Returns (communities, modularity, algorithm-name)."""
    # networkx returns a list of sets — one per community.
    communities = nx.community.louvain_communities(  # type: ignore[attr-defined]
        g,
        weight="weight",
        seed=_LOUVAIN_SEED,
    )
    # The library returns ``Iterable[set]``; coerce to a concrete list of
    # ``set[str]`` so ordering and downstream typing are stable.
    comm_list: list[set[str]] = [set(c) for c in communities]
    modularity = float(
        nx.community.modularity(g, comm_list, weight="weight")  # type: ignore[attr-defined]
    )
    return comm_list, modularity, "louvain"


def _connected_components_partition(
    g: nx.Graph[str],
) -> tuple[list[set[str]], float, str]:
    """Fallback: just connected components, no modularity."""
    comm_list: list[set[str]] = [set(c) for c in nx.connected_components(g)]
    return comm_list, 0.0, "connected_components"


def _dominant_issuer_for_members(
    members: set[str],
    edge_issuers: dict[tuple[str, str], list[str]],
) -> tuple[str | None, int]:
    """Return (issuer, shared_cert_count) for the cluster.

    ``shared_cert_count`` is the number of cert-entry contributions
    aggregated across edges fully inside the cluster (not unique
    certs — we don't track cert IDs). It tracks how much intra-
    cluster co-issuance the cluster represents.
    """
    issuer_counter: Counter[str] = Counter()
    edge_count_in_cluster = 0
    for (a, b), issuers in edge_issuers.items():
        if a in members and b in members:
            edge_count_in_cluster += len(issuers)
            issuer_counter.update(issuers)
    if not issuer_counter:
        return None, edge_count_in_cluster
    issuer, _ = issuer_counter.most_common(1)[0]
    return issuer, edge_count_in_cluster


def build_infrastructure_clusters(
    entries: list[dict[str, Any]],
) -> InfrastructureClusterReport:
    """Run the v1.8 graph layer over cert entries.

    Always returns a report. The shape of the report is stable:

      * Empty graph / fewer than two nodes / no edges → ``algorithm
        = "skipped"``, empty ``clusters``, ``modularity = 0.0``.
      * Graph above ``MAX_GRAPH_NODES`` → connected-components
        fallback.
      * Otherwise → Louvain partition with computed modularity.

    Output is sorted by cluster size (largest first) and capped by
    ``MAX_CLUSTERS``. Within each cluster, members are sorted and
    capped by ``MAX_MEMBERS_PER_CLUSTER``.
    """
    g, edge_issuers, truncated = _build_graph(entries)
    node_count = int(g.number_of_nodes())
    edge_count = int(g.number_of_edges())

    if node_count < 2 or edge_count == 0:
        return InfrastructureClusterReport(
            clusters=(),
            modularity=0.0,
            algorithm="skipped",
            node_count=node_count,
            edge_count=edge_count,
        )

    if truncated or node_count > MAX_GRAPH_NODES:
        comms, modularity, algorithm = _connected_components_partition(g)
    else:
        try:
            comms, modularity, algorithm = _louvain_partition(g)
        except (nx.NetworkXError, RuntimeError, ValueError) as exc:
            logger.warning(
                "Louvain failed on %d-node graph: %s — falling back to connected components",
                node_count,
                exc,
            )
            comms, modularity, algorithm = _connected_components_partition(g)

    # Sort communities by size desc, then alphabetically by min-member
    # for deterministic ordering when sizes tie.
    comms.sort(key=lambda c: (-len(c), min(c) if c else ""))

    clusters: list[InfrastructureCluster] = []
    cluster_id = 0
    for community in comms:
        if len(community) < MIN_CLUSTER_SIZE:
            continue
        members_sorted = sorted(community)[:MAX_MEMBERS_PER_CLUSTER]
        members_set = set(members_sorted)
        dominant, shared = _dominant_issuer_for_members(members_set, edge_issuers)
        clusters.append(
            InfrastructureCluster(
                cluster_id=cluster_id,
                members=tuple(members_sorted),
                size=len(members_sorted),
                shared_cert_count=shared,
                dominant_issuer=dominant,
            )
        )
        cluster_id += 1
        if len(clusters) >= MAX_CLUSTERS:
            break

    # Build the edge surface for ``export_graph``. Sort by shared-cert
    # count descending, then alphabetically by source/target so equal-
    # weight edges have a deterministic order. Cap at MAX_EDGES_RETAINED
    # to bound JSON payload size on heavy targets.
    raw_edges: list[InfrastructureEdge] = []
    for u, v, data in g.edges(data=True):
        # Canonicalise the edge so source < target alphabetically;
        # makes ``edges`` deterministic regardless of which direction
        # networkx happened to emit.
        source, target = (u, v) if u < v else (v, u)
        raw_edges.append(
            InfrastructureEdge(
                source=str(source),
                target=str(target),
                shared_cert_count=int(data.get("shared_certs", 1)),
            )
        )
    raw_edges.sort(key=lambda e: (-e.shared_cert_count, e.source, e.target))
    surfaced_edges = tuple(raw_edges[:MAX_EDGES_RETAINED])

    return InfrastructureClusterReport(
        clusters=tuple(clusters),
        modularity=modularity,
        algorithm=algorithm,
        node_count=node_count,
        edge_count=edge_count,
        edges=surfaced_edges,
    )
