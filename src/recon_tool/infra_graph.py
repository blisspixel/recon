"""CT co-occurrence graph + community detection.

Build an in-memory undirected graph from a domain's certificate
transparency entries, then run Louvain community detection (via
pure-Python ``networkx``) to summarize co-occurrence structure that
single-certificate fingerprinting misses.

Graph shape
-----------
Nodes are non-wildcard SAN hostnames. For every certificate entry,
the SANs in that cert form a clique: each pair of SANs gets one
edge whose weight aggregates:

  * ``shared_certs``: number of certs both SANs appeared on together.
  * ``issuers``: set of issuer names contributing to the edge.

The aggregate edge weight passed to Louvain is ``shared_certs`` itself. This is
the current heuristic, not calibrated relationship strength; large SAN sets can
bias the clique projection. Issuer overlap is preserved in the edge attributes
for downstream attribution but does not double-count.

Algorithm choice
----------------
Louvain (``networkx.algorithms.community.louvain_communities``) is retained as
the dependency-minimal shipped heuristic. This is not a claim of theoretical
superiority over Leiden or a statistically inferred community model. See
``docs/correlation.md`` section 2.3 for the current semantics and section 6 for
the benchmark required before changing graph machinery.

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
from recon_tool.validator import is_safe_dns_name, strip_control_chars

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

# Bound graph construction by the number of cert entries processed, not just by
# node growth. A fixed small SAN set reused across tens of thousands of certs
# never trips MAX_GRAPH_NODES, yet still re-runs combinations() per entry and
# accumulates one issuer sample per edge per entry, so the entry count is the
# real amplification dimension. 1000 matches the crt.sh cert-summary cap.
_MAX_GRAPH_ENTRIES = 1000

# Cap how many issuer samples accumulate per edge. The dominant issuer only
# needs the most-common, not every contribution, so a handful of samples is
# enough and the per-edge list cannot grow with the entry count.
_MAX_EDGE_ISSUER_SAMPLES = 32

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
        # Defense in depth: SAN sets reaching this layer are already
        # charset-filtered by cert_providers, but the graph must not depend
        # on a non-local invariant. Drop any name with non-DNS characters
        # so a future caller passing unfiltered entries cannot inject
        # control bytes into cluster members / graph nodes.
        if not is_safe_dns_name(n):
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

    for idx, entry in enumerate(entries):
        if idx >= _MAX_GRAPH_ENTRIES:
            # Bound work by entry count even when the node count is frozen
            # (a small SAN set reused across many certs never trips the node
            # cap but still re-runs combinations() and grows edge_issuers).
            # Route to the connected-components fallback on the partial graph.
            truncated = True
            break
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
        # Strip control bytes: the issuer becomes a cluster's dominant_issuer,
        # which is emitted in --json and the get_infrastructure_clusters MCP
        # tool. This is the issuer path the build_cert_summary strip misses.
        issuer = strip_control_chars(str(issuer_raw)) if isinstance(issuer_raw, str) else ""

        for a, b in combinations(sorted(sans), 2):
            if g.has_edge(a, b):
                data = g[a][b]
                data["shared_certs"] = int(data.get("shared_certs", 0)) + 1
                data["weight"] = float(data["shared_certs"])
            else:
                g.add_edge(a, b, shared_certs=1, weight=1.0)
            if issuer:
                samples = edge_issuers.setdefault((a, b), [])
                if len(samples) < _MAX_EDGE_ISSUER_SAMPLES:
                    samples.append(issuer)
    return g, edge_issuers, truncated


def _louvain_partition(g: nx.Graph[str]) -> tuple[list[set[str]], float, str]:
    """Run Louvain. Returns (communities, modularity, algorithm-name)."""
    # Re-insert nodes in a content-determined (sorted) order before running
    # Louvain. networkx seeds its initial communities and its internal shuffle
    # from node insertion order, which here follows cert-entry arrival order
    # (the crt.sh response / CertSpotter pagination, which is not stable across
    # requests); without this, two runs of the same domain could produce
    # different clusters on tied moves. Edge data is preserved; only iteration
    # order is normalized.
    ordered: nx.Graph[str] = nx.Graph()
    ordered.add_nodes_from(sorted(g.nodes()))
    ordered.add_edges_from(g.edges(data=True))
    g = ordered
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


# Number of Louvain runs (distinct seeds) in the partition-stability sweep.
# Small on purpose: the sweep multiplies Louvain cost, and the CT graphs the
# layer sees are small and sparse, where a handful of seeds already exposes
# degeneracy when it exists.
_STABILITY_RUNS = 8


def adjusted_rand_index(p1: list[set[str]], p2: list[set[str]]) -> float:
    """Adjusted Rand index between two partitions of the same node set.

    Computed from the contingency table (Hubert & Arabie 1985), pure Python.
    By convention the degenerate case (expected index equals maximum index,
    e.g. both partitions trivial — all-singletons or one block) returns 1.0
    when the partitions are identical and 0.0 otherwise, so a stable trivial
    partition does not read as unstable.
    """

    def _comb2(n: int) -> int:
        return n * (n - 1) // 2

    label1: dict[str, int] = {}
    for i, block in enumerate(p1):
        for node in block:
            label1[node] = i
    label2: dict[str, int] = {}
    for j, block in enumerate(p2):
        for node in block:
            label2[node] = j

    contingency: dict[tuple[int, int], int] = {}
    for node, i in label1.items():
        key = (i, label2[node])
        contingency[key] = contingency.get(key, 0) + 1

    sum_ij = sum(_comb2(n) for n in contingency.values())
    sum_i = sum(_comb2(len(block)) for block in p1)
    sum_j = sum(_comb2(len(block)) for block in p2)
    total = _comb2(sum(len(block) for block in p1))
    if total == 0:
        return 1.0
    expected = (sum_i * sum_j) / total
    maximum = (sum_i + sum_j) / 2.0
    if abs(maximum - expected) < 1e-12:
        return 1.0 if sum_ij == maximum else 0.0
    return (sum_ij - expected) / (maximum - expected)


def _partition_stability(g: nx.Graph[str], runs: int = _STABILITY_RUNS) -> float | None:
    """Mean pairwise ARI of Louvain partitions across a seed sweep (CAL11).

    Louvain is degenerate on many graphs (Good et al. 2010): near-equal-
    modularity partitions can differ structurally, and a single modularity
    score cannot see that. The honest report is consensus across seeds: 1.0
    when every seed lands on the same partition, lower when the partition is
    seed-dependent. Returns None when a sweep run fails — stability is then
    unknown, not 1.0.
    """
    ordered: nx.Graph[str] = nx.Graph()
    ordered.add_nodes_from(sorted(g.nodes()))
    ordered.add_edges_from(g.edges(data=True))
    partitions: list[list[set[str]]] = []
    for offset in range(runs):
        try:
            communities = nx.community.louvain_communities(  # type: ignore[attr-defined]
                ordered,
                weight="weight",
                seed=_LOUVAIN_SEED + offset,
            )
        except (nx.NetworkXError, RuntimeError, ValueError):
            return None
        partitions.append([set(c) for c in communities])
    scores = [
        adjusted_rand_index(partitions[i], partitions[j])
        for i in range(len(partitions))
        for j in range(i + 1, len(partitions))
    ]
    if not scores:
        return None
    return round(sum(scores) / len(scores), 4)


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
    # Deterministic tie-break (highest count, then lexicographic). Cert arrival
    # order is unstable across requests (see the module docstring), so
    # most_common's insertion-order tie-break would leak nondeterminism into the
    # emitted dominant_issuer.
    issuer = min(issuer_counter, key=lambda s: (-issuer_counter[s], s))
    return issuer, edge_count_in_cluster


def build_infrastructure_clusters(
    entries: list[dict[str, Any]],
) -> InfrastructureClusterReport:
    """Run the graph layer over cert entries.

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

    partition_stability: float | None = None
    stability_runs = 0
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
        if algorithm == "louvain":
            partition_stability = _partition_stability(g)
            if partition_stability is not None:
                stability_runs = _STABILITY_RUNS

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
        partition_stability=partition_stability,
        stability_runs=stability_runs,
    )
