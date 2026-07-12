"""Unit tests for the v1.8 CT co-occurrence graph layer.

Covers:
- Graph builder skips wildcards / empty / single-SAN certs.
- Louvain detects two cleanly-separated cliques with high modularity.
- Connected-components fallback fires above the node cap.
- ``skipped`` envelope on empty / trivial inputs.
- Cluster member sorting, cap on members, cap on cluster count.
- Edge surface is sorted by weight and capped.
- Determinism — repeated runs produce the same partition.
"""

from __future__ import annotations

import itertools
from unittest.mock import Mock

import networkx as nx
import pytest

from recon_tool.infra_graph import (
    MAX_CLUSTERS,
    MAX_EDGES_RETAINED,
    MAX_GRAPH_NODES,
    MAX_MEMBERS_PER_CLUSTER,
    MIN_CLUSTER_SIZE,
    _clean_sans,
    adjusted_rand_index,
    build_infrastructure_clusters,
)
from recon_tool.models import InfrastructureClusterReport


def _entry(names: list[str], issuer: str = "Test CA", not_before: str = "2025-01-01T00:00:00") -> dict:
    return {
        "dns_names": names,
        "issuer_name": issuer,
        "not_before": not_before,
        "not_after": "2026-01-01T00:00:00",
    }


def _unaggregated_graph_snapshot(
    entries: list[dict],
) -> tuple[set[str], dict[tuple[str, str], tuple[int, float]], dict[tuple[str, str], tuple[str, ...]], bool]:
    """Preserve the pre-aggregation builder as a differential test oracle."""
    from recon_tool import infra_graph

    graph: nx.Graph[str] = nx.Graph()
    edge_issuers: dict[tuple[str, str], list[str]] = {}
    truncated = False
    for index, entry in enumerate(entries):
        if index >= infra_graph._MAX_GRAPH_ENTRIES:
            truncated = True
            break
        if graph.number_of_nodes() >= MAX_GRAPH_NODES:
            truncated = True
            break
        sans = _clean_sans(entry.get("dns_names"))
        if len(sans) < 2:
            continue
        if len(sans) > infra_graph._MAX_SANS_PER_CERT_FOR_EDGES:
            sans = sorted(sans)[: infra_graph._MAX_SANS_PER_CERT_FOR_EDGES]
        issuer_raw = entry.get("issuer_name")
        issuer = infra_graph.strip_control_chars(str(issuer_raw)) if isinstance(issuer_raw, str) else ""
        for left, right in itertools.combinations(sorted(sans), 2):
            if graph.has_edge(left, right):
                data = graph[left][right]
                data["shared_certs"] = int(data.get("shared_certs", 0)) + 1
                data["weight"] = float(data["shared_certs"])
            else:
                graph.add_edge(left, right, shared_certs=1, weight=1.0)
            if issuer:
                samples = edge_issuers.setdefault((left, right), [])
                if len(samples) < infra_graph._MAX_EDGE_ISSUER_SAMPLES:
                    samples.append(issuer)
    edge_snapshot = {
        (min(left, right), max(left, right)): (int(data["shared_certs"]), float(data["weight"]))
        for left, right, data in graph.edges(data=True)
    }
    issuer_snapshot = {edge: tuple(issuers) for edge, issuers in edge_issuers.items()}
    return set(graph.nodes), edge_snapshot, issuer_snapshot, truncated


class TestEmptyAndTrivial:
    def test_empty_entries_returns_skipped(self):
        report = build_infrastructure_clusters([])
        assert report.algorithm == "skipped"
        assert report.clusters == ()
        assert report.modularity == 0.0
        assert report.node_count == 0
        assert report.edge_count == 0
        assert report.edges == ()

    def test_only_wildcards_skips(self):
        report = build_infrastructure_clusters([_entry(["*.example.com"])])
        assert report.algorithm == "skipped"
        assert report.node_count == 0

    def test_single_san_cert_skips(self):
        # One SAN can't form an edge (need at least a pair)
        report = build_infrastructure_clusters([_entry(["only.example.com"])])
        assert report.algorithm == "skipped"
        assert report.edge_count == 0

    def test_disconnected_singletons_have_no_edges(self):
        # Two single-SAN entries → two nodes, zero edges → skipped
        entries = [_entry(["a.example.com"]), _entry(["b.example.com"])]
        report = build_infrastructure_clusters(entries)
        assert report.algorithm == "skipped"


class TestLouvainPartition:
    def test_two_cliques_partition_cleanly(self):
        entries = [
            _entry(["a.example.com", "b.example.com", "c.example.com"], "LE"),
            _entry(["a.example.com", "b.example.com"], "LE"),
            _entry(["x.example.com", "y.example.com", "z.example.com"], "DigiCert"),
            _entry(["x.example.com", "y.example.com"], "DigiCert"),
        ]
        report = build_infrastructure_clusters(entries)
        assert report.algorithm == "louvain"
        assert len(report.clusters) == 2
        assert report.modularity > 0.4  # two clean cliques → high modularity
        # Cluster 0 is the larger one (or alphabetically smaller on tie).
        member_sets = {tuple(c.members) for c in report.clusters}
        assert ("a.example.com", "b.example.com", "c.example.com") in member_sets
        assert ("x.example.com", "y.example.com", "z.example.com") in member_sets

    def test_dominant_issuer_picked(self):
        entries = [
            _entry(["a.example.com", "b.example.com"], "LE"),
            _entry(["a.example.com", "b.example.com"], "LE"),
            _entry(["a.example.com", "b.example.com"], "DigiCert"),
        ]
        report = build_infrastructure_clusters(entries)
        assert report.clusters[0].dominant_issuer == "LE"

    def test_dominant_issuer_tie_break_is_deterministic(self):
        # Two certs over the same SAN pair from different issuers tie on the
        # cluster's issuer count. The winner must be content-determined, not
        # dependent on (unstable) cert arrival order.
        entries = [
            _entry(["a.example.com", "b.example.com"], issuer="IssuerX"),
            _entry(["a.example.com", "b.example.com"], issuer="IssuerY"),
        ]
        fwd = build_infrastructure_clusters(entries)
        rev = build_infrastructure_clusters(list(reversed(entries)))
        assert fwd.clusters
        assert rev.clusters
        assert fwd.clusters[0].dominant_issuer == rev.clusters[0].dominant_issuer == "IssuerX"

    def test_shared_cert_count_aggregates(self):
        entries = [
            _entry(["a.example.com", "b.example.com"], "LE"),
            _entry(["a.example.com", "b.example.com"], "LE"),
            _entry(["a.example.com", "b.example.com"], "LE"),
        ]
        report = build_infrastructure_clusters(entries)
        # Three certs each contributed one edge between a and b.
        assert report.clusters[0].shared_cert_count == 3

    def test_clusters_sorted_by_size_desc(self):
        # 4-clique + 2-clique → 4-clique should be cluster_id 0
        entries = [
            _entry(["a.example.com", "b.example.com", "c.example.com", "d.example.com"], "LE"),
            _entry(["x.example.com", "y.example.com"], "DigiCert"),
        ]
        report = build_infrastructure_clusters(entries)
        assert report.clusters[0].size >= report.clusters[1].size
        assert report.clusters[0].cluster_id == 0
        assert report.clusters[1].cluster_id == 1

    def test_stability_reuses_primary_partition(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The eight-seed stability sweep must execute each seed exactly once."""
        from recon_tool import infra_graph

        original = nx.community.louvain_communities
        seeds: list[int] = []
        partitions: list[list[set[str]]] = []

        def tracked_louvain(*args, **kwargs):
            communities = original(*args, **kwargs)
            seeds.append(kwargs["seed"])
            partitions.append([set(community) for community in communities])
            return communities

        monkeypatch.setattr(nx.community, "louvain_communities", tracked_louvain)
        entries = [
            _entry(["a.example.com", "b.example.com", "c.example.com"]),
            _entry(["a.example.com", "b.example.com"]),
            _entry(["x.example.com", "y.example.com", "z.example.com"]),
            _entry(["x.example.com", "y.example.com"]),
        ]

        report = build_infrastructure_clusters(entries)

        assert seeds == list(range(infra_graph._LOUVAIN_SEED, infra_graph._LOUVAIN_SEED + 8))
        scores = [
            adjusted_rand_index(partitions[left], partitions[right])
            for left in range(len(partitions))
            for right in range(left + 1, len(partitions))
        ]
        assert report.partition_stability == round(sum(scores) / len(scores), 4)
        assert report.stability_runs == 8


class TestEdgeSurface:
    def test_edges_sorted_by_weight_desc(self):
        entries = [
            _entry(["a.example.com", "b.example.com"], "LE"),
            _entry(["a.example.com", "b.example.com"], "LE"),
            _entry(["c.example.com", "d.example.com"], "LE"),
        ]
        report = build_infrastructure_clusters(entries)
        # a-b has 2 shared certs; c-d has 1. a-b must come first.
        assert report.edges[0].source == "a.example.com"
        assert report.edges[0].target == "b.example.com"
        assert report.edges[0].shared_cert_count == 2
        assert report.edges[-1].shared_cert_count == 1

    def test_edges_canonicalized_alphabetically(self):
        # Order of names within a cert shouldn't change which way the
        # edge is written — source < target always.
        entries = [_entry(["z.example.com", "a.example.com"])]
        report = build_infrastructure_clusters(entries)
        assert all(e.source < e.target for e in report.edges)

    def test_edges_capped(self):
        # Build a complete graph on N nodes — has N*(N-1)/2 edges. Pick
        # N just above the floor for the cap, then assert the cap held.
        names = [f"h{i}.example.com" for i in range(80)]  # 80 → 3160 edges
        entries = [_entry(names)]
        report = build_infrastructure_clusters(entries)
        assert len(report.edges) <= MAX_EDGES_RETAINED


class TestConnectedComponentsFallback:
    def test_oversized_graph_falls_back(self):
        # Generate a graph above MAX_GRAPH_NODES so the fallback path
        # triggers. Use small overlapping windows so connected
        # components produces a meaningful partition.
        chunks = []
        for chunk_idx in range(11):  # 11 chunks of ~50 names each → ~550 nodes
            chunk_names = [f"c{chunk_idx}-h{i}.example.com" for i in range(50)]
            chunks.append(_entry(chunk_names))
        report = build_infrastructure_clusters(chunks)
        assert report.node_count == MAX_GRAPH_NODES
        assert report.algorithm == "connected_components"
        assert report.modularity == 0.0


class TestCaps:
    def test_cluster_count_capped(self):
        # Build many disconnected small cliques; the report should
        # surface at most MAX_CLUSTERS even if more exist.
        entries = []
        for cluster_idx in range(MAX_CLUSTERS + 5):
            entries.append(_entry([f"c{cluster_idx}-a.example.com", f"c{cluster_idx}-b.example.com"]))
        report = build_infrastructure_clusters(entries)
        assert len(report.clusters) <= MAX_CLUSTERS

    def test_members_per_cluster_capped(self):
        # One giant clique larger than the per-cluster cap.
        names = [f"h{i}.example.com" for i in range(MAX_MEMBERS_PER_CLUSTER + 10)]
        entries = [_entry(names)]
        report = build_infrastructure_clusters(entries)
        for c in report.clusters:
            assert len(c.members) <= MAX_MEMBERS_PER_CLUSTER

    def test_min_cluster_size_filters_singletons(self):
        # A graph with one big clique and one singleton should not
        # surface the singleton.
        entries = [
            _entry(["a.example.com", "b.example.com", "c.example.com"]),
        ]
        report = build_infrastructure_clusters(entries)
        for c in report.clusters:
            assert c.size >= MIN_CLUSTER_SIZE


class TestDeterminism:
    def test_repeated_runs_produce_same_partition(self):
        entries = [
            _entry(["a.example.com", "b.example.com", "c.example.com"]),
            _entry(["x.example.com", "y.example.com", "z.example.com"]),
        ]
        first = build_infrastructure_clusters(entries)
        second = build_infrastructure_clusters(entries)
        assert first.clusters == second.clusters
        assert first.modularity == second.modularity
        assert first.edges == second.edges

    def test_partition_invariant_to_entry_order(self):
        # Reordering the same certs must not change the partition: node insertion
        # order (and thus Louvain seeding/shuffling) was previously cert-entry
        # arrival order, which is not stable across CT responses.
        e1 = _entry(["a.example.com", "b.example.com"])
        e2 = _entry(["b.example.com", "c.example.com"])
        e3 = _entry(["c.example.com", "a.example.com"])
        e4 = _entry(["d.example.com", "e.example.com", "f.example.com"])
        forward = build_infrastructure_clusters([e1, e2, e3, e4])
        reordered = build_infrastructure_clusters([e4, e3, e2, e1])
        assert forward.clusters == reordered.clusters
        assert forward.modularity == reordered.modularity


class TestReportShape:
    def test_returns_report_dataclass(self):
        report = build_infrastructure_clusters([])
        assert isinstance(report, InfrastructureClusterReport)

    def test_member_strings_lowercased(self):
        # Cert SANs are uppercased / mixed in raw input; cleaning
        # should normalise.
        entries = [_entry(["A.Example.COM", "B.example.com"])]
        report = build_infrastructure_clusters(entries)
        for cluster in report.clusters:
            for m in cluster.members:
                assert m == m.lower()

    @pytest.mark.parametrize("issuer_value", [None, "", 42, [], {}])
    def test_non_string_issuer_is_tolerated(self, issuer_value):
        entries = [
            {
                "dns_names": ["a.example.com", "b.example.com"],
                "issuer_name": issuer_value,
                "not_before": "2025-01-01",
                "not_after": "2026-01-01",
            }
        ]
        report = build_infrastructure_clusters(entries)
        # Either dominant_issuer is None (when issuer was unparseable)
        # or it's the empty string — both are acceptable as long as
        # the build did not raise.
        if report.clusters:
            assert report.clusters[0].dominant_issuer in (None, "", str(issuer_value))


class TestSanAndIssuerSanitization:
    """The graph layer is self-protecting: SAN names with control bytes are
    dropped, and a control-byte issuer does not survive into
    dominant_issuer (the issuer path the cert-summary strip does not cover)."""

    def test_clean_sans_drops_control_byte_names(self):
        out = _clean_sans(["evil\x1bx.example.com", "ok.example.com", "a b.example.com"])
        assert out == ["ok.example.com"]

    def test_dominant_issuer_control_chars_stripped(self):
        report = build_infrastructure_clusters([_entry(["a.example.com", "b.example.com"], issuer="Evil\x1b[31m CA")])
        assert report.clusters, "a 2-SAN cert should form one cluster"
        for cluster in report.clusters:
            assert cluster.dominant_issuer is None or "\x1b" not in cluster.dominant_issuer


class TestRepeatedHyperedgeAggregation:
    def test_consecutive_identical_certificates_expand_pairs_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recon_tool import infra_graph

        names = [f"host-{index}.example.com" for index in range(60)]
        entries = [_entry(names)] * 1000
        combinations_spy = Mock(wraps=itertools.combinations)
        monkeypatch.setattr(infra_graph, "combinations", combinations_spy)

        report = build_infrastructure_clusters(entries)

        assert combinations_spy.call_count == 1
        assert report.edge_count == 1770
        assert report.edges
        assert all(edge.shared_cert_count == 1000 for edge in report.edges)

    def test_issuer_sample_cap_preserves_arrival_order_across_groups(self) -> None:
        names = ["a.example.com", "b.example.com"]
        entries = [_entry(names, issuer="First CA")] * 40 + [_entry(names, issuer="Second CA")] * 40

        report = build_infrastructure_clusters(entries)

        assert report.clusters
        assert report.clusters[0].dominant_issuer == "First CA"
        assert report.edges[0].shared_cert_count == 80

    @pytest.mark.parametrize(
        "entries",
        [
            [_entry(["a.example.com", "b.example.com"])] * 1005,
            [_entry(["a.example.com", "b.example.com"], issuer="First CA")] * 40
            + [_entry(["a.example.com", "b.example.com"], issuer="Second CA")] * 40,
            [
                _entry(["a.example.com", "b.example.com", "c.example.com"], issuer="First CA"),
                _entry(["b.example.com", "c.example.com", "d.example.com"], issuer="Second CA"),
                _entry(["a.example.com", "b.example.com", "c.example.com"], issuer="First CA"),
                _entry(["*.example.com", "not a host"], issuer="Ignored CA"),
            ],
            [_entry([f"cluster-{cluster}-host-{index}.example.com" for index in range(50)]) for cluster in range(11)],
        ],
    )
    def test_aggregation_matches_the_unaggregated_graph_contract(self, entries: list[dict]) -> None:
        from recon_tool.infra_graph import _build_graph

        graph, issuers, truncated = _build_graph(entries)
        edge_snapshot = {
            (min(left, right), max(left, right)): (int(data["shared_certs"]), float(data["weight"]))
            for left, right, data in graph.edges(data=True)
        }
        actual = (
            set(graph.nodes),
            edge_snapshot,
            {edge: tuple(samples) for edge, samples in issuers.items()},
            truncated,
        )

        assert actual == _unaggregated_graph_snapshot(entries)
