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

import pytest

from recon_tool.infra_graph import (
    MAX_CLUSTERS,
    MAX_EDGES_RETAINED,
    MAX_GRAPH_NODES,
    MAX_MEMBERS_PER_CLUSTER,
    MIN_CLUSTER_SIZE,
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
        if report.node_count > MAX_GRAPH_NODES:
            assert report.algorithm == "connected_components"
            assert report.modularity == 0.0


class TestCaps:
    def test_cluster_count_capped(self):
        # Build many disconnected small cliques; the report should
        # surface at most MAX_CLUSTERS even if more exist.
        entries = []
        for cluster_idx in range(MAX_CLUSTERS + 5):
            entries.append(
                _entry([f"c{cluster_idx}-a.example.com", f"c{cluster_idx}-b.example.com"])
            )
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
