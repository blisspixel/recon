"""Unit tests for the v1.8 MCP graph-export tools.

Covers ``get_infrastructure_clusters`` and ``export_graph``:
- Both surface the cached cluster report without re-running detection.
- Cluster output mirrors the InfrastructureClusterReport shape.
- export_graph builds the node + edge envelope plus cluster_assignment.
- Both gracefully handle ``infrastructure_clusters=None`` (skipped envelope).
- Resolver errors propagate as ``error`` field.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from recon_tool import server
from recon_tool.models import (
    ConfidenceLevel,
    InfrastructureCluster,
    InfrastructureClusterReport,
    InfrastructureEdge,
    TenantInfo,
)


def _info_with_clusters() -> TenantInfo:
    report = InfrastructureClusterReport(
        clusters=(
            InfrastructureCluster(
                cluster_id=0,
                members=("a.example.com", "b.example.com"),
                size=2,
                shared_cert_count=4,
                dominant_issuer="LE",
            ),
            InfrastructureCluster(
                cluster_id=1,
                members=("x.example.com", "y.example.com"),
                size=2,
                shared_cert_count=2,
                dominant_issuer="DigiCert",
            ),
        ),
        modularity=0.42,
        algorithm="louvain",
        node_count=4,
        edge_count=2,
        edges=(
            InfrastructureEdge("a.example.com", "b.example.com", 4),
            InfrastructureEdge("x.example.com", "y.example.com", 2),
        ),
    )
    return TenantInfo(
        tenant_id=None,
        display_name="Example",
        default_domain="example.com",
        queried_domain="example.com",
        confidence=ConfidenceLevel.MEDIUM,
        infrastructure_clusters=report,
    )


def _info_without_clusters() -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="Empty",
        default_domain="empty.com",
        queried_domain="empty.com",
        confidence=ConfidenceLevel.LOW,
        infrastructure_clusters=None,
    )


@pytest.fixture
def stub_resolve(monkeypatch: pytest.MonkeyPatch):
    """Stub _resolve_or_cache so MCP tools can run without network."""

    def _make(info: TenantInfo | str):
        async def _stub(domain: str):
            if isinstance(info, str):
                return info  # error message
            return (info, ())

        monkeypatch.setattr(server, "_resolve_or_cache", _stub)

    return _make


class TestGetInfrastructureClusters:
    def test_returns_cluster_envelope(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        out = asyncio.run(server.get_infrastructure_clusters("example.com"))
        payload = json.loads(out)
        assert payload["domain"] == "example.com"
        assert payload["algorithm"] == "louvain"
        assert payload["modularity"] == pytest.approx(0.42)
        assert payload["node_count"] == 4
        assert payload["edge_count"] == 2
        assert len(payload["clusters"]) == 2
        first = payload["clusters"][0]
        assert first["cluster_id"] == 0
        assert first["size"] == 2
        assert first["dominant_issuer"] == "LE"
        assert first["members"] == ["a.example.com", "b.example.com"]

    def test_skipped_envelope_when_no_report(self, stub_resolve):
        stub_resolve(_info_without_clusters())
        out = asyncio.run(server.get_infrastructure_clusters("empty.com"))
        payload = json.loads(out)
        assert payload["algorithm"] == "skipped"
        assert payload["modularity"] == 0.0
        assert payload["clusters"] == []

    def test_resolver_error_returns_error_field(self, stub_resolve):
        stub_resolve("Domain validation failed")
        out = asyncio.run(server.get_infrastructure_clusters("bad..com"))
        payload = json.loads(out)
        assert "error" in payload


class TestExportGraph:
    def test_returns_nodes_and_edges(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        out = asyncio.run(server.export_graph("example.com"))
        payload = json.loads(out)
        assert payload["domain"] == "example.com"
        assert payload["algorithm"] == "louvain"
        assert payload["node_count"] == 4
        assert payload["edge_count"] == 2
        assert sorted(payload["nodes"]) == [
            "a.example.com",
            "b.example.com",
            "x.example.com",
            "y.example.com",
        ]
        assert payload["edges"][0]["shared_cert_count"] == 4

    def test_cluster_assignment_maps_members(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        out = asyncio.run(server.export_graph("example.com"))
        payload = json.loads(out)
        assignment = payload["cluster_assignment"]
        assert assignment["a.example.com"] == 0
        assert assignment["b.example.com"] == 0
        assert assignment["x.example.com"] == 1
        assert assignment["y.example.com"] == 1

    def test_includes_disclaimer(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        out = asyncio.run(server.export_graph("example.com"))
        payload = json.loads(out)
        assert "disclaimer" in payload
        assert "ownership" in payload["disclaimer"].lower()

    def test_skipped_envelope_when_no_report(self, stub_resolve):
        stub_resolve(_info_without_clusters())
        out = asyncio.run(server.export_graph("empty.com"))
        payload = json.loads(out)
        assert payload["algorithm"] == "skipped"
        assert payload["nodes"] == []
        assert payload["edges"] == []
        assert payload["cluster_assignment"] == {}

    def test_resolver_error_returns_error_field(self, stub_resolve):
        stub_resolve("Domain validation failed")
        out = asyncio.run(server.export_graph("bad..com"))
        payload = json.loads(out)
        assert "error" in payload
