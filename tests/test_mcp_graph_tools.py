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
from mcp.server.fastmcp.exceptions import ToolError

from recon_tool import server, server_app
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

        monkeypatch.setattr(server_app, "resolve_or_cache", _stub)

    return _make


class TestGetInfrastructureClusters:
    def test_returns_cluster_envelope(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        payload = asyncio.run(server.get_infrastructure_clusters("example.com"))
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
        assert first["members_omitted"] == 0
        assert payload["member_limit_per_cluster"] == 0

    def test_skipped_envelope_when_no_report(self, stub_resolve):
        stub_resolve(_info_without_clusters())
        payload = asyncio.run(server.get_infrastructure_clusters("empty.com"))
        assert payload["algorithm"] == "skipped"
        assert payload["modularity"] == 0.0
        assert payload["clusters"] == []
        assert payload["member_limit_per_cluster"] == 0

    def test_member_limit_returns_omitted_counts(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        payload = asyncio.run(server.get_infrastructure_clusters("example.com", member_limit_per_cluster=1))
        assert payload["member_limit_per_cluster"] == 1
        assert payload["clusters"][0]["members"] == ["a.example.com"]
        assert payload["clusters"][0]["members_omitted"] == 1
        assert "sorted cluster members" in payload["selection_rule"]

    def test_negative_member_limit_rejected(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        with pytest.raises(ToolError, match="member_limit_per_cluster"):
            asyncio.run(server.get_infrastructure_clusters("example.com", member_limit_per_cluster=-1))

    def test_resolver_error_raises_tool_error(self, stub_resolve):
        stub_resolve("Domain validation failed")
        with pytest.raises(ToolError, match="Domain validation failed"):
            asyncio.run(server.get_infrastructure_clusters("bad..com"))


class TestExportGraph:
    def test_returns_nodes_and_edges(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        payload = asyncio.run(server.export_graph("example.com"))
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
        assert payload["node_limit"] == 0
        assert payload["edge_limit"] == 0
        assert payload["nodes_omitted"] == 0
        assert payload["edges_omitted"] == 0

    def test_cluster_assignment_maps_members(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        payload = asyncio.run(server.export_graph("example.com"))
        assignment = payload["cluster_assignment"]
        assert assignment["a.example.com"] == 0
        assert assignment["b.example.com"] == 0
        assert assignment["x.example.com"] == 1
        assert assignment["y.example.com"] == 1

    def test_includes_disclaimer(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        payload = asyncio.run(server.export_graph("example.com"))
        assert "disclaimer" in payload
        assert "ownership" in payload["disclaimer"].lower()

    def test_skipped_envelope_when_no_report(self, stub_resolve):
        stub_resolve(_info_without_clusters())
        payload = asyncio.run(server.export_graph("empty.com"))
        assert payload["algorithm"] == "skipped"
        assert payload["nodes"] == []
        assert payload["edges"] == []
        assert payload["cluster_assignment"] == {}
        assert payload["nodes_omitted"] == 0
        assert payload["edges_omitted"] == 0
        assert "ownership" in payload["disclaimer"].lower()

    def test_compact_limits_return_omitted_counts(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        payload = asyncio.run(server.export_graph("example.com", node_limit=2, edge_limit=1))
        assert payload["node_limit"] == 2
        assert payload["edge_limit"] == 1
        assert payload["nodes"] == ["a.example.com", "b.example.com"]
        assert payload["edges"] == [{"source": "a.example.com", "target": "b.example.com", "shared_cert_count": 4}]
        assert payload["cluster_assignment"] == {"a.example.com": 0, "b.example.com": 0}
        assert payload["nodes_omitted"] == 2
        assert payload["edges_omitted"] == 1
        assert payload["cluster_assignment_omitted"] == 2
        assert "weighted degree" in payload["selection_rule"]

    def test_negative_graph_limit_rejected(self, stub_resolve):
        stub_resolve(_info_with_clusters())
        with pytest.raises(ToolError, match="node_limit"):
            asyncio.run(server.export_graph("example.com", node_limit=-1))

    def test_resolver_error_raises_tool_error(self, stub_resolve):
        stub_resolve("Domain validation failed")
        with pytest.raises(ToolError, match="Domain validation failed"):
            asyncio.run(server.export_graph("bad..com"))


# ── v1.8.1: end-to-end FastMCP transport smoke test ───────────────────


class TestMcpToolRegistry:
    """Verify the v1.8 graph tools are wired into the FastMCP registry
    and reachable through the same code path that the stdio JSON-RPC
    handler uses on a ``tools/call`` request.
    """

    def test_both_tools_registered(self):
        from recon_tool.server import mcp

        names = {t.name for t in asyncio.run(mcp.list_tools())}
        assert "get_infrastructure_clusters" in names
        assert "export_graph" in names

    def test_get_infrastructure_clusters_via_call_tool(self, stub_resolve):
        """Invoke through ``mcp.call_tool`` — the same dispatch
        FastMCP's stdio transport calls on tools/call. Verifies the
        tool is not just registered but actually reachable."""
        from recon_tool.server import mcp

        stub_resolve(_info_with_clusters())
        content, structured = asyncio.run(mcp.call_tool("get_infrastructure_clusters", {"domain": "example.com"}))
        assert content, "expected at least one TextContent payload"
        payload = json.loads(content[0].text)
        assert payload["domain"] == "example.com"
        assert payload["algorithm"] == "louvain"
        assert payload["clusters"], "cluster list should be non-empty"
        # Structured output is the navigable object itself (not a {"result": ...}
        # wrapper): the tool returns a dict, so FastMCP surfaces it directly.
        assert structured["domain"] == "example.com"
        assert structured["algorithm"] == "louvain"

    def test_export_graph_via_call_tool(self, stub_resolve):
        from recon_tool.server import mcp

        stub_resolve(_info_with_clusters())
        content, _ = asyncio.run(mcp.call_tool("export_graph", {"domain": "example.com"}))
        payload = json.loads(content[0].text)
        assert payload["nodes"], "graph nodes should be non-empty"
        assert payload["edges"], "graph edges should be non-empty"
        assert payload["cluster_assignment"], "cluster_assignment map populated"
