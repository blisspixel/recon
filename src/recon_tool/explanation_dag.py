"""Canonical node construction and finalization for explanation DAGs."""

from __future__ import annotations

from typing import Any

from recon_tool.models import EvidenceRecord, ExplanationRecord

TERMINAL_NODE_TYPES = frozenset({"signal", "insight", "observation", "confidence"})


def evidence_node_id(evidence: EvidenceRecord, index: int) -> str:
    """Return a deterministic identifier for one evidence occurrence."""
    return f"evidence:{evidence.source_type}:{evidence.slug}:{evidence.rule_name}:{index}"


def slug_node_id(slug: str) -> str:
    return f"slug:{slug}"


def rule_node_id(rule: str, item_id: str, occurrence: int) -> str:
    """Return an item-scoped identifier for one fired-rule occurrence."""
    return f"rule:{len(item_id)}:{item_id}:{occurrence}:{len(rule)}:{rule}"


def item_node_id(item_type: str, name: str, occurrence: int, total: int) -> str:
    """Preserve the legacy id for unique terminals and scope duplicates."""
    if total == 1:
        return f"{item_type}:{name}"
    return f"{item_type}:{len(name)}:{name}:{occurrence}"


def evidence_sort_key(evidence: EvidenceRecord) -> tuple[str, str, str, str]:
    return evidence.source_type, evidence.slug, evidence.rule_name, evidence.raw_value


def record_sort_key(record: ExplanationRecord) -> tuple[Any, ...]:
    return (
        record.item_type,
        record.item_name,
        record.confidence_derivation,
        tuple(sorted(record.fired_rules)),
        tuple(sorted(record.weakening_conditions)),
        record.curated_explanation,
        tuple(sorted(evidence_sort_key(evidence) for evidence in record.matched_evidence)),
    )


def add_evidence_node(
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    evidence: EvidenceRecord,
    evidence_id: str,
) -> None:
    """Add one evidence occurrence and its immediate slug edge."""
    nodes[evidence_id] = {
        "id": evidence_id,
        "type": "evidence",
        "name": f"{evidence.source_type}: {evidence.rule_name}",
        "source_type": evidence.source_type,
        "raw_value": evidence.raw_value,
        "rule_name": evidence.rule_name,
        "slug": evidence.slug,
    }
    slug_id = slug_node_id(evidence.slug)
    if slug_id not in nodes:
        nodes[slug_id] = {"id": slug_id, "type": "slug", "name": evidence.slug}
    edges.append({"source": evidence_id, "target": slug_id, "relation": "detected-by"})


def disconnected_terminals(
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
) -> list[str]:
    """Return sorted terminal ids that no evidence occurrence can reach."""
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge["source"], []).append(edge["target"])
    reachable = {node_id for node_id, node in nodes.items() if node["type"] == "evidence"}
    frontier = list(reachable)
    while frontier:
        source = frontier.pop()
        for target in adjacency.get(source, []):
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    return sorted(
        node_id for node_id, node in nodes.items() if node["type"] in TERMINAL_NODE_TYPES and node_id not in reachable
    )


def finalize_dag(nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    """Deduplicate and canonicalize edges, then attach reachability diagnostics."""
    unique = {(edge["source"], edge["target"], edge["relation"]): edge for edge in edges}
    canonical_edges = [unique[key] for key in sorted(unique)]
    disconnected = disconnected_terminals(nodes, canonical_edges)
    return {
        "nodes": list(nodes.values()),
        "edges": canonical_edges,
        "schema_version": 1,
        "provenance_complete": not disconnected,
        "disconnected_terminals": disconnected,
    }
