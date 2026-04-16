"""Tests for v0.9.3 explanation DAG serialization."""

from __future__ import annotations

from recon_tool.explanation import build_explanation_dag
from recon_tool.models import EvidenceRecord, ExplanationRecord


def _ev(source_type: str, slug: str, rule: str = "test-rule", value: str = "raw") -> EvidenceRecord:
    return EvidenceRecord(
        source_type=source_type,
        raw_value=value,
        rule_name=rule,
        slug=slug,
    )


def _rec(
    item_type: str,
    name: str,
    matched: tuple[EvidenceRecord, ...] = (),
    fired: tuple[str, ...] = (),
    weakening: tuple[str, ...] = (),
) -> ExplanationRecord:
    return ExplanationRecord(
        item_name=name,
        item_type=item_type,
        matched_evidence=matched,
        fired_rules=fired,
        confidence_derivation="",
        weakening_conditions=weakening,
        curated_explanation="",
    )


# ── Shape ───────────────────────────────────────────────────────────────


class TestShape:
    def test_empty_input_returns_empty_dag(self):
        out = build_explanation_dag([], ())
        assert out == {"nodes": [], "edges": [], "schema_version": 1}

    def test_returns_nodes_edges_schema_version(self):
        out = build_explanation_dag([], ())
        assert set(out.keys()) == {"nodes", "edges", "schema_version"}

    def test_schema_version_is_1(self):
        out = build_explanation_dag([], ())
        assert out["schema_version"] == 1


# ── Node types ─────────────────────────────────────────────────────────


class TestNodeTypes:
    def test_evidence_seeds_evidence_and_slug_nodes(self):
        ev = _ev("TXT", "microsoft365")
        out = build_explanation_dag([], (ev,))
        types = {n["type"] for n in out["nodes"]}
        assert "evidence" in types
        assert "slug" in types

    def test_signal_record_produces_signal_node(self):
        rec = _rec("signal", "Edge Layering")
        out = build_explanation_dag([rec], ())
        types = {n["type"] for n in out["nodes"]}
        assert "signal" in types
        names = {n["name"] for n in out["nodes"] if n["type"] == "signal"}
        assert "Edge Layering" in names

    def test_insight_record_produces_insight_node(self):
        rec = _rec("insight", "Federated identity observed")
        out = build_explanation_dag([rec], ())
        types = {n["type"] for n in out["nodes"]}
        assert "insight" in types

    def test_observation_record_produces_observation_node(self):
        rec = _rec("observation", "DMARC policy is reject")
        out = build_explanation_dag([rec], ())
        types = {n["type"] for n in out["nodes"]}
        assert "observation" in types

    def test_confidence_record_produces_confidence_node(self):
        rec = _rec("confidence", "Overall Confidence")
        out = build_explanation_dag([rec], ())
        types = {n["type"] for n in out["nodes"]}
        assert "confidence" in types

    def test_rule_node_added_for_fired_rules(self):
        rec = _rec("signal", "X", fired=("rule-a",))
        out = build_explanation_dag([rec], ())
        rules = [n for n in out["nodes"] if n["type"] == "rule"]
        assert len(rules) == 1
        assert rules[0]["name"] == "rule-a"


# ── Edges ──────────────────────────────────────────────────────────────


class TestEdges:
    def test_evidence_to_slug_detected_by(self):
        ev = _ev("TXT", "microsoft365")
        out = build_explanation_dag([], (ev,))
        relations = {e["relation"] for e in out["edges"]}
        assert "detected-by" in relations

    def test_slug_to_signal_contributes_to(self):
        ev = _ev("TXT", "cloudflare")
        rec = _rec("signal", "Edge Layering", matched=(ev,))
        out = build_explanation_dag([rec], (ev,))
        relations = {e["relation"] for e in out["edges"]}
        assert "contributes-to" in relations

    def test_rule_to_item_fired(self):
        rec = _rec("signal", "S", fired=("rule-x",))
        out = build_explanation_dag([rec], ())
        relations = {e["relation"] for e in out["edges"]}
        assert "fired" in relations

    def test_edges_are_deduped(self):
        """Two evidence records for the same slug shouldn't produce
        duplicate slug → item edges."""
        ev1 = _ev("TXT", "microsoft365", rule="r1")
        ev2 = _ev("MX", "microsoft365", rule="r2")
        rec = _rec("signal", "S", matched=(ev1, ev2))
        out = build_explanation_dag([rec], (ev1, ev2))
        # Only one "slug:microsoft365 → signal:S" edge
        contribs = [
            e for e in out["edges"]
            if e["source"] == "slug:microsoft365"
            and e["target"] == "signal:S"
            and e["relation"] == "contributes-to"
        ]
        assert len(contribs) == 1


# ── Terminal reachability invariant ─────────────────────────────────────


class TestTerminalReachability:
    def test_signal_terminal_reachable_from_evidence(self):
        """Every signal node must be reachable from at least one
        evidence node via a short path."""
        ev = _ev("TXT", "okta")
        rec = _rec("signal", "Identity Stack", matched=(ev,))
        out = build_explanation_dag([rec], (ev,))

        # Walk: evidence → slug → signal
        edges_by_src: dict[str, list[dict[str, object]]] = {}
        for e in out["edges"]:
            edges_by_src.setdefault(e["source"], []).append(e)

        evidence_ids = {n["id"] for n in out["nodes"] if n["type"] == "evidence"}
        signal_id = "signal:Identity Stack"

        # BFS from each evidence node, see if we reach the signal
        reachable = False
        for start in evidence_ids:
            frontier: list[str] = [start]
            visited: set[str] = {start}
            while frontier:
                node = frontier.pop()
                if node == signal_id:
                    reachable = True
                    break
                for e in edges_by_src.get(node, []):
                    tgt = e["target"]
                    if isinstance(tgt, str) and tgt not in visited:
                        visited.add(tgt)
                        frontier.append(tgt)
            if reachable:
                break
        assert reachable


# ── Metadata preservation ──────────────────────────────────────────────


class TestMetadata:
    def test_signal_carries_confidence_derivation(self):
        rec = ExplanationRecord(
            item_name="S",
            item_type="signal",
            matched_evidence=(),
            fired_rules=(),
            confidence_derivation="derivation text",
            weakening_conditions=("weaken1",),
            curated_explanation="curated",
        )
        out = build_explanation_dag([rec], ())
        signal = next(n for n in out["nodes"] if n["type"] == "signal")
        assert signal["confidence_derivation"] == "derivation text"
        assert signal["weakening_conditions"] == ["weaken1"]
        assert signal["curated_explanation"] == "curated"

    def test_evidence_carries_raw_value(self):
        ev = _ev("TXT", "x", rule="r", value="the raw txt value")
        out = build_explanation_dag([], (ev,))
        evidence = next(n for n in out["nodes"] if n["type"] == "evidence")
        assert evidence["raw_value"] == "the raw txt value"
        assert evidence["source_type"] == "TXT"
        assert evidence["slug"] == "x"


# ── Determinism ─────────────────────────────────────────────────────────


class TestDeterminism:
    def test_same_input_produces_same_output(self):
        ev = _ev("TXT", "x")
        rec = _rec("signal", "S", matched=(ev,), fired=("r",))
        a = build_explanation_dag([rec], (ev,))
        b = build_explanation_dag([rec], (ev,))
        assert a == b
