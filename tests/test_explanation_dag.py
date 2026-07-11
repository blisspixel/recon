"""Tests for explanation DAG serialization."""

from __future__ import annotations

from recon_tool.explanation import build_explanation_dag, explain_confidence
from recon_tool.models import ConfidenceLevel, EvidenceRecord, ExplanationRecord, SourceResult


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
        assert out == {
            "nodes": [],
            "edges": [],
            "schema_version": 1,
            "provenance_complete": True,
            "disconnected_terminals": [],
        }

    def test_returns_exact_top_level_shape(self):
        out = build_explanation_dag([], ())
        assert set(out) == {
            "nodes",
            "edges",
            "schema_version",
            "provenance_complete",
            "disconnected_terminals",
        }

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

    def test_evidence_to_matching_rule_preserves_full_path(self):
        ev = _ev("TXT", "microsoft365", rule="tenant-fingerprint")
        rec = _rec(
            "signal",
            "Tenant observed",
            matched=(ev,),
            fired=("tenant-fingerprint",),
        )

        out = build_explanation_dag([rec], (ev,))

        evidence_id = next(n["id"] for n in out["nodes"] if n["type"] == "evidence")
        rule_id = next(n["id"] for n in out["nodes"] if n["type"] == "rule")
        assert {"source": evidence_id, "target": rule_id, "relation": "matched-rule"} in out["edges"]
        assert {
            "source": rule_id,
            "target": "signal:Tenant observed",
            "relation": "fired",
        } in out["edges"]
        assert out["provenance_complete"] is True

    def test_multiple_rules_link_only_their_exact_evidence(self):
        first = _ev("TXT", "first", rule="rule-a", value="first-value")
        second = _ev("MX", "second", rule="rule-b", value="second-value")
        rec = _rec(
            "signal",
            "Composite",
            matched=(first, second),
            fired=("rule-a", "rule-b"),
        )

        out = build_explanation_dag([rec], (first, second))

        evidence_ids = {node["raw_value"]: node["id"] for node in out["nodes"] if node["type"] == "evidence"}
        rule_ids = {node["name"]: node["id"] for node in out["nodes"] if node["type"] == "rule"}
        matched_edges = {
            (edge["source"], edge["target"]) for edge in out["edges"] if edge["relation"] == "matched-rule"
        }
        assert matched_edges == {
            (evidence_ids["first-value"], rule_ids["rule-a"]),
            (evidence_ids["second-value"], rule_ids["rule-b"]),
        }

    def test_edges_are_deduped(self):
        """Two evidence records for the same slug shouldn't produce
        duplicate slug → item edges."""
        ev1 = _ev("TXT", "microsoft365", rule="r1")
        ev2 = _ev("MX", "microsoft365", rule="r2")
        rec = _rec("signal", "S", matched=(ev1, ev2))
        out = build_explanation_dag([rec], (ev1, ev2))
        # Only one "slug:microsoft365 → signal:S" edge
        contribs = [
            e
            for e in out["edges"]
            if e["source"] == "slug:microsoft365" and e["target"] == "signal:S" and e["relation"] == "contributes-to"
        ]
        assert len(contribs) == 1


class TestEvidenceOccurrences:
    def test_matched_evidence_reuses_global_occurrence_id(self):
        unrelated = _ev("MX", "proofpoint", rule="gateway", value="mx.example")
        matched = _ev("TXT", "microsoft365", rule="tenant", value="ms=tenant")
        rec = _rec("signal", "Tenant", matched=(matched,))

        out = build_explanation_dag([rec], (unrelated, matched))

        evidence = [node for node in out["nodes"] if node["type"] == "evidence"]
        assert len(evidence) == 2
        matched_node = next(node for node in evidence if node["raw_value"] == "ms=tenant")
        assert matched_node["id"].endswith(":1")

    def test_equal_occurrences_remain_distinct_without_local_id_collisions(self):
        unrelated = _ev("NS", "cloudflare", rule="nameserver", value="ns1.example")
        first = _ev("TXT", "microsoft365", rule="tenant", value="first")
        second = _ev("TXT", "microsoft365", rule="tenant", value="second")
        rec = _rec("signal", "Tenant", matched=(second, first))

        out = build_explanation_dag([rec], (unrelated, first, second))

        evidence = [node for node in out["nodes"] if node["type"] == "evidence"]
        assert len(evidence) == 3
        assert {node["raw_value"]: node["id"] for node in evidence} == {
            "ns1.example": "evidence:NS:cloudflare:nameserver:0",
            "first": "evidence:TXT:microsoft365:tenant:1",
            "second": "evidence:TXT:microsoft365:tenant:2",
        }


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
        assert out["provenance_complete"] is True
        assert out["disconnected_terminals"] == []

    def test_disconnected_terminals_are_sorted_and_mark_incomplete(self):
        connected_evidence = _ev("TXT", "okta", rule="identity-rule")
        connected = _rec(
            "signal",
            "Connected",
            matched=(connected_evidence,),
            fired=("identity-rule",),
        )
        disconnected_z = _rec("insight", "Zulu")
        disconnected_a = _rec("observation", "Alpha")

        out = build_explanation_dag(
            [disconnected_z, connected, disconnected_a],
            (connected_evidence,),
        )

        assert out["provenance_complete"] is False
        assert out["disconnected_terminals"] == ["insight:Zulu", "observation:Alpha"]

    def test_no_evidence_marks_terminal_disconnected(self):
        out = build_explanation_dag([_rec("confidence", "Overall Confidence")], ())

        assert out["provenance_complete"] is False
        assert out["disconnected_terminals"] == ["confidence:Overall Confidence"]

    def test_confidence_rules_do_not_claim_unretained_source_lineage(self):
        tenant_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        winning_evidence = _ev(
            "HTTP",
            "microsoft365",
            rule="oidc-tenant",
            value=f"tenant_id={tenant_id}",
        )
        results = [
            SourceResult(
                source_name="oidc_discovery",
                tenant_id=tenant_id,
                evidence=(winning_evidence,),
            ),
            SourceResult(source_name="dns_records", error="timeout"),
        ]
        record = explain_confidence(
            results,
            ConfidenceLevel.LOW,
            ConfidenceLevel.LOW,
            ConfidenceLevel.LOW,
        )

        out = build_explanation_dag([record], (winning_evidence,))

        rule_nodes = {node["name"]: node["id"] for node in out["nodes"] if node["type"] == "rule"}
        assert "Source: oidc_discovery (success)" in rule_nodes
        assert "Source: dns_records (failed)" in rule_nodes
        assert all(edge["relation"] != "matched-rule" for edge in out["edges"])
        assert {
            "source": "slug:microsoft365",
            "target": "confidence:Overall Confidence",
            "relation": "contributes-to",
        } in out["edges"]
        assert out["provenance_complete"] is True
        assert out["disconnected_terminals"] == []

    def test_shared_rule_label_does_not_cross_connect_terminals(self):
        evidence = _ev("TXT", "okta", rule="identity-rule")
        supported = _rec(
            "signal",
            "Supported",
            matched=(evidence,),
            fired=("identity-rule",),
        )
        unsupported = _rec("observation", "Unsupported", fired=("identity-rule",))

        out = build_explanation_dag([supported, unsupported], (evidence,))

        rule_nodes = [node for node in out["nodes"] if node["type"] == "rule"]
        assert len(rule_nodes) == 2
        assert len({node["id"] for node in rule_nodes}) == 2
        assert out["provenance_complete"] is False
        assert out["disconnected_terminals"] == ["observation:Unsupported"]

    def test_colon_bearing_rule_components_cannot_collide(self):
        first_evidence = _ev("TXT", "first", rule="B:0:C", value="first")
        second_evidence = _ev("MX", "second", rule="C", value="second")
        first = _rec(
            "signal",
            "A",
            matched=(first_evidence,),
            fired=("B:0:C",),
        )
        second = _rec(
            "signal",
            "A:0:B",
            matched=(second_evidence,),
            fired=("C",),
        )

        out = build_explanation_dag([first, second], (first_evidence, second_evidence))

        rule_nodes = [node for node in out["nodes"] if node["type"] == "rule"]
        assert len(rule_nodes) == 2
        assert len({node["id"] for node in rule_nodes}) == 2
        for rule_node in rule_nodes:
            inbound = [
                edge
                for edge in out["edges"]
                if edge["target"] == rule_node["id"] and edge["relation"] == "matched-rule"
            ]
            outbound = [
                edge for edge in out["edges"] if edge["source"] == rule_node["id"] and edge["relation"] == "fired"
            ]
            assert len(inbound) == 1
            assert len(outbound) == 1
        assert out == build_explanation_dag([first, second], (first_evidence, second_evidence))


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

    def test_evidence_permutation_produces_the_same_graph(self) -> None:
        first = _ev("TXT", "alpha", rule="alpha-rule", value="a")
        second = _ev("MX", "beta", rule="beta-rule", value="b")
        rec = _rec(
            "signal",
            "Stable",
            matched=(first, second),
            fired=("alpha-rule", "beta-rule"),
        )

        forward = build_explanation_dag([rec], (first, second))
        reverse = build_explanation_dag([rec], (second, first))

        assert forward == reverse

    def test_duplicate_terminal_names_keep_independent_occurrences(self) -> None:
        first = _ev("TXT", "first", rule="first-rule", value="a")
        second = _ev("MX", "second", rule="second-rule", value="b")
        records = [
            _rec("observation", "same", matched=(first,), fired=("first-rule",)),
            _rec("observation", "same", matched=(second,), fired=("second-rule",)),
        ]

        out = build_explanation_dag(records, (second, first))
        terminals = [node for node in out["nodes"] if node["type"] == "observation"]

        assert len(terminals) == 2
        assert len({node["id"] for node in terminals}) == 2
        for terminal in terminals:
            inbound_rules = [
                edge
                for edge in out["edges"]
                if edge["target"] == terminal["id"] and edge["relation"] == "fired"
            ]
            assert len(inbound_rules) == 1
