"""One-defect network YAMLs: every loader validation branch, pinned.

The corrected 2026-06 mutation sweep (validation/mutation-gate.md)
showed its largest surviving cluster in the network loader's validation
and warning branches: the behavior suites load either the shipped YAML
(always valid) or wholesale-malformed shapes (the fuzz suite), so the
individual boundary comparisons and warning set-operations in between
were never pinned. Each test here loads a minimal network that is valid
except for exactly one defect and asserts the specific rejection, with
boundary values chosen to kill comparison-flip mutants (0.0 and 1.0 sit
exactly on the open-interval bounds). The warning tests pin the
group-absence hygiene both ways: the shipped network loads silently,
and a deliberately-uncovered group warns by name.

Part of the mutation kill-set (mutation.toml); keep it fast.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
import yaml

from recon_tool.bayesian import load_network


def _spec(**node_overrides: Any) -> dict[str, Any]:
    """A minimal valid two-node network; override fields on the second node."""
    node: dict[str, Any] = {
        "name": "child",
        "description": "child node",
        "prior": 0.3,
        "evidence": [{"slug": "marker", "likelihood": [0.8, 0.1]}],
    }
    node.update(node_overrides)
    return {"version": 1, "nodes": [{"name": "root", "description": "root node", "prior": 0.5}, node]}


def _load(tmp_path: Path, spec: dict[str, Any]):
    p = tmp_path / "net.yaml"
    p.write_text(yaml.safe_dump(spec), encoding="utf-8")
    return load_network(p)


def _rejects(tmp_path: Path, spec: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        _load(tmp_path, spec)


class TestPriorAndCptValidation:
    def test_prior_must_be_numeric(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _spec(prior="high"), "requires numeric 'prior'")

    @pytest.mark.parametrize("bad", [0.0, 1.0, -0.2, 1.5, 1.9, -0.5])
    def test_prior_open_interval_boundaries(self, tmp_path: Path, bad: float) -> None:
        # 0.0 / 1.0 sit on the bounds (a < flipped to <= accepts them); the
        # well-outside 1.9 / -0.5 kill a bound-constant mutation that widens
        # the interval (e.g. ``< 1.0`` -> ``< 2.0`` or ``0.0 <`` -> ``-1.0 <``).
        _rejects(tmp_path, _spec(prior=bad), r"outside \(0, 1\)")

    def test_parents_require_cpt(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _spec(prior=None, parents=["root"]), "requires 'cpt'")

    @pytest.mark.parametrize("bad", [0.0, 1.0, 1.9, -0.5])
    def test_cpt_values_open_interval(self, tmp_path: Path, bad: float) -> None:
        spec = _spec(prior=None, parents=["root"], cpt={"root=present": bad, "root=absent": 0.2})
        _rejects(tmp_path, spec, r"outside \(0, 1\)")

    def test_cpt_entries_must_be_str_to_float(self, tmp_path: Path) -> None:
        spec = _spec(prior=None, parents=["root"], cpt={"root=present": "high", "root=absent": 0.2})
        _rejects(tmp_path, spec, "str→float")

    def test_cpt_missing_assignment(self, tmp_path: Path) -> None:
        spec = _spec(prior=None, parents=["root"], cpt={"root=present": 0.9})
        _rejects(tmp_path, spec, "CPT missing keys")

    def test_cpt_unexpected_assignment(self, tmp_path: Path) -> None:
        spec = _spec(
            prior=None,
            parents=["root"],
            cpt={"root=present": 0.9, "root=absent": 0.2, "root=maybe": 0.5},
        )
        _rejects(tmp_path, spec, "unexpected keys")


class TestEvidenceValidation:
    def test_evidence_must_be_list(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _spec(evidence={"slug": "x"}), "'evidence' must be a list")

    def test_evidence_entries_must_be_mappings(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _spec(evidence=["marker"]), "must be mappings")

    def test_exactly_one_of_slug_or_signal(self, tmp_path: Path) -> None:
        both = [{"slug": "a", "signal": "b", "likelihood": [0.8, 0.1]}]
        neither = [{"likelihood": [0.8, 0.1]}]
        _rejects(tmp_path, _spec(evidence=both), "exactly one")
        _rejects(tmp_path, _spec(evidence=neither), "exactly one")

    def test_empty_name_rejected(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _spec(evidence=[{"slug": "", "likelihood": [0.8, 0.1]}]), "missing name")

    def test_likelihood_must_be_pair(self, tmp_path: Path) -> None:
        _rejects(
            tmp_path,
            _spec(evidence=[{"slug": "m", "likelihood": [0.8]}]),
            r"must be \[float, float\]",
        )

    @pytest.mark.parametrize(
        "pair", [[0.0, 0.1], [1.0, 0.1], [0.8, 0.0], [0.8, 1.0], [1.9, 0.1], [-0.5, 0.1], [0.8, 1.9], [0.8, -0.5]]
    )
    def test_likelihood_open_interval_boundaries(self, tmp_path: Path, pair: list[float]) -> None:
        # Boundary values catch a strict/loose comparison flip; the
        # well-outside 1.9 / -0.5 (per element) catch a widened bound constant.
        _rejects(
            tmp_path,
            _spec(evidence=[{"slug": "m", "likelihood": pair}]),
            r"strictly in \(0, 1\)",
        )

    @pytest.mark.parametrize("group", ["", 5])
    def test_group_must_be_nonempty_string(self, tmp_path: Path, group: Any) -> None:
        _rejects(
            tmp_path,
            _spec(evidence=[{"slug": "m", "likelihood": [0.8, 0.1], "group": group}]),
            "non-empty string",
        )


class TestNodeShapeValidation:
    def test_node_must_be_mapping(self, tmp_path: Path) -> None:
        spec = {"version": 1, "nodes": ["root"]}
        _rejects(tmp_path, spec, "must be a mapping")

    def test_name_required(self, tmp_path: Path) -> None:
        spec = {"version": 1, "nodes": [{"description": "x", "prior": 0.5}]}
        _rejects(tmp_path, spec, "missing required 'name'")

    def test_duplicate_names_rejected(self, tmp_path: Path) -> None:
        spec = _spec(name="root")
        _rejects(tmp_path, spec, "duplicate node name")

    def test_description_must_be_string(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _spec(description=5), "'description' must be a string")

    def test_parents_must_be_string_list(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _spec(prior=None, parents="root"), "list of strings")

    def test_missingness_enum(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _spec(missingness="adversarial"), "'hideable' or 'declarative'")


class TestTopologyValidation:
    def test_unknown_parent(self, tmp_path: Path) -> None:
        spec = _spec(prior=None, parents=["ghost"], cpt={"ghost=present": 0.9, "ghost=absent": 0.2})
        _rejects(tmp_path, spec, "parent 'ghost' not defined")

    def test_cycle_detected(self, tmp_path: Path) -> None:
        spec = {
            "version": 1,
            "nodes": [
                {
                    "name": "a",
                    "description": "a",
                    "parents": ["b"],
                    "cpt": {"b=present": 0.9, "b=absent": 0.2},
                },
                {
                    "name": "b",
                    "description": "b",
                    "parents": ["a"],
                    "cpt": {"a=present": 0.9, "a=absent": 0.2},
                },
            ],
        }
        _rejects(tmp_path, spec, "cycle detected")


def _declarative(group_absence: Any, *, second_group: bool = True) -> dict[str, Any]:
    evidence = [
        {"signal": "g1a", "likelihood": [0.9, 0.1], "group": "gx"},
        {"signal": "g1b", "likelihood": [0.6, 0.2], "group": "gx"},
    ]
    if second_group:
        evidence.append({"signal": "g2a", "likelihood": [0.7, 0.2], "group": "gy"})
    node: dict[str, Any] = {
        "name": "decl",
        "description": "declarative node",
        "prior": 0.4,
        "missingness": "declarative",
        "evidence": evidence,
    }
    if group_absence is not None:
        node["group_absence"] = group_absence
    return {"version": 1, "nodes": [node]}


class TestGroupAbsenceValidation:
    def test_only_valid_on_declarative(self, tmp_path: Path) -> None:
        spec = _spec(
            evidence=[{"slug": "m", "likelihood": [0.8, 0.1], "group": "g"}],
            group_absence={"g": [0.2, 0.8]},
        )
        _rejects(tmp_path, spec, "only valid on declarative")

    def test_must_be_mapping(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _declarative([0.2, 0.8]), "must be a mapping")

    def test_unknown_group_rejected(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _declarative({"gz": [0.2, 0.8]}), "has no bindings")

    def test_pair_shape(self, tmp_path: Path) -> None:
        _rejects(tmp_path, _declarative({"gx": [0.2]}), r"must be \[float, float\]")

    @pytest.mark.parametrize("pair", [[0.0, 0.8], [0.2, 1.0], [1.9, 0.8], [0.2, -0.5]])
    def test_pair_open_interval_boundaries(self, tmp_path: Path, pair: list[float]) -> None:
        _rejects(tmp_path, _declarative({"gx": pair}), r"in \(0, 1\)")


class TestGroupAbsenceWarnings:
    def test_shipped_network_loads_without_group_absence_warnings(self, caplog: pytest.LogCaptureFixture) -> None:
        # The shipped network's declarative node covers its group, and its
        # hideable grouped nodes must warn about nothing. A spurious
        # warning here means the uncovered-group set arithmetic broke.
        with caplog.at_level(logging.WARNING, logger="recon_tool.bayesian"):
            load_network()
        assert not [r for r in caplog.records if "uninformative" in r.getMessage()]

    def test_uncovered_group_warns_by_name(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        # gx is covered, gy is not: the warning must name gy and only gy.
        with caplog.at_level(logging.WARNING, logger="recon_tool.bayesian"):
            _load(tmp_path, _declarative({"gx": [0.2, 0.8]}))
        messages = [r.getMessage() for r in caplog.records if "no group_absence entry" in r.getMessage()]
        assert len(messages) == 1
        assert "gy" in messages[0]
        assert "gx" not in messages[0].split("groups", 1)[1].split("have", 1)[0]

    def test_declarative_grouped_without_any_group_absence_warns(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="recon_tool.bayesian"):
            _load(tmp_path, _declarative(None))
        messages = [r.getMessage() for r in caplog.records if "no group_absence" in r.getMessage()]
        assert len(messages) == 1
        assert "gx" in messages[0]
        assert "gy" in messages[0]

    def test_valid_declarative_network_round_trips(self, tmp_path: Path) -> None:
        net = _load(tmp_path, _declarative({"gx": [0.2, 0.8], "gy": [0.3, 0.7]}))
        node = net.get("decl")
        assert node.missingness == "declarative"
        assert sorted(g for g, _, _ in node.group_absence) == ["gx", "gy"]
