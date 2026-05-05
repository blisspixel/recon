"""Adversarial schema and inference fuzzing for the v1.9 layer.

Each test feeds the loader or the inference engine inputs designed to
either crash a naive implementation or produce silently wrong results.
The contract is: every input either succeeds with a well-formed network
/ inference result, or raises a ``ValueError`` with a useful message.
We never want a Python traceback escaping into operator output.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest
import yaml

from recon_tool.bayesian import (
    BayesianNetwork,
    infer,
    load_network,
    load_priors_override,
)


def _write(path: Path, spec: object) -> Path:
    path.write_text(yaml.safe_dump(spec), encoding="utf-8")
    return path


# ── Adversarial schema inputs ─────────────────────────────────────────


class TestAdversarialSchema:
    def test_empty_yaml(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.yaml"
        p.write_text("", encoding="utf-8")
        with pytest.raises(ValueError, match="expected mapping"):
            load_network(p)

    def test_yaml_null_top(self, tmp_path: Path) -> None:
        p = tmp_path / "null.yaml"
        p.write_text("~", encoding="utf-8")
        with pytest.raises(ValueError, match="expected mapping"):
            load_network(p)

    def test_yaml_string_top(self, tmp_path: Path) -> None:
        p = tmp_path / "str.yaml"
        p.write_text("hello", encoding="utf-8")
        with pytest.raises(ValueError, match="expected mapping"):
            load_network(p)

    def test_no_nodes_field(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "x.yaml", {"version": 1})
        with pytest.raises(ValueError, match="non-empty list"):
            load_network(p)

    def test_empty_nodes_list(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "x.yaml", {"version": 1, "nodes": []})
        with pytest.raises(ValueError, match="non-empty list"):
            load_network(p)

    def test_nodes_not_a_list(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "x.yaml", {"version": 1, "nodes": {"foo": "bar"}})
        with pytest.raises(ValueError, match="non-empty list"):
            load_network(p)

    def test_node_not_a_mapping(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "x.yaml", {"version": 1, "nodes": ["a", "b"]})
        with pytest.raises(ValueError, match="must be a mapping"):
            load_network(p)

    def test_node_missing_name(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "x.yaml", {"version": 1, "nodes": [{"description": "x", "prior": 0.5}]})
        with pytest.raises(ValueError, match="missing required 'name'"):
            load_network(p)

    def test_node_empty_name(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "x.yaml", {"version": 1, "nodes": [{"name": "", "description": "x", "prior": 0.5}]})
        with pytest.raises(ValueError, match="missing required 'name'"):
            load_network(p)

    def test_duplicate_node_names(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "dup.yaml",
            {
                "version": 1,
                "nodes": [
                    {"name": "a", "description": "x", "prior": 0.5},
                    {"name": "a", "description": "y", "prior": 0.6},
                ],
            },
        )
        with pytest.raises(ValueError, match="duplicate node name"):
            load_network(p)

    def test_parents_not_a_list(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {
                "version": 1,
                "nodes": [{"name": "a", "description": "x", "parents": "not-a-list", "cpt": {}}],
            },
        )
        with pytest.raises(ValueError, match="'parents' must be a list"):
            load_network(p)

    def test_parents_with_non_string_entry(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {
                "version": 1,
                "nodes": [{"name": "a", "description": "x", "parents": [123], "cpt": {}}],
            },
        )
        with pytest.raises(ValueError, match="'parents' must be a list of strings"):
            load_network(p)

    def test_negative_prior(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "x.yaml", {"version": 1, "nodes": [{"name": "a", "description": "x", "prior": -0.1}]})
        with pytest.raises(ValueError, match="outside"):
            load_network(p)

    def test_prior_as_string(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "x.yaml", {"version": 1, "nodes": [{"name": "a", "description": "x", "prior": "high"}]})
        with pytest.raises(ValueError, match="numeric 'prior'"):
            load_network(p)

    def test_cpt_value_out_of_range(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {
                "version": 1,
                "nodes": [
                    {"name": "a", "description": "x", "prior": 0.5},
                    {
                        "name": "b",
                        "description": "x",
                        "parents": ["a"],
                        "cpt": {"a=present": 1.5, "a=absent": 0.5},
                    },
                ],
            },
        )
        with pytest.raises(ValueError, match="cpt value"):
            load_network(p)

    def test_cpt_value_as_string(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {
                "version": 1,
                "nodes": [
                    {"name": "a", "description": "x", "prior": 0.5},
                    {
                        "name": "b",
                        "description": "x",
                        "parents": ["a"],
                        "cpt": {"a=present": "yes", "a=absent": 0.5},
                    },
                ],
            },
        )
        with pytest.raises(ValueError, match="cpt entries must be"):
            load_network(p)

    def test_cpt_extra_keys(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {
                "version": 1,
                "nodes": [
                    {"name": "a", "description": "x", "prior": 0.5},
                    {
                        "name": "b",
                        "description": "x",
                        "parents": ["a"],
                        "cpt": {"a=present": 0.3, "a=absent": 0.5, "extra=key": 0.1},
                    },
                ],
            },
        )
        with pytest.raises(ValueError, match="unexpected keys"):
            load_network(p)

    def test_evidence_neither_slug_nor_signal(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {
                "version": 1,
                "nodes": [
                    {"name": "a", "description": "x", "prior": 0.5, "evidence": [{"likelihood": [0.5, 0.5]}]},
                ],
            },
        )
        with pytest.raises(ValueError, match="exactly one of 'slug' / 'signal'"):
            load_network(p)

    def test_evidence_likelihood_wrong_length(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {
                "version": 1,
                "nodes": [
                    {"name": "a", "description": "x", "prior": 0.5, "evidence": [{"slug": "x", "likelihood": [0.5]}]},
                ],
            },
        )
        with pytest.raises(ValueError, match="must be"):
            load_network(p)

    def test_evidence_likelihood_with_strings(self, tmp_path: Path) -> None:
        node = {
            "name": "a",
            "description": "x",
            "prior": 0.5,
            "evidence": [{"slug": "x", "likelihood": ["high", "low"]}],
        }
        p = _write(tmp_path / "x.yaml", {"version": 1, "nodes": [node]})
        with pytest.raises(ValueError, match="\\[float, float\\]"):
            load_network(p)

    def test_evidence_likelihood_negative(self, tmp_path: Path) -> None:
        node = {
            "name": "a",
            "description": "x",
            "prior": 0.5,
            "evidence": [{"slug": "x", "likelihood": [-0.1, 0.5]}],
        }
        p = _write(tmp_path / "x.yaml", {"version": 1, "nodes": [node]})
        with pytest.raises(ValueError, match="strictly in"):
            load_network(p)

    def test_evidence_not_a_list(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {"version": 1, "nodes": [{"name": "a", "description": "x", "prior": 0.5, "evidence": "no"}]},
        )
        with pytest.raises(ValueError, match="'evidence' must be a list"):
            load_network(p)

    def test_self_loop_cycle(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {
                "version": 1,
                "nodes": [
                    {
                        "name": "a",
                        "description": "x",
                        "parents": ["a"],
                        "cpt": {"a=present": 0.5, "a=absent": 0.5},
                    }
                ],
            },
        )
        with pytest.raises(ValueError, match="cycle detected"):
            load_network(p)

    def test_three_node_cycle(self, tmp_path: Path) -> None:
        p = _write(
            tmp_path / "x.yaml",
            {
                "version": 1,
                "nodes": [
                    {"name": "a", "description": "x", "parents": ["c"], "cpt": {"c=present": 0.5, "c=absent": 0.5}},
                    {"name": "b", "description": "x", "parents": ["a"], "cpt": {"a=present": 0.5, "a=absent": 0.5}},
                    {"name": "c", "description": "x", "parents": ["b"], "cpt": {"b=present": 0.5, "b=absent": 0.5}},
                ],
            },
        )
        with pytest.raises(ValueError, match="cycle detected"):
            load_network(p)

    def test_unicode_node_names_accepted(self, tmp_path: Path) -> None:
        # Unicode names should be accepted (no policy against them in v1.9).
        p = _write(
            tmp_path / "u.yaml",
            {"version": 1, "nodes": [{"name": "café", "description": "x", "prior": 0.5}]},
        )
        net = load_network(p)
        assert any(n.name == "café" for n in net.nodes)

    def test_long_node_names_accepted(self, tmp_path: Path) -> None:
        long_name = "a" * 500
        p = _write(
            tmp_path / "long.yaml",
            {"version": 1, "nodes": [{"name": long_name, "description": "x", "prior": 0.5}]},
        )
        net = load_network(p)
        assert any(n.name == long_name for n in net.nodes)


# ── Adversarial inference inputs ──────────────────────────────────────


@pytest.fixture
def shipped_net() -> BayesianNetwork:
    return load_network()


class TestAdversarialInference:
    def test_empty_observed_iterables(self, shipped_net: BayesianNetwork) -> None:
        result = infer(shipped_net, [], [], priors_override={})
        assert len(result.posteriors) == len(shipped_net.nodes)

    def test_observed_with_unknown_slugs(self, shipped_net: BayesianNetwork) -> None:
        # Unknown slugs are silently ignored — no node has them as
        # evidence bindings, so they don't affect inference.
        result = infer(
            shipped_net,
            observed_slugs=["fake-1", "fake-2", "definitely-not-real"],
            observed_signals=["fake-signal"],
            priors_override={},
        )
        # Posteriors should equal priors (no evidence applied).
        for p in result.posteriors:
            node = shipped_net.get(p.name)
            if node.prior is not None:
                assert abs(p.posterior - node.prior) < 1e-3

    def test_observed_iterables_can_be_generators(self, shipped_net: BayesianNetwork) -> None:
        # Should accept any Iterable, not just lists.
        result = infer(
            shipped_net,
            observed_slugs=(s for s in ["microsoft365"]),
            observed_signals=iter(["dmarc_reject"]),
            priors_override={},
        )
        m365 = next(p for p in result.posteriors if p.name == "m365_tenant")
        assert m365.posterior > 0.5  # significantly above 0.30 prior

    def test_duplicate_observed_slugs(self, shipped_net: BayesianNetwork) -> None:
        # Passing a duplicate should not double-count it (set semantics
        # internally).
        single = infer(shipped_net, ["microsoft365"], [], priors_override={})
        dup = infer(shipped_net, ["microsoft365", "microsoft365", "microsoft365"], [], priors_override={})
        s_m365 = next(p for p in single.posteriors if p.name == "m365_tenant")
        d_m365 = next(p for p in dup.posteriors if p.name == "m365_tenant")
        assert abs(s_m365.posterior - d_m365.posterior) < 1e-6

    def test_negative_conflict_count_treated_as_zero(self, shipped_net: BayesianNetwork) -> None:
        # The conflict count is supplied externally. Negative values
        # should not produce wider intervals than zero conflicts.
        zero = infer(shipped_net, ["microsoft365"], [], conflict_field_count=0, priors_override={})
        # Engine implementation: max(_MIN_N_EFF, ...) clamps. Negative
        # conflict count would inflate n_eff above the floor — verify
        # that doesn't break interval math.
        neg = infer(shipped_net, ["microsoft365"], [], conflict_field_count=-5, priors_override={})

        def width(r, name):
            p = next(p for p in r.posteriors if p.name == name)
            return p.interval_high - p.interval_low

        # Negative count just means more n_eff (tighter interval).
        # The thing we care about: no crash, no NaN.
        assert not math.isnan(width(neg, "m365_tenant"))
        assert width(neg, "m365_tenant") <= width(zero, "m365_tenant") + 1e-6

    def test_huge_conflict_count_does_not_crash(self, shipped_net: BayesianNetwork) -> None:
        result = infer(shipped_net, ["microsoft365"], [], conflict_field_count=10**9, priors_override={})
        for p in result.posteriors:
            assert not math.isnan(p.posterior)
            assert not math.isnan(p.interval_low)
            assert not math.isnan(p.interval_high)
            assert p.n_eff >= 4.0  # floor

    def test_priors_override_with_no_root_node_match(self, shipped_net: BayesianNetwork) -> None:
        # Override targeting a node that doesn't exist or isn't a root
        # is silently ignored.
        result = infer(shipped_net, [], [], priors_override={"nonexistent_node": 0.99})
        # All posteriors should equal priors as if no override given.
        baseline = infer(shipped_net, [], [], priors_override={})
        for p1, p2 in zip(result.posteriors, baseline.posteriors, strict=True):
            assert abs(p1.posterior - p2.posterior) < 1e-9


# ── Adversarial priors override files ─────────────────────────────────


class TestAdversarialPriorsOverride:
    def test_yaml_with_only_comments(self, tmp_path: Path) -> None:
        p = tmp_path / "comments.yaml"
        p.write_text("# nothing useful\n# nope\n", encoding="utf-8")
        out = load_priors_override(p)
        assert out == {}

    def test_priors_with_string_keys_only(self, tmp_path: Path) -> None:
        p = tmp_path / "good.yaml"
        p.write_text(yaml.safe_dump({"node_a": 0.7, "node_b": 0.3}), encoding="utf-8")
        out = load_priors_override(p)
        assert out == {"node_a": 0.7, "node_b": 0.3}

    def test_priors_with_int_keys_skipped(self, tmp_path: Path) -> None:
        p = tmp_path / "intkey.yaml"
        p.write_text(yaml.safe_dump({1: 0.5, "good": 0.7}), encoding="utf-8")
        out = load_priors_override(p)
        assert out == {"good": 0.7}

    def test_priors_with_nested_priors_block(self, tmp_path: Path) -> None:
        p = tmp_path / "nested.yaml"
        p.write_text(yaml.safe_dump({"priors": {"a": 0.5, "b": 0.6}}), encoding="utf-8")
        out = load_priors_override(p)
        assert out == {"a": 0.5, "b": 0.6}

    def test_priors_with_priors_block_not_a_mapping(self, tmp_path: Path) -> None:
        p = tmp_path / "bad-nested.yaml"
        p.write_text(yaml.safe_dump({"priors": [1, 2, 3]}), encoding="utf-8")
        out = load_priors_override(p)
        assert out == {}

    def test_priors_with_negative_value(self, tmp_path: Path) -> None:
        p = tmp_path / "neg.yaml"
        p.write_text(yaml.safe_dump({"a": -0.5, "b": 0.5}), encoding="utf-8")
        out = load_priors_override(p)
        assert out == {"b": 0.5}
