"""Numerical failure must not turn accepted extreme models into uniform beliefs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from recon_tool.bayesian import _query_marginal, infer, load_network


def _write_model(tmp_path: Path, scale: float, *, absence: bool = False) -> Path:
    node: dict[str, Any] = {
        "name": "claim",
        "description": "synthetic claim",
        "prior": 0.2,
        "evidence": [{"slug": name, "likelihood": [10 * scale, scale]} for name in ("first", "second")],
    }
    if absence:
        node["missingness"] = "declarative"
        node["group_absence"] = {}
        for binding in node["evidence"]:
            binding["group"] = binding["slug"]
            node["group_absence"][binding["group"]] = [10 * scale, scale]
    path = tmp_path / "network.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "nodes": [node]}), encoding="utf-8")
    return path


@pytest.mark.parametrize("scale", [1e-2, 1e-150])
@pytest.mark.parametrize("absence", [False, True])
def test_representable_extreme_evidence_preserves_hand_computed_posterior(
    tmp_path: Path, scale: float, absence: bool
) -> None:
    network = load_network(_write_model(tmp_path, scale, absence=absence))
    result = infer(network, [] if absence else ["first", "second"], [], priors_override={})
    # Prior odds = 1/4, two LR=10 units give odds=25 and posterior=25/26.
    assert result.posteriors[0].posterior == round(25 / 26, 4)
    assert {unit.posterior_without for unit in result.posteriors[0].unit_counterfactuals} == {round(5 / 7, 4)}


@pytest.mark.parametrize("absence", [False, True])
def test_unrepresentable_evidence_product_fails_explicitly(tmp_path: Path, absence: bool) -> None:
    # The schema accepts each strictly positive probability. Their products
    # underflow, despite having the same mathematical posterior as above.
    network = load_network(_write_model(tmp_path, 1e-200, absence=absence))
    with pytest.raises(FloatingPointError, match="evidence likelihood lost numerical precision"):
        infer(network, [] if absence else ["first", "second"], [], priors_override={})


def test_underflow_between_valid_node_factors_fails_explicitly(tmp_path: Path) -> None:
    path = tmp_path / "independent.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "nodes": [
                    {
                        "name": "claim",
                        "prior": 0.2,
                        "evidence": [{"slug": "first", "likelihood": [1e-200, 1e-201]}],
                    },
                    {
                        "name": "independent",
                        "prior": 0.5,
                        "evidence": [{"slug": "second", "likelihood": [1e-200, 1e-200]}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    network = load_network(path)
    # Every local evidence factor is representable. The unrelated neutral
    # evidence cancels mathematically, leaving the first posterior at 5/7.
    # Probability-space elimination cannot represent their combined scale.
    with pytest.raises(FloatingPointError, match="factor multiplication underflow"):
        infer(network, ["first", "second"], [], priors_override={})


@pytest.mark.parametrize("mass", [0.0, float("inf"), float("nan")])
def test_invalid_normalization_is_not_a_uniform_posterior(mass: float) -> None:
    factor = {frozenset({("claim", "present")}): mass, frozenset({("claim", "absent")}): mass}
    with pytest.raises(FloatingPointError, match="invalid normalization mass"):
        _query_marginal([factor], "claim", ["claim"])


def test_numerical_guard_remains_enabled_under_python_optimization(tmp_path: Path) -> None:
    path = _write_model(tmp_path, 1e-200)
    result = subprocess.run(  # noqa: S603 - current interpreter and a caller-owned synthetic test fixture
        [
            sys.executable,
            "-O",
            "-c",
            "from pathlib import Path; import sys; "
            "from recon_tool.bayesian import infer, load_network; "
            "infer(load_network(Path(sys.argv[1])), ['first', 'second'], [], priors_override={})",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "FloatingPointError: Bayesian evidence likelihood lost numerical precision" in result.stderr
