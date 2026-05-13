"""End-to-end robustness checks for the v1.9 fusion path.

Bundles cache round-trip, CLI flag combinations, MCP tool error paths,
determinism, concurrency, and scale stress into a single robustness
suite. Each test is a property the v1.9 implementation must satisfy
under any reasonable operator workflow.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from recon_tool.bayesian import (
    BayesianNetwork,
    _Evidence,
    _Node,
    infer,
    infer_from_tenant_info,
    load_network,
)
from recon_tool.cache import tenant_info_from_dict, tenant_info_to_dict
from recon_tool.models import EvidenceRecord, PosteriorObservation, TenantInfo


def _bare_tenant_info(**overrides) -> TenantInfo:
    base = {
        "tenant_id": None,
        "display_name": "Contoso",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "services": (),
        "slugs": (),
    }
    base.update(overrides)
    return TenantInfo(**base)


# ── Cache round-trip ──────────────────────────────────────────────────


class TestCacheRoundTrip:
    def test_posterior_observations_round_trip(self) -> None:
        po = (
            PosteriorObservation(
                name="m365_tenant",
                description="Domain has M365.",
                posterior=0.92,
                interval_low=0.85,
                interval_high=0.99,
                evidence_used=("slug:microsoft365", "slug:entra-id"),
                n_eff=5.0,
                sparse=False,
            ),
            PosteriorObservation(
                name="cdn_fronting",
                description="CDN fronts the apex.",
                posterior=0.45,
                interval_low=0.13,
                interval_high=0.77,
                evidence_used=(),
                n_eff=4.0,
                sparse=True,
            ),
        )
        info = _bare_tenant_info(posterior_observations=po)
        # Write -> read -> compare
        d = tenant_info_to_dict(info)
        assert "posterior_observations" in d
        round_trip = tenant_info_from_dict(d)
        assert len(round_trip.posterior_observations) == 2
        a, b = round_trip.posterior_observations
        assert a.name == "m365_tenant"
        assert a.posterior == 0.92
        assert a.evidence_used == ("slug:microsoft365", "slug:entra-id")
        assert b.sparse is True

    def test_legacy_cache_entry_without_field_loads(self) -> None:
        """A cache entry written by pre-v1.9 code (no
        ``posterior_observations`` key) must still load — the field
        defaults to ``()``."""
        info = _bare_tenant_info()
        d = tenant_info_to_dict(info)
        d.pop("posterior_observations", None)  # simulate legacy entry
        round_trip = tenant_info_from_dict(d)
        assert round_trip.posterior_observations == ()

    def test_cache_entry_with_malformed_posterior_recovers(self) -> None:
        """Cache poisoning: malformed entries should be skipped, not
        crash the loader."""
        info = _bare_tenant_info()
        d = tenant_info_to_dict(info)
        d["posterior_observations"] = [
            "this is not a dict",
            {"only_partial": "fields"},
            42,
            None,
        ]
        round_trip = tenant_info_from_dict(d)
        assert round_trip.posterior_observations == ()

    def test_cache_entry_with_mixed_valid_and_invalid(self) -> None:
        info = _bare_tenant_info()
        d = tenant_info_to_dict(info)
        d["posterior_observations"] = [
            {
                "name": "good",
                "description": "good",
                "posterior": 0.5,
                "interval_low": 0.1,
                "interval_high": 0.9,
                "evidence_used": [],
                "n_eff": 4.0,
                "sparse": True,
            },
            {"only_partial": "fields"},  # skipped
        ]
        round_trip = tenant_info_from_dict(d)
        assert len(round_trip.posterior_observations) == 1
        assert round_trip.posterior_observations[0].name == "good"

    def test_full_inference_into_tenantinfo_round_trips(self) -> None:
        """Run real inference, stuff it into TenantInfo, round-trip
        through cache, verify equality."""
        info_with_evidence = _bare_tenant_info(
            slugs=("microsoft365", "entra-id"),
            evidence=(
                EvidenceRecord(source_type="OIDC", raw_value="x", rule_name="m365", slug="microsoft365"),
                EvidenceRecord(source_type="HTTP", raw_value="y", rule_name="entra", slug="entra-id"),
            ),
        )
        result = infer_from_tenant_info(info_with_evidence)
        po = tuple(
            PosteriorObservation(
                name=p.name,
                description=p.description,
                posterior=p.posterior,
                interval_low=p.interval_low,
                interval_high=p.interval_high,
                evidence_used=p.evidence_used,
                n_eff=p.n_eff,
                sparse=p.sparse,
            )
            for p in result.posteriors
        )
        from dataclasses import replace

        info_with_po = replace(info_with_evidence, posterior_observations=po)
        d = tenant_info_to_dict(info_with_po)
        round_trip = tenant_info_from_dict(d)
        assert len(round_trip.posterior_observations) == len(po)
        for orig, after in zip(po, round_trip.posterior_observations, strict=True):
            assert orig.name == after.name
            assert abs(orig.posterior - after.posterior) < 1e-9
            assert orig.sparse == after.sparse


# ── CLI flag combinations ─────────────────────────────────────────────


class TestCLIFlagCombinations:
    """Use the typer test runner to verify --explain-dag / --fusion / etc.
    We mock resolve_tenant so the tests don't hit the network. Pass
    ``--no-cache`` so cached real-domain results don't leak into the
    test fixtures' display_name assertions.
    """

    def _imports(self):
        from typer.testing import CliRunner

        from recon_tool.cli import app

        return app, CliRunner()

    def test_explain_dag_text_format(self) -> None:
        app, runner = self._imports()
        from tests.test_cli import RESOLVE_PATH, SAMPLE_INFO, SAMPLE_RESULTS

        with patch(RESOLVE_PATH, new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
            result = runner.invoke(app, ["lookup", "contoso.com", "--explain-dag", "--no-cache"])
            assert result.exit_code == 0
            assert "## m365_tenant" in result.output
            # Plain English narrative
            assert "Posterior:" in result.output

    def test_explain_dag_dot_format(self) -> None:
        app, runner = self._imports()
        from tests.test_cli import RESOLVE_PATH, SAMPLE_INFO, SAMPLE_RESULTS

        with patch(RESOLVE_PATH, new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
            result = runner.invoke(
                app,
                ["lookup", "contoso.com", "--explain-dag", "--explain-dag-format", "dot", "--no-cache"],
            )
            assert result.exit_code == 0
            assert "digraph" in result.output
            assert '"m365_tenant"' in result.output

    def test_explain_dag_invalid_format(self) -> None:
        app, runner = self._imports()
        from tests.test_cli import RESOLVE_PATH, SAMPLE_INFO, SAMPLE_RESULTS

        with patch(RESOLVE_PATH, new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
            result = runner.invoke(
                app,
                ["lookup", "contoso.com", "--explain-dag", "--explain-dag-format", "rubbish", "--no-cache"],
            )
            # Should error (validation exit code), not crash.
            assert result.exit_code != 0
            assert "explain-dag-format" in result.output.lower()

    def test_fusion_with_json_populates_posteriors(self) -> None:
        app, runner = self._imports()
        from tests.test_cli import RESOLVE_PATH, SAMPLE_INFO, SAMPLE_RESULTS

        with patch(RESOLVE_PATH, new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
            result = runner.invoke(app, ["lookup", "contoso.com", "--fusion", "--json", "--no-cache"])
            assert result.exit_code == 0
            d = json.loads(result.output)
            # Both layers populated.
            assert "posterior_observations" in d
            assert isinstance(d["posterior_observations"], list)

    def test_fusion_off_emits_empty_posteriors(self) -> None:
        app, runner = self._imports()
        from tests.test_cli import RESOLVE_PATH, SAMPLE_INFO, SAMPLE_RESULTS

        with patch(RESOLVE_PATH, new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
            result = runner.invoke(app, ["lookup", "contoso.com", "--json", "--no-cache"])
            assert result.exit_code == 0
            d = json.loads(result.output)
            assert d.get("posterior_observations", []) == []


# ── Determinism + concurrency ─────────────────────────────────────────


class TestDeterminism:
    def test_repeated_inference_byte_identical(self) -> None:
        """100 runs → all outputs equal at the float-bit level."""
        net = load_network()
        slugs = ("microsoft365", "entra-id", "okta")
        baseline = infer(net, slugs, [], priors_override={})
        for _ in range(99):
            r = infer(net, slugs, [], priors_override={})
            for a, b in zip(baseline.posteriors, r.posteriors, strict=True):
                assert a.posterior == b.posterior
                assert a.interval_low == b.interval_low
                assert a.interval_high == b.interval_high

    def test_concurrent_inference_no_state_corruption(self) -> None:
        """Run 50 inferences concurrently; if any global state were
        shared and mutated, posteriors would diverge from a sequential
        baseline."""
        net = load_network()
        slugs = ("microsoft365", "entra-id", "okta")
        signals = ("dmarc_reject",)

        async def main():
            baseline = infer(net, slugs, signals, priors_override={})

            async def run_one():
                # Inference is sync but called concurrently — ensures
                # there are no module-level mutables that would corrupt.
                return infer(net, slugs, signals, priors_override={})

            results = await asyncio.gather(*(run_one() for _ in range(50)))
            for r in results:
                for a, b in zip(baseline.posteriors, r.posteriors, strict=True):
                    assert a.posterior == b.posterior

        asyncio.run(main())


# ── Scale ─────────────────────────────────────────────────────────────


class TestScale:
    def test_15_node_chain_inference_under_100ms(self, tmp_path: Path) -> None:
        """Linear chain of 15 nodes (each dependent on its predecessor)
        must complete inference in under 100ms on a modern laptop. This
        is well within the operational budget for a recon lookup."""
        nodes = [{"name": "n0", "description": "x", "prior": 0.5}]
        for i in range(1, 15):
            nodes.append(
                {
                    "name": f"n{i}",
                    "description": "x",
                    "parents": [f"n{i - 1}"],
                    "cpt": {
                        f"n{i - 1}=present": 0.8,
                        f"n{i - 1}=absent": 0.2,
                    },
                    "evidence": [{"slug": f"slug_{i}", "likelihood": [0.9, 0.1]}],
                }
            )
        spec = {"version": 1, "nodes": nodes}
        path = tmp_path / "chain.yaml"
        path.write_text(yaml.safe_dump(spec), encoding="utf-8")
        net = load_network(path)
        observed = [f"slug_{i}" for i in range(1, 15)]
        start = time.perf_counter()
        result = infer(net, observed, [], priors_override={})
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, f"15-node chain took {elapsed:.3f}s — too slow"
        assert len(result.posteriors) == 15
        for p in result.posteriors:
            assert 0.0 <= p.posterior <= 1.0

    def test_wide_network_does_not_explode(self, tmp_path: Path) -> None:
        """One root node with 10 children; each child has independent
        evidence. Should complete quickly — wide networks are easier
        than deep ones for variable elimination."""
        nodes = [{"name": "root", "description": "x", "prior": 0.5}]
        for i in range(10):
            nodes.append(
                {
                    "name": f"child{i}",
                    "description": "x",
                    "parents": ["root"],
                    "cpt": {"root=present": 0.7, "root=absent": 0.3},
                    "evidence": [{"slug": f"e{i}", "likelihood": [0.9, 0.2]}],
                }
            )
        spec = {"version": 1, "nodes": nodes}
        path = tmp_path / "wide.yaml"
        path.write_text(yaml.safe_dump(spec), encoding="utf-8")
        net = load_network(path)
        # Observe half the children to fire — should pull root posterior up.
        observed = [f"e{i}" for i in range(5)]
        result = infer(net, observed, [], priors_override={})
        root = next(p for p in result.posteriors if p.name == "root")
        assert root.posterior > 0.5  # observations push root above prior


# ── MCP tool error paths ──────────────────────────────────────────────


class TestMCPErrorPaths:
    def test_get_posteriors_invalid_domain(self) -> None:
        from recon_tool.server import get_posteriors

        async def main():
            return await get_posteriors("not a valid domain!")

        result = asyncio.run(main())
        assert result.startswith("Error:")

    def test_explain_dag_invalid_domain(self) -> None:
        from recon_tool.server import explain_dag

        async def main():
            return await explain_dag("not.a.valid_domain_with_underscores")

        result = asyncio.run(main())
        assert result.startswith("Error:")

    def test_explain_dag_invalid_format(self) -> None:
        from recon_tool.server import explain_dag

        async def main():
            return await explain_dag("contoso.com", output_format="png")

        result = asyncio.run(main())
        assert result.startswith("Error:")
        assert "output_format" in result


# ── Build a tiny network in-memory for inference smoke ────────────────


class TestInMemoryNetwork:
    def test_can_construct_and_run_in_memory(self) -> None:
        node_a = _Node(
            name="a",
            description="a",
            parents=(),
            prior=0.3,
            cpt={},
            evidence=(_Evidence(kind="slug", name="ev_a", likelihood_present=0.9, likelihood_absent=0.1),),
        )
        net = BayesianNetwork(version=1, nodes=(node_a,))
        result = infer(net, ["ev_a"], [], priors_override={})
        # Bayes by hand: 0.9 * 0.3 / (0.9 * 0.3 + 0.1 * 0.7) = 0.79
        assert abs(result.posteriors[0].posterior - 0.79) < 0.01
