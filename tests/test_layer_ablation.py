"""Pin the layer-ablation harness's pure logic.

`validation/layer_ablation.py` compares the Bayesian layer with slug-matching
baselines under an independent-Bernoulli misspecification stress test and what
the graph layer adds over connected components (planted partitions with
bridging noise). Everything here is synthetic and deterministic; the
hand-value cross-checks tie the baselines to independently-pinned engine
arithmetic.
"""

from __future__ import annotations

import random

import pytest

from validation.layer_ablation import (
    any_fired_prediction,
    connected_components_partition,
    main,
    planted_corpus,
    run_graph_ablation,
    strongest_only_prediction,
)


class TestBaselinePredictors:
    def test_any_fired(self) -> None:
        assert any_fired_prediction({"a", "b"}, {"b", "c"}) == 1.0
        assert any_fired_prediction({"a", "b"}, {"c"}) == 0.0
        assert any_fired_prediction(set(), {"c"}) == 0.0

    def test_strongest_only_no_fire_is_the_prior(self) -> None:
        assert strongest_only_prediction(0.3, []) == 0.3

    def test_strongest_only_matches_single_binding_posterior(self) -> None:
        # prior 0.30 updated by the microsoft365 binding's LLR
        # (ln(0.95/0.03)) must reproduce the engine's single-slug posterior
        # 0.9314 (pinned in test_evidence_semantics_diagnostics).
        import math

        p = strongest_only_prediction(0.30, [math.log(0.95 / 0.03)])
        assert p == pytest.approx(0.9314, abs=1e-4)

    def test_strongest_only_picks_max_abs_llr(self) -> None:
        # A strong negative LLR outweighs a weak positive one.
        weak_up, strong_down = 0.2, -2.0
        p = strongest_only_prediction(0.5, [weak_up, strong_down])
        assert p < 0.5


class TestPlantedCorpus:
    def test_shapes_and_disjoint_clusters(self) -> None:
        rng = random.Random(3)
        entries, planted = planted_corpus(4, 5, 6, 7, rng)
        assert len(planted) == 4
        assert all(len(c) == 5 for c in planted)
        all_hosts = set().union(*planted)
        assert len(all_hosts) == 20  # disjoint
        assert len(entries) == 4 * 6 + 7

    def test_noise_certs_bridge_two_clusters(self) -> None:
        rng = random.Random(3)
        entries, planted = planted_corpus(3, 4, 2, 5, rng)
        noise = [e for e in entries if e["issuer_name"] == "Synthetic CDN CA"]
        assert len(noise) == 5
        for e in noise:
            names = e["dns_names"]
            owners = {i for i, c in enumerate(planted) if set(names) & c}
            assert len(owners) == 2  # spans exactly two planted clusters


class TestConnectedComponentsBaseline:
    def test_unions_shared_cert_hosts(self) -> None:
        entries = [
            {"dns_names": ["a.example.com", "b.example.com"]},
            {"dns_names": ["c.example.com", "d.example.com"]},
            {"dns_names": ["b.example.com", "c.example.com"]},  # bridge
        ]
        parts = connected_components_partition(entries)
        assert len(parts) == 1
        assert parts[0] == {"a.example.com", "b.example.com", "c.example.com", "d.example.com"}

    def test_wildcards_ignored(self) -> None:
        entries = [{"dns_names": ["*.example.com", "a.example.com", "b.example.com"]}]
        parts = connected_components_partition(entries)
        assert parts == [{"a.example.com", "b.example.com"}]


class TestGraphAblation:
    def test_louvain_resists_bridging_noise_components_do_not(self) -> None:
        rows = run_graph_ablation(clusters=5, hosts_per_cluster=6, intra_certs=10, noise_grid=[0, 8], seed=11)
        clean, noisy = rows[0], rows[1]
        assert clean.ari_louvain == pytest.approx(1.0)
        assert clean.ari_components == pytest.approx(1.0)
        # Bridged: community detection holds, naive grouping collapses.
        assert noisy.ari_louvain > noisy.ari_components
        assert noisy.ari_louvain > 0.9
        assert noisy.ari_components < 0.5


def test_cli_labels_bayesian_ablation_as_misspecification_stress(capsys) -> None:
    assert main(["--samples", "2", "--skip-graph"]) == 0
    output = capsys.readouterr().out
    assert "independent-Bernoulli misspecification stress test" in output
    assert "not the committed generative model" in output
