"""Contract tests for the network-free performance characterization harness."""

from __future__ import annotations

import pytest

from scripts.characterize_performance import (
    _dense_graph_entries,
    _isolated_config_directory,
    _nearest_rank,
    _repeated_graph_entries,
    build_cases,
    characterize,
)


def test_nearest_rank_uses_observed_samples() -> None:
    values = [0.5, 0.1, 0.4, 0.2, 0.3]
    assert _nearest_rank(values, 0.5) == 0.3
    assert _nearest_rank(values, 0.95) == 0.5


def test_nearest_rank_rejects_an_empty_sample() -> None:
    with pytest.raises(ValueError, match="values must not be empty"):
        _nearest_rank([], 0.5)


@pytest.mark.parametrize("quantile", [0.0, 1.1])
def test_nearest_rank_rejects_invalid_quantiles(quantile: float) -> None:
    with pytest.raises(ValueError, match="quantile must be in"):
        _nearest_rank([1.0], quantile)


def test_dense_graph_fixture_has_exact_declared_shape() -> None:
    entries = _dense_graph_entries()
    names = [name for entry in entries for name in entry["dns_names"]]
    assert len(entries) == 1000
    assert all(len(entry["dns_names"]) == 20 for entry in entries)
    assert len(set(names)) == 200


def test_repeated_graph_fixture_has_exact_declared_shape() -> None:
    entries = _repeated_graph_entries()
    first_names = entries[0]["dns_names"]
    assert len(entries) == 1000
    assert len(first_names) == 60
    assert all(entry["dns_names"] == first_names for entry in entries)


def test_case_catalog_separates_default_and_stress_workloads() -> None:
    with _isolated_config_directory():
        default_names = {case.name for case in build_cases(include_stress=False)}
        stress_names = {case.name for case in build_cases(include_stress=True)}
    assert len(default_names) == 11
    assert {
        "batch_fusion_25_domains_repeated_setup_reference",
        "batch_fusion_25_domains_snapshot",
        "fingerprint_catalog_split_yaml_reference",
        "fingerprint_catalog_cold_load",
    }.issubset(default_names)
    assert stress_names - default_names == {"ct_graph_dense_1000x20", "ct_graph_repeated_1000x60"}


@pytest.mark.parametrize(
    ("repetitions", "warmups", "message"),
    [(0, 0, "repetitions must be at least 1"), (1, -1, "warmups must be at least 0")],
)
def test_characterize_rejects_invalid_run_counts(repetitions: int, warmups: int, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        characterize(repetitions=repetitions, warmups=warmups, include_stress=False)
