"""Work, materialization and completeness contracts for supplied batch inputs."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from dataclasses import replace
from itertools import combinations
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from recon_tool.batch_correlation import MAX_PEERS_PER_DOMAIN, MAX_TOKEN_PEER_ENTRIES, attach_batch_correlations
from recon_tool.cli.batch import batch_emit_json
from recon_tool.clustering import compute_shared_token_report
from recon_tool.ecosystem import MAX_PAIR_VISITS, build_ecosystem_report
from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.models import CertSummary, TenantInfo


def _info(domain: str, **kwargs: Any) -> TenantInfo:
    return TenantInfo(tenant_id=None, display_name="", default_domain=domain, queried_domain=domain, **kwargs)


def _records(infos: dict[str, TenantInfo]) -> list[dict[str, Any]]:
    return [{"queried_domain": domain} for domain in infos]


def test_maximum_shared_identity_groups_have_linear_peer_work_and_output() -> None:
    infos = {
        f"d{i:05d}.invalid": replace(
            _info(f"d{i:05d}.invalid"),
            tenant_id="00000000-0000-4000-8000-000000000001",
            display_name="Synthetic Group",
        )
        for i in range(10_000)
    }
    records = _records(infos)
    attach_batch_correlations(records, infos)
    peer_references = 0
    examined = 0
    for record in records:
        diagnostic = record["correlation_completeness"]
        assert diagnostic["omitted_tenant_peers"] == 9_999 - MAX_PEERS_PER_DOMAIN
        assert diagnostic["omitted_display_name_peers"] == 9_999 - MAX_PEERS_PER_DOMAIN
        assert not diagnostic["enumeration_complete"]
        examined += diagnostic["peer_candidates_examined"]
        for field in ("shared_tenant", "shared_display_name"):
            peers = record[field][0]["peers"]
            assert len(peers) == MAX_PEERS_PER_DOMAIN
            assert record["queried_domain"] not in peers
            peer_references += len(peers)
    assert examined <= 2 * 10_000 * (MAX_PEERS_PER_DOMAIN + 1)
    assert peer_references == 2 * 10_000 * MAX_PEERS_PER_DOMAIN
    # This synthetic short-name fixture has a bounded encoded projection too;
    # it is not a machine-independent RSS or arbitrary-input byte claim.
    assert len(json.dumps(records).encode("utf-8")) < 32 * 1024 * 1024


@pytest.mark.parametrize("size", [200, 201])
def test_token_cardinality_boundary_is_explicit(size: int) -> None:
    tokens = {f"d{i:03d}.invalid": ("synthetic-verification=opaque",) for i in range(size)}
    report = compute_shared_token_report(tokens, max_entries=50_000, max_encoded_bytes=8 * 1024 * 1024)
    if size == 200:
        assert report.emitted_entries == 200 * 199
        assert len(report.clusters) == 200
        assert report.omitted_peers == report.high_cardinality_peers == {}
    else:
        assert report.emitted_entries == 0
        assert report.clusters == {}
        assert report.high_cardinality_peers == dict.fromkeys(tokens, 200)
        infos = {domain: _info(domain, site_verification_tokens=values) for domain, values in tokens.items()}
        records = _records(infos)
        attach_batch_correlations(records, infos)
        assert all("shared_verification_tokens" not in record for record in records)
        assert all(record["correlation_completeness"]["high_cardinality_token_peers"] == 200 for record in records)
        assert all(not record["correlation_completeness"]["enumeration_complete"] for record in records)


def test_token_budget_admits_whole_symmetric_groups_in_stable_order() -> None:
    tokens = {f"d{i:03d}.invalid": tuple(f"synthetic={j:02d}" for j in range(30)) for i in range(50)}
    report = compute_shared_token_report(tokens, max_entries=MAX_TOKEN_PEER_ENTRIES)
    assert report.emitted_entries == 20 * 50 * 49
    assert report.output_limited
    assert set(report.omitted_peers.values()) == {10 * 49}
    assert report == compute_shared_token_report(
        dict(reversed(tuple(tokens.items()))), max_entries=MAX_TOKEN_PEER_ENTRIES
    )
    for domain, entries in report.clusters.items():
        for entry in entries:
            assert any(peer.peer == domain and peer.token == entry.token for peer in report.clusters[entry.peer])


def test_token_encoding_budget_accounts_for_escaped_values_and_exact_boundary() -> None:
    tokens = {"a.invalid": ("synthetic=\u00e9\n" * 20,), "b.invalid": ("synthetic=\u00e9\n" * 20,)}
    full = compute_shared_token_report(tokens)
    assert full.emitted_entries == 2
    exact = compute_shared_token_report(tokens, max_encoded_bytes=full.encoded_bytes_budgeted)
    assert exact == full
    limited = compute_shared_token_report(tokens, max_encoded_bytes=full.encoded_bytes_budgeted - 1)
    assert limited.clusters == {}
    assert limited.omitted_peers == {"a.invalid": 1, "b.invalid": 1}
    assert limited.encoded_bytes_budgeted == 0
    assert limited.output_limited


@pytest.mark.parametrize("budget", [{"max_entries": -1}, {"max_encoded_bytes": -1}])
def test_invalid_projection_budget_rejected(budget: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="nonnegative"):
        compute_shared_token_report({}, **budget)


def test_no_overlap_at_maximum_size_does_not_compare_every_domain_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    yielded = 0

    def counted_pairs(members: Sequence[str], size: int) -> Iterator[tuple[str, ...]]:
        nonlocal yielded
        for pair in combinations(members, size):
            yielded += 1
            yield pair

    monkeypatch.setattr("recon_tool.ecosystem.combinations", counted_pairs)
    infos = {
        f"d{i:05d}.invalid": _info(f"d{i:05d}.invalid", slugs=tuple(f"s-{i}-{j}" for j in range(3)))
        for i in range(10_000)
    }
    report = build_ecosystem_report(infos)
    assert report.hyperedges == ()
    assert report.completeness["pair_search_complete"] is True
    assert report.completeness["pair_visits"] == report.completeness["unique_pairs_examined"] == yielded == 0
    assert report.completeness["baseline_slugs_filtered"] == 0


def test_work_budget_bounds_nonqualifying_overlaps_not_only_output(monkeypatch: pytest.MonkeyPatch) -> None:
    yielded = 0

    def counted_pairs(members: Sequence[str], size: int) -> Iterator[tuple[str, ...]]:
        nonlocal yielded
        for pair in combinations(members, size):
            yielded += 1
            yield pair

    monkeypatch.setattr("recon_tool.ecosystem.combinations", counted_pairs)
    infos = {
        f"d{i:04d}.invalid": _info(
            f"d{i:04d}.invalid", slugs=("shared", f"unique-{i}-a", f"unique-{i}-b") if i < 600 else ()
        )
        for i in range(1_200)
    }
    report = build_ecosystem_report(infos)
    assert report.hyperedges == ()
    assert report.completeness["pair_visits"] == yielded == MAX_PAIR_VISITS
    assert report.completeness["pair_visits_possible"] == 600 * 599 // 2
    assert report.completeness["pair_search_complete"] is False
    assert report.completeness["unvisited_qualifying_edges_unknown"] is True
    assert report.completeness["known_omitted_edges_lower_bound"] == 0


@pytest.mark.parametrize("size", [100, 101])
def test_edge_member_boundary_counts_known_omissions(size: int) -> None:
    summary = CertSummary(1, 1, 1, 0, 10, ("Synthetic CA",))
    infos = {f"d{i:03d}.invalid": _info(f"d{i:03d}.invalid", cert_summary=summary) for i in range(size)}
    report = build_ecosystem_report(infos)
    assert len(report.hyperedges) == 1
    assert len(report.hyperedges[0].members) == min(size, 100)
    assert report.completeness["omitted_member_occurrences"] == max(0, size - 100)


@pytest.mark.parametrize("groups", [200, 201])
def test_edge_output_boundary_counts_known_omissions(groups: int) -> None:
    infos = {
        f"d{i:04d}.invalid": _info(
            f"d{i:04d}.invalid", cert_summary=CertSummary(1, 1, 1, 0, 10, (f"Synthetic CA {i // 2:03d}",))
        )
        for i in range(groups * 2)
    }
    report = build_ecosystem_report(infos)
    assert len(report.hyperedges) == min(groups, 200)
    assert report.completeness["known_omitted_edges_lower_bound"] == max(0, groups - 200)
    assert report.completeness["unvisited_qualifying_edges_unknown"] is False


def test_candidate_cap_is_distinct_from_pair_and_final_output_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("recon_tool.ecosystem._MAX_CANDIDATE_HYPEREDGES", 3)
    infos = {f"d{i}.invalid": _info(f"d{i}.invalid", slugs=("a", "b", "c")) for i in range(4)}
    report = build_ecosystem_report(infos)
    assert len(report.hyperedges) == report.completeness["pair_visits"] == 3
    assert report.completeness["candidate_limit_reached"] is True
    assert report.completeness["unvisited_qualifying_edges_unknown"] is True


@pytest.mark.parametrize("groups", [2_000, 2_001])
def test_candidate_group_boundary_counts_exact_known_omissions(groups: int) -> None:
    infos = {
        f"d{i:05d}.invalid": _info(
            f"d{i:05d}.invalid", cert_summary=CertSummary(1, 1, 1, 0, 10, (f"Synthetic CA {i // 2:04d}",))
        )
        for i in range(groups * 2)
    }
    report = build_ecosystem_report(infos)
    assert len(report.hyperedges) == 200
    assert report.completeness["known_omitted_candidates"] == max(0, groups - 2_000)
    assert report.completeness["candidate_limit_reached"] is (groups > 2_000)
    assert report.completeness["known_omitted_edges_lower_bound"] == groups - 200
    assert report.completeness["unvisited_qualifying_edges_unknown"] is False


def test_baseline_filter_and_failed_sources_are_distinct_from_no_overlap() -> None:
    infos = {f"d{i}.invalid": _info(f"d{i}.invalid", slugs=("a", "b", "c")) for i in range(5)}
    infos["d0.invalid"] = replace(infos["d0.invalid"], degraded_sources=("crt.sh",))
    report = build_ecosystem_report(infos, input_count=6)
    assert report.hyperedges == ()
    assert report.completeness["baseline_slugs_filtered"] == 3
    assert report.completeness["failed_namespaces"] == report.completeness["source_unavailable_namespaces"] == 1
    assert report.completeness["pair_search_complete"] is True


def test_batch_json_keeps_array_and_wrapper_contracts_with_limits(capsys: pytest.CaptureFixture[str]) -> None:
    infos = {f"d{i}.invalid": _info(f"d{i}.invalid", site_verification_tokens=("synthetic=shared",)) for i in range(2)}
    schema = json.loads((Path(__file__).parents[1] / "docs/recon-schema.json").read_text())
    for ecosystem in (False, True):
        batch_emit_json([format_tenant_dict(info) for info in infos.values()], infos, include_ecosystem=ecosystem)
        payload = json.loads(capsys.readouterr().out)
        definition = "BatchResult" if ecosystem else "BatchArray"
        Draft202012Validator(schema).evolve(schema=schema["$defs"][definition]).validate(payload)
        rows = payload["domains"] if ecosystem else payload
        assert all(row["correlation_completeness"]["enumeration_complete"] for row in rows)
        assert all(row["shared_verification_tokens"] for row in rows)
        if ecosystem:
            assert payload["ecosystem_completeness"]["pair_search_complete"]


def test_permutations_preserve_retained_peers_edges_and_diagnostics() -> None:
    infos = {
        f"d{i:03d}.invalid": replace(
            _info(f"d{i:03d}.invalid", slugs=("a", "b", "c") if i < 15 else ()), display_name="Synthetic"
        )
        for i in range(30)
    }
    records = _records(infos)
    reversed_infos = dict(reversed(tuple(infos.items())))
    reversed_records = _records(reversed_infos)
    attach_batch_correlations(records, infos)
    attach_batch_correlations(reversed_records, reversed_infos)
    assert records == list(reversed(reversed_records))
    assert build_ecosystem_report(infos) == build_ecosystem_report(reversed_infos)
