"""Interrupted maintenance keeps durable starts and uncertainty about legacy starts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from recon_tool.collection_limits import admit_dns_query, admit_namespace
from validation import bounded_catalog_collection as launcher
from validation import scan
from validation.catalog_baseline import aggregate_records
from validation.catalog_receipts import (
    collection_metadata,
    completion_summary,
    read_frozen_frame,
    read_json,
    start_recorder,
    write_private_event,
)
from validation.prepare_catalog_round import REPO_ROOT


def _frame(root: Path) -> Path:
    path = root / "frame.txt"
    path.write_text("alpha.test\nbeta.test\ngamma.test\ndelta.test\n", encoding="utf-8")
    return path


def test_real_batch_cli_propagates_budget_exhaustion_without_fabricating_a_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from typing import NoReturn

    import dns.resolver

    from recon_tool import resolver
    from recon_tool.sources import dns_base
    from recon_tool.sources.dns import DNSSource

    calls: list[str] = []

    class Resolver:
        async def resolve(self, name: str, _rdtype: str, *, lifetime: float) -> NoReturn:
            assert lifetime > 0
            calls.append(name)
            raise dns.resolver.NoAnswer

    fake = Resolver()
    monkeypatch.setattr(dns_base, "get_resolver", lambda: fake)
    monkeypatch.setattr(resolver, "default_pool", lambda: resolver.SourcePool([DNSSource()]))
    frame = _frame(tmp_path)
    run = tmp_path / "actual-batch"
    status = launcher.main(
        [
            "--corpus",
            str(frame),
            "--run-dir",
            str(run),
            "--max-namespaces",
            "4",
            "--max-dns-queries",
            "1",
            "--concurrency",
            "1",
            "--allow-network",
        ]
    )
    assert status == launcher.BUDGET_STOP
    assert len(calls) == 1
    assert capsys.readouterr().out == ""
    budget = read_json(run / "collection-budget.json")
    assert budget["stopped_reason"] == "dns_query_budget"
    assert budget["dns_queries_reserved"] == 1
    summary = completion_summary(run, admitted=4, records=[])
    assert summary["terminal_success"] == 0
    assert summary["known_started_lower_bound"] == 1
    assert summary["unfinished_known_started"] == 1
    assert summary["known_unattempted"] == 3


def _recorder(root: Path, frame: Path):
    members, digest = read_frozen_frame(frame, 4)
    return start_recorder(
        root, {"schema_version": 1, "namespace_count": len(members), "corpus": str(frame), "frame_sha256": digest}
    )


def test_private_events_are_immutable_and_repeated_identical_event_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "event.json"
    value = {"schema_version": 1, "outcome": "blocked"}
    write_private_event(path, value)
    before = path.read_bytes()
    write_private_event(path, value, idempotent=True)
    assert path.read_bytes() == before
    with pytest.raises(ValueError, match="already exists"):
        write_private_event(path, value | {"outcome": "completed"}, idempotent=True)
    assert path.read_bytes() == before


def test_private_events_cannot_land_in_a_public_repository_directory() -> None:
    path = REPO_ROOT / "docs" / "private-maintenance-example.json"
    with pytest.raises(ValueError, match="private validation output root"):
        write_private_event(path, {"private": True})
    assert not path.exists()


def test_durable_partial_counts_separate_started_unfinished_and_proven_unattempted(tmp_path: Path) -> None:
    frame = _frame(tmp_path)
    record = _recorder(tmp_path, frame)
    for domain in ("alpha.test", "beta.test", "gamma.test"):
        record(domain)
    summary = completion_summary(
        tmp_path,
        admitted=4,
        records=[
            {"queried_domain": "alpha.test"},
            {"domain": "beta.test", "record_type": "error", "error_kind": "lookup"},
        ],
    )
    assert summary == {
        "admitted": 4,
        "terminal_success": 1,
        "terminal_error": 1,
        "unfinished": 2,
        "known_started_lower_bound": 3,
        "unfinished_known_started": 1,
        "unfinished_start_unknown": 0,
        "known_unattempted": 1,
        "start_receipts_complete": True,
    }


def test_legacy_interruption_does_not_relabel_unfinished_as_unattempted(tmp_path: Path) -> None:
    records = [
        {"domain": "alpha.test", "record_type": "error", "error_kind": "lookup"},
        {"domain": "beta.test", "record_type": "error", "error_kind": "lookup"},
    ]
    summary = completion_summary(tmp_path, admitted=4, records=records)
    assert summary["known_started_lower_bound"] == 2
    assert summary["unfinished_start_unknown"] == 2
    assert summary["known_unattempted"] == 0
    assert summary["start_receipts_complete"] is False
    aggregate, queue = aggregate_records(records, min_count=1, min_distinct_namespaces=1, max_samples=0)
    assert aggregate["measured_input_records"] == 0
    assert aggregate["error_records"] == 2
    assert not any(queue.values())
    assert all(row["classified_rate"] is None for row in aggregate["record_types"].values())


def test_invalid_or_changed_receipts_withhold_accounting_and_preserve_original(tmp_path: Path) -> None:
    frame = _frame(tmp_path)
    record = _recorder(tmp_path, frame)
    record("alpha.test")
    marker = tmp_path / "namespace-starts" / "admission.json"
    original = marker.read_bytes()
    frame.write_text("outside.test\n", encoding="utf-8")
    metadata = collection_metadata(tmp_path, admitted=4, records=[{"queried_domain": "alpha.test"}])
    assert metadata["collection_completion"]["availability"] == "unavailable"
    assert marker.read_bytes() == original


def test_terminal_without_durable_start_is_not_treated_as_valid_completion(tmp_path: Path) -> None:
    _recorder(tmp_path, _frame(tmp_path))
    with pytest.raises(ValueError, match="matching durable start"):
        completion_summary(tmp_path, admitted=4, records=[{"queried_domain": "alpha.test"}])


@pytest.mark.parametrize("contents", ["alpha.test\nalpha.test\n", "WWW.ALPHA.TEST\n", "alpha.test;bad\n", ""])
def test_frame_is_not_silently_repaired_or_expanded(contents: str, tmp_path: Path) -> None:
    path = tmp_path / "frame.txt"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError, match=r"frame|domain|Domain|Invalid"):
        read_frozen_frame(path, 4)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "receipt.json"
    path.write_text('{"schema_version":1,"schema_version":2}')
    with pytest.raises(ValueError, match="duplicate field"):
        read_json(path)


def _arguments(root: Path) -> list[str]:
    return [
        "--corpus",
        str(_frame(root)),
        "--run-dir",
        str(root / "run"),
        "--max-namespaces",
        "4",
        "--max-dns-queries",
        "2",
        "--allow-network",
    ]


def test_launcher_stops_existing_cli_at_query_cap_and_preserves_started_partial(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run() -> None:
        admit_namespace("alpha.test")
        admit_dns_query()
        print('{"queried_domain":"alpha.test","record_type":"resolved"}', flush=True)
        admit_namespace("beta.test")
        admit_dns_query()
        admit_dns_query()
        pytest.fail("query budget failed to stop the producer")

    monkeypatch.setattr("recon_tool.cli.run", fake_run)
    assert launcher.main(_arguments(tmp_path)) == launcher.BUDGET_STOP
    result = json.loads(capsys.readouterr().out)
    assert result["queried_domain"] == "alpha.test"
    receipt = read_json(tmp_path / "run" / "collection-budget.json")
    assert receipt["dns_queries_reserved"] == 2
    assert receipt["stopped_reason"] == "dns_query_budget"
    summary = completion_summary(tmp_path / "run", admitted=4, records=[result])
    assert summary["unfinished_known_started"] == 1
    assert summary["known_unattempted"] == 2
    assert summary["unfinished_start_unknown"] == 0
    with pytest.raises(ValueError, match="already exists"):
        launcher.main(_arguments(tmp_path))


def test_launcher_requires_explicit_network_invocation_before_creating_receipts(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path)
    arguments.remove("--allow-network")
    with pytest.raises(SystemExit) as exc:
        launcher.main(arguments)
    assert exc.value.code == 2
    assert not (tmp_path / "run").exists()


def test_launcher_does_not_report_success_after_unexpected_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail() -> None:
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr("recon_tool.cli.run", fail)
    with pytest.raises(RuntimeError, match="synthetic failure"):
        launcher.main(_arguments(tmp_path))
    assert read_json(tmp_path / "run" / "collection-budget.json")["exit_code"] == 1


def test_scan_uses_budget_launcher_and_finalizes_cap_stop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    commands: list[list[str]] = []

    class Process:
        returncode = launcher.BUDGET_STOP

        def __init__(self, command: list[str], **_kwargs: object) -> None:
            commands.append(command)

        def communicate(self, timeout: float | None = None) -> tuple[None, str]:
            assert timeout == 600
            return None, ""

    monkeypatch.setattr(scan.subprocess, "Popen", Process)
    args = argparse.Namespace(concurrency=2, timeout=30, max_runtime=600, ct=False, json_array=False, max_dns_queries=2)
    result = scan._run_batch(_frame(tmp_path), tmp_path, args=args, domain_count=4)
    assert not result.completed
    assert not result.timed_out
    assert commands[0][1:3] == ["-m", "validation.bounded_catalog_collection"]
    assert "--allow-network" in commands[0]
    assert commands[0][commands[0].index("--max-namespaces") + 1] == "4"
