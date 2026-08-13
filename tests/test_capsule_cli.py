"""CLI coverage for capture, offline replay, and classified comparison."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from recon_tool.capsule import CollectionContext, build_capsule, write_capsule
from recon_tool.cli import app
from recon_tool.exit_codes import EXIT_VALIDATION
from recon_tool.models import ConfidenceLevel, EvidenceRecord, SourceResult, TenantInfo

runner = CliRunner()
_END = datetime(2026, 8, 13, 12, 0, 3, tzinfo=UTC)


def _fixture() -> tuple[TenantInfo, list[SourceResult]]:
    evidence = EvidenceRecord("TXT", "v=DMARC1; p=reject", "DMARC", "dmarc")
    info = TenantInfo(
        tenant_id=None,
        display_name="Example Industries Ltd",
        default_domain="example.com",
        queried_domain="example.com",
        confidence=ConfidenceLevel.HIGH,
        services=("DMARC",),
        slugs=("dmarc",),
        dmarc_policy="reject",
        evidence=(evidence,),
        resolved_at=_END.isoformat(),
        ct_attempt_outcome="skipped",
    )
    source = SourceResult(
        source_name="dns_records",
        dmarc_policy="reject",
        raw_dns_records=(("TXT", evidence.raw_value),),
        evidence=(evidence,),
        ct_attempt_outcome="skipped",
    )
    return info, [source]


def _written_capsule(path: Path, *, vantage: str = "caller-local") -> None:
    info, results = _fixture()
    capsule = build_capsule(
        info,
        results,
        CollectionContext(
            started_at=_END - timedelta(seconds=2),
            ended_at=_END,
            ct_enabled=False,
            direct_probes=False,
            timeout_seconds=30.0,
            vantage=vantage,
        ),
    )
    write_capsule(path, capsule)


def test_capsule_help_lists_three_operations() -> None:
    result = runner.invoke(app, ["capsule", "--help"])
    assert result.exit_code == 0
    assert "capture" in result.stdout
    assert "replay" in result.stdout
    assert "compare" in result.stdout


def test_capture_writes_capsule_and_json_receipt(tmp_path: Path) -> None:
    output = tmp_path / "example-capsule.json"
    info, results = _fixture()
    with patch("recon_tool.resolver.resolve_tenant", new=AsyncMock(return_value=(info, results))) as resolve:
        result = runner.invoke(
            app,
            [
                "capsule",
                "capture",
                "example.com",
                "--output",
                str(output),
                "--no-ct",
                "--timeout",
                "30",
                "--vantage",
                "resolver-west",
                "--json",
            ],
        )
    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout)
    capsule = json.loads(output.read_text(encoding="utf-8"))
    assert receipt["record_type"] == "observation_capsule_write"
    assert receipt["queried_domain"] == "example.com"
    assert receipt["content_digest"] == capsule["content_digest"]
    assert capsule["collection"]["vantage"] == "resolver-west"
    assert capsule["collection"]["options"]["ct_enabled"] is False
    resolve.assert_awaited_once_with(
        "example.com",
        timeout=30.0,
        skip_ct=True,
        active_probes=False,
    )


def test_capture_human_receipt_is_informative(tmp_path: Path) -> None:
    output = tmp_path / "example-capsule.json"
    info, results = _fixture()
    with patch("recon_tool.resolver.resolve_tenant", new=AsyncMock(return_value=(info, results))):
        result = runner.invoke(app, ["capsule", "capture", "example.com", "-o", str(output), "--no-ct"])
    assert result.exit_code == 0, result.output
    assert "Observation capsule written" in result.stdout
    assert "Observations" in result.stdout
    assert "source roles" in result.stdout
    assert "sha256:" in result.stdout


def test_capture_refuses_existing_file_without_force(tmp_path: Path) -> None:
    output = tmp_path / "example-capsule.json"
    _written_capsule(output)
    info, results = _fixture()
    with patch("recon_tool.resolver.resolve_tenant", new=AsyncMock(return_value=(info, results))):
        result = runner.invoke(app, ["capsule", "capture", "example.com", "-o", str(output), "--no-ct"])
    assert result.exit_code == EXIT_VALIDATION
    assert "already exists" in result.output


def test_capture_rejects_invalid_domain_before_collection(tmp_path: Path) -> None:
    output = tmp_path / "bad.json"
    resolve = AsyncMock()
    with patch("recon_tool.resolver.resolve_tenant", new=resolve):
        result = runner.invoke(app, ["capsule", "capture", "not a domain", "-o", str(output)])
    assert result.exit_code == EXIT_VALIDATION
    assert not output.exists()
    resolve.assert_not_awaited()


def test_replay_json_is_parseable_and_names_no_network_result(tmp_path: Path) -> None:
    path = tmp_path / "capsule.json"
    _written_capsule(path)
    result = runner.invoke(app, ["capsule", "replay", str(path), "--json"])
    assert result.exit_code == 0, result.output
    replay = json.loads(result.stdout)
    assert replay["record_type"] == "observation_capsule_replay"
    assert replay["queried_domain"] == "example.com"
    assert replay["result"]["record_type"] == "lookup"


def test_replay_human_output_surfaces_context_and_network_boundary(tmp_path: Path) -> None:
    path = tmp_path / "capsule.json"
    _written_capsule(path)
    result = runner.invoke(app, ["capsule", "replay", str(path)])
    assert result.exit_code == 0, result.output
    assert "Observation capsule replay" in result.stdout
    assert "Context match" in result.stdout
    assert "Network calls" in result.stdout
    assert "none" in result.stdout


def test_compare_json_classifies_collection_and_time(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _written_capsule(before, vantage="resolver-a")
    _written_capsule(after, vantage="resolver-b")
    result = runner.invoke(
        app,
        [
            "capsule",
            "compare",
            str(before),
            str(after),
            "--after-as-of",
            "2026-08-14T12:00:03Z",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    delta = json.loads(result.stdout)
    assert delta["record_type"] == "observation_capsule_delta"
    assert delta["observation"]["changed"] is False
    assert delta["collection_regime"]["changed"] is True
    assert delta["time_evaluation"]["changed"] is True
    assert delta["interpretation"]["changed"] is False


def test_compare_human_output_names_four_classes(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _written_capsule(before)
    _written_capsule(after)
    result = runner.invoke(app, ["capsule", "compare", str(before), str(after)])
    assert result.exit_code == 0, result.output
    assert "Observation" in result.stdout
    assert "Collection" in result.stdout
    assert "Time evaluation" in result.stdout
    assert "Interpretation" in result.stdout


def test_replay_rejects_missing_or_malformed_capsule(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["capsule", "replay", str(tmp_path / "missing.json")])
    assert missing.exit_code == EXIT_VALIDATION

    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text("{", encoding="utf-8")
    malformed = runner.invoke(app, ["capsule", "replay", str(malformed_path)])
    assert malformed.exit_code == EXIT_VALIDATION
    assert "Could not load capsule" in malformed.output


def test_replay_rejects_invalid_as_of(tmp_path: Path) -> None:
    path = tmp_path / "capsule.json"
    _written_capsule(path)
    result = runner.invoke(app, ["capsule", "replay", str(path), "--as-of", "tomorrow"])
    assert result.exit_code == EXIT_VALIDATION
    assert "as_of" in result.output
