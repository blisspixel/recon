# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportAttributeAccessIssue=none, reportIndexIssue=none, reportOperatorIssue=none
# pyright: reportUnknownArgumentType=none, reportUnknownMemberType=none, reportUnknownVariableType=none
"""Offline admission, disclosure and one-use holdout contracts."""

from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any

import pytest

from validation import catalog_maintenance as workflow
from validation import catalog_maintenance_round as rounds
from validation.catalog_receipts import read_json
from validation.prepare_catalog_round import REPO_ROOT, catalog_digest_sha256, digest_bytes


def _fixture(tmp_path: Path, **changes: Any) -> tuple[Path, Path]:
    inputs = tmp_path / "inputs"
    inputs.mkdir(parents=True)
    for name in ("plan", "round", "attributes"):
        source = REPO_ROOT / f"docs/examples/catalog-maintenance-{name}.json"
        (inputs / source.name).write_bytes(source.read_bytes())
    (inputs / "community.txt").write_text("alpha.test\nwww.alpha.test\nbeta.test\n", encoding="ascii")
    (inputs / "institution.txt").write_text("gamma.test\n", encoding="ascii")
    plan_path = inputs / "catalog-maintenance-plan.json"
    plan = read_json(plan_path)
    plan.update(changes)
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    return plan_path, tmp_path / "private-state"


def _path(root: Path) -> Path:
    return root / "rounds/synthetic-demo-v1/admission.json"


def test_public_offline_example_is_repeatable_private_and_explicitly_incomplete(tmp_path: Path) -> None:
    receipt = workflow.demo(tmp_path)
    original = (tmp_path / "offline-demo.json").read_bytes()
    assert workflow.demo(tmp_path) == receipt
    assert (tmp_path / "offline-demo.json").read_bytes() == original
    assert receipt["network_calls"] == 0
    assert all(receipt["controls"].values())
    assert receipt["sampling"]["missing_strata"] == ["commerce"]
    assert receipt["sampling"]["namespaces"] == 3
    assert receipt["sampling"]["normalized_duplicates_removed"] == 1
    assert receipt["sampling"]["declared_dependency_groups"] == 1
    assert receipt["sampling"]["independent_sample_size"] is None
    assert receipt["sampling"]["unknown_attributes"]["scale"] == 3
    lesson = receipt["failure_lesson"]
    assert lesson["completion"]["unfinished_start_unknown"] == 2
    assert lesson["completion"]["known_unattempted"] == 0
    assert lesson["typed_aggregate"]["measured_input_records"] == 0
    assert all(row["classified_rate"] is None for row in lesson["typed_aggregate"]["record_types"].values())
    assert receipt["promotion"] == "none"
    assert "20_row_minimum" in receipt["stratified_publication"]


def test_admission_freezes_source_bytes_strata_vintage_and_exclusions(tmp_path: Path) -> None:
    plan, root = _fixture(tmp_path)
    admitted = rounds.prepare_admission(plan, root)
    prepared = admitted["prepared"]
    frozen_plan = read_json(_path(root).parent / "maintenance-plan.json")
    assert rounds.canonical_json_digest(frozen_plan) == admitted["plan_digest"]
    assert prepared["frame"]["count"] == 3
    assert prepared["sampling"]["unknown_dependency_namespaces"] == 1
    (plan.parent / "community.txt").write_text("changed.test\n", encoding="ascii")
    assert rounds.prepare_admission(plan, root) == admitted
    frozen = read_json(Path(prepared["round_plan"]))
    assert frozen["source"]["revision"] == "2026-10-23 synthetic v1"
    assert Path(frozen["strata"][0]["input"]).read_text(encoding="ascii").startswith("alpha.test\n")
    for archive in prepared["archives"]:
        assert digest_bytes(Path(archive["frozen"]).read_bytes()) == archive["sha256"]


def test_frozen_attributes_cannot_change_after_admission(tmp_path: Path) -> None:
    plan, root = _fixture(tmp_path)
    admitted = rounds.prepare_admission(plan, root)
    Path(admitted["attribute_archive"]["frozen"]).write_text('{"schema_version":1,"rows":[]}')
    with pytest.raises(ValueError, match="frozen maintenance source changed"):
        rounds.collect_admission(_path(root), attempt=1, allow_network=True)


def test_changed_admission_and_interrupted_preparation_are_never_overwritten(tmp_path: Path) -> None:
    plan, root = _fixture(tmp_path)
    rounds.prepare_admission(plan, root)
    original = _path(root).read_bytes()
    data = read_json(plan)
    data["budgets"]["max_namespaces"] += 1
    plan.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="admitted plan changed"):
        rounds.prepare_admission(plan, root)
    assert _path(root).read_bytes() == original
    _path(root).unlink()  # Reproduce an interrupted prepare with only its durable reservation.
    with pytest.raises(ValueError, match="already exists"):
        rounds.prepare_admission(plan, root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_namespaces", 2),
        ("max_dns_queries", 0),
        ("concurrency", True),
        ("max_attempts", 1.0),
        ("namespace_timeout_seconds", -1),
    ],
)
def test_malformed_or_exhausted_budgets_refuse_admission(tmp_path: Path, field: str, value: object) -> None:
    plan, root = _fixture(tmp_path)
    data = read_json(plan)
    data["budgets"][field] = value
    plan.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match=r"maintenance|normalized frame|positive"):
        rounds.prepare_admission(plan, root)
    assert not _path(root).exists()


def test_exclusions_are_executed_without_replacing_or_expanding_targets(tmp_path: Path) -> None:
    plan, root = _fixture(tmp_path, exclusions=["excluded.txt"])
    (plan.parent / "excluded.txt").write_text("beta.test\n", encoding="ascii")
    with pytest.raises(ValueError, match="overlaps exclusions"):
        rounds.prepare_admission(plan, root)
    assert not _path(root).exists()


@pytest.mark.parametrize("member", ["alpha.test", "www.alpha.test", "outside.test"])
def test_duplicate_subhost_or_outside_attribute_rows_are_rejected(tmp_path: Path, member: str) -> None:
    plan, root = _fixture(tmp_path)
    attributes = plan.parent / "catalog-maintenance-attributes.json"
    data = read_json(attributes)
    data["rows"].append({"domain": member, "basis": "Explicit malformed fixture row."})
    attributes.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="attribute rows"):
        rounds.prepare_admission(plan, root)


def test_collection_is_explicit_bounded_and_attempts_never_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, root = _fixture(tmp_path)
    rounds.prepare_admission(plan, root)
    calls = []

    def collect(command: list[str], **kwargs: Any) -> CompletedProcess[str]:
        calls.append(command)
        assert (_path(root).parent / "attempt-01-started.json").exists()
        return CompletedProcess(command, 75)

    monkeypatch.setattr(rounds.subprocess, "run", collect)
    with pytest.raises(ValueError, match="allow-network"):
        rounds.collect_admission(_path(root), attempt=1)
    assert not calls
    result = rounds.collect_admission(_path(root), attempt=1, allow_network=True)
    assert result["returncode"] == 75
    assert "--ct" not in calls[0]
    assert "--direct-probes" not in calls[0]
    assert calls[0][calls[0].index("--max-dns-queries") + 1] == "100"
    assert calls[0][calls[0].index("--max-runtime") + 1] == "600"
    original = (_path(root).parent / "attempt-01-started.json").read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        rounds.collect_admission(_path(root), attempt=1, allow_network=True)
    rounds.collect_admission(_path(root), attempt=2, allow_network=True)
    assert len(calls) == 2
    assert (_path(root).parent / "attempt-01-started.json").read_bytes() == original
    assert read_json(_path(root).parent / "attempt-02-started.json")["retry_of"] == 1
    with pytest.raises(ValueError, match="outside"):
        rounds.collect_admission(_path(root), attempt=3, allow_network=True)


def test_runtime_overlay_or_frame_changes_refuse_collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan, root = _fixture(tmp_path)
    admission = rounds.prepare_admission(plan, root)
    monkeypatch.setattr(rounds, "runtime_context", lambda: {"fingerprints": "changed"})
    with pytest.raises(ValueError, match="runtime context changed"):
        rounds.collect_admission(_path(root), attempt=1, allow_network=True)

    def original_context() -> dict[str, object]:
        return admission["runtime_context"]

    monkeypatch.setattr(rounds, "runtime_context", original_context)
    Path(admission["prepared"]["frame"]["path"]).write_text("other.test\n", encoding="ascii")
    with pytest.raises(ValueError, match="frame changed"):
        rounds.collect_admission(_path(root), attempt=1, allow_network=True)


def test_interrupted_attempt_needs_offline_finalization_before_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from validation.catalog_receipts import write_private_event

    plan, root = _fixture(tmp_path)
    admitted = rounds.prepare_admission(plan, root)
    campaign = _path(root).parent
    output = campaign / "attempt-01"
    run_dir = output / "retained-run"
    write_private_event(campaign / "attempt-01-started.json", {"attempt": 1, "output": str(output)})
    started = (campaign / "attempt-01-started.json").read_bytes()
    with pytest.raises(ValueError, match="still running or interrupted"):
        rounds.collect_admission(_path(root), attempt=2, allow_network=True)

    def offline(command: list[str], **_kwargs: Any) -> CompletedProcess[str]:
        assert command[1:3] == ["-m", "validation.scan"]
        assert command[command.index("--finalize-existing") + 1] == str(run_dir)
        manifest = read_json(Path(admitted["prepared"]["manifest"]))
        write_private_event(
            run_dir / "meta.json",
            {
                "corpus_path": admitted["prepared"]["frame"]["path"],
                "round_manifest_digest_sha256": manifest["manifest_digest_sha256"],
                "scan_finalized_utc": "2026-10-23T12:00:00Z",
                "batch_completed": False,
                "collection_completion": {"availability": "unavailable"},
            },
            idempotent=True,
        )
        return CompletedProcess(command, 0)

    monkeypatch.setattr(rounds.subprocess, "run", offline)
    receipt = rounds.finalize_admission(_path(root), attempt=1, run_dir=run_dir)
    assert receipt["collection_returncode"] is None
    assert receipt["batch_completed"] is False
    assert (campaign / "attempt-01-started.json").read_bytes() == started
    assert rounds.finalize_admission(_path(root), attempt=1, run_dir=run_dir) == receipt
    with pytest.raises(ValueError, match="outside the original"):
        rounds.finalize_admission(_path(root), attempt=1, run_dir=tmp_path / "other-run")


def test_consumed_holdout_cannot_be_relabelled_reordered_retried_or_used_for_development(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, root = _fixture(
        tmp_path, role="holdout", development_frame="development.txt", candidate_catalog_digest=catalog_digest_sha256()
    )
    (plan.parent / "development.txt").write_text("development.test\n", encoding="ascii")
    rounds.prepare_admission(plan, root)

    def collect(command: list[str], **_kwargs: Any) -> CompletedProcess[str]:
        return CompletedProcess(command, 1)

    monkeypatch.setattr(rounds.subprocess, "run", collect)
    rounds.collect_admission(_path(root), attempt=1, allow_network=True)
    assert len(list((root / "holdouts").glob("*.json"))) == 3
    with pytest.raises(ValueError, match="cannot be retried"):
        rounds.collect_admission(_path(root), attempt=2, allow_network=True)
    data = read_json(plan)
    data.update(id="renamed", role="development")
    plan.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="consumed holdout"):
        rounds.prepare_admission(plan, root)


def test_failed_artifact_evaluation_preserves_nulls_and_one_results_identity(tmp_path: Path) -> None:
    plan, root = _fixture(tmp_path)
    rounds.prepare_admission(plan, root)
    results = tmp_path / "results.ndjson"
    results.write_text(json.dumps({"record_type": "error", "domain": "alpha.test", "error_kind": "timeout"}) + "\n")
    receipt = workflow.evaluate(_path(root), results)
    assert receipt["status"] == "blocked"
    assert receipt["completion"]["unfinished_start_unknown"] == 2
    assert receipt["aggregate"]["measured_input_records"] == 0
    assert workflow.evaluate(_path(root), results) == receipt
    results.write_text(json.dumps({"record_type": "error", "domain": "beta.test", "error_kind": "timeout"}) + "\n")
    with pytest.raises(ValueError, match="consumed different results"):
        workflow.evaluate(_path(root), results)


@pytest.mark.parametrize(
    "paths",
    [
        ["validation/runs-private/raw.json"],
        ["validation/corpus-private/input.txt"],
        ["validation/**"],
        ["."],
        [".agent/private.json"],
        ["../outside.json"],
    ],
)
def test_publication_guard_catches_commit_and_upload_selection(paths: list[str]) -> None:
    with pytest.raises(ValueError, match="publication"):
        workflow.check_publication_paths(paths)


def test_publication_guard_accepts_only_explicit_reviewed_public_files() -> None:
    receipt = workflow.check_publication_paths(["README.md", "docs/catalog-maintenance.md"])
    assert receipt["status"] == "paths_checked"
    assert receipt["content_review"] == "still_required"


def test_documentation_mode_has_no_collection_or_measured_cohort(tmp_path: Path) -> None:
    plan, root = _fixture(tmp_path, role="documentation", round_plan=None, attributes_file=None)
    admission = rounds.prepare_admission(plan, root)
    assert admission["prepared"] == {}
    with pytest.raises(ValueError, match="outside"):
        rounds.collect_admission(_path(root), attempt=1, allow_network=True)
    with pytest.raises(ValueError, match="no measured cohort"):
        workflow.evaluate(_path(root), tmp_path)
