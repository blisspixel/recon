"""Supplied result admission is finite, atomic and compatible with valid bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from validation import catalog_result_input as inputs


@pytest.mark.parametrize("format_name", ["object", "array", "ndjson"])
def test_valid_formats_preserve_canonical_digest(tmp_path: Path, format_name: str) -> None:
    row = {"domain": "alpha.test", "record_type": "error"}
    text = json.dumps([row]) if format_name == "array" else json.dumps(row)
    if format_name == "ndjson":
        text += "\n" + json.dumps(row)
    path = tmp_path / "results.json"
    raw = text.encode()
    path.write_bytes(raw)
    digest, rows = inputs.load_evaluation_results(path, maximum_records=2, frame=frozenset({"alpha.test"}))
    assert rows == [row] * (2 if format_name == "ndjson" else 1)
    assert digest == hashlib.sha256(path.name.encode() + b"\0" + raw + b"\0").hexdigest()


def test_reduction_uses_the_same_snapshot_that_was_hashed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "results.json"
    raw = b'{"domain":"alpha.test"}'
    path.write_bytes(raw)
    original = inputs.read_bounded_regular_file

    def replace_after_read(path: Path, *, maximum_bytes: int, future_mtime_tolerance_seconds: None):
        result = original(path, maximum_bytes=maximum_bytes, future_mtime_tolerance_seconds=None)
        path.write_bytes(b'{"domain":"outside.test"}')
        return result

    monkeypatch.setattr(inputs, "read_bounded_regular_file", replace_after_read)
    digest, rows = inputs.load_evaluation_results(path, maximum_records=1, frame=frozenset({"alpha.test"}))
    assert rows == [{"domain": "alpha.test"}]
    assert digest == hashlib.sha256(path.name.encode() + b"\0" + raw + b"\0").hexdigest()


def test_oversized_file_is_refused_before_decoding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "results.json"
    path.write_bytes(b" " * 33)
    monkeypatch.setattr(inputs, "MAX_FILE_BYTES", 32)

    def refuse_decode(_text: str) -> object:
        pytest.fail("oversized bytes reached the decoder")

    monkeypatch.setattr(inputs, "_decode", refuse_decode)
    with pytest.raises(ValueError, match="byte limit"):
        inputs.load_evaluation_results(path, maximum_records=1, frame=frozenset())


@pytest.mark.parametrize("total", [20, 21])
def test_aggregate_byte_budget_applies_across_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, total: int
) -> None:
    for index in range(2):
        (tmp_path / f"results-{index}.json").write_bytes(b" " * 21)
    monkeypatch.setattr(inputs, "MAX_TOTAL_BYTES", total)
    with pytest.raises(ValueError, match="byte limit"):
        inputs.load_evaluation_results(tmp_path, maximum_records=1, frame=frozenset())


@pytest.mark.parametrize(
    ("constant", "maximum", "message"),
    [
        ("MAX_FILES", 1, "result-file"),
        ("MAX_ENTRIES", 1, "entry"),
        ("MAX_DIRECTORY_DEPTH", 0, "depth"),
    ],
)
def test_directory_work_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, constant: str, maximum: int, message: str
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "results-1.json").write_text("{}")
    (nested / "results-2.json").write_text("{}")
    monkeypatch.setattr(inputs, constant, maximum)
    with pytest.raises(ValueError, match=message):
        inputs.load_evaluation_results(tmp_path, maximum_records=1, frame=frozenset())


@pytest.mark.parametrize("text", ["[" * 101 + "]" * 101, "[]\n{bad}", "123", "[1]", '{"domain":"outside.test"}'])
def test_malformed_nested_and_outside_inputs_never_become_partial_results(tmp_path: Path, text: str) -> None:
    path = tmp_path / "results.json"
    path.write_text(text)
    with pytest.raises(ValueError, match=r"evaluation|Expecting"):
        inputs.load_evaluation_results(path, maximum_records=1, frame=frozenset({"alpha.test"}))


def test_record_cap_and_file_selection(tmp_path: Path) -> None:
    (tmp_path / "unrelated.ndjson").write_text("bad")
    (tmp_path / "results.json").write_text('[{"domain":"alpha.test"}, {"domain":"alpha.test"}]')
    with pytest.raises(ValueError, match="admitted frame"):
        inputs.load_evaluation_results(tmp_path, maximum_records=1, frame=frozenset({"alpha.test"}))


def test_symlink_result_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "original"
    source.write_text("{}")
    link = tmp_path / "results.json"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symbolic link"):
        inputs.load_evaluation_results(tmp_path, maximum_records=1, frame=frozenset())


@pytest.mark.parametrize("role", ["development", "holdout"])
def test_rejected_input_cannot_create_evaluation_or_consume_holdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    from recon_tool.json_limits import is_json_object
    from validation import catalog_maintenance as workflow
    from validation import catalog_maintenance_round as rounds
    from validation.prepare_catalog_round import catalog_digest_sha256

    seed = tmp_path / "seed"
    workflow.demo(seed)
    plan_path = seed / "demo-inputs/catalog-maintenance-plan.json"
    plan: object = json.loads(plan_path.read_text())
    assert is_json_object(plan)
    plan.update(role=role)
    if role == "holdout":
        plan.update(development_frame="development.txt", candidate_catalog_digest=catalog_digest_sha256())
        (plan_path.parent / "development.txt").write_text("development.test\n")
    plan_path.write_text(json.dumps(plan))
    root = tmp_path / "evaluation"
    rounds.prepare_admission(plan_path, root)
    path = tmp_path / "results.ndjson"
    path.write_bytes(b" " * 33)
    monkeypatch.setattr(inputs, "MAX_FILE_BYTES", 32)
    admission = root / "rounds/synthetic-demo-v1/admission.json"
    with pytest.raises(ValueError, match="byte limit"):
        workflow.evaluate(admission, path)
    assert not (admission.parent / "evaluations").exists()
    assert not (admission.parent / "holdout-evaluation-started.json").exists()
    assert not (root / "holdouts").exists()
