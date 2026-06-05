"""Regression test for the CT-budget summary writer in validation/scan.py.

scan.py is dev tooling outside the packaged wheel, so it is loaded by path.
The writer previously assumed NDJSON and would miscount (or crash on a list
element) when the batch ran under --json-array, which emits a single
pretty-printed JSON array. It now detects and handles both shapes.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCAN_PATH = Path(__file__).resolve().parents[1] / "validation" / "scan.py"


def _load_scan():
    spec = importlib.util.spec_from_file_location("_validation_scan", _SCAN_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def scan():
    return _load_scan()


def _counts(run_dir: Path) -> dict[str, int]:
    return json.loads((run_dir / "ct_budget_summary.json").read_text(encoding="utf-8"))["outcome_counts"]


def test_json_array_mode_counts_records(scan, tmp_path: Path) -> None:
    records = [
        {"ct_attempt_outcome": "cache_hit"},
        {"ct_attempt_outcome": "fresh"},
        {"queried_domain": "x"},  # no outcome -> not_attempted
    ]
    (tmp_path / "results.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    scan._write_ct_budget_summary(tmp_path / "results.json", tmp_path)
    assert _counts(tmp_path) == {"cache_hit": 1, "fresh": 1, "not_attempted": 1}


def test_empty_json_array_does_not_crash(scan, tmp_path: Path) -> None:
    (tmp_path / "results.json").write_text("[]", encoding="utf-8")
    scan._write_ct_budget_summary(tmp_path / "results.json", tmp_path)
    assert _counts(tmp_path) == {}


def test_ndjson_mode_still_works(scan, tmp_path: Path) -> None:
    lines = [
        json.dumps({"ct_attempt_outcome": "cache_hit"}),
        json.dumps({"ct_attempt_outcome": "cache_hit"}),
        json.dumps({"ct_attempt_outcome": "rate_limited"}),
    ]
    (tmp_path / "results.ndjson").write_text("\n".join(lines) + "\n", encoding="utf-8")
    scan._write_ct_budget_summary(tmp_path / "results.ndjson", tmp_path)
    assert _counts(tmp_path) == {"cache_hit": 2, "rate_limited": 1}
