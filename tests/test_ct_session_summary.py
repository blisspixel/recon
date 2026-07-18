from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SUMMARY_PATH = Path(__file__).resolve().parents[1] / "validation" / "summarize_ct_sessions.py"


def _load_summary():
    spec = importlib.util.spec_from_file_location("_ct_session_summary", _SUMMARY_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def summary():
    return _load_summary()


def _write_run(run_dir: Path, records: list[dict[str, object]], *, malformed_tail: bool = False) -> None:
    run_dir.mkdir(parents=True)
    lines = [json.dumps(record) for record in records]
    if malformed_tail:
        lines.append('{"queried_domain":')
    (run_dir / "results.ndjson").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (run_dir / "meta.json").write_text(
        json.dumps(
            {
                "domain_count": 10,
                "results_records": len(records),
                "batch_completed": False,
                "batch_timed_out": True,
                "ct_enabled": True,
            }
        ),
        encoding="utf-8",
    )


def test_summarize_sessions_deduplicates_by_best_outcome(summary, tmp_path: Path) -> None:
    run_a = tmp_path / "20260626-a"
    run_b = tmp_path / "20260626-b"
    _write_run(
        run_a,
        [
            {"queried_domain": "alpha.invalid", "ct_attempt_outcome": "breaker_open"},
            {"queried_domain": "beta.invalid", "ct_attempt_outcome": "live_success"},
        ],
        malformed_tail=True,
    )
    _write_run(
        run_b,
        [
            {"queried_domain": "alpha.invalid", "ct_attempt_outcome": "cache_hit"},
            {"queried_domain": "gamma.invalid", "ct_attempt_outcome": "live_rate_limited"},
            {"ct_attempt_outcome": "not_attempted"},
        ],
    )

    result = summary.summarize_sessions([run_a, run_b])
    rendered = json.dumps(result)

    assert result["session_count"] == 2
    assert result["record_count"] == 5
    assert result["records_with_domain"] == 4
    assert result["unique_domains_observed"] == 3
    assert result["ct_data_domains"] == 2
    assert result["degraded_or_unresolved_domains"] == 1
    assert result["raw_outcome_counts"] == {
        "breaker_open": 1,
        "cache_hit": 1,
        "live_rate_limited": 1,
        "live_success": 1,
        "not_attempted": 1,
    }
    assert result["best_outcome_counts"] == {
        "cache_hit": 1,
        "live_rate_limited": 1,
        "live_success": 1,
    }
    assert "alpha.invalid" not in rendered
    assert "beta.invalid" not in rendered
    assert "gamma.invalid" not in rendered


def test_summarize_sessions_accepts_legacy_json_array(summary, tmp_path: Path) -> None:
    run_dir = tmp_path / "legacy"
    run_dir.mkdir()
    (run_dir / "results.json").write_text(
        json.dumps(
            [
                {"queried_domain": "alpha.invalid", "ct_attempt_outcome": "live_success"},
                {"queried_domain": "beta.invalid", "ct_attempt_outcome": "cache_miss"},
            ]
        ),
        encoding="utf-8",
    )

    result = summary.summarize_sessions([run_dir])

    assert result["record_count"] == 2
    assert result["ct_data_domains"] == 1
    assert result["best_outcome_counts"] == {"cache_miss": 1, "live_success": 1}


def test_validate_private_path_rejects_public_repo_input(summary) -> None:
    with pytest.raises(ValueError, match="runs-private"):
        summary._validate_private_path(summary.REPO_ROOT / "validation" / "public-run", kind="input")


def test_validate_private_path_rejects_public_repo_output(summary) -> None:
    with pytest.raises(ValueError, match="runs-private"):
        summary._validate_private_path(summary.REPO_ROOT / "docs" / "ct-summary.json", kind="output")
