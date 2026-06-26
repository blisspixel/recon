"""Regression test for the CT-budget summary writer in validation/scan.py.

scan.py is dev tooling outside the packaged wheel, so it is loaded by path.
The writer previously assumed NDJSON and would miscount (or crash on a list
element) when the batch ran under --json-array, which emits a single
pretty-printed JSON array. It now detects and handles both shapes.
"""

from __future__ import annotations

import argparse
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


def test_count_result_records_skips_malformed_partial_tail(scan, tmp_path: Path) -> None:
    results = tmp_path / "results.ndjson"
    results.write_text('{"queried_domain":"contoso.com"}\n{"queried_domain":', encoding="utf-8")

    assert scan._count_result_records(results) == 1


def test_scan_output_root_allows_outside_repo(scan, tmp_path: Path) -> None:
    assert scan._validate_scan_output_root(tmp_path) == tmp_path.resolve(strict=False)


def test_scan_output_root_rejects_public_repo_path(scan) -> None:
    with pytest.raises(ValueError, match="validation/runs-private"):
        scan._validate_scan_output_root(scan.REPO_ROOT / "docs" / "scan-output")


def test_private_scan_input_rejects_public_repo_path(scan) -> None:
    with pytest.raises(ValueError, match="runs-private"):
        scan._validate_private_scan_input_path(scan.REPO_ROOT / "validation" / "public-results.ndjson")


def test_private_scan_input_allows_private_repo_path(scan) -> None:
    path = scan.REPO_ROOT / "validation" / "runs-private" / "stamp" / "results.ndjson"
    assert scan._validate_private_scan_input_path(path) == path.resolve(strict=False)


def test_ct_retry_corpus_writes_under_output_root_and_deduplicates(scan, tmp_path: Path) -> None:
    output_root = tmp_path / "runs-private"
    prior = output_root / "prior"
    prior.mkdir(parents=True)
    (prior / "results.ndjson").write_text(
        "\n".join(
            [
                json.dumps({"queried_domain": "contoso.com", "ct_attempt_outcome": "live_rate_limited"}),
                json.dumps({"queried_domain": "fabrikam.com", "ct_attempt_outcome": "breaker_open"}),
                json.dumps({"queried_domain": "contoso.com", "ct_attempt_outcome": "cache_miss"}),
                json.dumps({"queried_domain": "northwindtraders.com", "ct_attempt_outcome": "live_success"}),
                '{"queried_domain":',
            ]
        ),
        encoding="utf-8",
    )

    retry_corpus = scan._synthesize_ct_retry_corpus(prior, output_root)

    assert retry_corpus.parent == output_root / "_inputs"
    assert retry_corpus.read_text(encoding="utf-8").splitlines() == [
        "contoso.com",
        "fabrikam.com",
    ]


def test_ct_retry_corpus_accepts_legacy_json_array(scan, tmp_path: Path) -> None:
    output_root = tmp_path / "runs-private"
    prior = output_root / "prior"
    prior.mkdir(parents=True)
    (prior / "results.json").write_text(
        json.dumps(
            [
                {"queried_domain": "contoso.com", "ct_attempt_outcome": "live_other_failure"},
                {"queried_domain": "fabrikam.com", "ct_attempt_outcome": "cache_hit"},
            ]
        ),
        encoding="utf-8",
    )

    retry_corpus = scan._synthesize_ct_retry_corpus(prior, output_root)

    assert retry_corpus.parent == output_root / "_inputs"
    assert retry_corpus.read_text(encoding="utf-8").splitlines() == ["contoso.com"]


def test_ct_retry_corpus_validates_synthesized_domains(scan, tmp_path: Path) -> None:
    output_root = tmp_path / "runs-private"
    prior = output_root / "prior"
    prior.mkdir(parents=True)
    (prior / "results.ndjson").write_text(
        "\n".join(
            [
                json.dumps({"queried_domain": "contoso.com", "ct_attempt_outcome": "live_rate_limited"}),
                json.dumps({"queried_domain": "contoso.com\nexample.net", "ct_attempt_outcome": "cache_miss"}),
                json.dumps({"queried_domain": "mail.fabrikam.com", "ct_attempt_outcome": "breaker_open"}),
            ]
        ),
        encoding="utf-8",
    )

    retry_corpus = scan._synthesize_ct_retry_corpus(prior, output_root)

    assert retry_corpus.read_text(encoding="utf-8").splitlines() == [
        "contoso.com",
        "fabrikam.com",
    ]


def test_cli_options_reject_finalize_with_ct_retry(scan) -> None:
    args = argparse.Namespace(
        finalize_existing=Path("run"),
        ct_retry_from=Path("prior"),
        timeout=10.0,
        max_runtime=None,
        json_array=False,
    )

    with pytest.raises(ValueError, match="finalize-existing"):
        scan._validate_cli_options(args)


def test_run_batch_passes_timeout_to_recon_batch(scan, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = tmp_path / "domains.txt"
    corpus.write_text("contoso.com\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    seen: dict[str, object] = {}

    class FakePopen:
        pid = 12345
        returncode = 0

        def __init__(self, cmd, *, stdout, stderr, text, cwd, **kwargs):
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            self.stdout = stdout

        def communicate(self, timeout=None):
            seen["timeout"] = timeout
            self.stdout.write('{"queried_domain":"contoso.com"}\n')
            self.stdout.flush()
            return None, ""

    def fake_popen(cmd, **kwargs):
        seen["cmd"] = cmd
        return FakePopen(cmd, **kwargs)

    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)

    result = scan._run_batch(
        corpus,
        run_dir,
        args=argparse.Namespace(concurrency=2, timeout=9.0, max_runtime=None, ct=True, json_array=False),
        domain_count=1,
    )

    cmd = seen["cmd"]
    assert isinstance(cmd, list)
    assert result.completed is True
    assert result.timed_out is False
    assert seen["timeout"] is None
    assert cmd[cmd.index("--timeout") + 1] == "9.0"
    assert scan._count_result_records(result.results_path) == 1


def test_run_batch_finalizes_streamed_partial_on_max_runtime(
    scan, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "domains.txt"
    corpus.write_text("contoso.com\nnorthwind.com\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    class TimeoutPopen:
        pid = 12345
        returncode = None

        def __init__(self, cmd, *, stdout, stderr, text, cwd, **kwargs):
            self.cmd = cmd
            self.stdout = stdout
            self.calls = 0

        def communicate(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                self.stdout.write('{"queried_domain":"contoso.com","ct_attempt_outcome":"cache_hit"}\n')
                self.stdout.flush()
                raise scan.subprocess.TimeoutExpired(self.cmd, timeout)
            self.returncode = -9
            return None, ""

    def noop_terminate(proc: object) -> None:
        return None

    monkeypatch.setattr(scan.subprocess, "Popen", TimeoutPopen)
    monkeypatch.setattr(scan, "_terminate_process_tree", noop_terminate)

    result = scan._run_batch(
        corpus,
        run_dir,
        args=argparse.Namespace(concurrency=1, timeout=15.0, max_runtime=1.0, ct=True, json_array=False),
        domain_count=2,
    )

    assert result.completed is False
    assert result.timed_out is True
    assert scan._count_result_records(result.results_path) == 1


def test_finalize_scan_writes_partial_meta(scan, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = tmp_path / "domains.txt"
    corpus.write_text("contoso.com\nnorthwind.com\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    results = run_dir / "results.ndjson"
    results.write_text('{"queried_domain":"contoso.com","ct_attempt_outcome":"cache_hit"}\n', encoding="utf-8")

    def fake_run_step(cmd, description: str) -> None:
        output = Path(cmd[cmd.index("--output") + 1])
        output.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(scan, "_run_step", fake_run_step)

    scan._finalize_scan(
        scan.FinalizeContext(
            results_path=results,
            run_dir=run_dir,
            stamp="stamp",
            output_root=tmp_path,
            compare_to=None,
            no_compare=False,
            ct=True,
            label="partial",
            corpus=corpus,
            domain_count=2,
            concurrency=1,
            timeout=15.0,
            max_runtime=1.0,
            min_count=3,
            batch_completed=False,
            batch_timed_out=True,
            started_utc="2026-06-26T00:00:00+00:00",
        )
    )

    meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["results_records"] == 1
    assert meta["domain_count"] == 2
    assert meta["batch_completed"] is False
    assert meta["batch_timed_out"] is True
    assert meta["batch_timeout_seconds"] == 15.0
    assert meta["batch_max_runtime_seconds"] == 1.0
    assert meta["compared_to"] is None
    assert _counts(run_dir) == {"cache_hit": 1}
