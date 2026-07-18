from __future__ import annotations

import json
from pathlib import Path

import pytest

from validation.run_corpus import (
    REPO_ROOT,
    _load_excluded_domains,
    _validate_output_dir,
    _write_filtered_manifest,
)


@pytest.mark.parametrize("private_name", ["runs-private", "live_runs", "local"])
def test_run_corpus_allows_private_validation_roots(private_name: str) -> None:
    output = REPO_ROOT / "validation" / private_name / "synthetic-run"

    assert _validate_output_dir(output) == output.resolve(strict=False)


def test_run_corpus_rejects_public_repository_output() -> None:
    output = REPO_ROOT / "validation" / "published-run"

    with pytest.raises(ValueError, match="private validation output root"):
        _validate_output_dir(output)


def test_run_corpus_allows_operator_path_outside_repository(tmp_path: Path) -> None:
    output = tmp_path / "private-run"

    assert _validate_output_dir(output) == output.resolve(strict=False)


def test_run_corpus_filters_prior_results_into_private_manifest(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("alpha.invalid\nsub.beta.invalid\nbeta.invalid\n", encoding="utf-8")
    prior = tmp_path / "prior"
    prior.mkdir()
    (prior / "results-1.json").write_text(
        json.dumps([{"queried_domain": "alpha.invalid"}]),
        encoding="utf-8",
    )
    output = tmp_path / "private-output"
    output.mkdir()

    excluded = _load_excluded_domains([prior])
    manifest, scheduled, excluded_rows = _write_filtered_manifest(corpus, output, excluded)

    assert scheduled == 1
    assert excluded_rows == 1
    assert manifest.read_text(encoding="utf-8") == "beta.invalid\n"


def test_run_corpus_loads_nested_ndjson_exclusions(tmp_path: Path) -> None:
    prior = tmp_path / "prior" / "nested"
    prior.mkdir(parents=True)
    (prior / "results.ndjson").write_text(
        "\n".join(
            [
                json.dumps({"queried_domain": "alpha.invalid"}),
                json.dumps({"domain": "sub.beta.invalid", "error_kind": "timeout", "record_type": "error"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    excluded = _load_excluded_domains([tmp_path / "prior"])

    assert excluded == {"alpha.invalid", "beta.invalid"}


def test_run_corpus_filtered_manifest_rejects_malformed_domain(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("valid.example\ninvalid.example;command\n", encoding="utf-8")
    output = tmp_path / "private-output"
    output.mkdir()

    with pytest.raises(ValueError, match="Malformed domain in corpus row 2"):
        _write_filtered_manifest(corpus, output, set())


def test_run_corpus_filtered_manifest_applies_limit_after_exclusions(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("alpha.invalid\nbeta.invalid\ngamma.invalid\n", encoding="utf-8")
    output = tmp_path / "private-output"
    output.mkdir()

    manifest, scheduled, excluded_rows = _write_filtered_manifest(
        corpus,
        output,
        {"alpha.invalid"},
        limit=1,
    )

    assert scheduled == 1
    assert excluded_rows == 1
    assert manifest.read_text(encoding="utf-8") == "beta.invalid\n"
