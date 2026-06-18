"""Validation hygiene guard regressions."""

from __future__ import annotations

from pathlib import Path

from scripts import check_validation_hygiene


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_private_run_paths_fail_even_if_forced_into_git(tmp_path: Path) -> None:
    paths = [
        "validation/live_runs/20260618/results.json",
        "validation/runs-private/20260618/results.json",
        "validation/corpus-private/saas.txt",
    ]

    violations = check_validation_hygiene.find_violations(tmp_path, paths)

    assert [violation.path for violation in violations] == paths
    assert all("private validation corpus or run output" in violation.detail for violation in violations)


def test_root_per_domain_json_dump_fails(tmp_path: Path) -> None:
    violations = check_validation_hygiene.find_violations(tmp_path, ["acme.com.json"])

    assert len(violations) == 1
    assert violations[0].path == "acme.com.json"
    assert "root per-domain JSON dump" in violations[0].detail


def test_target_domain_fields_fail_in_committed_validation_artifact(tmp_path: Path) -> None:
    _write(tmp_path, "validation/new-calibration.md", "queried_domain: acme.com\n")

    violations = check_validation_hygiene.find_violations(tmp_path, ["validation/new-calibration.md"])

    assert len(violations) == 1
    assert violations[0].line == 1
    assert "acme.com" in violations[0].detail


def test_recon_example_with_real_domain_fails(tmp_path: Path) -> None:
    _write(tmp_path, "validation/new-runbook.md", "Run `recon acme.com --json` locally.\n")

    violations = check_validation_hygiene.find_violations(tmp_path, ["validation/new-runbook.md"])

    assert len(violations) == 1
    assert "recon example uses a non-fictional domain" in violations[0].detail


def test_validation_corpus_lines_must_be_fictional_or_reserved(tmp_path: Path) -> None:
    _write(tmp_path, "validation/corpus-example.txt", "contoso.com\nexample.org\nacme.com\n")

    violations = check_validation_hygiene.find_violations(tmp_path, ["validation/corpus-example.txt"])

    assert len(violations) == 1
    assert "acme.com" in violations[0].detail


def test_synthetic_and_fictional_validation_artifacts_pass(tmp_path: Path) -> None:
    _write(tmp_path, "validation/new-calibration.md", "queried_domain: contoso.com\nRun `recon example.com`.\n")
    _write(tmp_path, "validation/synthetic_corpus/fixtures/sample.json", '{"queried_domain": "acme.com"}\n')

    violations = check_validation_hygiene.find_violations(
        tmp_path,
        ["validation/new-calibration.md", "validation/synthetic_corpus/fixtures/sample.json"],
    )

    assert violations == []
