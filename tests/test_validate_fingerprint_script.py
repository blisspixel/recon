"""Fingerprint validator regressions."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from recon_tool import fingerprint_validator
from recon_tool.cli import app

runner = CliRunner()


def _fingerprint_yaml(
    *,
    name: str = "Example Service",
    slug: str = "example-service",
    pattern: str = "^example-service-verification=",
) -> str:
    return (
        "fingerprints:\n"
        f"  - name: {name}\n"
        f"    slug: {slug}\n"
        "    category: SaaS\n"
        "    confidence: high\n"
        "    detections:\n"
        "      - type: txt\n"
        f'        pattern: "{pattern}"\n'
    )


def test_validate_file_skips_specificity_for_schema_rejected_pattern(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "fingerprints.yaml"
    path.write_text(
        "fingerprints:\n"
        "  - name: Unsafe Pattern\n"
        "    slug: unsafe-pattern\n"
        "    category: SaaS\n"
        "    confidence: high\n"
        "    detections:\n"
        "      - type: txt\n"
        '        pattern: "(a+)+"\n',
        encoding="utf-8",
    )

    def fail_if_called(pattern: str, detection_type: str):  # pragma: no cover - only runs on regression
        raise AssertionError(f"unexpected specificity call for {detection_type}:{pattern}")

    monkeypatch.setattr(fingerprint_validator, "evaluate_pattern", fail_if_called)

    total, passed, failed = fingerprint_validator._validate_file(  # pyright: ignore[reportPrivateUsage]
        path,
        quiet=True,
        skip_specificity=False,
        captured=[],
        slug_sources={},
        slug_names={},
        specificity_warnings=[],
    )

    assert total == 1
    assert passed == 0
    assert failed == ["fingerprints.yaml: Unsafe Pattern"]


def test_fingerprints_check_uses_packaged_validator(tmp_path: Path) -> None:
    path = tmp_path / "fingerprints.yaml"
    path.write_text(_fingerprint_yaml(), encoding="utf-8")

    result = runner.invoke(app, ["fingerprints", "check", str(path), "--quiet"])

    assert result.exit_code == 0
    assert "Validated 1 entries: 1 passed, 0 failed" in result.output


def test_validate_path_missing_path_returns_validation_code(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = fingerprint_validator.validate_path(tmp_path / "missing.yaml", quiet=True)

    captured = capsys.readouterr()
    assert code == 2
    assert "does not exist" in captured.err


def test_validate_path_rejects_invalid_yaml(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "fingerprints.yaml"
    path.write_text("fingerprints:\n  - name: [unterminated\n", encoding="utf-8")

    code = fingerprint_validator.validate_path(path, quiet=True)

    captured = capsys.readouterr()
    assert code == 1
    assert "invalid YAML" in captured.err
    assert "Validated 0 entries: 0 passed, 1 failed" in captured.out


def test_validate_path_rejects_unsupported_yaml_shape(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "fingerprints.yaml"
    path.write_text("not_fingerprints: []\n", encoding="utf-8")

    code = fingerprint_validator.validate_path(path, quiet=True)

    captured = capsys.readouterr()
    assert code == 1
    assert "must be either a list of fingerprints or a dict" in captured.err


def test_validate_path_rejects_non_list_fingerprints_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "fingerprints.yaml"
    path.write_text("fingerprints: nope\n", encoding="utf-8")

    code = fingerprint_validator.validate_path(path, quiet=True)

    captured = capsys.readouterr()
    assert code == 1
    assert "must be a list" in captured.err


def test_validate_path_rejects_empty_directory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = fingerprint_validator.validate_path(tmp_path, quiet=True)

    captured = capsys.readouterr()
    assert code == 2
    assert "no *.yaml files found" in captured.err


def test_validate_path_accepts_bare_list_and_prints_success_when_not_quiet(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "fingerprints.yaml"
    path.write_text(
        "- name: Example Service\n"
        "  slug: example-service\n"
        "  category: SaaS\n"
        "  confidence: high\n"
        "  detections:\n"
        "    - type: txt\n"
        '      pattern: "^example-service-verification="\n',
        encoding="utf-8",
    )

    code = fingerprint_validator.validate_path(path, quiet=False)

    captured = capsys.readouterr()
    assert code == 0
    assert "ok    fingerprints.yaml: Example Service" in captured.out
    assert "Validated 1 entries: 1 passed, 0 failed" in captured.out


def test_validate_path_reports_specificity_failures(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "fingerprints.yaml"
    path.write_text(_fingerprint_yaml(name="Broad Service", slug="broad-service", pattern=".*"), encoding="utf-8")

    code = fingerprint_validator.validate_path(path, quiet=False)

    captured = capsys.readouterr()
    assert code == 1
    assert "over-broad pattern" in captured.err
    assert "Specificity failures:" in captured.out


def test_validate_path_can_skip_specificity_gate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "fingerprints.yaml"
    path.write_text(_fingerprint_yaml(name="Broad Service", slug="broad-service", pattern=".*"), encoding="utf-8")

    code = fingerprint_validator.validate_path(path, quiet=True, skip_specificity=True)

    captured = capsys.readouterr()
    assert code == 0
    assert "over-broad pattern" not in captured.err
    assert "Validated 1 entries: 1 passed, 0 failed" in captured.out


def test_validate_path_reports_duplicate_slug_with_different_names(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = tmp_path / "a.yaml"
    second = tmp_path / "b.yaml"
    first.write_text(_fingerprint_yaml(name="First Service", slug="same-slug"), encoding="utf-8")
    second.write_text(_fingerprint_yaml(name="Second Service", slug="same-slug"), encoding="utf-8")

    code = fingerprint_validator.validate_path(tmp_path, quiet=True)

    captured = capsys.readouterr()
    assert code == 1
    assert "Duplicate slugs: 1" in captured.err
    assert "same-slug" in captured.err
    assert "First Service" in captured.err
    assert "Second Service" in captured.err


def test_validate_path_allows_duplicate_slug_with_same_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = tmp_path / "a.yaml"
    second = tmp_path / "b.yaml"
    first.write_text(_fingerprint_yaml(name="Same Service", slug="same-slug"), encoding="utf-8")
    second.write_text(
        _fingerprint_yaml(name="Same Service", slug="same-slug", pattern="^same-service-verification="),
        encoding="utf-8",
    )

    code = fingerprint_validator.validate_path(tmp_path, quiet=True)

    captured = capsys.readouterr()
    assert code == 0
    assert "Duplicate slugs" not in captured.err
    assert "Validated 2 entries: 2 passed, 0 failed" in captured.out


def test_main_delegates_to_validate_path(tmp_path: Path) -> None:
    path = tmp_path / "fingerprints.yaml"
    path.write_text(_fingerprint_yaml(), encoding="utf-8")

    assert fingerprint_validator.main([str(path), "--quiet"]) == 0
