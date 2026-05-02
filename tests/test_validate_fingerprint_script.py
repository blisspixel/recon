"""Fingerprint validator regressions."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from recon_tool import fingerprint_validator
from recon_tool.cli import app

runner = CliRunner()


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
        "        pattern: \"(a+)+\"\n",
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
    path.write_text(
        "fingerprints:\n"
        "  - name: Example Service\n"
        "    slug: example-service\n"
        "    category: SaaS\n"
        "    confidence: high\n"
        "    detections:\n"
        "      - type: txt\n"
        "        pattern: \"^example-service-verification=\"\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["fingerprints", "check", str(path), "--quiet"])

    assert result.exit_code == 0
    assert "Validated 1 entries: 1 passed, 0 failed" in result.output
