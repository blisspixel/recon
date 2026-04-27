"""Validation-script regressions."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


def _load_validate_fingerprint_script() -> ModuleType:
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "validate_fingerprint.py"
    spec = importlib.util.spec_from_file_location("validate_fingerprint_script", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load validation script from {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validate_fingerprint = _load_validate_fingerprint_script()


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

    monkeypatch.setattr(validate_fingerprint, "evaluate_pattern", fail_if_called)

    total, passed, failed = validate_fingerprint._validate_file(  # pyright: ignore[reportPrivateUsage]
        path,
        quiet=True,
        skip_specificity=False,
        captured=[],
        slug_sources={},
        specificity_warnings=[],
    )

    assert total == 1
    assert passed == 0
    assert failed == ["fingerprints.yaml: Unsafe Pattern"]
