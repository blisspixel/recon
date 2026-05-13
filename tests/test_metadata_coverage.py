"""Tests for the v1.9.7 metadata-coverage CI gate script.

The gate flipped from a percentage threshold to a presence check in
v1.9.7. Every detection in every category must carry a non-empty
``description`` field, or the script exits non-zero.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_metadata_coverage.py"


def _make_corpus(
    tmp_path: Path,
    detections_per_category: dict[str, list[dict]],
) -> Path:
    """Materialize a synthetic fingerprints/ directory."""
    out = tmp_path / "fp"
    out.mkdir()
    for category, detections in detections_per_category.items():
        # Pick a filename that maps to the requested category. The
        # script's _FILENAME_TO_CATEGORY maps surface.yaml to
        # infrastructure; for 'infrastructure' we use that filename.
        filename = f"{category}.yaml"
        spec = {
            "fingerprints": [
                {
                    "name": f"fp-{i}",
                    "slug": f"slug-{category}-{i}",
                    "category": category,
                    "confidence": "medium",
                    "detections": [d],
                }
                for i, d in enumerate(detections)
            ]
        }
        (out / filename).write_text(yaml.safe_dump(spec), encoding="utf-8")
    return out


def _run_script(corpus_dir: Path, *extra_args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 — argv list, no shell.
        [
            sys.executable,
            str(SCRIPT),
            "--fingerprints-dir",
            str(corpus_dir),
            *extra_args,
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        check=False,
    )


class TestCoverageGate:
    def test_passes_when_every_detection_has_description(self, tmp_path: Path) -> None:
        """v1.9.7 gate: every detection in every category has a
        non-empty description.
        """
        corpus = _make_corpus(
            tmp_path,
            {
                "identity": [
                    {"type": "txt", "pattern": "identity-1", "description": "ok"},
                    {"type": "txt", "pattern": "identity-2", "description": "ok"},
                ],
                "security": [
                    {"type": "txt", "pattern": "security-1", "description": "ok"},
                ],
                "infrastructure": [
                    {"type": "txt", "pattern": "infra-1", "description": "ok"},
                ],
                "ai": [
                    {"type": "txt", "pattern": "ai-1", "description": "ok"},
                ],
            },
        )
        result = _run_script(corpus)
        assert result.returncode == 0, result.stderr

    def test_fails_when_any_detection_missing_description(self, tmp_path: Path) -> None:
        """One missing description anywhere fails the gate."""
        corpus = _make_corpus(
            tmp_path,
            {
                "security": [
                    {"type": "txt", "pattern": "sec-1", "description": "ok"},
                    {"type": "txt", "pattern": "sec-2"},  # missing description
                ],
            },
        )
        result = _run_script(corpus)
        assert result.returncode == 1
        # Failure message names the slug + pattern that needs a fix.
        assert "sec-2" in result.stderr or "slug-security-1" in result.stderr

    def test_report_only_returns_zero_even_on_failure(self, tmp_path: Path) -> None:
        corpus = _make_corpus(
            tmp_path,
            {
                "security": [
                    {"type": "txt", "pattern": "sec-1"},
                    {"type": "txt", "pattern": "sec-2"},
                ],
            },
        )
        result = _run_script(corpus, "--report-only")
        assert result.returncode == 0

    def test_non_gated_categories_still_gate_in_v197(self, tmp_path: Path) -> None:
        """v1.9.0 had only three gated categories (identity, security,
        infrastructure); v1.9.7 gates every category. A missing
        description in ai is now a failure.
        """
        corpus = _make_corpus(
            tmp_path,
            {
                "ai": [
                    {"type": "txt", "pattern": "ai-1"},
                    {"type": "txt", "pattern": "ai-2"},
                ],
            },
        )
        result = _run_script(corpus)
        assert result.returncode == 1
        assert "ai-1" in result.stderr or "slug-ai-0" in result.stderr

    def test_reports_per_category_table(self, tmp_path: Path) -> None:
        corpus = _make_corpus(
            tmp_path,
            {
                "identity": [{"type": "txt", "pattern": "id-1", "description": "ok"}],
                "ai": [{"type": "txt", "pattern": "ai-1", "description": "ok"}],
            },
        )
        result = _run_script(corpus)
        assert "identity" in result.stdout
        assert "ai" in result.stdout
        assert "category" in result.stdout

    def test_failure_lists_exact_gap_locations(self, tmp_path: Path) -> None:
        """Per-detection gap report on failure: the script emits the
        exact slug and detection pattern of every detection missing a
        description, grouped by category. Contributors see "fix these
        N entries" rather than a percentage drop.
        """
        corpus = _make_corpus(
            tmp_path,
            {
                "security": [
                    {"type": "txt", "pattern": "sec-with-desc", "description": "ok"},
                    {"type": "txt", "pattern": "sec-missing-1"},
                    {"type": "mx", "pattern": "sec-missing-2"},
                ],
            },
        )
        result = _run_script(corpus)
        assert result.returncode == 1
        # Both missing detections show in the gap report.
        assert "sec-missing-1" in result.stderr
        assert "sec-missing-2" in result.stderr
        # The detection-with-description does not appear in the gap report
        # (it's in the stdout summary, but not in the stderr failure list).
        assert "sec-with-desc" not in result.stderr

    def test_invalid_directory(self, tmp_path: Path) -> None:
        result = _run_script(tmp_path / "does-not-exist")
        assert result.returncode == 2
        assert "not a directory" in result.stderr

    def test_handles_missing_detections_gracefully(self, tmp_path: Path) -> None:
        # A file with no detections (e.g. relationship-metadata-only) is
        # not a failure: it simply contributes zero detections.
        corpus_dir = tmp_path / "fp"
        corpus_dir.mkdir()
        (corpus_dir / "identity.yaml").write_text(
            yaml.safe_dump({"fingerprints": [{"name": "x", "slug": "x", "category": "identity"}]}),
            encoding="utf-8",
        )
        result = _run_script(corpus_dir)
        # No detections anywhere means no gaps; the gate passes.
        assert result.returncode == 0

    def test_handles_malformed_yaml(self, tmp_path: Path) -> None:
        # A file that is a list rather than a mapping is silently skipped.
        corpus_dir = tmp_path / "fp"
        corpus_dir.mkdir()
        (corpus_dir / "identity.yaml").write_text("- item1\n- item2\n", encoding="utf-8")
        result = _run_script(corpus_dir)
        assert result.returncode == 0

    def test_runs_against_shipped_catalog(self) -> None:
        """v1.9.7+: the shipped catalog is at 100 percent description
        coverage, so the gate must exit 0 without ``--report-only``.
        """
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
        assert result.returncode == 0, (
            "Shipped catalog must be at 100 percent description coverage. "
            f"Script output:\n{result.stdout}\n{result.stderr}"
        )
