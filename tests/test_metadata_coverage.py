"""Tests for the v1.9 metadata-coverage CI gate script."""

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
        # script's _FILENAME_TO_CATEGORY maps surface.yaml → infrastructure;
        # for 'infrastructure' we use that filename for one of the cases.
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
    def test_passes_when_all_gated_at_threshold(self, tmp_path: Path) -> None:
        """All detections in identity/security/infrastructure have descriptions."""
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
            },
        )
        result = _run_script(corpus)
        assert result.returncode == 0, result.stderr

    def test_fails_when_security_below_threshold(self, tmp_path: Path) -> None:
        # Two detections, only one with description → 50% < 70%.
        corpus = _make_corpus(
            tmp_path,
            {
                "security": [
                    {"type": "txt", "pattern": "sec-1", "description": "ok"},
                    {"type": "txt", "pattern": "sec-2"},  # no description
                ],
            },
        )
        result = _run_script(corpus)
        assert result.returncode == 1
        assert "security" in result.stderr
        assert "below threshold" in result.stderr

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

    def test_threshold_flag_lowered(self, tmp_path: Path) -> None:
        # 50% security → fails at default 70% but passes at 50%.
        corpus = _make_corpus(
            tmp_path,
            {
                "security": [
                    {"type": "txt", "pattern": "sec-1", "description": "ok"},
                    {"type": "txt", "pattern": "sec-2"},
                ],
            },
        )
        fail = _run_script(corpus)
        assert fail.returncode == 1
        ok = _run_script(corpus, "--threshold", "0.5")
        assert ok.returncode == 0

    def test_non_gated_categories_do_not_fail(self, tmp_path: Path) -> None:
        # ai is not in the gated list — even at 0% it passes.
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
        assert result.returncode == 0

    def test_reports_per_category_table(self, tmp_path: Path) -> None:
        corpus = _make_corpus(
            tmp_path,
            {
                "identity": [{"type": "txt", "pattern": "id-1", "description": "ok"}],
                "ai": [{"type": "txt", "pattern": "ai-1"}],
            },
        )
        result = _run_script(corpus)
        assert "identity" in result.stdout
        assert "ai" in result.stdout
        assert "category" in result.stdout

    def test_invalid_directory(self, tmp_path: Path) -> None:
        result = _run_script(tmp_path / "does-not-exist")
        assert result.returncode == 2
        assert "not a directory" in result.stderr

    def test_handles_missing_detections_gracefully(self, tmp_path: Path) -> None:
        # A file with no detections (e.g. relationship-metadata-only) is
        # not a failure — just contributes zero detections.
        corpus_dir = tmp_path / "fp"
        corpus_dir.mkdir()
        (corpus_dir / "identity.yaml").write_text(
            yaml.safe_dump({"fingerprints": [{"name": "x", "slug": "x", "category": "identity"}]}),
            encoding="utf-8",
        )
        result = _run_script(corpus_dir)
        # No gated category has detections → nothing to fail on
        assert result.returncode == 0

    def test_handles_malformed_yaml(self, tmp_path: Path) -> None:
        # A file that is a list rather than a mapping is silently skipped.
        corpus_dir = tmp_path / "fp"
        corpus_dir.mkdir()
        (corpus_dir / "identity.yaml").write_text("- item1\n- item2\n", encoding="utf-8")
        result = _run_script(corpus_dir)
        assert result.returncode == 0

    def test_runs_against_shipped_catalog(self) -> None:
        # The shipped catalog might be below threshold (currently is for
        # security/infrastructure as of v1.9 ship). With --report-only
        # the script must still exit 0.
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(SCRIPT), "--report-only"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
        assert result.returncode == 0
