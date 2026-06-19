"""Tests for the advisory diff coverage signal."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.diff_coverage import (
    CoverageFile,
    compute_diff_coverage,
    load_coverage_files,
    main,
    parse_changed_python_lines,
)


def test_parse_changed_python_lines_ignores_docs_and_deletions() -> None:
    diff = """diff --git a/src/recon_tool/example.py b/src/recon_tool/example.py
--- a/src/recon_tool/example.py
+++ b/src/recon_tool/example.py
@@ -10,2 +10,3 @@
 line unchanged
-old_line()
+new_line()
+another_line()
diff --git a/docs/notes.md b/docs/notes.md
--- a/docs/notes.md
+++ b/docs/notes.md
@@ -1 +1 @@
-old
+new
"""

    assert parse_changed_python_lines(diff) == {"src/recon_tool/example.py": {11, 12}}


def test_compute_diff_coverage_counts_only_measured_changed_lines() -> None:
    changed = {"src/recon_tool/example.py": {11, 12, 13}, "src/recon_tool/unmeasured.py": {1}}
    coverage = {
        "src/recon_tool/example.py": CoverageFile(
            executed_lines=frozenset({11, 13}),
            missing_lines=frozenset({12}),
        )
    }

    result = compute_diff_coverage(changed, coverage)

    assert result.changed_executable_lines == 3
    assert result.covered_lines == 2
    assert result.missing_lines == 1
    assert result.skipped_changed_lines == 1
    assert result.percent == 66.66666666666666
    assert result.missing_by_file == {"src/recon_tool/example.py": (12,)}


def test_load_coverage_files_reads_coverage_json(tmp_path: Path) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps(
            {
                "files": {
                    "src/recon_tool/example.py": {
                        "executed_lines": [1, 2],
                        "missing_lines": [3],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    loaded = load_coverage_files(coverage_path)

    assert loaded["src/recon_tool/example.py"].executed_lines == frozenset({1, 2})
    assert loaded["src/recon_tool/example.py"].missing_lines == frozenset({3})


def test_main_succeeds_for_doc_only_diff(tmp_path: Path, capsys) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps({"files": {}}), encoding="utf-8")
    diff_path = tmp_path / "diff.patch"
    diff_path.write_text(
        """diff --git a/docs/notes.md b/docs/notes.md
--- a/docs/notes.md
+++ b/docs/notes.md
@@ -1 +1 @@
-old
+new
""",
        encoding="utf-8",
    )

    assert main(["--coverage-json", str(coverage_path), "--diff-file", str(diff_path), "--fail-under", "100"]) == 0
    assert "No changed executable Python lines found" in capsys.readouterr().out


def test_main_fails_when_diff_coverage_below_threshold(tmp_path: Path, capsys) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps(
            {
                "files": {
                    "src/recon_tool/example.py": {
                        "executed_lines": [2],
                        "missing_lines": [1],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    diff_path = tmp_path / "diff.patch"
    diff_path.write_text(
        """diff --git a/src/recon_tool/example.py b/src/recon_tool/example.py
--- a/src/recon_tool/example.py
+++ b/src/recon_tool/example.py
@@ -1,0 +1,2 @@
+missing_line()
+covered_line()
""",
        encoding="utf-8",
    )

    assert main(["--coverage-json", str(coverage_path), "--diff-file", str(diff_path), "--fail-under", "75"]) == 1
    captured = capsys.readouterr()
    assert "1/2 changed executable line(s) covered" in captured.out
    assert "Diff coverage below threshold" in captured.err
