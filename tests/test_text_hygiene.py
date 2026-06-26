from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_checker() -> Any:
    spec = importlib.util.spec_from_file_location(
        "text_hygiene_checker",
        ROOT / "scripts" / "check_text_hygiene.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    cast(Any, spec.loader).exec_module(module)
    return module


CHECKER = _load_checker()


def test_added_lines_from_diff_tracks_new_line_numbers() -> None:
    diff = "\n".join(
        [
            "diff --git a/docs/example.md b/docs/example.md",
            "+++ b/docs/example.md",
            "@@ -2,0 +3,2 @@",
            "+first",
            "+second",
        ]
    )

    lines = CHECKER.added_lines_from_diff(diff, source="staged")

    assert [(line.path, line.line_number, line.text) for line in lines] == [
        ("docs/example.md", 3, "first"),
        ("docs/example.md", 4, "second"),
    ]


def test_forbidden_markers_detects_constructed_attribution() -> None:
    text = "Generated with " + "Cod" + "ex"
    expected_marker = "generated with " + "cod" + "ex"

    assert expected_marker in CHECKER.forbidden_markers(text)


def test_forbidden_markers_detects_constructed_em_dash() -> None:
    text = "left" + chr(0x2014) + "right"

    assert "em dash" in CHECKER.forbidden_markers(text)


def test_forbidden_markers_detects_constructed_pictograph() -> None:
    text = "ship " + chr(0x1F680)

    assert "pictograph" in CHECKER.forbidden_markers(text)


def test_audit_added_lines_reports_location() -> None:
    marker_text = "co-authored" + "-by: contributor"
    lines = [CHECKER.AddedLine("origin/main..HEAD", "README.md", 12, marker_text)]

    violations = CHECKER.audit_added_lines(lines)

    assert len(violations) == 1
    expected_marker = "co-authored" + "-by:"
    assert violations[0].render() == f"origin/main..HEAD: README.md:12: {expected_marker}: " + marker_text


def test_audit_added_lines_allows_clean_text() -> None:
    lines = [CHECKER.AddedLine("staged", "README.md", 2, "Plain project documentation.")]

    assert CHECKER.audit_added_lines(lines) == []


def test_collect_added_lines_decodes_utf8_em_dash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Git diff output must be decoded as UTF-8, not the platform locale, so an
    em dash (U+2014) in an added line is caught on Windows the same as in CI.
    Without the explicit encoding the local check silently misses it.
    """
    import subprocess

    def _git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)  # noqa: S603, S607

    _git("init", "-q")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "test")
    note = tmp_path / "note.txt"
    note.write_text("clean line\n", encoding="utf-8")
    _git("add", ".")
    _git("commit", "-qm", "init")
    em_dash = chr(0x2014)
    note.write_text(f"clean line\nadded {em_dash} dash\n", encoding="utf-8")
    _git("add", ".")

    monkeypatch.setattr(CHECKER, "ROOT", tmp_path)
    violations = CHECKER.audit_added_lines(CHECKER.collect_added_lines([]))

    assert any(v.marker == "em dash" for v in violations)
