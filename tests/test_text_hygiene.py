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


def test_collect_added_lines_audits_effective_tree_when_branch_is_ahead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diff = "\n".join(
        [
            "diff --git a/note.txt b/note.txt",
            "+++ b/note.txt",
            "@@ -1 +1 @@",
            "-superseded committed line",
            "+clean effective line",
        ]
    )
    calls: list[list[str]] = []

    def fake_diff(args: list[str]) -> str:
        calls.append(args)
        return diff

    monkeypatch.setattr(CHECKER, "_branch_status", lambda: "## main...origin/main [ahead 2]")
    monkeypatch.setattr(CHECKER, "_diff_or_error", fake_diff)
    monkeypatch.setattr(CHECKER, "_untracked_added_lines", list)

    lines = CHECKER.collect_added_lines([])

    assert calls == [["diff", "--no-ext-diff", "-U0", "origin/main"]]
    assert [(line.source, line.text) for line in lines] == [("origin/main effective tree", "clean effective line")]


def test_collect_added_lines_audits_untracked_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def _git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)  # noqa: S603, S607

    _git("init", "-q")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "test")
    baseline = tmp_path / "baseline.txt"
    baseline.write_text("baseline\n", encoding="utf-8")
    _git("add", "baseline.txt")
    _git("commit", "-qm", "init")
    untracked = tmp_path / "new-note.txt"
    untracked.write_text(f"forbidden {chr(0x2014)} marker\n", encoding="utf-8")

    monkeypatch.setattr(CHECKER, "ROOT", tmp_path)
    violations = CHECKER.audit_added_lines(CHECKER.collect_added_lines([]))

    assert [(item.source, item.path, item.line_number, item.marker) for item in violations] == [
        ("untracked", "new-note.txt", 1, "em dash")
    ]


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


def test_identity_markers_detects_constructed_bot_identity() -> None:
    identity = "depend" + "abot" + "[b" + "ot]" + " <49699333+x@users.noreply.github.com>"
    expected_marker = "[b" + "ot]"

    assert expected_marker in CHECKER.identity_markers(identity)


def test_identity_markers_detects_constructed_assistant_address() -> None:
    identity = "An Assistant <noreply@" + "anthro" + "pic.com>"
    expected_marker = "noreply@" + "anthro" + "pic.com"

    assert expected_marker in CHECKER.identity_markers(identity)


def test_identity_markers_allows_maintainer_identity() -> None:
    assert CHECKER.identity_markers("Nick Seal <maintainer@example.invalid>") == ()


def test_identity_markers_do_not_reach_repository_text() -> None:
    """Vendor names the catalog documents must never fail the diff-line scope.

    The catalog carries verification-token prefixes naming model vendors, so an
    identity marker leaking into ``forbidden_markers`` would block legitimate
    fingerprint rules.
    """
    vendor_line = "  pattern: '^" + "anthro" + "pic-domain-verification='"

    assert CHECKER.forbidden_markers(vendor_line) == ()


def test_commit_lines_from_log_splits_identity_and_message() -> None:
    field = CHECKER._COMMIT_FIELD_SEPARATOR
    record = CHECKER._COMMIT_RECORD_SEPARATOR
    author = "Nick Seal <maintainer@example.invalid>"
    log = field.join(["abc1234", author, author, "Subject line\n\nBody line\n"]) + record

    lines = CHECKER.commit_lines_from_log(log, source="commit range")

    assert [(line.path, line.line_number, line.text) for line in lines] == [
        ("abc1234 (message)", 1, "Subject line"),
        ("abc1234 (message)", 2, ""),
        ("abc1234 (message)", 3, "Body line"),
    ]


def test_commit_lines_from_log_flags_bot_author() -> None:
    field = CHECKER._COMMIT_FIELD_SEPARATOR
    record = CHECKER._COMMIT_RECORD_SEPARATOR
    bot = "depend" + "abot" + "[b" + "ot]" + " <x@users.noreply.github.com>"
    human = "Nick Seal <maintainer@example.invalid>"
    log = field.join(["abc1234", bot, human, "Bump a dependency\n"]) + record

    lines = CHECKER.commit_lines_from_log(log, source="commit range")
    violations = CHECKER.audit_identity_lines(lines)

    assert len(violations) == 1
    assert violations[0].path == "abc1234 (author)"
    assert violations[0].marker.startswith("forbidden identity")


def test_message_file_mode_rejects_trailer(tmp_path: Path) -> None:
    trailer = "Co-Authored" + "-By: " + "Cla" + "ude" + " <noreply@example.invalid>"
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text(f"Fix a thing\n\nBody.\n\n{trailer}\n", encoding="utf-8")

    assert CHECKER.main(["--message-file", str(message)]) == 1


def test_message_file_mode_ignores_comment_lines(tmp_path: Path) -> None:
    """Git appends commented help text to the message buffer.

    Those lines are stripped before the commit is written, so auditing them
    would reject commits over text the author never wrote.
    """
    trailer = "Co-Authored" + "-By: " + "Cla" + "ude" + " <noreply@example.invalid>"
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text(f"Fix a thing\n\n# {trailer}\n", encoding="utf-8")

    assert CHECKER.main(["--message-file", str(message)]) == 0


def test_commits_mode_catches_trailer_a_diff_cannot_see(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A trailer lives only in commit metadata, so the added-line scope misses it."""
    import subprocess

    def _git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)  # noqa: S603, S607

    _git("init", "-q")
    _git("config", "user.email", "test@example.invalid")
    _git("config", "user.name", "test")
    note = tmp_path / "note.txt"
    note.write_text("clean line\n", encoding="utf-8")
    _git("add", ".")
    _git("commit", "-qm", "init")
    note.write_text("clean line\nsecond clean line\n", encoding="utf-8")
    _git("add", ".")
    trailer = "Co-Authored" + "-By: " + "Cla" + "ude" + " <noreply@example.invalid>"
    _git("commit", "-qm", f"Add a line\n\n{trailer}")

    monkeypatch.setattr(CHECKER, "ROOT", tmp_path)

    diff = subprocess.run(
        ["git", "diff", "-U0", "HEAD~1..HEAD"],  # noqa: S607
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    diff_violations = CHECKER.audit_added_lines(CHECKER.added_lines_from_diff(diff, source="range"))
    assert diff_violations == []

    commit_violations = CHECKER.audit_added_lines(CHECKER.collect_commit_lines(["HEAD~1..HEAD"]))
    assert any("co-authored" in v.marker for v in commit_violations)
