#!/usr/bin/env python3
"""Check added lines, commit messages, and commit identities for forbidden markers.

Three scopes, because attribution leaks through three different doors:

* added diff lines (default) - repo text a change introduces;
* commit messages (``--commits``, ``--message-file``) - trailers such as a
  co-author line, which never appear in a diff and so survived the older
  diff-only gate;
* commit author and committer identity (``--commits``) - a name or address
  belonging to an assistant or bot rather than a maintainer.

A trailer written into a commit on a side branch is permanent once pushed:
GitHub keeps every pull request head under ``refs/pull/*/head`` forever, and
no rewrite, branch deletion, or release deletion can remove it. The only
reliable control is to refuse the commit locally, before it exists, which is
what the ``--message-file`` mode does from a ``commit-msg`` hook.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")
ATTRIBUTION_MARKERS = tuple(
    "".join(parts)
    for parts in (
        ("co-authored", "-by:"),
        ("generated", "-by:"),
        ("generated with ", "cod", "ex"),
        ("generated with ", "cla", "ude"),
        ("generated with ", "github ", "copilot"),
        ("made by ", "cod", "ex"),
        ("made by ", "cla", "ude"),
        ("made by ", "github ", "copilot"),
        ("by ", "cod", "ex"),
        ("by ", "cla", "ude"),
    )
)
PICTOGRAPH_RANGES = (
    (0x1F000, 0x1FAFF),
    (0x2600, 0x27BF),
)
# Applied only to commit author and committer identity, never to repo text.
# The catalog legitimately documents vendor names such as the Anthropic and
# OpenAI verification-token prefixes, so these substrings must not reach the
# diff-line scanner.
IDENTITY_MARKERS = tuple(
    "".join(parts)
    for parts in (
        ("noreply@", "anthro", "pic.com"),
        ("cla", "ude"),
        ("cod", "ex"),
        ("cop", "ilot"),
        ("open", "ai.com"),
        ("[b", "ot]"),
    )
)
_COMMIT_FIELD_SEPARATOR = "\x00"
_COMMIT_RECORD_SEPARATOR = "\x1e"
# git expands these escapes itself. Passing the raw control characters in argv
# instead would fail on Windows, where CreateProcess rejects an embedded NUL.
_COMMIT_FIELD_ESCAPE = "%x00"
_COMMIT_RECORD_ESCAPE = "%x1e"


@dataclass(frozen=True)
class AddedLine:
    source: str
    path: str
    line_number: int | None
    text: str


@dataclass(frozen=True)
class TextHygieneViolation:
    source: str
    path: str
    line_number: int | None
    marker: str
    text: str

    def render(self) -> str:
        location = self.path
        if self.line_number is not None:
            location = f"{location}:{self.line_number}"
        return f"{self.source}: {location}: {self.marker}: {self.text}"


def _has_pictograph(text: str) -> bool:
    return any(start <= ord(char) <= end for char in text for start, end in PICTOGRAPH_RANGES)


def forbidden_markers(text: str) -> tuple[str, ...]:
    lowered = text.lower()
    markers = [marker for marker in ATTRIBUTION_MARKERS if marker in lowered]
    if "\u2014" in text:
        markers.append("em dash")
    if _has_pictograph(text):
        markers.append("pictograph")
    return tuple(markers)


def identity_markers(text: str) -> tuple[str, ...]:
    """Return forbidden markers for a commit author or committer identity."""
    lowered = text.lower()
    return tuple(marker for marker in IDENTITY_MARKERS if marker in lowered)


def commit_lines_from_log(log_text: str, *, source: str) -> list[AddedLine]:
    """Turn ``git log`` records into auditable lines.

    Each record contributes its author identity, its committer identity, and
    every line of its message body, so a trailer buried at the end of a long
    message is audited exactly like a subject line.
    """
    lines: list[AddedLine] = []
    for record in log_text.split(_COMMIT_RECORD_SEPARATOR):
        if not record.strip():
            continue
        parts = record.split(_COMMIT_FIELD_SEPARATOR)
        if len(parts) < 4:
            continue
        short = parts[0].strip()[:12]
        author = parts[1].strip()
        committer = parts[2].strip()
        message = parts[3]
        for role, identity in (("author", author), ("committer", committer)):
            for marker in identity_markers(identity):
                lines.append(AddedLine(source, f"{short} ({role})", None, f"{marker}: {identity}"))
        lines.extend(
            AddedLine(source, f"{short} (message)", number, text)
            for number, text in enumerate(message.splitlines(), start=1)
        )
    return lines


def collect_commit_lines(ranges: Iterable[str]) -> list[AddedLine]:
    """Audit commit metadata for each supplied range."""
    collected: list[AddedLine] = []
    log_format = _COMMIT_FIELD_ESCAPE.join(["%h", "%an <%ae>", "%cn <%ce>", "%B"])
    for commit_range in ranges:
        log = _diff_or_error(["log", f"--format={log_format}{_COMMIT_RECORD_ESCAPE}", commit_range])
        collected.extend(commit_lines_from_log(log, source=f"commit {commit_range}"))
    return collected


def audit_identity_lines(lines: Iterable[AddedLine]) -> list[TextHygieneViolation]:
    """Report identity lines, which arrive pre-flagged by ``commit_lines_from_log``."""
    violations: list[TextHygieneViolation] = []
    for line in lines:
        if line.line_number is None and line.path.endswith((" (author)", " (committer)")):
            marker, _, detail = line.text.partition(": ")
            violations.append(
                TextHygieneViolation(
                    source=line.source,
                    path=line.path,
                    line_number=None,
                    marker=f"forbidden identity {marker}",
                    text=detail,
                )
            )
    return violations


def added_lines_from_diff(diff_text: str, *, source: str) -> list[AddedLine]:
    lines: list[AddedLine] = []
    current_path = "<unknown>"
    new_line: int | None = None
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ b/"):
            current_path = raw_line.removeprefix("+++ b/")
            continue
        if raw_line.startswith("+++ "):
            current_path = raw_line.removeprefix("+++ ")
            continue
        hunk = HUNK_RE.match(raw_line)
        if hunk is not None:
            new_line = int(hunk.group("start"))
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            lines.append(AddedLine(source, current_path, new_line, raw_line[1:]))
            if new_line is not None:
                new_line += 1
            continue
        if raw_line.startswith("-") and not raw_line.startswith("---"):
            continue
        if new_line is not None:
            new_line += 1
    return lines


def audit_added_lines(lines: Iterable[AddedLine]) -> list[TextHygieneViolation]:
    violations: list[TextHygieneViolation] = []
    for line in lines:
        for marker in forbidden_markers(line.text):
            violations.append(
                TextHygieneViolation(
                    source=line.source,
                    path=line.path,
                    line_number=line.line_number,
                    marker=marker,
                    text=line.text.strip(),
                )
            )
    return violations


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    # Decode git's UTF-8 diff output as UTF-8 explicitly. Without this, text
    # mode falls back to the platform locale (cp1252 on Windows), which mangles
    # an em dash (U+2014) into other code points so the local check misses what
    # CI (UTF-8 locale) catches.
    return subprocess.run(  # noqa: S603 - fixed git argv.
        ["git", *args],  # noqa: S607 - maintainer git executable resolved from PATH.
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )


def _diff_or_error(args: list[str]) -> str:
    result = _run_git(args)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or f"git {' '.join(args)} failed"
        raise RuntimeError(detail)
    return result.stdout


def _branch_status() -> str:
    result = _run_git(["status", "--short", "--branch"])
    if result.returncode != 0:
        return ""
    return result.stdout.splitlines()[0] if result.stdout.splitlines() else ""


def _untracked_added_lines() -> list[AddedLine]:
    """Return every text line in untracked, non-ignored files as newly added."""
    output = _diff_or_error(["ls-files", "--others", "--exclude-standard", "-z"])
    lines: list[AddedLine] = []
    root = ROOT.resolve()
    for relative in (item for item in output.split("\0") if item):
        candidate = ROOT / relative
        try:
            if candidate.is_symlink():
                text = str(candidate.readlink())
            else:
                resolved = candidate.resolve()
                resolved.relative_to(root)
                if not resolved.is_file():
                    continue
                raw = resolved.read_bytes()
                if b"\0" in raw:
                    continue
                text = raw.decode("utf-8", errors="replace")
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"cannot audit untracked path {relative!r}: {exc}") from exc
        normalized_path = Path(relative).as_posix()
        lines.extend(
            AddedLine("untracked", normalized_path, line_number, line)
            for line_number, line in enumerate(text.splitlines(), start=1)
        )
    return lines


def collect_added_lines(ranges: Iterable[str]) -> list[AddedLine]:
    collected: list[AddedLine] = []
    explicit_ranges = list(ranges)
    if explicit_ranges:
        for commit_range in explicit_ranges:
            diff = _diff_or_error(["diff", "--no-ext-diff", "-U0", commit_range])
            collected.extend(added_lines_from_diff(diff, source=commit_range))
        return collected

    status = _branch_status()
    if "origin/main" in status and "[ahead " in status:
        diff = _diff_or_error(["diff", "--no-ext-diff", "-U0", "origin/main"])
        collected.extend(added_lines_from_diff(diff, source="origin/main effective tree"))
        collected.extend(_untracked_added_lines())
        return collected

    for label, args in (
        ("staged", ["diff", "--cached", "--no-ext-diff", "-U0"]),
        ("unstaged", ["diff", "--no-ext-diff", "-U0"]),
    ):
        diff = _diff_or_error(args)
        collected.extend(added_lines_from_diff(diff, source=label))

    collected.extend(_untracked_added_lines())
    return collected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check added diff lines for attribution markers, em dashes, and pictographs."
    )
    parser.add_argument(
        "--range",
        action="append",
        default=[],
        help="Commit range to inspect with git diff -U0. May be repeated.",
    )
    parser.add_argument(
        "--commits",
        action="append",
        default=[],
        help=(
            "Commit range whose messages and author/committer identities to inspect. "
            "May be repeated. Catches trailers, which never appear in a diff."
        ),
    )
    parser.add_argument(
        "--message-file",
        help=(
            "Path to a prepared commit message to inspect, for use from a commit-msg "
            "hook. Refuses the commit before it exists, which is the only durable "
            "control: a pushed pull request head cannot be purged from GitHub."
        ),
    )
    args = parser.parse_args(argv)

    scope = "added lines"
    try:
        if args.message_file is not None:
            scope = "commit message"
            text = Path(args.message_file).read_text(encoding="utf-8", errors="replace")
            body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
            lines = [
                AddedLine("commit-msg", args.message_file, number, line)
                for number, line in enumerate(body.splitlines(), start=1)
            ]
            violations = audit_added_lines(lines)
        elif args.commits:
            scope = "commit metadata"
            collected = collect_commit_lines(args.commits)
            identity = [
                line
                for line in collected
                if line.line_number is None and line.path.endswith((" (author)", " (committer)"))
            ]
            message = [line for line in collected if line not in identity]
            violations = audit_identity_lines(identity) + audit_added_lines(message)
        else:
            violations = audit_added_lines(collect_added_lines(args.range))
    except (RuntimeError, OSError) as exc:
        print(f"Text hygiene check failed: {exc}", file=sys.stderr)
        return 1

    if violations:
        print(f"Text hygiene check failed on {scope}:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation.render()}", file=sys.stderr)
        if scope != "added lines":
            print(
                "\nRemove the marker and amend. Attribution trailers are forbidden in this\n"
                "repository: see the Attribution section of AGENTS.md. A trailer that reaches\n"
                "a pushed branch is permanent, because GitHub retains every pull request head.",
                file=sys.stderr,
            )
        return 1
    print(f"OK: no attribution markers, em dashes, or pictographs in {scope}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
