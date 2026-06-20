#!/usr/bin/env python3
"""Check added lines for forbidden attribution and text markers."""

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
    return subprocess.run(  # noqa: S603 - fixed git argv.
        ["git", *args],  # noqa: S607 - maintainer git executable resolved from PATH.
        cwd=ROOT,
        text=True,
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


def collect_added_lines(ranges: Iterable[str]) -> list[AddedLine]:
    collected: list[AddedLine] = []
    explicit_ranges = list(ranges)
    if explicit_ranges:
        for commit_range in explicit_ranges:
            diff = _diff_or_error(["diff", "--no-ext-diff", "-U0", commit_range])
            collected.extend(added_lines_from_diff(diff, source=commit_range))
        return collected

    for label, args in (
        ("staged", ["diff", "--cached", "--no-ext-diff", "-U0"]),
        ("unstaged", ["diff", "--no-ext-diff", "-U0"]),
    ):
        diff = _diff_or_error(args)
        collected.extend(added_lines_from_diff(diff, source=label))

    status = _branch_status()
    if "origin/main" in status and "[ahead " in status:
        diff = _diff_or_error(["diff", "--no-ext-diff", "-U0", "origin/main..HEAD"])
        collected.extend(added_lines_from_diff(diff, source="origin/main..HEAD"))
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
    args = parser.parse_args(argv)

    try:
        violations = audit_added_lines(collect_added_lines(args.range))
    except RuntimeError as exc:
        print(f"Text hygiene check failed: {exc}", file=sys.stderr)
        return 1

    if violations:
        print("Text hygiene check failed on added lines:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation.render()}", file=sys.stderr)
        return 1
    print("OK: added lines contain no attribution markers, em dashes, or pictographs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
