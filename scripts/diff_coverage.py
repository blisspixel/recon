#!/usr/bin/env python3
"""Report coverage for changed executable Python lines.

This is an advisory maintainer signal, not part of the blocking CI gate. Run a
coverage-producing test command first, then:

    python -m coverage json -o coverage.json
    python scripts/diff_coverage.py --coverage-json coverage.json

By default the script compares the working tree diff. Use ``--diff-file`` to
check a saved unified diff, or ``--base`` to compare against another ref.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class CoverageFile:
    executed_lines: frozenset[int]
    missing_lines: frozenset[int]

    @property
    def measured_lines(self) -> frozenset[int]:
        return self.executed_lines | self.missing_lines


@dataclass(frozen=True)
class DiffCoverageResult:
    changed_executable_lines: int
    covered_lines: int
    missing_lines: int
    skipped_changed_lines: int
    missing_by_file: dict[str, tuple[int, ...]]

    @property
    def percent(self) -> float | None:
        if self.changed_executable_lines == 0:
            return None
        return (self.covered_lines / self.changed_executable_lines) * 100.0


def _normalize_path(path: str) -> str | None:
    if path == "/dev/null":
        return None
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path.replace("\\", "/")


def parse_changed_python_lines(diff_text: str) -> dict[str, set[int]]:
    """Return added or modified Python line numbers from a unified diff."""
    changed: dict[str, set[int]] = {}
    current_path: str | None = None
    new_line: int | None = None

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            current_path = _normalize_path(line[4:].split("\t", 1)[0])
            if current_path is not None and not current_path.endswith(".py"):
                current_path = None
            new_line = None
            continue

        match = _HUNK_RE.match(line)
        if match:
            new_line = int(match.group(1))
            continue

        if current_path is None or new_line is None:
            continue
        if line.startswith("+"):
            changed.setdefault(current_path, set()).add(new_line)
            new_line += 1
        elif line.startswith("-"):
            continue
        elif line.startswith(" "):
            new_line += 1
        elif line == r"\ No newline at end of file":
            continue

    return changed


def load_coverage_files(path: Path) -> dict[str, CoverageFile]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    files = payload.get("files")
    if not isinstance(files, Mapping):
        raise ValueError(f"coverage JSON has no files object: {path}")

    out: dict[str, CoverageFile] = {}
    for raw_name, raw_record in files.items():
        if not isinstance(raw_name, str) or not isinstance(raw_record, Mapping):
            continue
        executed = _line_set(raw_record.get("executed_lines"))
        missing = _line_set(raw_record.get("missing_lines"))
        out[_normalize_path(raw_name) or raw_name] = CoverageFile(
            executed_lines=frozenset(executed),
            missing_lines=frozenset(missing),
        )
    return out


def _line_set(value: object) -> set[int]:
    if not isinstance(value, list):
        return set()
    return {line for line in value if isinstance(line, int)}


def compute_diff_coverage(
    changed_lines: Mapping[str, set[int]],
    coverage_files: Mapping[str, CoverageFile],
) -> DiffCoverageResult:
    changed_executable = 0
    covered = 0
    missing = 0
    skipped = 0
    missing_by_file: dict[str, tuple[int, ...]] = {}

    for path, lines in sorted(changed_lines.items()):
        coverage = coverage_files.get(path)
        if coverage is None:
            skipped += len(lines)
            continue
        executable = lines & set(coverage.measured_lines)
        skipped += len(lines - executable)
        file_missing = sorted(executable & set(coverage.missing_lines))
        file_covered = executable & set(coverage.executed_lines)
        changed_executable += len(executable)
        covered += len(file_covered)
        missing += len(file_missing)
        if file_missing:
            missing_by_file[path] = tuple(file_missing)

    return DiffCoverageResult(
        changed_executable_lines=changed_executable,
        covered_lines=covered,
        missing_lines=missing,
        skipped_changed_lines=skipped,
        missing_by_file=missing_by_file,
    )


def _load_diff(args: argparse.Namespace) -> str:
    diff_file = args.diff_file
    if diff_file is not None:
        return Path(diff_file).read_text(encoding="utf-8")

    cmd = ["git", "diff", "--unified=0"]
    if args.base is not None:
        cmd.append(f"{args.base}...HEAD")
    completed = subprocess.run(  # noqa: S603 - fixed git argv with optional ref.
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "git diff failed")
    return completed.stdout


def _format_result(result: DiffCoverageResult) -> str:
    if result.percent is None:
        return (
            "No changed executable Python lines found. "
            f"Skipped changed lines: {result.skipped_changed_lines}."
        )
    lines = [
        (
            "Diff coverage: "
            f"{result.covered_lines}/{result.changed_executable_lines} "
            f"changed executable line(s) covered ({result.percent:.1f}%)."
        )
    ]
    if result.skipped_changed_lines:
        lines.append(f"Skipped non-executable or unmeasured changed line(s): {result.skipped_changed_lines}.")
    if result.missing_by_file:
        lines.append("Missing changed line(s):")
        for path, missing_lines in result.missing_by_file.items():
            rendered = ", ".join(str(line) for line in missing_lines)
            lines.append(f"  {path}: {rendered}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report coverage for changed executable Python lines.")
    parser.add_argument("--coverage-json", type=Path, default=Path("coverage.json"), help="Coverage.py JSON file.")
    parser.add_argument("--diff-file", type=Path, help="Unified diff file to read instead of running git diff.")
    parser.add_argument("--base", help="Git base ref for diffing, e.g. origin/main. Defaults to working tree diff.")
    parser.add_argument("--fail-under", type=float, help="Return nonzero if diff coverage is below this percent.")
    args = parser.parse_args(argv)

    try:
        diff_text = _load_diff(args)
        changed = parse_changed_python_lines(diff_text)
        coverage = load_coverage_files(args.coverage_json)
        result = compute_diff_coverage(changed, coverage)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(_format_result(result))
    if args.fail_under is not None and result.percent is not None and result.percent < args.fail_under:
        print(f"Diff coverage below threshold: {result.percent:.1f}% < {args.fail_under:.1f}%.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
