#!/usr/bin/env python3
"""Fail when a cross-reference to a correlation.md section points at a heading
that does not exist.

The theory doc (docs/correlation.md) is referenced by section number from many
places: other docs, code comments, validation memos. When the doc is
renumbered, those references rot silently. The traceability checker validates
backticked code references (tests, functions, files) via the AST, not prose
section anchors, so a dead "correlation.md section" pointer slips through. This
checker closes that gap.

It builds the set of section numbers that head correlation.md, then scans the
repo for explicit "correlation.md <number>" cross-references and reports any
number with no matching heading. It only validates references that name the
file, not bare in-document section marks, so it does not trip over academic
citations that use the same mark for another work's sections.

Run:

    python scripts/check_section_links.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "correlation.md"

# A numbered heading: "### 4.3 The asymmetric ..." or "## 4 Correlation".
_HEADING = re.compile(r"^#{1,6}\s+(\d+(?:\.\d+)*)\b")
# An explicit cross-reference: "correlation.md", optional punctuation and an
# optional "section(s)" word, then the section number that directly follows the
# file name. The [^\w\n] run stops at the first letter, so a later number on the
# line (a version, a date) is not mistaken for the referenced section.
_XREF = re.compile(r"correlation\.md[^\w\n]*(?:sections?\s+)?(\d+\.\d+(?:\.\d+)*)\b")

_SCAN_GLOBS = ("*.md", "*.py", "*.yaml", "*.json")
_SKIP_DIRS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__"}


def valid_sections() -> set[str]:
    out: set[str] = set()
    for line in DOC.read_text(encoding="utf-8").splitlines():
        m = _HEADING.match(line)
        if m:
            out.add(m.group(1))
    return out


def _iter_files() -> list[Path]:
    seen: set[Path] = set()
    for glob in _SCAN_GLOBS:
        for p in REPO_ROOT.rglob(glob):
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            seen.add(p)
    return sorted(seen)


def dangling_refs(sections: set[str], files: list[Path] | None = None) -> list[str]:
    out: list[str] = []
    for path in files if files is not None else _iter_files():
        try:
            rel = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            rel = str(path)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for num in sorted(set(_XREF.findall(line))):
                if num not in sections:
                    out.append(f"{rel}:{i}: correlation.md section {num} has no such heading")
    return out


def main(argv: list[str] | None = None) -> int:
    sections = valid_sections()
    if not sections:
        print("FAIL: could not parse any section headings from correlation.md")
        return 1
    argv = sys.argv[1:] if argv is None else argv
    files = [Path(a) for a in argv] if argv else None
    bad = dangling_refs(sections, files)
    if bad:
        print(f"FAIL: {len(bad)} dangling correlation.md section reference(s):")
        for b in bad:
            print(f"  {b}")
        return 1
    print(f"OK: every correlation.md section reference resolves ({len(sections)} headings).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
