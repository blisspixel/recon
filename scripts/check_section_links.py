#!/usr/bin/env python3
"""Fail when a correlation.md section number or Markdown anchor is dangling.

The theory doc (docs/correlation.md) is referenced by section number from many
places: other docs, code comments, validation memos. When the doc is
renumbered, those references rot silently. The traceability checker validates
backticked code references (tests, functions, files) via the AST, not prose
section anchors, so a dead "correlation.md section" pointer slips through. This
checker closes that gap.

It builds the numbered sections and GitHub-style heading anchors in
correlation.md, then scans explicit prose references and Markdown links. It only
validates references that name the file, so it does not trip over academic
citations that use the same section number for another work.

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
_HEADING_TEXT = re.compile(r"^#{1,6}\s+(.+?)\s*$")
# An explicit cross-reference start: "correlation.md", optional punctuation and
# an optional "section(s)" word, then a whole or dotted section identifier. The
# ``[^\w\n]`` run stops at the first unrelated word, so a later version or date
# on the line is not mistaken for a section reference.
_XREF_START = re.compile(
    r"""
    correlation\.md(?!\#)[^\w\n]*
    (?:
        (?:sections?\s+|§\s*)(\d+(?:\.\d+)*)(?![\w.])
        |
        (\d+\.\d+(?:\.\d+)*)(?![\w.])
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
# Additional identifiers in the same reference, for example ``sections 3.4 and
# 5``, ``sections 3.2, 3.3, and 3.4``, or ``4.10-4.11``. This is applied only
# immediately after an ``_XREF_START`` match, so unrelated numbers later in the
# sentence remain out of scope.
_XREF_CONTINUATION = re.compile(
    r"\s*(?:,\s*(?:and\s+)?|and\s+|&\s*|[-–]\s*)(\d+(?:\.\d+)*)(?![\w.])",
    re.IGNORECASE,
)
_ANCHOR_XREF = re.compile(r"correlation\.md#([a-z0-9][a-z0-9-]*)", re.IGNORECASE)

_SCAN_GLOBS = ("*.md", "*.py", "*.yaml", "*.json")
_SKIP_DIRS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__"}


def valid_sections() -> set[str]:
    out: set[str] = set()
    for line in DOC.read_text(encoding="utf-8").splitlines():
        m = _HEADING.match(line)
        if m:
            out.add(m.group(1))
    return out


def _heading_anchor(text: str) -> str:
    """Return the GitHub-style anchor for recon's ASCII Markdown headings."""
    normalized = re.sub(r"[^a-z0-9 _-]", "", text.lower())
    return re.sub(r"-+", "-", normalized.replace(" ", "-")).strip("-")


def valid_anchors() -> set[str]:
    out: set[str] = set()
    for line in DOC.read_text(encoding="utf-8").splitlines():
        if match := _HEADING_TEXT.match(line):
            out.add(_heading_anchor(match.group(1)))
    return out


def _section_refs_in_line(line: str) -> set[str]:
    """Return every section identifier in explicit correlation.md references."""
    refs: set[str] = set()
    for match in _XREF_START.finditer(line):
        refs.add(match.group(1) or match.group(2))
        cursor = match.end()
        while continuation := _XREF_CONTINUATION.match(line, cursor):
            refs.add(continuation.group(1))
            cursor = continuation.end()
    return refs


def _iter_files() -> list[Path]:
    seen: set[Path] = set()
    for glob in _SCAN_GLOBS:
        for p in REPO_ROOT.rglob(glob):
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            seen.add(p)
    return sorted(seen)


def dangling_refs(
    sections: set[str],
    files: list[Path] | None = None,
    anchors: set[str] | None = None,
) -> list[str]:
    anchors = valid_anchors() if anchors is None else anchors
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
            for num in sorted(_section_refs_in_line(line)):
                if num not in sections:
                    out.append(f"{rel}:{i}: correlation.md section {num} has no such heading")
            for anchor in sorted({value.lower() for value in _ANCHOR_XREF.findall(line)}):
                if anchor not in anchors:
                    out.append(f"{rel}:{i}: correlation.md#{anchor} has no such heading anchor")
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
    print(
        "OK: every correlation.md section reference and Markdown anchor "
        f"resolves ({len(sections)} numbered headings, {len(valid_anchors())} anchors)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
