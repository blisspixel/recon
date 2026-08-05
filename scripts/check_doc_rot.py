#!/usr/bin/env python3
"""Fail when Markdown rots in ways that render silently wrong on github.com.

Two failure classes, both drawn from a real incident. On 2026-07-11 a single
commit converted 285 lines of working ``$``-delimited math in
``docs/correlation.md`` into ``\\( ... \\)`` and ``\\[ ... \\]``, and replaced
five sections with one-paragraph pointer stubs that existed only to preserve an
anchor. Both survived every gate for three weeks, because no checker looked at
either thing.

1. **Math delimiters.** GitHub's Markdown renderer does not support LaTeX
   ``\\(`` or ``\\[`` delimiters. It treats them as escaped literal brackets,
   drops the backslash, and prints the raw LaTeX in running prose. The
   ``$``-delimited forms are the ones that render, so the others are rejected.

2. **Pointer stubs.** A section whose body only redirects the reader is not
   content. ``check_section_links.py`` verifies that a referenced section number
   resolves, which a stub satisfies perfectly, so a hollowed-out section reads
   as a live cross-reference target while carrying nothing.

Both checks skip fenced code blocks and inline code spans, because documenting
either pattern is legitimate and this file itself does it.

Run with::

    uv run python scripts/check_doc_rot.py
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

# Scanned surfaces: the docs tree plus the two root documents readers reach
# first. CHANGELOG.md is excluded because its historical entries preserve the
# wording used when each version shipped and must not be rewritten.
_SCAN_DIRECTORIES = ("docs",)
_SCAN_FILES = ("README.md", "ROADMAP.md")

_FENCE = re.compile(r"^\s*(```|~~~)")
_INLINE_CODE = re.compile(r"`[^`]*`")
_HEADING = re.compile(r"^(#{2,6})\s+(.*)$")

# GitHub renders neither of these as math. Matching the opening delimiters is
# enough; a document never has one without meaning to open a math span.
_BROKEN_MATH = re.compile(r"\\\(|\\\[")

# A body under this many words that also redirects the reader is a pointer, not
# a section. Real short sections exist in this repository (an eight-word "Setup",
# an eleven-word "Reporting vulnerabilities"), so length alone is not evidence;
# the redirect vocabulary is what separates a terse section from a hollow one.
_STUB_MAX_WORDS = 60

_REDIRECT = re.compile(
    r"\b(?:former section|formerly section|see section|is now section|are now section"
    r"|moved to section|superseded by section|replaced by section"
    r"|retained (?:only )?as an anchor|legacy .{0,30}anchor)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One rejected location, reported as an editor-navigable reference."""

    path: Path
    line: int
    check: str
    detail: str

    def render(self) -> str:
        """Return the finding as ``path:line: check: detail``.

        Repository paths are reported relative to the root so an editor can jump
        to them. A path outside the root still reports, absolutely, rather than
        raising: ``check_paths`` accepts arbitrary files.
        """
        try:
            location = self.path.relative_to(_ROOT).as_posix()
        except ValueError:
            location = self.path.as_posix()
        return f"{location}:{self.line}: {self.check}: {self.detail}"


def _strip_inline_code(line: str) -> str:
    """Blank out inline code spans so documented patterns are not flagged."""
    return _INLINE_CODE.sub("``", line)


def _code_fence_mask(lines: list[str]) -> list[bool]:
    """Return, per line, whether that line sits inside a fenced code block."""
    inside = False
    mask: list[bool] = []
    for line in lines:
        if _FENCE.match(line):
            # The fence markers themselves count as code so an opening fence
            # carrying an info string is never scanned as prose.
            mask.append(True)
            inside = not inside
            continue
        mask.append(inside)
    return mask


def _check_math_delimiters(path: Path, lines: list[str], mask: list[bool]) -> list[Finding]:
    """Reject LaTeX delimiters that github.com does not render as math."""
    findings: list[Finding] = []
    for index, line in enumerate(lines, start=1):
        if mask[index - 1]:
            continue
        match = _BROKEN_MATH.search(_strip_inline_code(line))
        if match is None:
            continue
        found = match.group(0)
        wanted = "$...$" if found == "\\(" else "$$...$$"
        findings.append(
            Finding(
                path,
                index,
                "math-delimiter",
                f"{found} does not render as math on github.com; use {wanted}",
            )
        )
    return findings


def _check_unbalanced_display_math(path: Path, lines: list[str], mask: list[bool]) -> list[Finding]:
    """Reject an odd number of ``$$`` fences, which swallows the text after it."""
    opens: list[int] = []
    for index, line in enumerate(lines, start=1):
        if mask[index - 1]:
            continue
        for _ in range(_strip_inline_code(line).count("$$")):
            if opens:
                opens.pop()
            else:
                opens.append(index)
    return [Finding(path, line, "display-math", "unclosed $$ display-math block") for line in opens]


def _check_pointer_stubs(path: Path, lines: list[str], mask: list[bool]) -> list[Finding]:
    """Reject sections whose body only redirects the reader elsewhere."""
    headings: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        if mask[index]:
            continue
        match = _HEADING.match(line)
        if match is not None:
            headings.append((index, len(match.group(1)), match.group(2).strip()))

    findings: list[Finding] = []
    for position, (index, level, title) in enumerate(headings):
        following = headings[position + 1] if position + 1 < len(headings) else None
        # A heading that introduces subsections is a container. Its own body is
        # allowed to be an intro sentence or nothing at all.
        if following is not None and following[1] > level:
            continue
        end = following[0] if following is not None else len(lines)
        body = "\n".join(lines[index + 1 : end]).strip()
        if len(body.split()) >= _STUB_MAX_WORDS:
            continue
        if _REDIRECT.search(body) is None and _REDIRECT.search(title) is None:
            continue
        findings.append(
            Finding(
                path,
                index + 1,
                "pointer-stub",
                f'"{title}" redirects the reader without carrying content; restore it or remove the heading',
            )
        )
    return findings


def _scanned_paths() -> list[Path]:
    """Return every Markdown file in scope, in a stable order."""
    paths: list[Path] = []
    for directory in _SCAN_DIRECTORIES:
        paths.extend(sorted((_ROOT / directory).rglob("*.md")))
    paths.extend(_ROOT / name for name in _SCAN_FILES if (_ROOT / name).is_file())
    return paths


def check_paths(paths: list[Path]) -> list[Finding]:
    """Return every finding across the supplied Markdown files."""
    findings: list[Finding] = []
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        mask = _code_fence_mask(lines)
        findings.extend(_check_math_delimiters(path, lines, mask))
        findings.extend(_check_unbalanced_display_math(path, lines, mask))
        findings.extend(_check_pointer_stubs(path, lines, mask))
    return findings


def main(argv: list[str] | None = None) -> int:
    """Report Markdown rot and fail closed when any is found."""
    parser = argparse.ArgumentParser(description="Reject Markdown that renders silently wrong on github.com.")
    parser.parse_args(argv)

    paths = _scanned_paths()
    findings = check_paths(paths)
    if findings:
        print(f"FAIL: {len(findings)} Markdown rendering or content defect(s):")
        for finding in findings:
            print(f"  {finding.render()}")
        return 1

    print(f"OK: {len(paths)} Markdown files carry renderable math and no pointer-stub sections.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
