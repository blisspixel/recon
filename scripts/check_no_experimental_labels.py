"""CI gate: no active EXPERIMENTAL labels on user-facing surfaces.

The v2.0 quality bar requires zero EXPERIMENTAL labels in
user-facing surfaces (CLI help, MCP tool descriptions, JSON schema
field descriptions, schema reference docs). Discussion of the
historical EXPERIMENTAL label in the roadmap, migration guide,
and release-process docs is legitimate prose, not a label.

This script:

1. Scans the user-facing surfaces.
2. Pattern-matches for the active-label shapes: ``EXPERIMENTAL``
   in all-caps as a parenthetical / prefix / suffix qualifier.
3. Exits non-zero on any hit.

What COUNTS as an active label:
  - ``EXPERIMENTAL`` in all-caps surrounded by parens / brackets
    / commas / dashes.
  - ``EXPERIMENTAL`` immediately followed by ``:`` or ``--``.
  - The word ``experimental`` lowercase as a Stability column
    value (e.g. ``| **experimental** |`` in markdown tables).

What does NOT count (and is explicitly allowed):
  - Prose like "the layer was experimental in v1.9.x" — past-tense
    discussion of the historical label.
  - Process docs explaining the EXPERIMENTAL → stable transition.

Run from repo root: ``python scripts/check_no_experimental_labels.py``
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Surfaces the gate scans. These are the operator-facing surfaces
# where an active EXPERIMENTAL label would mislead a v2.0+ user.
_SCANNED_FILES: tuple[Path, ...] = (
    REPO_ROOT / "recon_tool" / "cli.py",
    REPO_ROOT / "recon_tool" / "server.py",
    REPO_ROOT / "recon_tool" / "models.py",
    REPO_ROOT / "recon_tool" / "formatter.py",
    REPO_ROOT / "recon_tool" / "bayesian.py",
    REPO_ROOT / "recon_tool" / "bayesian_dag.py",
    REPO_ROOT / "recon_tool" / "fusion.py",
    REPO_ROOT / "recon_tool" / "data" / "bayesian_network.yaml",
    REPO_ROOT / "docs" / "recon-schema.json",
    REPO_ROOT / "docs" / "schema.md",
    REPO_ROOT / "docs" / "stability.md",
    REPO_ROOT / "docs" / "mcp.md",
    REPO_ROOT / "README.md",
)

# Patterns that match an active label, not prose discussion.
_LABEL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\(EXPERIMENTAL\)"),
    re.compile(r"\[EXPERIMENTAL\]"),
    re.compile(r"\bEXPERIMENTAL\s*[:\-—]"),
    re.compile(r"^\s*EXPERIMENTAL\b", re.MULTILINE),
    re.compile(r",\s*EXPERIMENTAL\b"),
    re.compile(r"\bEXPERIMENTAL\s*\)"),
    # Markdown stability-column shape: `| **experimental** |`
    re.compile(r"\|\s*\*\*experimental\*\*\s*\|", re.IGNORECASE),
    # CLI help-text prefix: `[EXPERIMENTAL]` or `[EXPERIMENTAL v1.9]`
    re.compile(r"\[EXPERIMENTAL[^\]]*\]"),
)


def scan_file(path: Path) -> list[tuple[int, str]]:
    """Return ``(line_number, line_text)`` for each active-label hit."""
    if not path.exists():
        return []
    hits: list[tuple[int, str]] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for idx, line in enumerate(lines, start=1):
        for pattern in _LABEL_PATTERNS:
            if pattern.search(line):
                hits.append((idx, line.rstrip()))
                break
    return hits


def main() -> int:
    total_hits = 0
    for path in _SCANNED_FILES:
        hits = scan_file(path)
        if hits:
            total_hits += len(hits)
            rel = path.relative_to(REPO_ROOT)
            print(f"\n{rel} ({len(hits)} hit{'s' if len(hits) != 1 else ''}):")
            for line_num, text in hits:
                print(f"  {line_num}: {text}")

    if total_hits == 0:
        print("OK: zero active EXPERIMENTAL labels on user-facing surfaces.")
        return 0

    print(f"\nFAIL: {total_hits} active EXPERIMENTAL label(s) found.")
    print(
        "v2.0 quality bar requires zero. Either remove the label or move "
        "the discussion into prose form (the gate allows past-tense "
        "historical references in docs/roadmap.md and docs/migration-v2.md)."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
