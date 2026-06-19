"""Documentation guard for sparse-result weak-area notes."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "weak-areas.md"


def _section(title: str) -> str:
    text = DOC.read_text(encoding="utf-8")
    marker = f"## {title}"
    start = text.index(marker)
    rest = text[start + len(marker) :]
    next_heading = rest.find("\n## ")
    return rest if next_heading == -1 else rest[:next_heading]


def test_custom_dkim_selector_false_negative_note_is_explicit() -> None:
    section = _section("Custom DKIM selectors and branded email senders")
    compact = re.sub(r"\s+", " ", section)

    required_phrases = (
        "No DKIM observed",
        "not enumerable from DNS",
        "not observed at the probed selectors",
        'not "DKIM is absent."',
        "--explain",
        "provider-specific",
        "do not add broad selector guesses",
    )
    for phrase in required_phrases:
        assert phrase in compact


def test_unclassified_cname_termini_note_is_conservative() -> None:
    section = _section("Unclassified CNAME chain termini")
    compact = re.sub(r"\s+", " ", section)

    required_phrases = (
        "Unclassified surface",
        "--include-unclassified",
        "unclassified_cname_chains",
        "no built-in `cname_target` fingerprint matched",
        "not enough by itself to claim a specific vendor",
        "recon discover <domain>",
        "confirm the suffix against public vendor docs or repeated validation evidence",
        "add negative tests",
        "Do not turn a bare unknown terminus into a broad service claim",
    )
    for phrase in required_phrases:
        assert phrase in compact
