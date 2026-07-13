"""Markdown link regressions for live project docs."""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
_LIVE_DOCS = [
    _ROOT / "README.md",
    _ROOT / "CONTRIBUTING.md",
    _ROOT / "SECURITY.md",
    *_ROOT.glob("docs/**/*.md"),
]


def _target_path(raw_target: str, source: Path) -> Path | None:
    target = raw_target.split()[0].strip("<>")
    if not target or target.startswith(("#", "mailto:")) or "://" in target:
        return None
    file_part = target.split("#", 1)[0]
    if not file_part:
        return None
    return (source.parent / file_part).resolve()


def test_live_markdown_relative_links_resolve() -> None:
    broken: list[str] = []
    for path in sorted(_LIVE_DOCS):
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in _LINK_RE.finditer(line):
                target = _target_path(match.group(1), path)
                if target is not None and not target.exists():
                    rel = path.relative_to(_ROOT).as_posix()
                    broken.append(f"{rel}:{line_no}: {match.group(1)}")

    assert not broken, "Broken relative markdown links:\n" + "\n".join(broken)


def test_roadmap_history_keeps_declared_compatibility_anchors() -> None:
    text = (_ROOT / "docs" / "roadmap-history.md").read_text(encoding="utf-8")

    for anchor in (
        '<a id="v190--probabilistic-fusion-shipped"></a>',
        '<a id="v200--maturity"></a>',
    ):
        assert anchor in text
