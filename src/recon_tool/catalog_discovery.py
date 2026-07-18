"""Shared matching rules for local catalog discovery surfaces."""

from __future__ import annotations

import re

_CATEGORY_WORD_RE = re.compile(r"[a-z0-9]+")


def category_matches(category: str, query: str) -> bool:
    """Match a category by word prefix or a literal multiword phrase."""
    needle = query.strip().lower()
    if not needle:
        return False
    category_lower = category.lower()
    if " " in needle:
        return needle in category_lower
    return any(word.startswith(needle) for word in _CATEGORY_WORD_RE.findall(category_lower))
