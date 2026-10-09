"""Shared matching rules for local catalog discovery surfaces."""

from __future__ import annotations

import re

_CATEGORY_WORD_RE = re.compile(r"[a-z0-9]+")

MAX_CATEGORY_QUERY_LENGTH = 64


def normalize_category_query(query: str | None) -> str:
    """Validate, bound, and normalize a category query string once."""
    if query is None:
        return ""
    if not isinstance(query, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError("Category filter must be a string")
    if len(query) > MAX_CATEGORY_QUERY_LENGTH:
        raise ValueError(f"Category filter exceeds maximum length of {MAX_CATEGORY_QUERY_LENGTH} characters")
    if any(ord(c) < 32 or ord(c) == 127 or 0x80 <= ord(c) <= 0x9F for c in query):
        raise ValueError("Category filter cannot contain control characters")
    return query.strip().lower()


def category_matches_normalized(category: str, needle: str) -> bool:
    """Match a category against an already normalized needle without repeating normalization."""
    if not needle:
        return False
    category_lower = category.lower()
    if " " in needle:
        return needle in category_lower
    return any(word.startswith(needle) for word in _CATEGORY_WORD_RE.findall(category_lower))


def category_matches(category: str, query: str) -> bool:
    """Match a category by word prefix or a literal multiword phrase."""
    try:
        needle = normalize_category_query(query)
    except ValueError:
        return False
    return category_matches_normalized(category, needle)
