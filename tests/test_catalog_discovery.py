"""Shared catalog discovery semantics across CLI and MCP."""

from __future__ import annotations

import pytest
from recon_tool.catalog_discovery import category_matches


@pytest.mark.parametrize(
    ("category", "query", "expected"),
    [
        ("AI & Generative", "ai", True),
        ("Email", "ai", False),
        ("Security & Compliance", "comp", True),
        ("Data & Analytics", "data &", True),
        ("Data & Analytics", "analytics data", False),
        ("Infrastructure", "  infra  ", True),
        ("Infrastructure", "", False),
    ],
)
def test_category_matches_word_prefix_or_phrase(
    category: str,
    query: str,
    expected: bool,
) -> None:
    assert category_matches(category, query) is expected
