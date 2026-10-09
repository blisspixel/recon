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


def test_normalize_category_query_rejects_oversized_string() -> None:
    from recon_tool.catalog_discovery import normalize_category_query

    with pytest.raises(ValueError, match="exceeds maximum length"):
        normalize_category_query("a" * 65)


def test_normalize_category_query_rejects_control_characters() -> None:
    from recon_tool.catalog_discovery import normalize_category_query

    with pytest.raises(ValueError, match="control characters"):
        normalize_category_query("ai\x00")
    with pytest.raises(ValueError, match="control characters"):
        normalize_category_query("ai\x1b[0m")
    with pytest.raises(ValueError, match="control characters"):
        normalize_category_query("ai\n")


def test_normalize_category_query_normalizes_case_and_whitespace() -> None:
    from recon_tool.catalog_discovery import normalize_category_query

    assert normalize_category_query("  InFra  ") == "infra"
    assert normalize_category_query(None) == ""
