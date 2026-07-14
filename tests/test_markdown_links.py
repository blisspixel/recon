"""Repository-wide Markdown link and anchor gate."""

from __future__ import annotations

from pathlib import Path

from scripts.check_markdown_links import dangling_links


def test_all_tracked_markdown_links_resolve() -> None:
    assert dangling_links() == []


def test_checker_reports_missing_file_and_anchor(tmp_path: Path) -> None:
    target = tmp_path / "target.md"
    target.write_text("# Real Heading\n", encoding="utf-8")
    source = tmp_path / "source.md"
    source.write_text(
        "[missing](absent.md)\n[bad anchor](target.md#missing)\n",
        encoding="utf-8",
    )
    problems = dangling_links([source], root=tmp_path)
    assert any("missing link target" in problem for problem in problems)
    assert any("missing heading anchor" in problem for problem in problems)


def test_checker_ignores_links_inside_code(tmp_path: Path) -> None:
    source = tmp_path / "source.md"
    source.write_text(
        "`[inline](missing.md)`\n```md\n[fenced](missing.md)\n```\n",
        encoding="utf-8",
    )
    assert dangling_links([source], root=tmp_path) == []


def test_duplicate_heading_anchors_follow_github_suffixes(tmp_path: Path) -> None:
    target = tmp_path / "target.md"
    target.write_text("# Same\n\n# Same\n", encoding="utf-8")
    source = tmp_path / "source.md"
    source.write_text("[second](target.md#same-1)\n", encoding="utf-8")
    assert dangling_links([source], root=tmp_path) == []


def test_explicit_html_compatibility_anchor_resolves(tmp_path: Path) -> None:
    target = tmp_path / "target.md"
    target.write_text('<a id="stable-anchor"></a>\n\n# Changed Heading\n', encoding="utf-8")
    source = tmp_path / "source.md"
    source.write_text("[stable](target.md#stable-anchor)\n", encoding="utf-8")
    assert dangling_links([source], root=tmp_path) == []
