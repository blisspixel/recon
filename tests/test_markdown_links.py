"""Repository-wide Markdown link and anchor gate."""

from __future__ import annotations

from pathlib import Path

from scripts.check_markdown_links import dangling_links, package_description_relative_links


def test_all_tracked_markdown_links_resolve() -> None:
    assert dangling_links() == []


def test_package_description_links_are_pypi_safe() -> None:
    assert package_description_relative_links() == []


def test_package_description_checker_rejects_only_relative_destinations(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text(
        "\n".join(
            (
                "[anchor](#section)",
                "[external](https://example.com/guide)",
                "[email](mailto:maintainer@example.com)",
                "`[inline example](docs/inline.md)`",
                "```md",
                "[fenced example](docs/fenced.md)",
                "```",
                "    [indented example](docs/indented.md)",
                "[plain bracketed text]",
                "[broken](docs/guide.md)",
            )
        ),
        encoding="utf-8",
    )

    assert package_description_relative_links(source, root=tmp_path) == [
        "README.md:10: package-description link must be absolute: docs/guide.md"
    ]


def test_package_description_checker_handles_nested_badges_titles_and_references(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text(
        "\n".join(
            (
                '[ordinary](docs/ordinary.md "Ordinary title")',
                "",
                '[reference]: docs/reference.md "Reference title"',
                "",
                '[![badge](assets/badge.svg "Badge title")](docs/guide.md "Guide title")',
                '<a href="docs/html-guide.md">HTML guide</a>',
                '<img src="assets/html-badge.svg" alt="HTML badge">',
            )
        ),
        encoding="utf-8",
    )

    assert package_description_relative_links(source, root=tmp_path) == [
        "README.md:1: package-description link must be absolute: docs/ordinary.md",
        "README.md:3: package-description link must be absolute: docs/reference.md",
        "README.md:5: package-description link must be absolute: docs/guide.md",
        "README.md:5: package-description link must be absolute: assets/badge.svg",
        "README.md:6: package-description link must be absolute: docs/html-guide.md",
        "README.md:7: package-description link must be absolute: assets/html-badge.svg",
    ]


def test_package_description_checker_handles_commonmark_destination_boundaries(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text(
        "\n".join(
            (
                '[quoted](docs/missing.md "see (details")',
                "[angle](<docs/a(b.md>)",
                "[encoded scheme](https%3A//example.com/guide)",
                r"\[literal](docs/not-a-link.md)",
            )
        ),
        encoding="utf-8",
    )

    assert package_description_relative_links(source, root=tmp_path) == [
        "README.md:1: package-description link must be absolute: docs/missing.md",
        "README.md:2: package-description link must be absolute: docs/a(b.md",
        "README.md:3: package-description link must be absolute: https%3A//example.com/guide",
    ]


def test_package_description_checker_allows_only_fragment_only_pathless_targets(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text(
        "[fragment](#section)\n[top](#)\n[query](?download=1)\n[empty]()\n[query fragment](?#section)\n",
        encoding="utf-8",
    )

    assert package_description_relative_links(source, root=tmp_path) == [
        "README.md:3: package-description link must be absolute: ?download=1",
        "README.md:4: package-description link must be absolute: ",
        "README.md:5: package-description link must be absolute: ?#section",
    ]


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


def test_checker_validates_raw_html_destinations_but_not_html_in_code(tmp_path: Path) -> None:
    source = tmp_path / "source.md"
    source.write_text(
        '<a href="missing.html">missing</a>\n'
        '<a href="https://[">malformed</a>\n'
        "<a href>empty</a>\n"
        '```html\n<img src="ignored.svg">\n```\n'
        '    <a href="also-ignored.html">ignored</a>\n',
        encoding="utf-8",
    )

    assert dangling_links([source], root=tmp_path) == [
        "source.md:1: missing link target: missing.html",
        "source.md:2: invalid link target: https://[",
    ]
    assert package_description_relative_links(source, root=tmp_path) == [
        "source.md:1: package-description link must be absolute: missing.html",
        "source.md:2: invalid link target: https://[",
        "source.md:3: package-description link must be absolute: ",
    ]


def test_checker_decodes_path_and_commonmark_escapes_after_url_splitting(tmp_path: Path) -> None:
    hash_target = tmp_path / "a#b.md"
    hash_target.write_text("# Hash File\n", encoding="utf-8")
    parenthesized_target = tmp_path / "a(b).md"
    parenthesized_target.write_text("# Parenthesized File\n", encoding="utf-8")
    source = tmp_path / "source.md"
    source.write_text(
        "[hash](a%23b.md)\n" + r"[parenthesized](a\(b\).md)" + "\n",
        encoding="utf-8",
    )

    assert dangling_links([source], root=tmp_path) == []


def test_checker_validates_canonical_repository_targets(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    target = docs / "guide.md"
    target.write_text("# Real Heading\n", encoding="utf-8")
    source = tmp_path / "README.md"
    source.write_text(
        "\n".join(
            (
                "[valid](https://github.com/blisspixel/recon/blob/main/docs/guide.md#real-heading)",
                "[missing](https://github.com/blisspixel/recon/blob/main/docs/missing.md)",
                "[bad anchor](https://github.com/blisspixel/recon/blob/main/docs/guide.md#missing)",
                "[escape](https://github.com/blisspixel/recon/tree/main/../outside)",
                "[case and port](https://GITHUB.com:443/BlissPixel/ReCon/blob/main/docs/missing-case.md)",
            )
        ),
        encoding="utf-8",
    )

    assert dangling_links([source], root=tmp_path) == [
        "README.md:2: missing link target: https://github.com/blisspixel/recon/blob/main/docs/missing.md",
        "README.md:3: missing heading anchor: https://github.com/blisspixel/recon/blob/main/docs/guide.md#missing",
        "README.md:4: link escapes repository: https://github.com/blisspixel/recon/tree/main/../outside",
        "README.md:5: missing link target: https://GITHUB.com:443/BlissPixel/ReCon/blob/main/docs/missing-case.md",
    ]


def test_checker_ignores_links_inside_code(tmp_path: Path) -> None:
    source = tmp_path / "source.md"
    source.write_text(
        "`[inline](missing.md)`\n```md\n[fenced](missing.md)\n```\n",
        encoding="utf-8",
    )
    assert dangling_links([source], root=tmp_path) == []


def test_checker_reports_a_duplicate_target_at_its_first_source_location(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text(
        "[direct](docs/shared.md)\n\n[reference]: docs/shared.md\n",
        encoding="utf-8",
    )

    assert package_description_relative_links(source, root=tmp_path) == [
        "README.md:1: package-description link must be absolute: docs/shared.md"
    ]


def test_checker_reports_a_multiline_duplicate_at_its_first_source_location(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text(
        "[first\nlabel](docs/shared.md) and\n[later](docs/shared.md)\n",
        encoding="utf-8",
    )

    assert package_description_relative_links(source, root=tmp_path) == [
        "README.md:1: package-description link must be absolute: docs/shared.md"
    ]


def test_checker_locates_multiline_links_from_the_actual_inline_token(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text(
        "ordinary text\nstill ordinary\n[actual\nlink](docs/actual.md)\n",
        encoding="utf-8",
    )

    assert package_description_relative_links(source, root=tmp_path) == [
        "README.md:3: package-description link must be absolute: docs/actual.md"
    ]


def test_checker_does_not_attribute_real_links_to_multiline_code_spans(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text(
        "`\n[fake](docs/shared.md)\n`\n[real](docs/shared.md)\n",
        encoding="utf-8",
    )

    assert package_description_relative_links(source, root=tmp_path) == [
        "README.md:4: package-description link must be absolute: docs/shared.md"
    ]


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
