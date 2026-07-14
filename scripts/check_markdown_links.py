#!/usr/bin/env python3
"""Validate tracked Markdown relative links and GitHub-style heading anchors."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from bisect import bisect_left
from collections.abc import Callable
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, unquote, urlsplit

from markdown_it import MarkdownIt
from markdown_it.rules_inline import StateInline, autolink, html_inline, image, link
from markdown_it.token import Token

ROOT = Path(__file__).resolve().parents[1]
_FENCE = re.compile(r"^\s*(```+|~~~+)")
_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
_INLINE_CODE = re.compile(r"(`+)(.*?)\1")
_EXPLICIT_ANCHOR = re.compile(r"<a\b[^>]*\b(?:id|name)\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.IGNORECASE)
_SOURCE_OFFSET = "recon_source_offset"
_InlineRule = Callable[[StateInline, bool], bool]


def _positioned_rule(rule: _InlineRule) -> _InlineRule:
    def positioned(state: StateInline, silent: bool) -> bool:
        source_offset = state.pos
        initial_token_count = len(state.tokens)
        matched = rule(state, silent)
        if matched and not silent:
            for token in state.tokens[initial_token_count:]:
                token.meta.setdefault(_SOURCE_OFFSET, source_offset)
        return matched

    return positioned


_MARKDOWN = MarkdownIt("commonmark")
for _rule_name, _rule in (
    ("link", link),
    ("image", image),
    ("autolink", autolink),
    ("html_inline", html_inline),
):
    _MARKDOWN.inline.ruler.at(_rule_name, _positioned_rule(_rule))


class _HTMLDestinationParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.destinations: list[tuple[int, str]] = []

    def _record(self, attributes: list[tuple[str, str | None]]) -> None:
        line_number, _column = self.getpos()
        for name, value in attributes:
            if name.casefold() in {"href", "src"}:
                self.destinations.append((line_number, value or ""))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del tag
        self._record(attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del tag
        self._record(attrs)


def _visible_lines(text: str, *, strip_inline_code: bool = True) -> list[tuple[int, str]]:
    visible: list[tuple[int, str]] = []
    fence: str | None = None
    for line_number, line in enumerate(text.splitlines(), 1):
        marker = _FENCE.match(line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token[0]
            elif token[0] == fence:
                fence = None
            continue
        if fence is None:
            visible.append((line_number, _INLINE_CODE.sub("", line) if strip_inline_code else line))
    return visible


def _heading_slug(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\[([^]]+)]\([^)]+\)", r"\1", text)
    text = text.replace("`", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return re.sub(r"\s+", "-", text).strip("-")


def heading_anchors(path: Path) -> set[str]:
    counts: dict[str, int] = {}
    anchors: set[str] = set()
    for _line_number, line in _visible_lines(path.read_text(encoding="utf-8"), strip_inline_code=False):
        anchors.update(match.group(1).lower() for match in _EXPLICIT_ANCHOR.finditer(line))
        match = _HEADING.match(line)
        if match is None:
            continue
        base = _heading_slug(match.group(1))
        if not base:
            continue
        occurrence = counts.get(base, 0)
        counts[base] = occurrence + 1
        anchors.add(base if occurrence == 0 else f"{base}-{occurrence}")
    return anchors


def _token_destination(token: Token) -> str | None:
    attribute = "href" if token.type == "link_open" else "src" if token.type == "image" else None
    value = token.attrGet(attribute) if attribute is not None else None
    return value if isinstance(value, str) else None


def _source_line(token: Token, content_length: int, newline_offsets: list[int], block_start: int) -> int:
    source_offset = token.meta.get(_SOURCE_OFFSET)
    if not isinstance(source_offset, int) or not 0 <= source_offset <= content_length:
        return block_start + 1
    return block_start + bisect_left(newline_offsets, source_offset) + 1


def _destination_locations(children: list[Token], content: str, block_start: int) -> list[tuple[int, str]]:
    targets: list[tuple[int, str]] = []
    newline_offsets = [index for index, character in enumerate(content) if character == "\n"]
    for child in children:
        target = _token_destination(child)
        source_line = _source_line(child, len(content), newline_offsets, block_start)
        if target is not None:
            targets.append((source_line, target))
        elif child.type == "html_inline":
            targets.extend(
                (source_line + relative_line - 1, html_target)
                for relative_line, html_target in _html_destinations(child.content)
            )
    return targets


def _html_destinations(content: str) -> list[tuple[int, str]]:
    parser = _HTMLDestinationParser()
    parser.feed(content)
    parser.close()
    return parser.destinations


def _record_targets(targets: list[str], line_number: int, locations: dict[str, tuple[int, int]], sequence: int) -> int:
    for target in targets:
        candidate = (line_number, sequence)
        current = locations.get(target)
        if current is None or candidate < current:
            locations[target] = candidate
        sequence += 1
    return sequence


def _link_targets(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8")
    locations: dict[str, tuple[int, int]] = {}
    sequence = 0

    environment: dict[str, Any] = {}
    tokens = _MARKDOWN.parse(text, environment)
    references = environment.get("references")
    if isinstance(references, dict):
        for reference in references.values():
            if not isinstance(reference, dict):
                continue
            target = reference.get("href")
            mapping = reference.get("map")
            if not isinstance(target, str):
                continue
            line_number = mapping[0] + 1 if isinstance(mapping, list) and mapping and isinstance(mapping[0], int) else 1
            sequence = _record_targets([target], line_number, locations, sequence)

    for token in tokens:
        if token.type == "inline":
            block_start = token.map[0] if token.map else 0
            for line_number, target in _destination_locations(token.children or [], token.content, block_start):
                sequence = _record_targets([target], line_number, locations, sequence)
        elif token.type == "html_block":
            start = token.map[0] if token.map else 0
            for relative_line, target in _html_destinations(token.content):
                sequence = _record_targets([target], start + relative_line, locations, sequence)

    return [
        (line_number, target)
        for target, (line_number, _order) in sorted(locations.items(), key=lambda item: (item[1][0], item[1][1]))
    ]


def _canonical_repository_path(parsed: SplitResult) -> Path | None:
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.casefold() != "https"
        or hostname is None
        or hostname.casefold() != "github.com"
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    path = unquote(parsed.path)
    parts = path.split("/")
    if (
        len(parts) >= 6
        and parts[0] == ""
        and parts[1].casefold() == "blisspixel"
        and parts[2].casefold() == "recon"
        and parts[3].casefold() in {"blob", "tree"}
        and parts[4] == "main"
    ):
        return Path(*parts[5:])
    return None


def _split_target(target: str) -> SplitResult | None:
    try:
        return urlsplit(target)
    except ValueError:
        return None


def _tracked_markdown(root: Path) -> list[Path]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not available")
    result = subprocess.run(  # noqa: S603 - resolved executable and fixed argv.
        [git, "ls-files", "-z", "--", "*.md"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip() or "git ls-files failed")
    return [root / raw.decode("utf-8") for raw in result.stdout.split(b"\0") if raw]


def package_description_relative_links(path: Path | None = None, *, root: Path = ROOT) -> list[str]:
    """Return README destinations that would resolve relative to the PyPI page."""
    source = root / "README.md" if path is None else path
    rel_source = source.relative_to(root).as_posix() if source.is_relative_to(root) else str(source)
    problems: list[str] = []
    for line_number, raw_target in _link_targets(source):
        target = raw_target
        parsed = _split_target(target)
        if parsed is None:
            problems.append(f"{rel_source}:{line_number}: invalid link target: {raw_target}")
            continue
        if parsed.scheme or parsed.netloc or target.startswith("//"):
            continue
        if target.startswith("#"):
            continue
        problems.append(f"{rel_source}:{line_number}: package-description link must be absolute: {raw_target}")
    return problems


def dangling_links(files: list[Path] | None = None, *, root: Path = ROOT) -> list[str]:
    files = _tracked_markdown(root) if files is None else files
    anchor_cache: dict[Path, set[str]] = {}
    problems: list[str] = []
    for source in files:
        if not source.exists():
            continue
        rel_source = source.relative_to(root).as_posix() if source.is_relative_to(root) else str(source)
        for line_number, raw_target in _link_targets(source):
            target = raw_target
            parsed = _split_target(target)
            if parsed is None:
                problems.append(f"{rel_source}:{line_number}: invalid link target: {raw_target}")
                continue
            repository_path = _canonical_repository_path(parsed)
            if repository_path is not None:
                if repository_path.is_absolute() or repository_path.drive or ".." in repository_path.parts:
                    problems.append(f"{rel_source}:{line_number}: link escapes repository: {raw_target}")
                    continue
                target_path = repository_path
                resolved = root / target_path
            elif parsed.scheme or parsed.netloc or target.startswith("//"):
                continue
            else:
                decoded_path = unquote(parsed.path)
                target_path = Path(decoded_path) if decoded_path else Path(source.name)
                resolved = (
                    root / str(target_path).lstrip("/\\")
                    if str(target_path).startswith(("/", "\\"))
                    else source.parent / target_path
                )
            resolved = resolved.resolve()
            if not resolved.is_relative_to(root.resolve()):
                problems.append(f"{rel_source}:{line_number}: link escapes repository: {raw_target}")
                continue
            if not resolved.exists():
                problems.append(f"{rel_source}:{line_number}: missing link target: {raw_target}")
                continue
            anchor = unquote(parsed.fragment).lower()
            if anchor and resolved.suffix.lower() == ".md":
                anchors = anchor_cache.setdefault(resolved, heading_anchors(resolved))
                if anchor not in anchors:
                    problems.append(f"{rel_source}:{line_number}: missing heading anchor: {raw_target}")
    return problems


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    files = [Path(item).resolve() for item in argv] if argv else None
    try:
        problems = dangling_links(files)
        readme = ROOT / "README.md"
        if files is None or readme.resolve() in files:
            problems.extend(package_description_relative_links(readme))
        problems = list(dict.fromkeys(problems))
    except (OSError, RuntimeError, UnicodeDecodeError) as exc:
        print(f"FAIL: could not validate Markdown links: {exc}")
        return 1
    if problems:
        print(f"FAIL: {len(problems)} Markdown link problem(s):")
        for problem in problems:
            print(f"  {problem}")
        return 1
    count = len(files) if files is not None else len(_tracked_markdown(ROOT))
    print(
        "OK: relative links, heading anchors, and package-description destinations "
        f"resolve across {count} Markdown files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
