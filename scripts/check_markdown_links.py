#!/usr/bin/env python3
"""Validate tracked Markdown relative links and GitHub-style heading anchors."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
_FENCE = re.compile(r"^\s*(```+|~~~+)")
_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
_INLINE_LINK = re.compile(r"\[[^]]*]\(([^)]+)\)")
_REFERENCE_TARGET = re.compile(r"^\s{0,3}\[[^]]+]:\s*(\S+)")
_INLINE_CODE = re.compile(r"(`+)(.*?)\1")
_EXPLICIT_ANCHOR = re.compile(r"<a\b[^>]*\b(?:id|name)\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.IGNORECASE)


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


def _target_from_raw(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("<") and ">" in raw:
        return raw[1 : raw.index(">")]
    return raw.split(maxsplit=1)[0]


def _link_targets(path: Path) -> list[tuple[int, str]]:
    targets: list[tuple[int, str]] = []
    for line_number, line in _visible_lines(path.read_text(encoding="utf-8")):
        targets.extend((line_number, _target_from_raw(match.group(1))) for match in _INLINE_LINK.finditer(line))
        reference = _REFERENCE_TARGET.match(line)
        if reference is not None:
            targets.append((line_number, _target_from_raw(reference.group(1))))
    return targets


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


def dangling_links(files: list[Path] | None = None, *, root: Path = ROOT) -> list[str]:
    files = _tracked_markdown(root) if files is None else files
    anchor_cache: dict[Path, set[str]] = {}
    problems: list[str] = []
    for source in files:
        if not source.exists():
            continue
        rel_source = source.relative_to(root).as_posix() if source.is_relative_to(root) else str(source)
        for line_number, raw_target in _link_targets(source):
            target = unquote(raw_target)
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or target.startswith("//"):
                continue
            target_path = Path(parsed.path) if parsed.path else Path(source.name)
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
            anchor = parsed.fragment.lower()
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
    except (OSError, RuntimeError, UnicodeDecodeError) as exc:
        print(f"FAIL: could not validate Markdown links: {exc}")
        return 1
    if problems:
        print(f"FAIL: {len(problems)} dangling Markdown link(s):")
        for problem in problems:
            print(f"  {problem}")
        return 1
    count = len(files) if files is not None else len(_tracked_markdown(ROOT))
    print(f"OK: relative links and heading anchors resolve across {count} Markdown files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
