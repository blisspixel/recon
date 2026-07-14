#!/usr/bin/env python3
"""Fail closed when a release tag does not match the source being published."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_CHANGELOG_HEADING = re.compile(r"^## \[(?P<version>[^]]+)] - (?P<date>\d{4}-\d{2}-\d{2})\s*$", re.MULTILINE)
_SEMVER_COMPONENT = r"(?:0|[1-9][0-9]*)"
_STABLE_VERSION = re.compile(rf"^{_SEMVER_COMPONENT}\.{_SEMVER_COMPONENT}\.{_SEMVER_COMPONENT}$")


class ReleaseTagError(RuntimeError):
    """The tag cannot safely publish the checked-out source tree."""


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed git argv plus validated commit/ref strings.
        cmd,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _project_version(root: Path) -> str:
    with (root / "pyproject.toml").open("rb") as handle:
        version = tomllib.load(handle).get("project", {}).get("version")
    if not isinstance(version, str) or _STABLE_VERSION.fullmatch(version) is None:
        raise ReleaseTagError("pyproject.toml project.version must be a stable X.Y.Z release")
    return version


def _changelog_notes(root: Path, version: str) -> tuple[str, str]:
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    matches = list(_CHANGELOG_HEADING.finditer(text))
    match = next((item for item in matches if item.group("version") == version), None)
    if match is None:
        raise ReleaseTagError(f"CHANGELOG.md has no dated section for {version}")
    try:
        dt.date.fromisoformat(match.group("date"))
    except ValueError as exc:
        raise ReleaseTagError(f"CHANGELOG.md has an invalid release date for {version}") from exc
    next_heading = next((item.start() for item in matches if item.start() > match.start()), len(text))
    notes = text[match.end() : next_heading].strip()
    if not notes:
        raise ReleaseTagError(f"CHANGELOG.md release section {version} has no notes")
    return match.group("date"), notes


def validate_release_tag(
    root: Path,
    *,
    tag: str,
    sha: str,
    main_ref: str,
    runner: Runner = _run,
) -> str:
    """Return the project version after tag, changelog, and ancestry checks."""
    version = _project_version(root)
    expected_tag = f"v{version}"
    if tag != expected_tag:
        raise ReleaseTagError(f"Release tag {tag!r} does not match project version {expected_tag!r}")
    _changelog_notes(root, version)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
        raise ReleaseTagError("Release SHA must be a full 40-character Git object ID")
    ancestry = runner(["git", "merge-base", "--is-ancestor", sha, main_ref])
    if ancestry.returncode != 0:
        detail = ancestry.stderr.strip() or ancestry.stdout.strip() or "tag commit is not on main"
        raise ReleaseTagError(f"Release tag commit is not contained in {main_ref}: {detail}")
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=os.environ.get("GITHUB_REF_NAME", ""))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--main-ref", default="refs/remotes/origin/main")
    args = parser.parse_args(argv)
    try:
        version = validate_release_tag(ROOT, tag=args.tag, sha=args.sha, main_ref=args.main_ref)
    except (OSError, ReleaseTagError, tomllib.TOMLDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"OK: v{version} matches the project, changelog, and main ancestry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
