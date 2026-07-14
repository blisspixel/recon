"""Release-tag preflight regressions."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.validate_release_tag import ReleaseTagError, validate_release_tag


def _root(tmp_path: Path, *, version: str = "2.5.9", notes: str = "- Fixed a bug.\n") -> Path:
    (tmp_path / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## [{version}] - 2026-07-13\n\n{notes}",
        encoding="utf-8",
    )
    return tmp_path


def _runner(returncode: int = 0) -> object:
    def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        assert cmd[:3] == ["git", "merge-base", "--is-ancestor"]
        return subprocess.CompletedProcess(cmd, returncode, "", "not on main" if returncode else "")

    return run


def test_matching_tag_with_notes_and_main_ancestry_passes(tmp_path: Path) -> None:
    version = validate_release_tag(
        _root(tmp_path),
        tag="v2.5.9",
        sha="a" * 40,
        main_ref="refs/remotes/origin/main",
        runner=_runner(),  # type: ignore[arg-type]
    )
    assert version == "2.5.9"


def test_mismatched_tag_fails_before_git(tmp_path: Path) -> None:
    with pytest.raises(ReleaseTagError, match="does not match"):
        validate_release_tag(
            _root(tmp_path),
            tag="v9.9.9",
            sha="a" * 40,
            main_ref="refs/remotes/origin/main",
            runner=_runner(),  # type: ignore[arg-type]
        )


def test_non_main_tag_fails(tmp_path: Path) -> None:
    with pytest.raises(ReleaseTagError, match="not contained"):
        validate_release_tag(
            _root(tmp_path),
            tag="v2.5.9",
            sha="a" * 40,
            main_ref="refs/remotes/origin/main",
            runner=_runner(1),  # type: ignore[arg-type]
        )


def test_empty_changelog_notes_fail(tmp_path: Path) -> None:
    with pytest.raises(ReleaseTagError, match="has no notes"):
        validate_release_tag(
            _root(tmp_path, notes=""),
            tag="v2.5.9",
            sha="a" * 40,
            main_ref="refs/remotes/origin/main",
            runner=_runner(),  # type: ignore[arg-type]
        )


def test_leading_zero_project_version_fails(tmp_path: Path) -> None:
    with pytest.raises(ReleaseTagError, match=r"stable X\.Y\.Z"):
        validate_release_tag(
            _root(tmp_path, version="02.5.9"),
            tag="v02.5.9",
            sha="a" * 40,
            main_ref="refs/remotes/origin/main",
            runner=_runner(),  # type: ignore[arg-type]
        )
