"""Release preparation transactions against disposable, offline Git repositories."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from scripts import release

_ORIGINAL = b"old version\r\n"
_UPDATED = b"new version\n"
_UNRELATED = b"unchanged outside the release transaction\n"


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed test-owned Git arguments and temporary cwd.
        ["git", *args],  # noqa: S607 - use the same Git executable as the release helper.
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    return result.stdout.strip()


@pytest.fixture
def preparation_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, list[str]]:
    # Neither inherited repository pointers nor user signing, hooks, templates,
    # identity, or attribute configuration may affect this disposable repo.
    for name in tuple(os.environ):
        if name.startswith("GIT_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_ATTR_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "0")
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "")
    root = tmp_path / "release preparation"
    root.mkdir()
    _git(root, "init", "--quiet", "--initial-branch=release/2.19.0", "--template=")
    for key, value in (
        ("user.name", "Release Test"),
        ("user.email", "release-test@example.invalid"),
        ("commit.gpgSign", "false"),
        ("tag.gpgSign", "false"),
        ("core.autocrlf", "false"),
        ("core.hooksPath", ".git/disabled-hooks"),
    ):
        _git(root, "config", "--local", key, value)
    owned = root / "version.txt"
    generated = root / "generated.txt"
    owned.write_bytes(_ORIGINAL)
    (root / "unrelated.txt").write_bytes(_UNRELATED)
    _git(root, "add", "version.txt", "unrelated.txt")
    _git(root, "commit", "--quiet", "-m", "Synthetic starting point")
    events: list[str] = []

    def bump(current: str, new: str, release_date: str) -> None:
        assert (current, new, release_date) == ("2.18.4", "2.19.0", "2026-09-05")
        events.append("bump")
        owned.write_bytes(_UPDATED)
        generated.write_bytes(b"new generated artifact\n")

    def quality() -> None:
        events.append("quality")

    def readiness(*, allow_non_main: bool = False) -> None:
        assert allow_non_main
        events.append("readiness")

    monkeypatch.setattr(release, "ROOT", root)
    monkeypatch.setattr(release, "_release_mutation_paths", lambda: (owned, generated))
    monkeypatch.setattr(release, "_bump_release_surfaces", bump)
    monkeypatch.setattr(release, "_run_quality_gate", quality)
    monkeypatch.setattr(release, "_run_release_readiness", readiness)
    return root, events


def test_real_git_preparation_commits_owned_paths_without_a_tag(preparation_repo: tuple[Path, list[str]]) -> None:
    root, events = preparation_repo
    starting_head = _git(root, "rev-parse", "HEAD")
    assert _git(root, "remote") == ""
    assert _git(root, "tag", "--list") == ""
    release._check_preparation_branch()
    release._check_clean_tree()

    # Exercise the transaction directly: preflight fetching and interactive
    # choices are covered separately, and this repository has no remote.
    release._create_local_release("2.18.4", "2.19.0", "2026-09-05", prepare_only=True)

    assert events == ["bump", "quality", "readiness"]
    assert _git(root, "rev-parse", "HEAD") != starting_head
    assert _git(root, "rev-parse", "HEAD^") == starting_head
    assert _git(root, "log", "-1", "--format=%s") == "v2.19.0: release"
    assert _git(root, "diff", "--name-only", "HEAD^", "HEAD").splitlines() == ["generated.txt", "version.txt"]
    assert (root / "version.txt").read_bytes() == _UPDATED
    assert (root / "generated.txt").read_bytes() == b"new generated artifact\n"
    assert (root / "unrelated.txt").read_bytes() == _UNRELATED
    assert _git(root, "status", "--porcelain") == ""
    assert _git(root, "branch", "--show-current") == "release/2.19.0"
    assert _git(root, "tag", "--list") == ""
    assert _git(root, "remote") == ""


@pytest.mark.parametrize("failure", ["quality", "readiness", "committed-quality", "interrupted-quality"])
def test_real_git_preparation_failure_restores_head_index_bytes_and_existing_tag(
    preparation_repo: tuple[Path, list[str]], monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    root, events = preparation_repo
    starting_head = _git(root, "rev-parse", "HEAD")
    starting_index_tree = _git(root, "write-tree")
    _git(root, "tag", "--no-sign", "unrelated-existing-tag", starting_head)
    starting_tags = _git(root, "show-ref", "--tags")
    intermediate_commits: list[str] = []

    def fail_quality() -> None:
        events.append("quality")
        assert (root / "version.txt").read_bytes() == _UPDATED
        assert (root / "generated.txt").exists()
        if failure == "committed-quality":
            # Model a gate/tool advancing HEAD before failing. This is an actual
            # commit, not a mocked command or the helper's final commit stage.
            _git(root, "add", "version.txt", "generated.txt")
            _git(root, "commit", "--quiet", "-m", "Synthetic intermediate commit")
            intermediate_commits.append(_git(root, "rev-parse", "HEAD"))
        else:
            # Include a changed real index in the rollback contract as well.
            _git(root, "add", "version.txt", "generated.txt")
        if failure == "interrupted-quality":
            raise KeyboardInterrupt
        raise RuntimeError("synthetic quality failure")

    def fail_readiness(*, allow_non_main: bool = False) -> None:
        assert allow_non_main
        events.append("readiness")
        raise RuntimeError("synthetic readiness failure")

    if failure == "readiness":
        monkeypatch.setattr(release, "_run_release_readiness", fail_readiness)
    else:
        monkeypatch.setattr(release, "_run_quality_gate", fail_quality)
    expected_error = KeyboardInterrupt if failure == "interrupted-quality" else release.ReleaseError

    with pytest.raises(expected_error):
        release._create_local_release("2.18.4", "2.19.0", "2026-09-05", prepare_only=True)

    assert events == (["bump", "quality", "readiness"] if failure == "readiness" else ["bump", "quality"])
    if failure == "committed-quality":
        assert len(intermediate_commits) == 1
        assert intermediate_commits[0] != starting_head
        assert _git(root, "rev-parse", f"{intermediate_commits[0]}^") == starting_head
    assert _git(root, "rev-parse", "HEAD") == starting_head
    assert _git(root, "write-tree") == starting_index_tree
    assert _git(root, "diff", "--cached", "--name-only") == ""
    assert (root / "version.txt").read_bytes() == _ORIGINAL
    assert not (root / "generated.txt").exists()
    assert (root / "unrelated.txt").read_bytes() == _UNRELATED
    assert _git(root, "status", "--porcelain") == ""
    assert _git(root, "branch", "--show-current") == "release/2.19.0"
    assert _git(root, "show-ref", "--tags") == starting_tags
    assert _git(root, "remote") == ""
