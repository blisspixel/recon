"""Release-script regressions."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts import release


def test_release_script_points_at_src_layout_init() -> None:
    assert release.INIT_PY == release.ROOT / "src" / "recon_tool" / "__init__.py"
    assert release.INIT_PY.exists()


def test_release_script_version_consistency_reads_src_layout_init() -> None:
    assert release._check_version_consistency() == release._read_current_version()


def test_release_quality_gate_runs_complete_local_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(release, "_run", fake_run)

    release._run_quality_gate()

    assert commands == [["uv", "run", "python", "scripts/check.py"]]


def test_release_push_command_names_only_the_reviewed_tag() -> None:
    assert release._release_push_command("2.3.7") == [
        "git",
        "push",
        "--atomic",
        "origin",
        "main",
        "refs/tags/v2.3.7:refs/tags/v2.3.7",
    ]


def test_release_push_failure_preserves_validated_local_release(monkeypatch: pytest.MonkeyPatch) -> None:
    def confirm(_message: str, default_no: bool = True) -> bool:
        assert default_no
        return True

    def failed_run(
        cmd: list[str], check: bool = True, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        assert cmd == release._release_push_command("2.5.9")
        assert not check
        assert not capture
        return subprocess.CompletedProcess(cmd, 1, "", "credentials unavailable")

    monkeypatch.setattr(release, "_prompt_confirm", confirm)
    monkeypatch.setattr(release, "_run", failed_run)

    with pytest.raises(release.ReleaseError, match="local commit and tag were preserved") as error:
        release._offer_release_push("2.5.9")

    assert "credentials unavailable" not in str(error.value)


def test_release_rejects_prerelease_versions() -> None:
    with pytest.raises(release.ReleaseError, match="valid semver"):
        release._validate_new_version("2.6.0-beta.1", "2.5.8")


def test_release_rejects_leading_zero_versions() -> None:
    with pytest.raises(release.ReleaseError, match="valid semver"):
        release._validate_new_version("02.5.9", "2.5.8")


def test_release_requires_head_to_match_refreshed_upstream(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
        if cmd == [
            "git",
            "fetch",
            "--no-tags",
            "origin",
            "+refs/heads/main:refs/remotes/origin/main",
        ]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(cmd, 0, "local\n", "")
        if cmd == ["git", "rev-parse", "refs/remotes/origin/main"]:
            return subprocess.CompletedProcess(cmd, 0, "remote\n", "")
        raise AssertionError(cmd)

    monkeypatch.setattr(release, "_run", fake_run)
    with pytest.raises(release.ReleaseError, match="does not exactly match"):
        release._check_upstream_current(fetch=True)


def test_release_rejects_impossible_changelog_date(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("## [2.5.9] - 2026-99-99\n\n- Notes.\n", encoding="utf-8")
    monkeypatch.setattr(release, "CHANGELOG", changelog)
    with pytest.raises(release.ReleaseError, match="invalid release date"):
        release._changelog_release_date("2.5.9")


def test_release_surface_generation_writes_both_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plugin = tmp_path / "plugin.json"
    plugin.write_text('{"version": "2.5.8"}\n', encoding="utf-8")
    citation = tmp_path / "CITATION.cff"
    citation.write_text('version: 2.5.8\ndate-released: "2026-07-13"\n', encoding="utf-8")
    commands: list[list[str]] = []

    monkeypatch.setattr(release, "PLUGIN_MANIFEST", plugin)
    monkeypatch.setattr(release, "CITATION", citation)
    monkeypatch.setattr(release, "_VERSIONED_DOCS", ())
    monkeypatch.setattr(release, "_REVIEWED_DOCS", ())

    def ignore_version_write(_version: str, _dry: bool) -> None:
        return None

    def ignore_lock_write(_dry: bool) -> None:
        return None

    monkeypatch.setattr(release, "_bump_pyproject", ignore_version_write)
    monkeypatch.setattr(release, "_bump_init", ignore_version_write)
    monkeypatch.setattr(release, "_bump_lockfile", ignore_lock_write)

    def fake_run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(release, "_run", fake_run)
    release._bump_release_surfaces("2.5.8", "2.5.9", "2026-07-13")
    assert commands == [
        [
            "uv",
            "run",
            "python",
            "scripts/generate_surface_inventory.py",
            "--write",
            "--write-cli-surface",
        ]
    ]


def test_release_rollback_restores_files_index_commit_and_owned_tag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    changed = tmp_path / "version.txt"
    changed.write_text("new", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
        del check, capture
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(release, "_run", fake_run)
    release._rollback_local_release("abc123", {changed: b"old"}, "v2.5.9")
    assert changed.read_text(encoding="utf-8") == "old"
    assert ["git", "tag", "-d", "v2.5.9"] in commands
    assert ["git", "reset", "--mixed", "abc123"] in commands


def test_release_validates_after_prospective_bump(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    confirmations = iter((True, False))

    def no_upstream_check(*, fetch: bool) -> None:
        assert fetch

    def accept_version(_new: str, _current: str) -> None:
        return None

    def accept_changelog(_version: str) -> None:
        return None

    def release_date(_version: str) -> str:
        return "2026-07-13"

    def confirm(_message: str, default_no: bool = True) -> bool:
        del default_no
        return next(confirmations)

    def record_bump(_current: str, _new: str, _release_date: str) -> None:
        events.append("bump")

    def fake_input(_prompt: str) -> str:
        return "2.5.9"

    def no_tag(_version: str) -> None:
        return None

    monkeypatch.setattr(release, "_check_branch", lambda: None)
    monkeypatch.setattr(release, "_check_clean_tree", lambda: None)
    monkeypatch.setattr(release, "_check_upstream_current", no_upstream_check)
    monkeypatch.setattr(release, "_check_version_consistency", lambda: "2.5.8")
    monkeypatch.setattr(release, "_validate_new_version", accept_version)
    monkeypatch.setattr(release, "_check_changelog_has_entry", accept_changelog)
    monkeypatch.setattr(release, "_changelog_release_date", release_date)
    monkeypatch.setattr(release, "_check_tag_absent", no_tag)
    monkeypatch.setattr(release, "_prompt_confirm", confirm)
    monkeypatch.setattr(release, "_snapshot_release_files", dict)
    monkeypatch.setattr(release, "_release_mutation_paths", tuple)
    monkeypatch.setattr(release, "_bump_release_surfaces", record_bump)
    monkeypatch.setattr(release, "_run_quality_gate", lambda: events.append("quality"))
    monkeypatch.setattr(release, "_run_release_readiness", lambda: events.append("readiness"))
    monkeypatch.setattr("builtins.input", fake_input)

    def fake_run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
        if cmd == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(cmd, 0, "start\n", "")
        if cmd[:2] == ["git", "commit"]:
            events.append("commit")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(release, "_run", fake_run)
    assert release.main([]) == 0
    assert events == ["bump", "quality", "readiness", "commit"]
