"""Release-script regressions."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts import release


def _confirm_release(_message: str, default_no: bool = True) -> bool:
    assert default_no
    return True


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

    def failed_run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
        assert cmd == release._release_push_command("2.5.9")
        assert not check
        assert not capture
        return subprocess.CompletedProcess(cmd, 1, "", "credentials unavailable")

    monkeypatch.setattr(release, "_prompt_confirm", confirm)
    monkeypatch.setattr(release, "_run", failed_run)

    with pytest.raises(release.ReleaseError, match="local commit and tag were preserved") as error:
        release._offer_release_push("2.5.9")

    assert "credentials unavailable" not in str(error.value)


def test_successful_tag_push_does_not_claim_publication(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def successful_run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(release, "_prompt_confirm", _confirm_release)
    monkeypatch.setattr(release, "_run", successful_run)

    release._offer_release_push("2.19.0")

    output = capsys.readouterr().out
    assert "Tag v2.19.0 pushed; publication pending" in output
    assert "Released v2.19.0" not in output


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


def test_release_surface_generation_updates_installers_and_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plugin = tmp_path / "plugin.json"
    plugin.write_text('{"version": "2.6.3"}\n', encoding="utf-8")
    citation = tmp_path / "CITATION.cff"
    citation.write_text('version: 2.6.3\ndate-released: "2026-07-13"\n', encoding="utf-8")
    unix_installer = tmp_path / "install.sh"
    unix_installer.write_text('VERSION="2.6.3"\n', encoding="utf-8")
    windows_installer = tmp_path / "install.ps1"
    windows_installer.write_text('$Version = "2.6.3"\n', encoding="utf-8")
    supply_chain = tmp_path / "supply-chain.md"
    legacy_digest = "3d5218e00e969874dda40956d677e131d392dbf9"
    supply_chain.write_text(
        "\n".join(
            (
                "git clone --branch v2.6.3 --single-branch https://github.com/blisspixel/recon.git recon-2.6.3",
                "cd recon-2.6.3",
                "VERSION=2.6.3",
                '$Version = "2.6.3"',
                "VERSION=2.6.3  # rebuild recipe",
                'if [ "${VERSION}" = "2.6.3" ]; then',
                'if ($Version -eq "2.6.3") {',
                f"LEGACY_SBOM_ATTESTATION_SHA={legacy_digest}",
                f'$LegacySbomAttestationSha = "{legacy_digest}"',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    monkeypatch.setattr(release, "PLUGIN_MANIFEST", plugin)
    monkeypatch.setattr(release, "CITATION", citation)
    monkeypatch.setattr(release, "_VERSIONED_DOC_MARKERS", ())
    monkeypatch.setattr(release, "_SUPPLY_CHAIN_DOC", supply_chain)
    monkeypatch.setattr(release, "_VERSIONED_INSTALLERS", (unix_installer, windows_installer))
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
    release._bump_release_surfaces("2.6.3", "2.6.4", "2026-07-13")
    assert unix_installer.read_text(encoding="utf-8") == 'VERSION="2.6.4"\n'
    assert windows_installer.read_text(encoding="utf-8") == '$Version = "2.6.4"\n'
    updated_supply_chain = supply_chain.read_text(encoding="utf-8")
    assert "git clone --branch v2.6.4 --single-branch" in updated_supply_chain
    assert "cd recon-2.6.4" in updated_supply_chain
    assert updated_supply_chain.count("VERSION=2.6.4") == 2
    assert '$Version = "2.6.4"' in updated_supply_chain
    assert 'if [ "${VERSION}" = "2.6.3" ]; then' in updated_supply_chain
    assert 'if ($Version -eq "2.6.3") {' in updated_supply_chain
    assert updated_supply_chain.count(legacy_digest) == 2
    assert commands == [
        [
            "uv",
            "run",
            "python",
            "scripts/generate_agent_plugin.py",
        ],
        [
            "uv",
            "run",
            "python",
            "scripts/generate_surface_inventory.py",
            "--write",
            "--write-cli-surface",
        ],
    ]


def test_release_rollback_tracks_every_generated_agent_plugin_file() -> None:
    relative = {path.relative_to(release.ROOT).as_posix() for path in release._GENERATED_RELEASE_FILES}

    assert {
        "agents/agent-plugin/plugin.json",
        "agents/agent-plugin/mcp.json",
        "agents/agent-plugin/README.md",
        "agents/agent-plugin/LICENSE",
        "agents/agent-plugin/skills/recon/SKILL.md",
        "agents/agent-plugin/skills/recon-fingerprint-triage/SKILL.md",
    } <= relative


def test_release_version_replacement_rejects_ambiguous_historical_reference(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    document = tmp_path / "ROADMAP.md"
    original = "Current status: v2.6.4.\nHistorical exception: v2.6.4.\n"
    document.write_text(original, encoding="utf-8")
    monkeypatch.setattr(release, "ROOT", tmp_path)

    with pytest.raises(release.ReleaseError, match="exactly one occurrence"):
        release._replace_required(document, "2.6.4", "2.6.5")

    assert document.read_text(encoding="utf-8") == original


def test_release_versioned_doc_marker_preserves_historical_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    document = tmp_path / "ROADMAP.md"
    document.write_text(
        "recon **v2.6.4** is the current production baseline.\n| **v2.6.4** | Historical milestone |\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        release,
        "_VERSIONED_DOC_MARKERS",
        ((document, "recon **v{version}** is the current production baseline"),),
    )

    release._bump_versioned_docs("2.6.4", "2.6.5")

    assert document.read_text(encoding="utf-8") == (
        "recon **v2.6.5** is the current production baseline.\n| **v2.6.4** | Historical milestone |\n"
    )


def test_release_transaction_owns_both_installer_helpers() -> None:
    owned = set(release._release_mutation_paths())

    assert release.ROOT / "scripts" / "install.sh" in owned
    assert release.ROOT / "scripts" / "install.ps1" in owned
    assert release._SUPPLY_CHAIN_DOC in owned


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


@pytest.mark.parametrize("branch", ["main", ""])
def test_release_preparation_requires_a_named_non_main_branch(monkeypatch: pytest.MonkeyPatch, branch: str) -> None:
    def fake_run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert cmd == ["git", "branch", "--show-current"]
        return subprocess.CompletedProcess(cmd, 0, branch, "")

    monkeypatch.setattr(release, "_run", fake_run)

    with pytest.raises(release.ReleaseError, match="named non-main branch"):
        release._check_preparation_branch()


def _preparation_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    failure: str = "",
    stale_upstream: bool = False,
    worktree_status: str = "",
) -> tuple[Path, list[list[str]], list[str]]:
    version = tmp_path / "version.txt"
    version.write_bytes(b"old version\n")
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("## [2.19.0] - 2026-09-05\n\nRelease notes.\n", encoding="utf-8")
    commands: list[list[str]] = []
    events: list[str] = []

    def bump(_current: str, _new: str, _date: str) -> None:
        events.append("bump")
        version.write_bytes(b"new version\n")

    def quality() -> None:
        events.append("quality")
        if failure == "quality":
            raise release.ReleaseError("synthetic quality failure")
        if failure == "interrupt":
            raise KeyboardInterrupt

    def version_input(_prompt: str) -> str:
        return "2.19.0"

    def fake_run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
        del capture
        commands.append(cmd)
        fixed_responses = {
            ("git", "branch", "--show-current"): (0, "release/2.19.0\n"),
            ("git", "status", "--porcelain"): (0, worktree_status),
            ("git", "fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main"): (0, ""),
            ("git", "show-ref", "--verify", "--quiet", "refs/tags/v2.19.0"): (1, ""),
        }
        if response := fixed_responses.get(tuple(cmd)):
            return subprocess.CompletedProcess(cmd, response[0], response[1], "")
        if cmd[:2] == ["git", "rev-parse"]:
            value = "other" if stale_upstream and cmd[-1] == "refs/remotes/origin/main" else "start"
            return subprocess.CompletedProcess(cmd, 0, value, "")
        if cmd[:4] == ["uv", "run", "python", "scripts/release_readiness.py"]:
            assert cmd[4:] == ["--allow-dirty", "--allow-non-main"]
            events.append("readiness")
            return subprocess.CompletedProcess(cmd, int(failure == "readiness"), "", "")
        if cmd[:2] == ["git", "add"]:
            assert cmd[2:] == ["version.txt"]
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["git", "commit"]:
            events.append("commit")
            if failure == "commit":
                assert check
                raise subprocess.CalledProcessError(1, cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd == ["git", "reset", "--mixed", "start"]:
            events.append("rollback")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(cmd)

    monkeypatch.setattr(release, "ROOT", tmp_path)
    monkeypatch.setattr(release, "CHANGELOG", changelog)
    monkeypatch.setattr(release, "_run", fake_run)
    monkeypatch.setattr(release, "_check_version_consistency", lambda: "2.18.4")
    monkeypatch.setattr(release, "_release_mutation_paths", lambda: (version,))
    monkeypatch.setattr(release, "_bump_release_surfaces", bump)
    monkeypatch.setattr(release, "_run_quality_gate", quality)
    monkeypatch.setattr(release, "_prompt_confirm", _confirm_release)
    monkeypatch.setattr("builtins.input", version_input)
    return version, commands, events


def test_prepare_only_validates_and_commits_owned_paths_without_tagging_or_pushing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    version, commands, events = _preparation_fixture(monkeypatch, tmp_path)

    assert release.main(["--prepare-only"]) == 0

    assert events == ["bump", "quality", "readiness", "commit"]
    assert version.read_bytes() == b"new version\n"
    assert commands[:3] == [
        ["git", "branch", "--show-current"],
        ["git", "status", "--porcelain"],
        ["git", "fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main"],
    ]
    assert not any(cmd[:2] in (["git", "tag"], ["git", "push"]) for cmd in commands)
    output = capsys.readouterr().out
    assert "No tag was created and nothing was pushed" in output
    assert "Do not tag before the preparation has merged" in output


def test_prepare_only_rejects_a_branch_not_at_refreshed_main(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    version, commands, events = _preparation_fixture(monkeypatch, tmp_path, stale_upstream=True)

    assert release.main(["--prepare-only"]) == 1

    assert version.read_bytes() == b"old version\n"
    assert events == []
    assert not any(cmd[:2] in (["git", "add"], ["git", "commit"], ["git", "tag"]) for cmd in commands)


def test_prepare_only_rejects_uncommitted_changes_before_fetch_or_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    version, commands, events = _preparation_fixture(monkeypatch, tmp_path, worktree_status=" M version.txt\n")

    assert release.main(["--prepare-only"]) == 1

    assert events == []
    assert version.read_bytes() == b"old version\n"
    assert commands == [["git", "branch", "--show-current"], ["git", "status", "--porcelain"]]


def test_prepare_only_declined_confirmation_does_not_mutate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    version, commands, events = _preparation_fixture(monkeypatch, tmp_path)

    def decline(_message: str, default_no: bool = True) -> bool:
        assert default_no
        return False

    monkeypatch.setattr(release, "_prompt_confirm", decline)

    assert release.main(["--prepare-only"]) == 0

    assert events == []
    assert version.read_bytes() == b"old version\n"
    assert not any(cmd[:2] in (["git", "add"], ["git", "commit"], ["git", "tag"]) for cmd in commands)


@pytest.mark.parametrize("failure", ["quality", "readiness", "commit", "interrupt"])
def test_prepare_only_rolls_back_owned_files_and_index_without_touching_tags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    version, commands, events = _preparation_fixture(monkeypatch, tmp_path, failure=failure)

    assert release.main(["--prepare-only"]) == (130 if failure == "interrupt" else 1)

    assert version.read_bytes() == b"old version\n"
    assert events[-1] == "rollback"
    assert ["git", "reset", "--mixed", "start"] in commands
    assert not any(cmd[:2] in (["git", "tag"], ["git", "push"]) for cmd in commands)
    # Only preflight checks local tag absence. A tag-free rollback never reads
    # or deletes a tag that this preparation transaction did not create.
    assert sum(cmd[:2] == ["git", "show-ref"] for cmd in commands) == 1


def test_prepare_only_dry_run_preserves_release_files_and_git_refs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    version, commands, events = _preparation_fixture(monkeypatch, tmp_path)

    assert release.main(["--prepare-only", "--dry-run"]) == 0

    assert version.read_bytes() == b"old version\n"
    assert events == ["quality"]
    forbidden = {"fetch", "add", "commit", "tag", "push", "reset"}
    assert not any(cmd[0] == "git" and cmd[1] in forbidden for cmd in commands)
    output = capsys.readouterr().out
    assert "without a tag or push" in output
    assert "validation may write local artifacts" in output
