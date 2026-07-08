from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_TEXT_SUFFIXES = {
    ".cfg",
    ".cff",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
LOCAL_TOOL_ARTIFACT_PROBES = {
    ".coverage": ".coverage",
    ".hypothesis": ".hypothesis/probe",
    ".pytest_cache": ".pytest_cache/probe",
    ".ruff_cache": ".ruff_cache/probe",
    ".venv": ".venv/probe",
    ".claude": ".claude/probe",
}


def _tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],  # noqa: S607 - fixed developer-tool argv
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]


def _git_ignores(relative_path: str) -> bool:
    result = subprocess.run(  # noqa: S603 - fixed developer-tool argv with test-controlled probes
        ["git", "check-ignore", "--quiet", "--", relative_path],  # noqa: S607 - fixed developer-tool argv
        cwd=ROOT,
        check=False,
    )
    return result.returncode == 0


def _non_root_agent_dirs() -> list[str]:
    skipped = {".agent", ".git", ".hypothesis", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv"}
    offenders: list[str] = []
    for child in ROOT.iterdir():
        if not child.is_dir() or child.name in skipped:
            continue
        for path in child.rglob(".agent"):
            if path.is_dir():
                offenders.append(path.relative_to(ROOT).as_posix())
    return sorted(offenders)


def test_agent_and_log_working_directories_are_gitignored() -> None:
    obsolete_docs_agent_dir = "docs/" + ".agent/"
    gitignore_lines = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert "/.agent/" in gitignore_lines
    assert "/logs/" in gitignore_lines
    assert ".agent/" not in gitignore_lines
    assert "logs/" not in gitignore_lines
    assert obsolete_docs_agent_dir not in gitignore_lines


def test_agent_and_log_ignore_rules_are_root_anchored() -> None:
    nested_agent_probe = "docs/" + ".agent/probe.md"

    assert _git_ignores(".agent/probe.md")
    assert _git_ignores("logs/probe.txt")
    assert not _git_ignores(nested_agent_probe)
    assert not _git_ignores("docs/logs/probe.txt")


def test_no_nested_agent_working_directories_exist() -> None:
    assert _non_root_agent_dirs() == []


def test_local_tool_artifact_roots_are_gitignored_and_untracked() -> None:
    tracked = set(_tracked_files())

    for root_name, probe in LOCAL_TOOL_ARTIFACT_PROBES.items():
        tracked_under_root = [
            path
            for path in tracked
            if path == root_name or path.startswith(f"{root_name}/")
        ]
        assert _git_ignores(probe), root_name
        assert tracked_under_root == []


def test_public_tracked_text_does_not_reference_docs_agent_state() -> None:
    forbidden = "docs/" + ".agent"
    offenders: list[str] = []

    for relative in _tracked_files():
        path = ROOT / relative
        if not path.exists():
            continue
        if path.suffix.lower() not in PUBLIC_TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if forbidden in text:
            offenders.append(relative)

    assert offenders == []


def test_root_package_shadow_is_not_tracked() -> None:
    tracked_root_package_paths = [path for path in _tracked_files() if path.startswith("recon_tool/")]

    assert tracked_root_package_paths == []
