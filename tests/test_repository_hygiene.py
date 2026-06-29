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


def _tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],  # noqa: S607 - fixed developer-tool argv
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]


def test_agent_and_log_working_directories_are_gitignored() -> None:
    obsolete_docs_agent_dir = "docs/" + ".agent/"
    gitignore_lines = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert ".agent/" in gitignore_lines
    assert "logs/" in gitignore_lines
    assert obsolete_docs_agent_dir not in gitignore_lines


def test_public_tracked_text_does_not_reference_docs_agent_state() -> None:
    forbidden = "docs/" + ".agent"
    offenders: list[str] = []

    for relative in _tracked_files():
        path = ROOT / relative
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
