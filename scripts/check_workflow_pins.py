#!/usr/bin/env python3
"""Enforce immutable workflow action pins."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"
INSTALLERS = (ROOT / "scripts" / "install.sh", ROOT / "scripts" / "install.ps1")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<ref>[^#\s]+)(?:\s+#\s*(?P<comment>\S.*))?$")
DOWNLOAD_THEN_RUN_RE = re.compile(r"(bash\s+<\(\s*curl|curl\b.*\|\s*(?:bash|sh)|wget\b.*\|\s*(?:bash|sh))")
POWERSHELL_DOWNLOAD_THEN_RUN_RE = re.compile(
    r"((?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b.*\|\s*(?:iex|Invoke-Expression)|"
    r"Invoke-Expression\s*\(\s*(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b)"
)


def _workflow_files() -> list[Path]:
    return sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))


def _repo_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _check_workflow(path: Path) -> list[str]:
    errors: list[str] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        uses_match = USES_RE.match(line)
        if uses_match:
            ref = uses_match.group("ref")
            comment = uses_match.group("comment")
            if ref.startswith(("./", "docker://")):
                continue
            if "@" not in ref:
                errors.append(f"{_repo_path(path)}:{lineno}: action reference has no @ ref: {ref}")
                continue
            version = ref.rsplit("@", 1)[1]
            if not SHA_RE.fullmatch(version):
                errors.append(f"{_repo_path(path)}:{lineno}: action reference is not pinned to a full SHA: {ref}")
            if not comment:
                errors.append(f"{_repo_path(path)}:{lineno}: pinned action needs a version comment for maintainability")
        if DOWNLOAD_THEN_RUN_RE.search(line):
            errors.append(f"{_repo_path(path)}:{lineno}: download-and-run shell pattern is not allowed in workflows")
    return errors


def _check_installers() -> list[str]:
    errors: list[str] = []
    for installer in INSTALLERS:
        for lineno, line in enumerate(installer.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "#>")):
                continue
            if re.search(r"\bpip\s+install\b", line):
                errors.append(f"{_repo_path(installer)}:{lineno}: installer must not bootstrap unpinned pip packages")
            if DOWNLOAD_THEN_RUN_RE.search(line) or POWERSHELL_DOWNLOAD_THEN_RUN_RE.search(line):
                errors.append(f"{_repo_path(installer)}:{lineno}: installer must not execute remote installers")
    return errors


def main() -> int:
    errors: list[str] = []
    for path in _workflow_files():
        errors.extend(_check_workflow(path))
    errors.extend(_check_installers())

    if errors:
        print("Workflow pin check failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print("OK: workflow actions are pinned to full SHAs and installer bootstrap is bounded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
