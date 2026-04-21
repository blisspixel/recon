#!/usr/bin/env python
"""Semi-automated release flow for recon.

Handles the human-side steps of cutting a release: verify the working tree
is clean, bump version consistently in pyproject.toml + __init__.py + uv.lock,
run the quality gate (ruff + pyright + pytest + coverage), confirm the
CHANGELOG has an entry, commit, tag, and prompt before push.

The GitHub Actions release pipeline (`.github/workflows/release.yml`) takes
over after the tag is pushed: build the wheel, publish to PyPI via OIDC,
create the GitHub release with changelog notes.

Usage:
    python scripts/release.py [--dry-run]

Dry-run mode exercises all the checks and prints what would happen, but
makes no file, git, or network changes.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INIT_PY = ROOT / "recon_tool" / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"

_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
_INIT_VERSION_RE = re.compile(r'__version__\s*=\s*"([^"]+)"')
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


class ReleaseError(Exception):
    """Raised when a precondition fails and the release must abort."""


def _run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
    # cmd is a developer-controlled list of arguments from this script itself;
    # no user-supplied interpolation reaches the subprocess. ruff S603 is a
    # generic warning that doesn't apply to this closed code path.
    return subprocess.run(  # noqa: S603
        cmd,
        cwd=ROOT,
        text=True,
        capture_output=capture,
        check=check,
    )


def _prompt_confirm(message: str, default_no: bool = True) -> bool:
    """y/N prompt (default No). Returns True if the user said yes."""
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    while True:
        answer = input(message + suffix).strip().lower()
        if not answer:
            return not default_no
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.")


# ── Preflight checks ──────────────────────────────────────────────────────


def _check_branch() -> None:
    """Must be on main."""
    branch = _run(["git", "branch", "--show-current"]).stdout.strip()
    if branch != "main":
        msg = f"Current branch is {branch!r}; releases must be cut from main"
        raise ReleaseError(msg)


def _check_clean_tree() -> None:
    """Git working tree must be clean (no staged or unstaged changes)."""
    status = _run(["git", "status", "--porcelain"]).stdout
    if status.strip():
        msg = "Working tree has uncommitted changes:\n" + status
        raise ReleaseError(msg)


def _read_current_version() -> str:
    match = _VERSION_RE.search(PYPROJECT.read_text(encoding="utf-8"))
    if not match:
        msg = f"Could not find version in {PYPROJECT}"
        raise ReleaseError(msg)
    return match.group(1)


def _read_init_version() -> str:
    match = _INIT_VERSION_RE.search(INIT_PY.read_text(encoding="utf-8"))
    if not match:
        msg = f"Could not find __version__ fallback in {INIT_PY}"
        raise ReleaseError(msg)
    return match.group(1)


def _check_version_consistency() -> str:
    """Ensure pyproject and __init__ agree on current version."""
    pyproject_version = _read_current_version()
    init_version = _read_init_version()
    if pyproject_version != init_version:
        msg = (
            f"Version mismatch: pyproject.toml={pyproject_version!r} but "
            f"__init__.py fallback={init_version!r}. Resolve before releasing."
        )
        raise ReleaseError(msg)
    return pyproject_version


def _validate_new_version(new: str, current: str) -> None:
    """Must be a semver string higher than current."""
    if not _SEMVER_RE.match(new):
        msg = f"New version {new!r} is not a valid semver string (expected X.Y.Z)"
        raise ReleaseError(msg)
    if new == current:
        msg = f"New version {new!r} is the same as current"
        raise ReleaseError(msg)

    # crude but sufficient lexical check — semver ordering via tuple compare
    def _parts(v: str) -> tuple[int, ...]:
        base = v.split("-", 1)[0]
        return tuple(int(x) for x in base.split("."))

    if _parts(new) <= _parts(current):
        msg = f"New version {new!r} is not greater than current {current!r}"
        raise ReleaseError(msg)


def _check_changelog_has_entry(new_version: str) -> None:
    """CHANGELOG.md must contain a section for the new version."""
    content = CHANGELOG.read_text(encoding="utf-8")
    header = f"## [{new_version}]"
    if header not in content:
        msg = (
            f"No CHANGELOG entry for {new_version!r}.\n"
            f"Expected a section starting with: {header}\n"
            f"Edit {CHANGELOG} before running release."
        )
        raise ReleaseError(msg)


def _run_quality_gate() -> None:
    """Run ruff, pyright, pytest with coverage. Abort on any failure."""
    steps: list[tuple[str, list[str]]] = [
        ("ruff", ["uv", "run", "ruff", "check", "recon_tool/", "tests/", "scripts/"]),
        ("pyright", ["uv", "run", "pyright", "recon_tool/"]),
        (
            "pytest",
            [
                "uv",
                "run",
                "pytest",
                "tests/",
                "--cov=recon_tool",
                "--cov-fail-under=80",
                "-q",
            ],
        ),
    ]
    for name, cmd in steps:
        print(f"  running {name}...")
        result = _run(cmd, check=False, capture=True)
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            msg = f"Quality gate failed at {name} (exit code {result.returncode})"
            raise ReleaseError(msg)
        print(f"  ok  {name}")


# ── File mutations ────────────────────────────────────────────────────────


def _bump_pyproject(new_version: str, dry_run: bool) -> None:
    content = PYPROJECT.read_text(encoding="utf-8")
    updated = _VERSION_RE.sub(f'version = "{new_version}"', content, count=1)
    if dry_run:
        return
    PYPROJECT.write_text(updated, encoding="utf-8")


def _bump_init(new_version: str, dry_run: bool) -> None:
    content = INIT_PY.read_text(encoding="utf-8")
    updated = _INIT_VERSION_RE.sub(f'__version__ = "{new_version}"', content, count=1)
    if dry_run:
        return
    INIT_PY.write_text(updated, encoding="utf-8")


def _bump_lockfile(dry_run: bool) -> None:
    if dry_run:
        return
    _run(["uv", "lock"], capture=False)


# ── Release pipeline ──────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cut a recon release (version bump + commit + tag + push prompt).")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run all checks and print what would happen, but make no changes.",
    )
    args = parser.parse_args(argv)
    dry = args.dry_run

    try:
        if dry:
            print("[DRY RUN] No files will be modified, no git state will change.\n")

        print("->Checking branch...")
        _check_branch()
        print("->Checking clean working tree...")
        _check_clean_tree()
        print("->Checking version consistency...")
        current = _check_version_consistency()
        print(f"  current version: {current}")

        new_version = input("->New version (X.Y.Z): ").strip()
        _validate_new_version(new_version, current)
        print(f"  bumping {current} ->{new_version}")

        print("->Checking CHANGELOG...")
        _check_changelog_has_entry(new_version)
        print(f"  ok  found section ## [{new_version}]")

        print("->Running quality gate (ruff + pyright + pytest --cov-fail-under=80)...")
        _run_quality_gate()

        if not _prompt_confirm(f"Proceed with version bump to {new_version}?"):
            print("Aborted.")
            return 0

        print(f"->Updating pyproject.toml ->{new_version}")
        _bump_pyproject(new_version, dry)
        print(f"->Updating __init__.py fallback ->{new_version}")
        _bump_init(new_version, dry)
        print("->Regenerating uv.lock")
        _bump_lockfile(dry)

        if dry:
            print("\n[DRY RUN] Would: git add + commit + tag + prompt-to-push")
            print(f"[DRY RUN] Tag would be: v{new_version}")
            return 0

        print("->Committing...")
        _run(
            [
                "git",
                "add",
                "pyproject.toml",
                "recon_tool/__init__.py",
                "uv.lock",
                "CHANGELOG.md",
            ],
            capture=False,
        )
        _run(
            ["git", "commit", "-m", f"v{new_version}: release"],
            capture=False,
        )

        print(f"->Tagging v{new_version}...")
        _run(["git", "tag", f"v{new_version}"], capture=False)

        if _prompt_confirm(f"Push v{new_version} to origin main?", default_no=True):
            print("->Pushing...")
            _run(["git", "push", "origin", "main", "--tags"], capture=False)
            print(f"\nReleased v{new_version}. Watch the pipeline:")
            print("  https://github.com/blisspixel/recon/actions")
        else:
            print(
                f"\nCommit + tag v{new_version} are local only.\n"
                "To push later:  git push origin main --tags\n"
                "To abort:       git reset --hard HEAD~1 && git tag -d v{new_version}"
            )

    except ReleaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
