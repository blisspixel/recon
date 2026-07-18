#!/usr/bin/env python
"""Semi-automated release flow for recon.

Handles the human-side steps of cutting a release: verify clean and current
main state, confirm release notes, synchronize all code-owned version surfaces,
run the complete local gate on that prospective tree, commit, tag, and prompt
before an atomic push.

The GitHub Actions release pipeline (`.github/workflows/release.yml`) takes
over after the tag is pushed: seal the sdist and wheel, publish to PyPI via
OIDC, prove channel byte parity, then create the GitHub release with changelog
notes.

Usage:
    python scripts/release.py [--dry-run]

Dry-run mode exercises all the checks and prints what would happen, but
makes no file, git, or network changes.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INIT_PY = ROOT / "src" / "recon_tool" / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"
PLUGIN_MANIFEST = ROOT / "agents" / "claude-code" / ".claude-plugin" / "plugin.json"
CITATION = ROOT / "CITATION.cff"

_VERSIONED_DOCS = (
    ROOT / "ROADMAP.md",
    ROOT / "docs" / "roadmap.md",
    ROOT / "docs" / "engineering-refinement-plan.md",
    ROOT / "docs" / "supply-chain.md",
)
_VERSIONED_INSTALLERS = (
    ROOT / "scripts" / "install.sh",
    ROOT / "scripts" / "install.ps1",
)
_REVIEWED_DOCS = (
    ROOT / "docs" / "correlation.md",
    ROOT / "docs" / "statistical-assurance.md",
)
_GENERATED_RELEASE_FILES = (
    ROOT / "docs" / "surface-inventory.json",
    ROOT / "src" / "recon_tool" / "data" / "surface-inventory.json",
    ROOT / "docs" / "cli-surface.md",
)

_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
# __init__.py computes __version__ at runtime and only the _FALLBACK_VERSION
# constant is a literal, so the bump target is that constant, not __version__.
_INIT_VERSION_RE = re.compile(r'_FALLBACK_VERSION\s*=\s*"([^"]+)"')
_SEMVER_COMPONENT = r"(?:0|[1-9][0-9]*)"
_SEMVER_RE = re.compile(rf"^{_SEMVER_COMPONENT}\.{_SEMVER_COMPONENT}\.{_SEMVER_COMPONENT}$")


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


def _check_upstream_current(*, fetch: bool) -> None:
    """Require release preparation to start at the current origin/main tip."""
    if fetch:
        result = _run(
            [
                "git",
                "fetch",
                "--no-tags",
                "origin",
                "+refs/heads/main:refs/remotes/origin/main",
            ],
            check=False,
            capture=True,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "git fetch failed"
            raise ReleaseError(f"Could not refresh origin/main: {detail}")
    head = _run(["git", "rev-parse", "HEAD"]).stdout.strip()
    upstream = _run(["git", "rev-parse", "refs/remotes/origin/main"]).stdout.strip()
    if head != upstream:
        raise ReleaseError(
            "HEAD does not exactly match origin/main. Pull or reconcile the branch before cutting a release."
        )


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

    def _parts(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in v.split("."))

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


def _changelog_release_date(new_version: str) -> str:
    pattern = re.compile(rf"^## \[{re.escape(new_version)}] - (\d{{4}}-\d{{2}}-\d{{2}})\s*$", re.MULTILINE)
    match = pattern.search(CHANGELOG.read_text(encoding="utf-8"))
    if match is None:
        raise ReleaseError(f"CHANGELOG entry for {new_version!r} must include a YYYY-MM-DD release date")
    release_date = match.group(1)
    try:
        date.fromisoformat(release_date)
    except ValueError as exc:
        raise ReleaseError(f"CHANGELOG entry for {new_version!r} has an invalid release date") from exc
    return release_date


def _check_tag_absent(new_version: str) -> None:
    tag = f"v{new_version}"
    result = _run(["git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"], check=False)
    if result.returncode == 0:
        raise ReleaseError(f"Local tag {tag} already exists")
    if result.returncode != 1:
        raise ReleaseError(f"Could not determine whether local tag {tag} exists")


def _run_quality_gate() -> None:
    """Run the complete local CI-parity gate on the prospective release tree."""
    result = _run(["uv", "run", "python", "scripts/check.py"], check=False, capture=False)
    if result.returncode != 0:
        raise ReleaseError(f"Quality gate failed (exit code {result.returncode})")


def _run_release_readiness() -> None:
    result = _run(
        ["uv", "run", "python", "scripts/release_readiness.py", "--allow-dirty"],
        check=False,
        capture=False,
    )
    if result.returncode != 0:
        raise ReleaseError(f"Release readiness failed (exit code {result.returncode})")


# ── File mutations ────────────────────────────────────────────────────────


def _bump_pyproject(new_version: str, dry_run: bool) -> None:
    content = PYPROJECT.read_text(encoding="utf-8")
    updated = _VERSION_RE.sub(f'version = "{new_version}"', content, count=1)
    if dry_run:
        return
    PYPROJECT.write_text(updated, encoding="utf-8")


def _bump_init(new_version: str, dry_run: bool) -> None:
    content = INIT_PY.read_text(encoding="utf-8")
    updated = _INIT_VERSION_RE.sub(f'_FALLBACK_VERSION = "{new_version}"', content, count=1)
    if dry_run:
        return
    INIT_PY.write_text(updated, encoding="utf-8")


def _bump_lockfile(dry_run: bool) -> None:
    if dry_run:
        return
    _run(["uv", "lock"], capture=False)


def _replace_required(path: Path, old: str, new: str) -> None:
    content = path.read_text(encoding="utf-8")
    if old not in content:
        raise ReleaseError(f"Expected {old!r} in {path.relative_to(ROOT)}")
    path.write_text(content.replace(old, new), encoding="utf-8")


def _bump_release_surfaces(current: str, new: str, release_date: str) -> None:
    """Synchronize every code-owned version surface before validation."""
    _bump_pyproject(new, False)
    _bump_init(new, False)
    for path in _VERSIONED_DOCS:
        _replace_required(path, current, new)
    for path in _VERSIONED_INSTALLERS:
        _replace_required(path, current, new)
    for path in _REVIEWED_DOCS:
        content = path.read_text(encoding="utf-8")
        pattern = re.compile(rf"Reviewed against v{re.escape(current)} on\s+\d{{4}}-\d{{2}}-\d{{2}}")
        updated, count = pattern.subn(f"Reviewed against v{new} on\n{release_date}", content, count=1)
        if count != 1:
            raise ReleaseError(f"Could not update reviewed-version header in {path.relative_to(ROOT)}")
        path.write_text(updated, encoding="utf-8")

    plugin = json.loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(plugin, dict) or plugin.get("version") != current:
        raise ReleaseError("Claude Code plugin version does not match the current project version")
    plugin["version"] = new
    PLUGIN_MANIFEST.write_text(json.dumps(plugin, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    citation = CITATION.read_text(encoding="utf-8")
    citation, version_count = re.subn(r"^version:\s*.+$", f"version: {new}", citation, count=1, flags=re.MULTILINE)
    citation, date_count = re.subn(
        r'^date-released:\s*.+$',
        f'date-released: "{release_date}"',
        citation,
        count=1,
        flags=re.MULTILINE,
    )
    if version_count != 1 or date_count != 1:
        raise ReleaseError("CITATION.cff is missing version or date-released")
    CITATION.write_text(citation, encoding="utf-8")

    _bump_lockfile(False)
    _run(
        [
            "uv",
            "run",
            "python",
            "scripts/generate_surface_inventory.py",
            "--write",
            "--write-cli-surface",
        ],
        capture=False,
    )


def _release_mutation_paths() -> tuple[Path, ...]:
    return (
        PYPROJECT,
        INIT_PY,
        ROOT / "uv.lock",
        PLUGIN_MANIFEST,
        CITATION,
        *_VERSIONED_DOCS,
        *_VERSIONED_INSTALLERS,
        *_REVIEWED_DOCS,
        *_GENERATED_RELEASE_FILES,
    )


def _snapshot_release_files() -> dict[Path, bytes | None]:
    return {path: path.read_bytes() if path.exists() else None for path in _release_mutation_paths()}


def _restore_release_files(snapshot: dict[Path, bytes | None]) -> None:
    for path, content in snapshot.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(content)


def _release_push_command(version: str) -> list[str]:
    """Return the exact refspec push for one reviewed release tag."""
    tag = f"v{version}"
    return ["git", "push", "--atomic", "origin", "main", f"refs/tags/{tag}:refs/tags/{tag}"]


def _rollback_local_release(starting_head: str, snapshot: dict[Path, bytes | None], tag: str) -> None:
    """Restore the clean pre-release files, index, commit, and owned tag."""
    failures: list[str] = []
    tag_ref = f"refs/tags/{tag}"
    tag_check = _run(["git", "show-ref", "--verify", "--quiet", tag_ref], check=False)
    if tag_check.returncode == 0:
        delete = _run(["git", "tag", "-d", tag], check=False, capture=False)
        if delete.returncode != 0:
            failures.append(f"could not delete local tag {tag}")
    reset = _run(["git", "reset", "--mixed", starting_head], check=False, capture=False)
    if reset.returncode != 0:
        failures.append(f"could not restore HEAD and index to {starting_head}")
    try:
        _restore_release_files(snapshot)
    except OSError as exc:
        failures.append(f"could not restore release files: {exc}")
    if failures:
        raise ReleaseError("Local release rollback was incomplete: " + "; ".join(failures))


# ── Release pipeline ──────────────────────────────────────────────────────


def _release_preflight(*, dry: bool) -> tuple[str, str, str] | None:
    """Validate release inputs and return the current, next, and date values."""
    print("->Checking branch...")
    _check_branch()
    print("->Checking clean working tree...")
    _check_clean_tree()
    print("->Checking current origin/main...")
    _check_upstream_current(fetch=not dry)
    print("->Checking version consistency...")
    current = _check_version_consistency()
    print(f"  current version: {current}")

    new_version = input("->New version (X.Y.Z): ").strip()
    _validate_new_version(new_version, current)
    print(f"  bumping {current} ->{new_version}")
    print("->Checking CHANGELOG...")
    _check_changelog_has_entry(new_version)
    release_date = _changelog_release_date(new_version)
    _check_tag_absent(new_version)
    print(f"  ok  found section ## [{new_version}]")
    if not _prompt_confirm(f"Proceed with version bump to {new_version}?"):
        return None
    return current, new_version, release_date


def _run_dry_release(new_version: str) -> None:
    print("->Running current-tree quality gate for dry-run confidence...")
    _run_quality_gate()
    print("\n[DRY RUN] Would synchronize version surfaces, regenerate derived files, and rerun all gates.")
    print("[DRY RUN] Would: git add + commit + tag + atomic prompt-to-push")
    print(f"[DRY RUN] Tag would be: v{new_version}")


def _create_local_release(current: str, new_version: str, release_date: str) -> None:
    """Build and validate the prospective release, rolling back any failure."""
    snapshot = _snapshot_release_files()
    starting_head = _run(["git", "rev-parse", "HEAD"]).stdout.strip()
    tag = f"v{new_version}"
    try:
        print(f"->Synchronizing release surfaces ->{new_version}")
        _bump_release_surfaces(current, new_version, release_date)
        print("->Running authoritative post-bump quality gate...")
        _run_quality_gate()
        print("->Running post-bump release readiness...")
        _run_release_readiness()
        print("->Committing...")
        release_paths = [str(path.relative_to(ROOT)) for path in _release_mutation_paths()]
        _run(["git", "add", *release_paths], capture=False)
        _run(["git", "commit", "-m", f"v{new_version}: release"], capture=False)
        print(f"->Tagging {tag}...")
        _run(["git", "tag", tag], capture=False)
    except KeyboardInterrupt:
        _rollback_local_release(starting_head, snapshot, tag)
        raise
    except Exception as exc:
        try:
            _rollback_local_release(starting_head, snapshot, tag)
        except ReleaseError as rollback_exc:
            raise ReleaseError(f"Prospective release failed ({exc}); {rollback_exc}") from exc
        raise ReleaseError(f"Prospective release failed and all file changes were rolled back: {exc}") from exc


def _offer_release_push(new_version: str) -> None:
    """Offer one atomic push while preserving a validated local release on failure."""
    if not _prompt_confirm(f"Push v{new_version} to origin main?", default_no=True):
        print(
            f"\nCommit + tag v{new_version} are local only.\n"
            f"To push later:  git push --atomic origin main "
            f"refs/tags/v{new_version}:refs/tags/v{new_version}\n"
            "To undo safely: delete the local tag, then use git reset --keep HEAD~1 before making other changes."
        )
        return
    print("->Pushing...")
    try:
        result = _run(_release_push_command(new_version), check=False, capture=False)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReleaseError("Atomic push could not be completed; the local commit and tag were preserved") from exc
    if result.returncode != 0:
        raise ReleaseError(
            f"Atomic push failed with exit code {result.returncode}; the local commit and tag were preserved"
        )
    print(f"\nReleased v{new_version}. Watch the pipeline:")
    print("  https://github.com/blisspixel/recon/actions")


def _run_release(*, dry: bool) -> None:
    if dry:
        print("[DRY RUN] No files will be modified, no git state will change.\n")
    preflight = _release_preflight(dry=dry)
    if preflight is None:
        print("Aborted.")
        return
    current, new_version, release_date = preflight
    if dry:
        _run_dry_release(new_version)
        return
    _create_local_release(current, new_version, release_date)
    _offer_release_push(new_version)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cut a recon release (version bump + commit + tag + push prompt).")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run all checks and print what would happen, but make no changes.",
    )
    args = parser.parse_args(argv)
    try:
        _run_release(dry=args.dry_run)
    except ReleaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
