# Release Process

recon releases have two halves: a human-in-the-loop script that handles the
pre-push steps, and a GitHub Actions workflow that handles build + publish.

## TL;DR

```bash
# 1. Write the CHANGELOG entry for the new version.
#    Add a section starting with "## [X.Y.Z] — YYYY-MM-DD".

# 2. Run the release script.
uv run python scripts/release.py

# 3. Confirm the push when prompted. Pushing the vX.Y.Z tag triggers:
#    test → build wheel/sdist → publish to PyPI (OIDC) → GitHub release.
```

---

## Human half: `scripts/release.py`

The script enforces the pre-release checklist automatically. It runs:

1. **Branch check** — must be on `main` (refuses otherwise).
2. **Clean tree check** — no staged or unstaged changes (refuses otherwise).
3. **Version consistency** — `pyproject.toml` and `recon_tool/__init__.py`
   must currently agree on the old version.
4. **Prompt for the new version** — enforces `X.Y.Z` semver format, must be
   strictly greater than the current.
5. **CHANGELOG entry check** — requires a `## [X.Y.Z]` section to exist in
   `CHANGELOG.md`. Refuses otherwise.
6. **Quality gate** — runs `ruff check`, `pyright`, and
   `pytest --cov-fail-under=80` on the full test suite. Refuses on any
   failure.
7. **Confirmation prompt** — y/N, defaults to N. Abort here and nothing has
   changed.
8. **Version bump** — updates `pyproject.toml`, `recon_tool/__init__.py`
   fallback, and regenerates `uv.lock`.
9. **Git commit + tag** — commits the bumped files, tags `vX.Y.Z`.
10. **Push prompt** — y/N, defaults to N. If declined, the commit and tag
    exist locally only and can be reset.

### Dry-run mode

```bash
uv run python scripts/release.py --dry-run
```

Walks through all the checks and prints what would happen. Makes no file
changes, no git state changes, no network calls. Use this to verify the
quality gate passes before cutting an actual release.

---

## Automated half: `.github/workflows/release.yml`

Triggered by any tag matching `v*` pushed to the repo. The workflow:

1. **test** — installs deps, runs `pytest --cov-fail-under=80`, `ruff check`,
   exports locked runtime requirements, and audits those with `pip-audit`.
2. **build** — `uv build` produces the sdist and wheel under `dist/`.
3. **publish-pypi** — uses `pypa/gh-action-pypi-publish@release/v1` with
   OIDC (Trusted Publisher) to upload to PyPI. No static API tokens.
4. **github-release** — extracts the matching `## [X.Y.Z]` section from
   `CHANGELOG.md` as the release body, attaches the built artifacts, creates
   the GitHub release.

Each job is gated on the previous. If any of test/lint/audit fails, the
publish and release jobs never run.

---

## Pre-release checklist

Before running `scripts/release.py`:

- [ ] All planned changes for this version are merged to `main`.
- [ ] `CHANGELOG.md` has a finalized `## [X.Y.Z] — YYYY-MM-DD` section.
- [ ] `docs/roadmap.md` still describes the next work accurately and does not
      duplicate `CHANGELOG.md`.
- [ ] `docs/stability.md` has been updated if any public surface changed.
- [ ] `docs/schema.md` has been updated if any top-level JSON field changed.
- [ ] Test count + fingerprint count in `README.md` and `CLAUDE.md` are
      refreshed (not strictly required but nice).

---

## Hotfix releases

For a patch-level fix to the last released minor version:

1. Branch from the tag: `git checkout -b hotfix/v1.0.1 v1.0.0`
2. Cherry-pick or write the fix.
3. Add a `## [1.0.1] — YYYY-MM-DD` section to `CHANGELOG.md`.
4. Run `scripts/release.py` from the hotfix branch.
5. **IMPORTANT**: the script refuses to run off `main`. For hotfixes, merge
   the hotfix branch back to `main` first (fast-forward or with a merge
   commit), then tag from there. Don't skip the `main` requirement — the
   release workflow assumes the published tag tip is on `main`.

---

## Yanking a broken release

PyPI supports yanking (not deleting) a broken release. This discourages new
installs but leaves the version available for reproducibility of systems
that already pinned it.

```bash
# Using twine:
twine yank recon-tool --version X.Y.Z
```

After yanking:
1. Cut a `X.Y.(Z+1)` release with the fix using the normal process.
2. Add a note to the yanked version's CHANGELOG section explaining the yank.
3. Pin dependents to the new version where possible.

Never delete a tag from `origin`. Tags are part of the reproducibility
contract. If a tag is wrong, yank the PyPI release and cut a new one.

---

## Version numbering

recon follows [Semantic Versioning](https://semver.org) per the
[stability policy](stability.md).

- **MAJOR** (e.g. 1.x → 2.0): breaking change to any **stable** surface
  listed in `docs/stability.md`. Requires a deprecation window in the prior
  minor release.
- **MINOR** (e.g. 1.0 → 1.1): backward-compatible additions. New CLI flags,
  new optional JSON fields, new MCP tools, new fingerprints/signals.
  Breaking changes to **experimental** surfaces are allowed here.
- **PATCH** (e.g. 1.0.0 → 1.0.1): backward-compatible bug fixes. No new
  features, no schema changes.

Pre-1.0 releases did not honor this contract strictly — v0.9 and v0.10
included breaking changes within the minor. From 1.0 onward the contract
is enforced.

---

## Python support policy

The supported range is the set advertised in `pyproject.toml` classifiers and
tested in CI.

Current tested range: **Python 3.10 through 3.13**.

Dropping a Python version is a compatibility change and should be called out in
`CHANGELOG.md`. A minor release should warn first when practical.
