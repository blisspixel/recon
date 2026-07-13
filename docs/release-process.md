# Release Process

recon releases have two halves: a human-in-the-loop script that handles the
pre-push steps, and a GitHub Actions workflow that handles build + publish.

## TL;DR

```bash
# 1. Write the CHANGELOG entry for the new version.
#    Add a section starting with "## [X.Y.Z] - YYYY-MM-DD".
#    Generate the CLI surface line if commands or flags changed:
#    uv run python scripts/summarize_cli_surface_changes.py --old-ref vX.Y.Z

# 2. Run the local readiness preflight.
uv run python scripts/release_readiness.py

# 3. Run the release script.
uv run python scripts/release.py

# 4. Confirm the push when prompted. Pushing the vX.Y.Z tag triggers tests,
#    one sealed build and attestation path, then sibling PyPI publication and
#    GitHub Release jobs after their shared prerequisites pass.
```

---

## Local readiness gate: `scripts/release_readiness.py`

This gate is the maintainer-local preflight before relying on GitHub Actions.
It does not call the network by default and it is not part of the user-facing
`recon` CLI. It checks:

1. Branch, worktree, and upstream tracking state.
2. Version consistency across `pyproject.toml`, `src/recon_tool/__init__.py`,
   `docs/roadmap.md`, `CITATION.cff`, and the supply-chain consumer
   verification recipe.
3. `uv.lock` freshness with `uv lock --check`.
4. Coverage target parity across `scripts/check.py`, `scripts/release.py`,
   `.github/workflows/ci.yml`, and `.github/workflows/release.yml`.
5. README usage anchors, supply-chain recipe anchors, and project hygiene.
6. No tracked private corpus files or root per-domain JSON dumps.
7. Latest commit message hygiene: no generated-author markers and no em dash.

The release workflow also reruns the exact stable and candidate MCP SDK matrix
on the tagged tree before the build job can seal or publish artifacts. This
keeps a tag from bypassing the compatibility job that already blocks `main`.

During active edits, this is useful as a planning report:

```bash
uv run python scripts/release_readiness.py --allow-dirty
```

Before tagging or pushing a release, run it strictly:

```bash
uv run python scripts/release_readiness.py
```

After pushing `main`, add the optional remote check. In remote mode the gate
verifies required GitHub Actions checks for `HEAD`, public Scorecard API
freshness and code-owned control scores, PyPI's latest `recon-tool` release,
and the GitHub Release assets for the current version (wheel, sdist, SBOM, and
attestation export). It also verifies the PyPI wheel and sdist with
`pypi-attestations verify pypi`, then downloads the GitHub Release wheel and
sdist and runs `gh attestation verify` against both files:

```bash
uv run python scripts/release_readiness.py --remote
```

For automation or an optional maintainer loop, use JSON:

```bash
uv run python scripts/release_readiness.py --json
```

The JSON output is deliberately local and deterministic unless `--remote` is
passed. It is a maintainer signal, not a runtime contract for recon users.

---

## CLI surface change line: `scripts/summarize_cli_surface_changes.py`

Every release section should include a short `### Tool Surface Changes` entry
so skill and agent authors can scan command and flag changes without diffing
help output. Generate the line from the checked surface inventory:

```bash
uv run python scripts/summarize_cli_surface_changes.py --old-ref vX.Y.Z
```

Replace `vX.Y.Z` with the last released tag. The helper reads
`docs/surface-inventory.json` from that tag with `git show`, compares it with
the current generated inventory, and prints one changelog-ready sentence. Use
`--json` when release automation needs the structured diff instead of prose.

If commands and flags did not change, keep the generated no-change line. It
is cheap signal for downstream skill maintainers and avoids forcing them to
infer silence from the rest of the changelog.

---

## Human half: `scripts/release.py`

The script enforces the pre-release checklist automatically. It runs:

1. **Branch check**: must be on `main` (refuses otherwise).
2. **Clean tree check**: no staged or unstaged changes (refuses otherwise).
3. **Version consistency**: `pyproject.toml` and `src/recon_tool/__init__.py`
   must currently agree on the old version.
4. **Prompt for the new version**: enforces `X.Y.Z` semver format, must be
   strictly greater than the current.
5. **CHANGELOG entry check**: requires a `## [X.Y.Z]` section to exist in
   `CHANGELOG.md`. Refuses otherwise.
6. **Quality gate**: runs `ruff check`, `pyright`, and
   `pytest --cov-branch --cov-fail-under=90.2` on the full test suite.
   Refuses on any failure.
7. **Confirmation prompt**: y/N, defaults to N. Abort here and nothing has
   changed.
8. **Version bump**: updates `pyproject.toml`, `src/recon_tool/__init__.py`
   fallback, and regenerates `uv.lock`.
9. **Git commit + tag**: commits the bumped files, tags `vX.Y.Z`.
10. **Push prompt**: y/N, defaults to N. If accepted, the script pushes `main`
    and only the newly created tag through an exact refspec. If declined, the
    commit and tag exist locally only and can be reset.

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

1. **test**: installs dependencies, runs the exact stable and candidate MCP SDK
   matrix, strict type checking, `pytest --cov-branch --cov-fail-under=90.2`,
   `ruff check`, fingerprint and generated-artifact checks, and `pip-audit`.
2. **build**: after `test`, `uv build` produces the sdist and wheel under
   `dist/`; main CI separately requires matching hashes across two builds in
   one resolved job.
3. **attest**: after `build`, records GitHub artifact attestations for the wheel
   and sdist.
4. **export-attestations**: after `build` and `attest`, exports the GitHub
   artifact-attestation bundles as
   `recon-tool-<version>.intoto.jsonl` so the GitHub Release carries an offline,
   Scorecard-recognized provenance asset.
5. **sbom**: after `test`, generates the CycloneDX release SBOM independently of
   the package build path.
6. **publish-pypi**: after `build` and `attest`, uses
   `pypa/gh-action-pypi-publish@release/v1` with
   OIDC (Trusted Publisher) to upload to PyPI. No static API tokens.
7. **github-release**: after `build`, `attest`, `export-attestations`, and
   `sbom`, extracts the matching `## [X.Y.Z]` section from `CHANGELOG.md` as the
   release body and attaches the package, SBOM, and provenance artifacts.

The dependency graph blocks publication when a required predecessor fails while
allowing independent work, such as `build` and `sbom`, to run in parallel after
`test`.

Workflow permissions are least-privilege: read-only jobs use `contents: read`,
`attest` and `publish-pypi` receive `id-token: write` only where OIDC is needed,
and `github-release` is the only job with `contents: write`.

---

## Pre-release checklist

Before running `scripts/release.py`:

- [ ] All planned changes for this version are merged to `main`.
- [ ] `CHANGELOG.md` has a finalized `## [X.Y.Z] - YYYY-MM-DD` section.
- [ ] `CITATION.cff` matches that version and release date.
- [ ] `docs/roadmap.md` still describes the next work accurately and does not
      duplicate `CHANGELOG.md`.
- [ ] `docs/stability.md` has been updated if any public surface changed.
- [ ] `docs/schema.md` has been updated if any top-level JSON field changed.
- [ ] `CHANGELOG.md` includes the generated `### Tool Surface Changes` line.
- [ ] README examples and docs references still match the shipped CLI behavior.
- [ ] Exact stable and candidate MCP SDK compatibility passes on the release
      tree when MCP compatibility code or dependencies changed.
- [ ] `docs/supply-chain.md` keeps the consumer verification quick path on the
      current version and release asset names.

After the tag is published and the PyPI release exists:

- [ ] Confirm the GitHub Release assets include wheel, sdist, SBOM, and
      `recon-tool-<version>.intoto.jsonl`.
- [ ] Run `uv run python scripts/release_readiness.py --remote` after the
      release so CI, public Scorecard API freshness, PyPI files, PyPI
      provenance, GitHub Release assets, GitHub provenance attestations,
      and citation metadata are checked together.

The `pipx` / `uv` / `pip` install paths need no per-release action. They
resolve the latest from PyPI automatically.

---

## Hotfix releases

For a patch-level fix to the last released minor version:

1. Branch from the tag: `git checkout -b hotfix/v1.0.1 v1.0.0`
2. Cherry-pick or write the fix.
3. Add a `## [1.0.1] - YYYY-MM-DD` section to `CHANGELOG.md`.
4. Run `scripts/release.py` from the hotfix branch.
5. **IMPORTANT**: the script refuses to run off `main`. For hotfixes, merge
   the hotfix branch back to `main` first (fast-forward or with a merge
   commit), then tag from there. Don't skip the `main` requirement; the
   release workflow assumes the published tag tip is on `main`.

---

## Yanking a broken release

PyPI supports yanking (not deleting) a broken release. This discourages new
installs but leaves the version available for reproducibility of systems
that already pinned it. Twine does not provide a yank command. An authorized
project maintainer must open the affected release in the PyPI project management
UI, choose the yank action, and record a concise reason.

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

Pre-1.0 releases did not honor this contract; v0.9 and v0.10
included breaking changes within the minor. From 1.0 onward the contract
is enforced.

---

## Python support policy

The supported range is the set advertised in `pyproject.toml` classifiers and
tested in CI.

Current tested range: **Python 3.11 through 3.14**.

Dropping a Python version is a compatibility change and should be called out in
`CHANGELOG.md`. A minor release should warn first when practical.
