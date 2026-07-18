# Release Process

recon releases have two halves: a human-in-the-loop script that handles the
pre-push steps, and a GitHub Actions workflow that handles build + publish.

## TL;DR

```bash
# 1. Finalize the dated CHANGELOG entry and any tool-surface note, then commit
#    and push the planned release changes to main.
#    The local tree must be clean and HEAD must exactly match origin/main.
#    Generate the CLI surface line if commands or flags changed:
#    uv run python scripts/summarize_cli_surface_changes.py --old-ref vX.Y.Z

# 2. Run the local readiness preflight.
uv run python scripts/release_readiness.py

# 3. Run the release script.
uv run python scripts/release.py

# 4. Confirm the atomic main + exact-tag push when prompted. The tag triggers
#    source/tag preflight, the complete quality gate, one sealed build and
#    attestation path, SBOM validation, PyPI publication, channel parity, and
#    GitHub Release.
```

## Release Decision and Cadence

Release quality includes the signal a version sends to users. The default is a
coherent release batch, not one package version per merged pull request. Group
compatible fixes, catalog updates, and documentation needed to explain them
under one short release narrative, then run the existing atomic release path.

Cut an immediate patch release when a shipped correctness bug, security issue,
dependency failure, broken package, or release-artifact defect makes waiting
materially worse for users. A documentation-only change, planning change, issue
template change, repository metadata update, or internal proof refresh does not
by itself trigger a package release. Those changes can remain in `Unreleased`
until the next meaningful package batch.

Before choosing a version, answer three questions:

1. What user-visible problem or coherent capability does this release deliver?
2. Which stable surface changes, if any, require a minor rather than patch
   version under [stability.md](stability.md)?
3. Can a user understand the release from one concise summary plus the tool
   surface line?

If the first or third answer is unclear and no urgent exception applies, keep
the work on `main` and batch it. This policy changes cadence, not rigor: every
published version still uses the complete readiness, build, provenance, SBOM,
publication, and post-release verification path below.

---

## Local readiness gate: `scripts/release_readiness.py`

This gate is the maintainer-local preflight before relying on GitHub Actions.
It does not call the network by default and it is not part of the user-facing
`recon` CLI. It checks:

1. Branch, worktree, and `origin/main` tracking state.
2. Version consistency between `pyproject.toml` and the package fallback, plus
   current-version references in both roadmaps, `CITATION.cff`, and the
   supply-chain consumer-verification recipe.
3. `uv.lock` freshness with `uv lock --check`.
4. Coverage authority in `scripts/check.py` and main CI, with the release helper
   and release workflow required to delegate to that canonical gate.
5. README usage anchors, supply-chain recipe anchors, and repository hygiene.
6. No tracked private corpus files, validation outputs with target-domain
   fields, or root per-domain JSON dumps.
7. Commit-message hygiene across the relevant local commit range.

The release workflow independently validates that the tag, package version,
dated nonempty changelog section, tagged commit, and current `main` ancestry
agree. It then reruns the exact stable and candidate MCP SDK matrix and the
complete canonical gate on the tagged tree before a build can be sealed or
published. A manually pushed tag cannot bypass the controls on `main`.

During active edits, this is useful as a planning report:

```bash
uv run python scripts/release_readiness.py --allow-dirty
```

Before tagging or pushing a release, run it strictly:

```bash
uv run python scripts/release_readiness.py
```

After publishing the current version from the exact checked-out tag, add the
optional remote check. In remote mode the gate first requires the remote and
local current project-version tag plus `HEAD` to resolve to the same full
commit. It then verifies required GitHub Actions checks for `HEAD`, public
Scorecard API freshness and code-owned control scores, PyPI's exact
current-version record, and the exact four GitHub Release assets for the current
version. It verifies
both PyPI files with pinned `pypi-attestations==0.0.29`, validates the completed
CycloneDX SBOM without repairing it, and verifies the GitHub subjects required
by the exact release policy against the downloaded bundle with the release
workflow, tag ref, local release tag commit digest, and hosted-runner boundary.
The exact v2.6.3 historical exception requires wheel and sdist provenance plus
SBOM structure validation; every later release also requires SBOM provenance.
Its PyPI metadata reader is bounded and accepts only the exact version-scoped
pair from HTTPS `files.pythonhosted.org` URLs before any verifier runs. It also
reports the SHA-256 parity of both distribution files across PyPI and GitHub.
The remote check therefore requires the current release tag locally plus an
authenticated `gh` session or `GH_TOKEN`:

```bash
uv run python scripts/release_readiness.py --remote
```

For automation or an optional maintainer loop, use JSON:

```bash
uv run python scripts/release_readiness.py --json
```

The JSON output is deliberately local and deterministic unless `--remote` is
passed. Text and JSON both identify the assessed scope. Default text states
that remote publication checks were not assessed; default JSON reports
`"scope": "local"` and `"remote_checks_assessed": false`. With `--remote`,
those fields become `"local-and-remote"` and `true`. It is a maintainer signal,
not a runtime contract for recon users.

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

The script enforces the release transaction in this order:

1. **Branch and tree**: require a clean `main` worktree.
2. **Current upstream**: fetch `origin/main` and require `HEAD` to match it
   exactly. Being merely ahead, behind, or ancestrally related is insufficient.
3. **Current version**: require `pyproject.toml` and the package fallback to
   agree.
4. **New version**: accept stable `X.Y.Z` SemVer only, with no leading-zero
   components, and require it to be greater than the current version.
5. **Release notes and tag**: require a dated, calendar-valid
   `## [X.Y.Z] - YYYY-MM-DD` changelog section and an absent local release tag.
6. **Confirmation**: default to No before any mutation.
7. **Snapshot**: capture every file the release transaction owns.
8. **Synchronize surfaces**: update `pyproject.toml`, the package fallback,
   both roadmaps, the engineering refinement plan, supply-chain recipe,
   exact-version POSIX and PowerShell installer helpers,
   correlation and statistical-assurance review headers, Claude Code plugin
   manifest, `CITATION.cff`, `uv.lock`, generated surface inventories, and the
   generated CLI surface.
9. **Authoritative validation**: run the complete `scripts/check.py` gate on
   the prospective tree, then run release readiness with the expected dirty
   release-owned files.
10. **Commit and tag**: stage only the owned release paths, create the release
    commit, and create `vX.Y.Z`.
11. **Atomic push prompt**: default to No. If accepted, push `main` and only the
    exact new tag in one `git push --atomic` transaction. If declined, the
    commit and tag remain local for review.

Any exception or interruption inside the file-mutation, validation, commit, or
tag boundary deletes the owned tag if created, restores the starting index and
commit, and restores every snapshotted file. A declined or failed final push
does not discard the successfully validated local commit and tag.

### Dry-run mode

```bash
uv run python scripts/release.py --dry-run
```

Checks the current clean `main` tree against the locally known `origin/main`
ref, validates the proposed version, changelog entry, and local tag absence,
then runs the complete quality gate on the current tree. It makes no file or Git
changes and performs no network calls. It reports the prospective
synchronization and release transaction, but it cannot simulate the post-bump
tree or its release-readiness result.

---

## Automated half: `.github/workflows/release.yml`

Triggered by any tag matching `v*` pushed to the repo. The workflow:

1. **preflight**: checks out full history, fetches the current remote `main`, and
   validates exact stable tag syntax, package-version agreement, a dated
   nonempty changelog section, the tagged SHA, and containment in current
   `origin/main`.
2. **test**: after preflight, runs the exact stable and candidate MCP SDK matrix,
   then delegates to the complete `scripts/check.py` gate with added-line text
   hygiene covering the full previous-release-to-tag range. A separate
   hash-pinned runtime requirements export is audited with `pip-audit`.
3. **build**: after `test`, exact uv 0.11.17 uses the hash-locked build graph to
   produce one sdist, constructs one wheel from that exact sdist, and
   immediately seals both under `dist/`. Main CI runs the same sequence twice,
   requires matching hashes, and executes both entry points from one built
   wheel.
4. **package-smoke**: after `build`, downloads the sealed artifact into a
   separate read-only job, requires exactly one tag-matching canonical wheel
   and sdist, and executes both `recon --version` and
   `python -m recon_tool --version` from the wheel in isolated environments.
5. **sbom**: after `test`, generates the CycloneDX release SBOM independently of
   the package build path, adds the project root and dependency edge, and
   validates the resulting document. Findings may coexist with this artifact
   because the enforcing dependency audit already ran in `test`; SBOM tool or
   validation failure is fatal.
6. **attest**: after `build` and `sbom`, records one GitHub provenance
   attestation whose subject set contains the wheel, sdist, and completed SBOM.
7. **export-attestations**: after `build`, `sbom`, and `attest`, exports the
   GitHub artifact-attestation bundles as
   `recon-tool-<version>.intoto.jsonl` so the GitHub Release carries an offline,
   Scorecard-recognized provenance asset.
8. **publish-pypi**: after `build`, `attest`, `package-smoke`, and `sbom`, uses
   `pypa/gh-action-pypi-publish@release/v1` with OIDC Trusted Publishing and PEP
   740 attestations. No static API tokens.
9. **verify-pypi-parity**: after `publish-pypi`, downloads the sealed pair in a
   read-only job, waits for the exact two PyPI records, and requires both
   SHA-256 digests to match before GitHub publication can proceed.
10. **github-release**: after `build`, `attest`, `export-attestations`,
    `package-smoke`, `sbom`, and `verify-pypi-parity`, extracts the matching
    `## [X.Y.Z]` section from `CHANGELOG.md` as the release body and attaches
    the package, SBOM, and provenance artifacts.

The dependency graph blocks both publication channels when tag preflight, the
complete test gate, package build, installed-wheel smoke, provenance
attestation, or SBOM validation fails, while allowing `build` and `sbom` to run
independently after `test`. Once PyPI accepts its immutable files, a parity
failure blocks only the GitHub Release and leaves a visible partial-publication
state. Diagnose the failed row, preserve the existing PyPI files, and rerun the
same tag only when its sealed pair is byte-identical to PyPI. Never manually
rebuild or replace evidence, and never bypass a failed verifier to complete the
second channel.

### Recovery after partial publication

A failed tagged run is recoverable only through the original run and unchanged
tag. GitHub reruns retain the original `GITHUB_SHA` and `GITHUB_REF`; failed jobs
and jobs that depend on them may execute again. The parity gate therefore
remains the boundary that proves any rerun distribution bytes still match the
immutable PyPI files. The run-selection check also requires the chosen run's
`headSha` to equal the unchanged local tag and `HEAD` before a rerun begins.

Inspect and rerun the failed path with the exact run ID:

```bash
set -euo pipefail

recovery_fail() {
  printf 'FAIL: release recovery requires %s\n' "$1" >&2
  exit 1
}

VERSION="$(uv run python -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])')" || recovery_fail "uv to read the project version"
CURRENT_BRANCH="$(git branch --show-current)" || recovery_fail "git to report the current branch"
if ! test "${CURRENT_BRANCH}" = "main"; then
  recovery_fail "a clean main branch"
fi
WORKTREE_STATUS="$(git status --porcelain --untracked-files=normal)" || recovery_fail "git to inspect the worktree"
if ! test -z "${WORKTREE_STATUS}"; then
  recovery_fail "a clean worktree"
fi
HEAD_SHA="$(git rev-parse HEAD)" || recovery_fail "git to resolve HEAD"
TAG_SHA="$(git rev-list -n 1 "refs/tags/v${VERSION}" 2>/dev/null)" || recovery_fail "git to resolve the local tag v${VERSION}"
if ! test -n "${TAG_SHA}" || ! test "${HEAD_SHA}" = "${TAG_SHA}"; then
  recovery_fail "the local tag v${VERSION} to resolve to HEAD"
fi
RUN_ROW="$(gh run list --workflow Release \
  --branch "v${VERSION}" --event push --limit 1 --json databaseId,headSha \
  --jq '.[0] | [.databaseId, .headSha] | @tsv')" || recovery_fail "GitHub CLI to list the Release workflow run"
read -r RUN_ID RUN_HEAD_SHA <<< "${RUN_ROW}"
if ! test -n "${RUN_ID}"; then
  recovery_fail "an exact Release workflow run for v${VERSION}"
fi
if ! test "${RUN_HEAD_SHA}" = "${HEAD_SHA}"; then
  recovery_fail "the selected Release run to target HEAD"
fi
printf 'PASS: release recovery preconditions hold for run %s at %s\n' "${RUN_ID}" "${HEAD_SHA}"
gh run view "${RUN_ID}" --log-failed
gh run rerun "${RUN_ID}" --failed
gh run watch "${RUN_ID}" --exit-status
uv run python scripts/release_readiness.py --remote
```

Run this block in Bash or Git Bash so strict mode and the here-string use the
documented shell semantics. A named precondition failure exits before any rerun.

Use that rerun path for transient timeouts, rate limits, temporary 5xx
responses, delayed PyPI visibility, or a GitHub upload interruption after the
sealed pair already passed parity. Do not rerun blindly after a digest,
inventory, tag, signer, source, SBOM, or provenance mismatch. Preserve the
failed output and inspect the original workflow artifacts first.

This runbook applies to recovery of the current project version while clean
`main` still points at that exact release tag. If a GitHub Release already
exists, the workflow validates its exact tag and title, non-draft,
non-prerelease, and mutable state, and expected-only inventory, complete or
partial, before `gh release upload --clobber` can execute. It also rechecks the
remote tag against the original workflow SHA immediately before mutation. A
draft, prerelease, immutable release, unexpected asset, duplicate asset,
malformed response, missing tag, or moved tag stops recovery. If PyPI contains
incorrect immutable bytes, do not attempt to overwrite them;
follow the documented PyPI project-management yanking path and cut a corrected
version. A run is recovered only after the strict remote readiness command
passes in full.

Workflow permissions are least-privilege: read-only jobs use `contents: read`,
`attest` and `publish-pypi` receive `id-token: write` only where OIDC is needed,
and `github-release` is the only job with `contents: write`.

---

## Pre-release checklist

Before running `scripts/release.py`:

- [ ] All planned changes, including the new dated changelog section, are
      committed and pushed to `main`; the local tree is clean and exactly at
      `origin/main`.
- [ ] `CHANGELOG.md` has a finalized `## [X.Y.Z] - YYYY-MM-DD` section.
- [ ] `CITATION.cff`, both roadmaps, the package fallback, and the supply-chain
      recipe match the current project version. The helper updates them to the
      prospective version and changelog date inside its transaction.
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

- [ ] Confirm the GitHub Release contains exactly the wheel, sdist, SBOM, and
      `recon-tool-<version>.intoto.jsonl`.
- [ ] Run `uv run python scripts/release_readiness.py --remote` after the
      release so CI, public Scorecard API freshness, PyPI files, PyPI
      provenance, exact GitHub Release assets, completed SBOM, tag-bound GitHub
      provenance, cross-channel digests, and citation metadata are checked
      together.

The direct `pipx` / `uv` / `pip` install paths need no per-release action. The
release transaction updates and validates both reviewed installer-helper pins
before creating the tag.

---

## Hotfix releases

For a patch-level fix to the last released minor version:

1. Branch from the tag: `git checkout -b hotfix/v1.0.1 v1.0.0`
2. Cherry-pick or write the fix.
3. Add a `## [1.0.1] - YYYY-MM-DD` section to `CHANGELOG.md`.
4. Merge or fast-forward the hotfix to `main`, run the complete gate, and push
   `main` so the clean local tip exactly matches `origin/main`.
5. Run `scripts/release.py` from that current `main` tip. Do not tag the hotfix
   branch directly; the local helper and remote preflight both require the
   published tag commit to be on current `main`.

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
