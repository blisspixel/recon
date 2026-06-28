# Supply-chain and release integrity

How recon's releases are built, signed, and made verifiable. The goal is that a
consumer can trace a published artifact back to the exact source and workflow run
that produced it, and can rebuild it themselves to confirm nothing was altered.

This is kept proportionate to what recon is: a passive, zero-credential Python
tool. The measures below are the ones that return more than they cost; the
remaining aspirational items are listed at the end with the reason they are
deferred.

## What ships with every release

A `v*` tag triggers [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which produces and publishes:

| Property | Mechanism | How a consumer verifies it |
|---|---|---|
| **Trusted publishing** | PyPI publishes via GitHub OIDC, no long-lived API token (`pypa/gh-action-pypi-publish`) | The PyPI project page shows the publishing workflow as a trusted publisher |
| **Build-provenance attestation** | GitHub-native, OIDC-signed (`actions/attest-build-provenance`), linking the wheel and sdist to the workflow run. The signed bundles are also exported to the GitHub Release as `recon-tool-<version>.intoto.jsonl` for offline and Scorecard-compatible inspection | `gh attestation verify <file> --repo blisspixel/recon`; offline consumers can download the `.intoto.jsonl` release asset |
| **PyPI attestations (PEP 740)** | sigstore-signed attestations generated at publish time (`attestations: true`) and stored on PyPI | Modern installers verify automatically; the attestation is visible on the release's PyPI files |
| **Reproducible builds** | `SOURCE_DATE_EPOCH` pinned to the tagged commit's timestamp, so the wheel and sdist are byte-identical to a rebuild from the same source | See the recipe below |
| **CycloneDX SBOM** | Generated from the hash-pinned runtime lock (`pip-audit --format=cyclonedx-json`) and attached to the GitHub Release | Download `recon-tool-<version>.cdx.json` from the release assets |

## Reproducible builds

The build is bit-for-bit reproducible: the same source plus the same
`SOURCE_DATE_EPOCH` yields byte-identical artifacts. The release workflow pins
`SOURCE_DATE_EPOCH` to the tagged commit's committer timestamp, and
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) gates the property on
every change (the `reproducible-build` job builds twice and compares the wheel
and sdist sha256 hashes).

To verify a published release yourself:

```bash
# 1. Check out the exact tag.
git clone https://github.com/blisspixel/recon && cd recon
git checkout v<version>

# 2. Rebuild with the release's build-time stamp (the tagged commit timestamp).
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) uv build --out-dir /tmp/verify

# 3. Compare against the published artifacts (from PyPI or the GitHub Release).
sha256sum /tmp/verify/recon_tool-<version>-py3-none-any.whl
sha256sum /tmp/verify/recon_tool-<version>.tar.gz
```

The hashes match the published wheel and sdist. (Build into a directory outside
the checkout, as above, so the build output is not itself swept into the sdist.)

## Supply-chain isolation contract

The release jobs are scoped to least privilege, and the build is isolated from
dependency code that could tamper with it. In short: the `build` job is pure
(`uv build` then immediate artifact upload, no other dependency code runs), the
`test`, `sbom`, and `attest` jobs run on separate runners that never see
`dist/`, and only dependency-free publish / attestation jobs hold elevated
scopes minted from OIDC at publish time. The provenance export job downloads the
signed GitHub attestation bundles and uploads a `.intoto.jsonl` artifact for the
GitHub Release without running project dependency code. The PyPI and GitHub
release jobs wait for the provenance attestation path, so a release fails closed
if artifact attestation fails. The full rationale and threat model are
documented inline in [`release.yml`](../.github/workflows/release.yml).

## Repository posture checks

The repository also runs supply-chain posture checks outside the release flow:

- OpenSSF Scorecard publishes the public posture badge and SARIF results.
- CodeQL runs as scheduled SAST and can also be run on demand.
- ClusterFuzzLite runs a PR-scoped Atheris fuzzer over recon's local parser,
  normalization, cache deserialization, and formatter-serialization boundaries.
  The workflow is read-only, SHA-pinned, and bounded to 180 seconds of fuzzing
  per run. Its runtime dependency file is a hash-pinned export from `uv.lock`,
  and `scripts/check_clusterfuzzlite_requirements.py` gates that export against
  stale dependency data.
- Dependabot checks `uv` and GitHub Actions dependencies on a low-noise monthly
  schedule.
- Workflow actions are pinned to full commit SHAs, with the readable version kept
  in a trailing comment. `scripts/check_workflow_pins.py` gates this locally and
  in CI.
- Installer scripts do not bootstrap package managers by executing remote shell
  or PowerShell installers. Users install `uv` or `pipx` through their preferred
  trusted channel, then recon's installer installs or upgrades only
  `recon-tool`.
- Generated security and surface artifacts used by CI are checked locally and in
  the CI validation job, including ClusterFuzzLite requirements, schema source
  tracing, surface inventory, CLI surface docs, file-size ratchets, and PLR
  ratchets.
- Added-line text hygiene is checked locally and in CI so generated or manual
  changes cannot add attribution markers, em dashes, or pictographic symbols.
- Checkout steps set `persist-credentials: false`, so the workflow token is not
  left in the local Git config after source checkout.
- Every workflow job has an explicit timeout so CI and release automation fail
  closed instead of hanging indefinitely.
- Secret scanning and push protection are enabled for the repository.

The 2026-06-28 Scorecard review found one code-owned gap and several
repository-process gaps. The code-owned gap was an unpinned installer
download-and-run path; the installer now refuses to execute remote tool
installers. The Scorecard SARIF upload step also uses CodeQL Action v4 to avoid
the scheduled v3 deprecation. Live repository settings now enforce full-SHA
GitHub Action pins, enable Dependabot security updates, and protect `main` with
an active repository ruleset that requires the CI matrix, gitleaks, and
Scorecard checks, blocks deletion and non-fast-forward updates, and requires
linear history.

The remaining Scorecard limits are intentional or process-bound:

- Branch-Protection is not maximal because repository administrators can bypass
  the ruleset and PRs are not mandatory. That keeps the current clean-main
  single-maintainer workflow usable. A future multi-maintainer process can
  remove the bypass and require PRs.
- Code-Review is low until normal work flows through reviewed pull requests.
  Creating fake review history would be worse than the score.
- Maintained is low while the repository is younger than Scorecard's age window.
- CII-Best-Practices is low until the OpenSSF Best Practices Badge questionnaire
  is completed and linked.
- Contributors is low until outside contributors from distinct organizations
  participate naturally.

## Deferred, with reasons

- **Full SLSA Level 3 provenance** via the `slsa-framework/slsa-github-generator`
  reusable workflow. The GitHub-native build-provenance attestation plus the
  PEP 740 PyPI attestations already give consumers a verifiable
  source-to-artifact link from two independent roots of trust; the additional L3
  generator is a larger moving part than a passive single-maintainer tool
  warrants. Recorded as aspirational in [roadmap.md](roadmap.md).
- **Recurring third-party audits and long-term-support branches.** For a
  zero-credential passive tool these cost more than they return; see the
  assurance-track note in the roadmap.
