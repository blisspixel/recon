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
- Dependabot checks `uv` and GitHub Actions dependencies on a low-noise monthly
  schedule.
- Workflow actions are pinned to full commit SHAs, with the readable version kept
  in a trailing comment. `scripts/check_workflow_pins.py` gates this locally and
  in CI.
- Secret scanning and push protection are enabled for the repository.

Scorecard currently credits SAST, dependency-update tooling, least-privilege
workflow tokens, pinned workflow dependencies, packaging, the security policy,
and vulnerability posture. Its signed-release check looks at recent GitHub
Release assets, so future releases now attach the exported
`recon-tool-<version>.intoto.jsonl` provenance bundle alongside the wheel, sdist,
and SBOM.

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
