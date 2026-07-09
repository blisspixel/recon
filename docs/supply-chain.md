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
| **PyPI attestations (PEP 740)** | sigstore-signed attestations generated at publish time (`attestations: true`) and stored on PyPI | Fetch the file's PyPI provenance and verify it with `pypi-attestations verify pypi --repository https://github.com/blisspixel/recon <wheel-url>` |
| **Reproducible builds** | `SOURCE_DATE_EPOCH` pinned to the tagged commit's timestamp, so the wheel and sdist are byte-identical to a rebuild from the same source | See the recipe below |
| **CycloneDX SBOM** | Generated from the hash-pinned runtime lock (`pip-audit --format=cyclonedx-json`) and attached to the GitHub Release | Download `recon-tool-<version>.cdx.json` from the release assets |

## Consumer verification quick path

For a published version, consumers can check the release from both distribution
channels without trusting this repository's local state:

```bash
VERSION=2.3.5
VERIFY_DIR="$(mktemp -d)"

gh release download "v${VERSION}" \
  --repo blisspixel/recon \
  --pattern "recon_tool-${VERSION}-py3-none-any.whl" \
  --pattern "recon_tool-${VERSION}.tar.gz" \
  --pattern "recon-tool-${VERSION}.cdx.json" \
  --pattern "recon-tool-${VERSION}.intoto.jsonl" \
  --dir "${VERIFY_DIR}"

gh attestation verify \
  "${VERIFY_DIR}/recon_tool-${VERSION}-py3-none-any.whl" \
  --repo blisspixel/recon
gh attestation verify \
  "${VERIFY_DIR}/recon_tool-${VERSION}.tar.gz" \
  --repo blisspixel/recon
```

To verify the PyPI-hosted provenance, use the direct file URLs from the PyPI
JSON API, then verify both the wheel and sdist:

```bash
python - <<'PY' | while IFS= read -r file_url; do
    uvx --from pypi-attestations pypi-attestations verify pypi \
      --repository https://github.com/blisspixel/recon \
      "${file_url}"
  done
import json
import urllib.request

version = "2.3.5"
with urllib.request.urlopen("https://pypi.org/pypi/recon-tool/json", timeout=30) as response:
    payload = json.load(response)
for file_record in payload["releases"][version]:
    if file_record["filename"] in {
        f"recon_tool-{version}-py3-none-any.whl",
        f"recon_tool-{version}.tar.gz",
    }:
        print(file_record["url"])
PY
```

This path checks source-to-artifact provenance and integrity. It is not a claim
that installers enforce PyPI attestations automatically, and it is not a claim
that recon has reached a named SLSA level beyond the controls listed here.

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

## PyPI attestation verification

PyPI exposes attestations through the simple index and Integrity API as
file-level provenance objects. For a consumer-side check, install the
`pypi-attestations` CLI, get the released wheel's direct PyPI file URL, and run:

```bash
pypi-attestations verify pypi \
  --repository https://github.com/blisspixel/recon \
  <wheel-url>
```

That command downloads the wheel and provenance JSON from PyPI, checks that the
Trusted Publisher identity matches the repository argument, and cryptographically
verifies the wheel against the included attestations. Do not treat PyPI
attestations as installer-level enforcement unless the installer being used
documents that behavior.

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
- Dependency update automation checks `uv` and GitHub Actions dependencies on a
  low-noise monthly schedule.
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
- The cost-surface guard checks the packaged runtime, wheel package scope,
  project dependencies, and GitHub workflows for paid-provider SDKs, model API
  keys, image API calls, and validation-only paid harness invocations.
- Added-line text hygiene is checked locally and in CI so generated or manual
  changes cannot add attribution markers, em dashes, or pictographic symbols.
- Remote release readiness checks PyPI's latest `recon-tool` version and the
  GitHub Release asset set for the current version, so wheel, sdist, SBOM, and
  attestation drift is caught after publication rather than verified by hand.
  It also verifies public Scorecard API freshness for `HEAD`, checks that
  code-owned Scorecard controls remain green, checks the documented SAST floor,
  verifies the PyPI wheel and sdist with `pypi-attestations verify pypi`, then
  downloads the GitHub Release wheel and sdist and runs `gh attestation verify`
  against both artifacts.
- Checkout steps set `persist-credentials: false`, so the workflow token is not
  left in the local Git config after source checkout.
- Every workflow job has an explicit timeout so CI and release automation fail
  closed instead of hanging indefinitely.
- Secret scanning and push protection are enabled for the repository. The
  gitleaks workflow runs on pull requests, pushes to `main`, and a weekly
  full-history schedule with read-only repository permissions.
- `.github/CODEOWNERS` routes all repository paths to the maintainer account so
  external pull requests have a clear review owner.

The 2026-06-30 Scorecard recheck reports score `7.5` with the non-SAST
code-owned controls green. SAST reports `7` because CodeQL is scheduled and
manually dispatched rather than run on every push. The June 28 review found one
code-owned gap and several repository-process gaps. The code-owned gap was an
unpinned installer download-and-run path; the installer now refuses to execute
remote tool installers. The Scorecard SARIF upload step also uses CodeQL Action
v4 to avoid the scheduled v3 deprecation. Live repository settings now enforce
full-SHA GitHub Action pins, enable dependency security updates, and protect
`main` with an active repository ruleset that requires the CI matrix, gitleaks,
and Scorecard checks, blocks deletion and non-fast-forward updates, and requires
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
  is completed and linked. The questionnaire evidence worksheet lives in
  [openssf-badge-readiness.md](openssf-badge-readiness.md), and the current
  posture summary lives in [openssf-posture.md](openssf-posture.md).
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
