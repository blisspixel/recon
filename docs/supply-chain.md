# Supply-chain and release integrity

How recon's releases are built, signed, and made verifiable. The goal is that a
consumer can trace a published artifact back to the exact source and workflow
run that produced it, and can compare a local rebuild under a matched build
environment.

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
| **Same-job deterministic-build check** | `SOURCE_DATE_EPOCH` is fixed and CI builds twice in one Ubuntu job, then compares wheel and sdist hashes under the same resolved toolchain | See the bounded recipe and limitations below |
| **CycloneDX SBOM** | Generated from a runtime-requirements export of `uv.lock` (`pip-audit --format=cyclonedx-json`), completed with the `recon-tool` root component and dependency edge, validated as nonempty JSON, and attached to the GitHub Release. The isolated SBOM job may emit an artifact when findings exist because the separate enforcing audit already blocks the release test job. Any SBOM tool, output, or validation failure blocks both PyPI and GitHub publication | Download `recon-tool-<version>.cdx.json` from the release assets and inspect `metadata.component` and the root dependency entry |

## Consumer verification quick path

For a published version, consumers can check the release from both distribution
channels without trusting this repository's local state:

```bash
VERSION=2.6.2
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

version = "2.6.2"
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

## Deterministic-build evidence

The release workflow pins `SOURCE_DATE_EPOCH` to the tagged commit's committer
timestamp. [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) then tests
same-job repeatability on every change: its `reproducible-build` job builds the
same source twice in one Ubuntu job under the same Python, runner, and resolved
build-tool window, and compares the wheel and sdist SHA-256 hashes.

That check is evidence of deterministic behavior under the tested environment.
It is not proof that source plus `SOURCE_DATE_EPOCH` alone produces identical
bytes across operating systems, Python versions, `uv` versions, or independently
resolved build-backend versions. The build backend is declared in
`pyproject.toml`, but it is not part of the runtime `uv.lock` graph.

To verify a published release yourself:

```bash
# 1. Check out the exact tag.
git clone https://github.com/blisspixel/recon && cd recon
git checkout v<version>

# 2. Rebuild with the release's build-time stamp.
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) uv build --out-dir /tmp/verify

# 3. Compare against the published artifacts (from PyPI or the GitHub Release).
sha256sum /tmp/verify/recon_tool-<version>-py3-none-any.whl
sha256sum /tmp/verify/recon_tool-<version>.tar.gz
```

An exact hash match is strong confirmation under the consumer's resolved build
environment. A mismatch is not, by itself, evidence of tampering because the
published build toolchain is not fully frozen for cross-environment replay.
Use the signed provenance and PyPI attestations above to verify source and
workflow identity. Build into a directory outside the checkout, as above, so
the build output is not itself swept into the sdist.

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

The release jobs are scoped to least privilege. The `build` job runs `uv` and
the declared Hatchling build backend, which is part of the trusted build-tool
boundary, then immediately uploads the artifacts. No project runtime
dependency or unrelated tool runs after artifact creation and before sealing.
The `test`, `sbom`, and `attest` jobs run on separate runners that never see
`dist/`, and publish or attestation jobs with elevated OIDC-minted scopes do not
execute project runtime dependencies. The provenance export job downloads the
signed GitHub attestation bundles and uploads a `.intoto.jsonl` artifact for the
GitHub Release without running project dependency code. The PyPI and GitHub
release jobs wait for both provenance attestation and the validated SBOM, so a
release fails closed if either integrity path fails. The full rationale and
threat model are documented inline in
[`release.yml`](../.github/workflows/release.yml).

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
- Release tags pass a dependency-free preflight that requires the tag version,
  project version, dated nonempty changelog section, tagged commit, and current
  `main` ancestry to agree. The release test job then reruns the complete local
  gate, so a manually pushed tag cannot bypass it.
- The cost-surface guard checks the packaged runtime, wheel package scope,
  project dependencies, and GitHub workflows for paid-provider SDKs, model API
  keys, image API calls, and validation-only paid harness invocations.
- Added-line text hygiene is checked locally and across the complete pushed or
  pull-request commit range in CI so an earlier commit cannot hide a prohibited
  line behind a later cleanup commit.
- Tracked Markdown relative links and local heading anchors are checked locally,
  in main CI, and again by the release gate.
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

The 2026-07-13 Scorecard recheck for the exact v2.5.7 `HEAD` commit reports
score `8.3`, with SAST and the other measured code-owned controls at `10`. Remote
release readiness requires an overall score of at least `8.0` and requires SAST
to remain at `10`; the dated `8.3` value is a snapshot, not a permanent promise.
The June 28 review found one code-owned gap and several repository-process gaps.
The code-owned gap was an
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
