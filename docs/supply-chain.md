# Supply-chain and release integrity

How recon's releases are built, signed, and made verifiable. The goal is that a
consumer can trace a published artifact back to the exact source and workflow
run that produced it, and can compare a local rebuild under a matched build
environment.

This is kept proportionate to what recon is: a passive, zero-credential Python
tool. The measures below are the ones that return more than they cost; the
remaining aspirational items are listed at the end with the reason they are
deferred.

## What the current release workflow ships

A `v*` tag created from this source revision triggers
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which
produces and publishes:

| Property | Mechanism | How a consumer verifies it |
|---|---|---|
| **Trusted publishing** | PyPI publishes via GitHub OIDC, no long-lived API token (`pypa/gh-action-pypi-publish`) | The PyPI project page shows the publishing workflow as a trusted publisher |
| **Build-provenance attestation** | GitHub-native, OIDC-signed (`actions/attest-build-provenance`), linking the wheel, sdist, and completed SBOM to the workflow run. The signed bundles are also exported to the GitHub Release as `recon-tool-<version>.intoto.jsonl` for offline and Scorecard-compatible inspection. The exact historical v2.6.3 release predates the SBOM subject expansion and binds only its wheel and sdist | Verify the subjects required by the exact release policy against the exported bundle, release workflow, source tag, commit digest, and hosted-runner boundary as shown below |
| **PyPI attestations (PEP 740)** | sigstore-signed attestations generated at publish time (`attestations: true`) and stored on PyPI | Fetch the file's PyPI provenance and verify it with the pinned `pypi-attestations==0.0.29` command shown below |
| **Constrained deterministic-build check** | `SOURCE_DATE_EPOCH`, uv 0.11.17, and the exact hash-locked backend graph are fixed; CI builds the sdist and reconstructs its wheel twice in one Ubuntu job, then compares both hashes | See the bounded recipe and limitations below |
| **Sealed distribution gate** | A separate read-only release job requires exactly one tag-matching wheel and sdist, then executes both `recon --version` and `python -m recon_tool --version` from the wheel before either publication channel can run | Inspect the `package-smoke` job in the tagged release workflow run |
| **Published-channel parity gate** | After PyPI publication, a separate read-only job requires the exact wheel and sdist and compares their SHA-256 digests with the sealed build pair. GitHub Release publication cannot create or replace assets until parity passes | Inspect the `verify-pypi-parity` job or run `scripts/check_release_channel_parity.py` from the exact source tag |
| **CycloneDX SBOM** | Generated from a runtime-requirements export of `uv.lock` (`pip-audit --format=cyclonedx-json`), completed with the `recon-tool` root component and dependency edge, validated as nonempty JSON, and attached to the GitHub Release. The isolated SBOM job may emit an artifact when findings exist because the separate enforcing audit already blocks the release test job. Any SBOM tool, output, or validation failure blocks both PyPI and GitHub publication | Download `recon-tool-<version>.cdx.json` from the release assets and inspect `metadata.component` and the root dependency entry |

## Consumer verification quick path

Run either complete path below from a reviewed checkout of the exact source tag.
Both paths require Git, GitHub CLI `gh`, Python 3.11 through 3.14, `uv`/`uvx`,
and network access to GitHub and PyPI. GitHub CLI must have a working
authenticated session or a `GH_TOKEN` with public read access. These credentials
belong to verifier tooling; the recon runtime itself still needs none. The
recipes pin the `pypi-attestations==0.0.29` verifier release instead of floating
latest; uv and the verifier's transitive environment remain resolver-selected.
The optional `RECON_INSTALL_MANAGER` setting installs the exact verified local
wheel with the package manager that you select; leave it unset when ownership
is uncertain.

Acquire the reviewed source before running either recipe. From an empty parent
directory, these commands select the exact version tag and its commit instead
of mutable branch content:

```bash
git clone --branch v2.6.4 --single-branch https://github.com/blisspixel/recon.git recon-2.6.4
cd recon-2.6.4
```

Inspect this document and the referenced local scripts before execution. If you
already have a checkout, fetch tags and explicitly check out the same exact tag;
do not silently substitute `main` or a source archive whose tag you have not
reviewed.
The published v2.6.3 bundle covers its wheel and sdist; the recipe binds that
historical exception to commit
`3d5218e00e969874dda40956d677e131d392dbf9` and still validates the completed
SBOM structure. Every later release must also verify the SBOM as an attestation
subject.

### macOS or Linux

```bash
set -euo pipefail

VERSION=2.6.4
REPO=blisspixel/recon
LEGACY_SBOM_ATTESTATION_SHA=3d5218e00e969874dda40956d677e131d392dbf9
MAX_RELEASE_ASSET_BYTES=$((64 * 1024 * 1024))
VERIFY_DIR="$(mktemp -d)"
DIST_DIR="${VERIFY_DIR}/dist"
EVIDENCE_DIR="${VERIFY_DIR}/evidence"
URL_FILE="${VERIFY_DIR}/pypi-urls.txt"
mkdir -p "${DIST_DIR}" "${EVIDENCE_DIR}"
trap 'rm -rf "${VERIFY_DIR}"' EXIT

if [ "$(git describe --tags --exact-match)" != "v${VERSION}" ]; then
  echo "FAIL: checkout must be the exact v${VERSION} tag." >&2
  exit 1
fi
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo "FAIL: verification checkout must be clean." >&2
  exit 1
fi
SOURCE_SHA="$(git rev-parse HEAD)"
case "${SOURCE_SHA}" in
  *[!0-9a-f]*|"") echo "FAIL: source digest is not a full lowercase commit SHA." >&2; exit 1 ;;
esac
if [ "${#SOURCE_SHA}" -ne 40 ] && [ "${#SOURCE_SHA}" -ne 64 ]; then
  echo "FAIL: source digest must contain 40 or 64 hexadecimal characters." >&2
  exit 1
fi
gh auth status

EXPECTED_ASSETS="$(printf '%s\n' \
  "recon-tool-${VERSION}.cdx.json" \
  "recon-tool-${VERSION}.intoto.jsonl" \
  "recon_tool-${VERSION}-py3-none-any.whl" \
  "recon_tool-${VERSION}.tar.gz" | sort)"
ACTUAL_ASSETS="$(gh release view "v${VERSION}" --repo "${REPO}" \
  --json assets --jq '.assets[].name' | sort)"
if [ "${ACTUAL_ASSETS}" != "${EXPECTED_ASSETS}" ]; then
  echo "FAIL: GitHub Release does not contain the exact four expected assets." >&2
  exit 1
fi
UNSAFE_ASSETS="$(gh release view "v${VERSION}" --repo "${REPO}" \
  --json assets --jq ".assets[] | select(.size <= 0 or .size > ${MAX_RELEASE_ASSET_BYTES}) | .name")"
if [ -n "${UNSAFE_ASSETS}" ]; then
  echo "FAIL: GitHub Release reports an empty or oversized asset: ${UNSAFE_ASSETS}" >&2
  exit 1
fi

gh release download "v${VERSION}" \
  --repo "${REPO}" \
  --pattern "recon_tool-${VERSION}-py3-none-any.whl" \
  --pattern "recon_tool-${VERSION}.tar.gz" \
  --dir "${DIST_DIR}"
gh release download "v${VERSION}" \
  --repo "${REPO}" \
  --pattern "recon-tool-${VERSION}.cdx.json" \
  --pattern "recon-tool-${VERSION}.intoto.jsonl" \
  --dir "${EVIDENCE_DIR}"
for asset in "${DIST_DIR}"/* "${EVIDENCE_DIR}"/*; do
  ASSET_BYTES="$(wc -c < "${asset}")"
  if [ "${ASSET_BYTES}" -le 0 ] || [ "${ASSET_BYTES}" -gt "${MAX_RELEASE_ASSET_BYTES}" ]; then
    echo "FAIL: downloaded release asset is empty or oversized: ${asset}" >&2
    exit 1
  fi
done

python scripts/check_release_channel_parity.py \
  --version "${VERSION}" \
  --dist-dir "${DIST_DIR}" \
  --url-file "${URL_FILE}"
python - "${VERSION}" "${EVIDENCE_DIR}/recon-tool-${VERSION}.cdx.json" <<'PY'
import sys
from pathlib import Path

from scripts.finalize_sbom import validate_completed_sbom

validate_completed_sbom(Path(sys.argv[2]), sys.argv[1])
print(f"PASS: completed CycloneDX SBOM is valid for {sys.argv[1]}.")
PY

ATTESTATION_ARTIFACTS=(
  "${DIST_DIR}/recon_tool-${VERSION}-py3-none-any.whl"
  "${DIST_DIR}/recon_tool-${VERSION}.tar.gz"
)
if [ "${VERSION}" = "2.6.3" ]; then
  if [ "${SOURCE_SHA}" != "${LEGACY_SBOM_ATTESTATION_SHA}" ]; then
    echo "FAIL: v2.6.3 does not match its exact historical attestation exception." >&2
    exit 1
  fi
else
  ATTESTATION_ARTIFACTS+=("${EVIDENCE_DIR}/recon-tool-${VERSION}.cdx.json")
fi
for artifact in "${ATTESTATION_ARTIFACTS[@]}"; do
  gh attestation verify "${artifact}" \
    --bundle "${EVIDENCE_DIR}/recon-tool-${VERSION}.intoto.jsonl" \
    --repo "${REPO}" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --source-ref "refs/tags/v${VERSION}" \
    --source-digest "${SOURCE_SHA}" \
    --deny-self-hosted-runners
done

URL_COUNT=0
while IFS= read -r file_url; do
  [ -n "${file_url}" ] || { echo "FAIL: empty PyPI URL." >&2; exit 1; }
  uvx --from "pypi-attestations==0.0.29" pypi-attestations verify pypi \
    --repository "https://github.com/${REPO}" \
    "${file_url}"
  URL_COUNT=$((URL_COUNT + 1))
done < "${URL_FILE}"
if [ "${URL_COUNT}" -ne 2 ]; then
  echo "FAIL: expected exactly two validated PyPI artifact URLs." >&2
  exit 1
fi

WHEEL="${DIST_DIR}/recon_tool-${VERSION}-py3-none-any.whl"
if [ "$(uv run --isolated --no-project --with "${WHEEL}" recon --version)" != "recon ${VERSION}" ]; then
  echo "FAIL: wheel console entry point reported the wrong version." >&2
  exit 1
fi
if [ "$(uv run --isolated --no-project --with "${WHEEL}" python -m recon_tool --version)" != "recon ${VERSION}" ]; then
  echo "FAIL: wheel module entry point reported the wrong version." >&2
  exit 1
fi

case "${RECON_INSTALL_MANAGER:-}" in
  "") ;;
  uv) uv tool install --force "${WHEEL}" ;;
  pipx) pipx install --force "${WHEEL}" ;;
  *) echo "FAIL: RECON_INSTALL_MANAGER must be uv, pipx, or unset." >&2; exit 1 ;;
esac

echo "PASS: v${VERSION} has an exact asset set, valid SBOM, tag-bound bundle,"
echo "      PyPI provenance, channel byte parity, and both working wheel entry points."
```

### Windows PowerShell

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Version = "2.6.4"
$Repo = "blisspixel/recon"
$LegacySbomAttestationSha = "3d5218e00e969874dda40956d677e131d392dbf9"
$MaxReleaseAssetBytes = 64 * 1024 * 1024
$VerifyDir = Join-Path ([IO.Path]::GetTempPath()) ("recon-verify-" + [guid]::NewGuid())
$DistDir = Join-Path $VerifyDir "dist"
$EvidenceDir = Join-Path $VerifyDir "evidence"
$UrlFile = Join-Path $VerifyDir "pypi-urls.txt"
New-Item -ItemType Directory -Path $DistDir, $EvidenceDir | Out-Null

function Invoke-Native {
    param([string]$Label, [string]$Command, [string[]]$Arguments)
    $PreviousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $Output = @()
    $ExitCode = 1
    try {
        $Output = & $Command @Arguments
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousPreference
    }
    if ($ExitCode -ne 0) { throw "$Label failed with exit code $ExitCode." }
    return $Output
}

try {
    $Tag = (Invoke-Native "tag check" "git" @("describe", "--tags", "--exact-match")) -join "`n"
    if ($Tag.Trim() -ne "v$Version") { throw "Checkout must be the exact v$Version tag." }
    $Worktree = (Invoke-Native "worktree check" "git" @(
        "status", "--porcelain", "--untracked-files=normal"
    )) -join "`n"
    if ($Worktree.Trim()) { throw "Verification checkout must be clean." }
    $SourceSha = ((Invoke-Native "source digest" "git" @("rev-parse", "HEAD")) -join "`n").Trim().ToLowerInvariant()
    if ($SourceSha -notmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') {
        throw "Source digest must be a full 40- or 64-character commit SHA."
    }
    Invoke-Native "GitHub authentication" "gh" @("auth", "status") | Out-Host

    $ExpectedAssets = @(
        "recon-tool-$Version.cdx.json"
        "recon-tool-$Version.intoto.jsonl"
        "recon_tool-$Version-py3-none-any.whl"
        "recon_tool-$Version.tar.gz"
    ) | Sort-Object
    $ReleaseJson = (Invoke-Native "release asset inventory" "gh" @(
        "release", "view", "v$Version", "--repo", $Repo, "--json", "assets"
    )) -join "`n"
    $ActualAssets = @((ConvertFrom-Json $ReleaseJson).assets.name) | Sort-Object
    if (($ActualAssets -join "`n") -ne ($ExpectedAssets -join "`n")) {
        throw "GitHub Release does not contain the exact four expected assets."
    }
    foreach ($Asset in (ConvertFrom-Json $ReleaseJson).assets) {
        if ($null -eq $Asset.size -or $Asset.size -le 0 -or $Asset.size -gt $MaxReleaseAssetBytes) {
            throw "GitHub Release reports an empty or oversized asset: $($Asset.name)"
        }
    }

    Invoke-Native "distribution download" "gh" @(
        "release", "download", "v$Version", "--repo", $Repo,
        "--pattern", "recon_tool-$Version-py3-none-any.whl",
        "--pattern", "recon_tool-$Version.tar.gz", "--dir", $DistDir
    ) | Out-Host
    Invoke-Native "evidence download" "gh" @(
        "release", "download", "v$Version", "--repo", $Repo,
        "--pattern", "recon-tool-$Version.cdx.json",
        "--pattern", "recon-tool-$Version.intoto.jsonl", "--dir", $EvidenceDir
    ) | Out-Host
    foreach ($AssetPath in @(Get-ChildItem -LiteralPath $DistDir, $EvidenceDir -File)) {
        if ($AssetPath.Length -le 0 -or $AssetPath.Length -gt $MaxReleaseAssetBytes) {
            throw "Downloaded release asset is empty or oversized: $($AssetPath.FullName)"
        }
    }

    Invoke-Native "channel parity" "python" @(
        "scripts/check_release_channel_parity.py", "--version", $Version,
        "--dist-dir", $DistDir, "--url-file", $UrlFile
    ) | Out-Host
    $Sbom = Join-Path $EvidenceDir "recon-tool-$Version.cdx.json"
    $SbomCheck = 'import sys; from pathlib import Path; from scripts.finalize_sbom import validate_completed_sbom; validate_completed_sbom(Path(sys.argv[2]), sys.argv[1]); print(f"PASS: completed CycloneDX SBOM is valid for {sys.argv[1]}.")'
    Invoke-Native "SBOM validation" "python" @("-c", $SbomCheck, $Version, $Sbom) | Out-Host

    $Bundle = Join-Path $EvidenceDir "recon-tool-$Version.intoto.jsonl"
    $Wheel = Join-Path $DistDir "recon_tool-$Version-py3-none-any.whl"
    $Sdist = Join-Path $DistDir "recon_tool-$Version.tar.gz"
    $AttestationArtifacts = @($Wheel, $Sdist)
    if ($Version -eq "2.6.3") {
        if ($SourceSha -ne $LegacySbomAttestationSha) {
            throw "v2.6.3 does not match its exact historical attestation exception."
        }
    }
    else {
        $AttestationArtifacts += $Sbom
    }
    foreach ($Artifact in $AttestationArtifacts) {
        Invoke-Native "GitHub attestation verification" "gh" @(
            "attestation", "verify", $Artifact, "--bundle", $Bundle,
            "--repo", $Repo,
            "--signer-workflow", "$Repo/.github/workflows/release.yml",
            "--source-ref", "refs/tags/v$Version", "--source-digest", $SourceSha,
            "--deny-self-hosted-runners"
        ) | Out-Host
    }

    $Urls = @(Get-Content -LiteralPath $UrlFile | Where-Object { $_ })
    if ($Urls.Count -ne 2) { throw "Expected exactly two validated PyPI artifact URLs." }
    foreach ($FileUrl in $Urls) {
        Invoke-Native "PyPI attestation verification" "uvx" @(
            "--from", "pypi-attestations==0.0.29", "pypi-attestations", "verify", "pypi",
            "--repository", "https://github.com/$Repo", $FileUrl
        ) | Out-Host
    }

    $ConsoleVersion = (Invoke-Native "wheel console smoke" "uv" @(
        "run", "--isolated", "--no-project", "--with", $Wheel, "recon", "--version"
    )) -join "`n"
    if ($ConsoleVersion.Trim() -ne "recon $Version") {
        throw "Wheel console entry point reported the wrong version."
    }
    $ModuleVersion = (Invoke-Native "wheel module smoke" "uv" @(
        "run", "--isolated", "--no-project", "--with", $Wheel,
        "python", "-m", "recon_tool", "--version"
    )) -join "`n"
    if ($ModuleVersion.Trim() -ne "recon $Version") {
        throw "Wheel module entry point reported the wrong version."
    }

    if ($env:RECON_INSTALL_MANAGER -eq "uv") {
        Invoke-Native "verified-wheel install" "uv" @("tool", "install", "--force", $Wheel) | Out-Host
    }
    elseif ($env:RECON_INSTALL_MANAGER -eq "pipx") {
        Invoke-Native "verified-wheel install" "pipx" @("install", "--force", $Wheel) | Out-Host
    }
    elseif ($env:RECON_INSTALL_MANAGER) {
        throw "RECON_INSTALL_MANAGER must be uv, pipx, or unset."
    }

    Write-Host "PASS: v$Version has an exact asset set, valid SBOM, tag-bound bundle,"
    Write-Host "      PyPI provenance, channel byte parity, and both working wheel entry points."
}
finally {
    if (Test-Path -LiteralPath $VerifyDir) {
        Remove-Item -LiteralPath $VerifyDir -Recurse -Force -ErrorAction Stop
    }
}
```

Each recipe stops on a producer, inventory, digest, verifier, SBOM, bundle,
signer, tag, or entry-point failure and prints the consolidated success line
only after every required check passes. If an install manager was selected,
open a new terminal and confirm `recon --version` reports the same version. The
verification path does not make installers enforce PyPI attestations
automatically. It is also not a claim that recon has reached a named SLSA level
beyond the controls listed here.

### Failure and recovery map

Treat the final `PASS` line as the only complete success state. Before it:

| Failure class | Required action |
|---|---|
| Missing local prerequisite or GitHub authentication | Repair the named prerequisite or read-only authentication, then restart from the same clean tag checkout. This failure makes no claim about artifact trust. |
| Timeout, transient network response, or delayed publication visibility | Keep the checkout and tag unchanged, then rerun the complete recipe. Do not reuse partial output from the temporary directory. |
| Asset inventory, digest, SBOM structure, bundle, signer, source ref, source digest, hosted-runner, version, or entry-point mismatch | Stop. Do not install the artifact and do not replace evidence. Preserve the failing output for maintainer investigation. |
| Optional install step fails after the verification checks pass | Verification may be complete, but installation is not. The temporary directory is removed on failure; resolve package-manager ownership and rerun the complete flow. |

The recipes never repair producer evidence. A permanent mismatch requires a
new, correctly produced release rather than weakening a verifier or replacing
an immutable published file.

## Deterministic-build evidence

The release workflow fixes `SOURCE_DATE_EPOCH` to the tagged commit's committer
timestamp and selects uv 0.11.17. `pyproject.toml` declares exact Hatchling
1.31.0 in both the build system and a non-default PEP 735 `build` group.
[`build-constraints.txt`](../build-constraints.txt) is the frozen export of that
group's `uv.lock` closure. Every backend package has an exact version and
SHA-256 hashes, and each artifact command uses both `--build-constraints` and
`--require-hashes`.

The constraint fixes dependency identity and makes updates reviewable. It does
not prove that a selected build dependency is free of vulnerabilities; normal
dependency review and the isolated release-job boundary remain separate
controls.

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) tests same-job
repeatability on every change. Its `reproducible-build` job creates one sdist,
constructs the wheel from that exact sdist, repeats that sequence in the same
Ubuntu job, and compares both artifact hashes. The tagged release uses the same
two commands before immediately sealing `dist/`.

This fixes uv-version and backend-resolver drift in the tested build path. It
does not prove byte identity across different Python versions, operating
systems, runner images, archive implementations, or other host environment
details. The release and CI paths use Python 3.11 on Ubuntu; a consumer seeking
an exact hash match should reproduce those inputs as closely as practical.

To verify a published release yourself:

```bash
# 1. Check out the exact tag.
VERSION=2.6.4  # replace with the release being verified
git clone https://github.com/blisspixel/recon
cd recon
git checkout "v${VERSION}"

# 2. Confirm the tag-selected build executable and match release Python.
uv --version  # must report uv 0.11.17; pyproject.toml rejects drift
export UV_PYTHON=3.11
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"

# 3. Build the sdist, then reconstruct the wheel from that exact sdist.
uv build --sdist --out-dir /tmp/verify \
  --build-constraints build-constraints.txt --require-hashes
uv build --wheel "/tmp/verify/recon_tool-${VERSION}.tar.gz" \
  --out-dir /tmp/verify \
  --build-constraints build-constraints.txt --require-hashes

# 4. Compare against the published artifacts (from PyPI or the GitHub Release).
sha256sum "/tmp/verify/recon_tool-${VERSION}-py3-none-any.whl"
sha256sum "/tmp/verify/recon_tool-${VERSION}.tar.gz"
```

An exact hash match is strong confirmation under a matched host environment. A
mismatch is not, by itself, evidence of tampering because the runner and host
environment are not fully content-addressed. Use the signed provenance and
PyPI attestations above to verify source and workflow identity. Build into a
directory outside the checkout, as above, so build output is not swept into
the sdist. The sdist itself includes `build-constraints.txt`, so its build-tool
boundary remains inspectable after source distribution.

Maintainers regenerate the constraint after an intentional build-group update
with the following command. `tests/test_build_constraints.py` fails if the
export, exact root requirement, hashes, selected uv version, or workflow use
drifts.

```bash
uv export --frozen --only-group build --no-emit-project \
  --format requirements.txt --no-header \
  --output-file build-constraints.txt
```

## PyPI attestation verification

PyPI exposes attestations through the simple index and Integrity API as
file-level provenance objects. For a consumer-side check, get the released
wheel's direct PyPI file URL and run the reviewed verifier version:

```bash
uvx --from "pypi-attestations==0.0.29" pypi-attestations verify pypi \
  --repository https://github.com/blisspixel/recon \
  <wheel-url>
```

That command downloads the wheel and provenance JSON from PyPI, checks that the
Trusted Publisher identity matches the repository argument, and cryptographically
verifies the wheel against the included attestations. Do not treat PyPI
attestations as installer-level enforcement unless the installer being used
documents that behavior.

## Supply-chain isolation contract

The release jobs are scoped to least privilege. The `build` job runs exact uv
and the hash-locked Hatchling graph, creates the sdist, constructs the wheel
from that sdist, then immediately uploads both artifacts. No project runtime
dependency or unrelated tool runs after artifact creation and before sealing.
The `package-smoke` job downloads the sealed distribution into a separate
read-only runner, rejects anything except one tag-matching wheel and sdist,
and executes both installed entry points without OIDC or write permissions.
The `test` and `sbom` jobs run on separate runners that never see `dist/`.
The `attest` job downloads only the sealed distribution and completed SBOM, and
jobs with elevated OIDC-minted scopes do not execute project runtime
dependencies. The provenance export job downloads the signed GitHub
attestation bundles for the wheel, sdist, and SBOM and uploads a
`.intoto.jsonl` artifact for the GitHub Release without running project
dependency code. PyPI publication waits
for sealed-distribution validation and wheel execution, provenance attestation,
and the validated SBOM. GitHub publication additionally waits until the exact
PyPI wheel and sdist match the sealed pair byte for byte. A parity failure after
PyPI accepts immutable files blocks the GitHub Release and leaves an explicit
partial-publication state. Existing GitHub Release recovery validates the exact
tag, title, non-draft, non-prerelease, and mutable state, plus expected-only
inventory, complete or partial, before any `--clobber` upload can run. It also
requires the remote tag to resolve to the original workflow SHA. Maintainers
must diagnose the mismatch and rerun the same tagged workflow only when the
sealed bytes match the existing PyPI files; they must never manually rebuild,
replace, or work around either channel's evidence. The full rationale and
recovery boundary are documented in [release-process.md](release-process.md).

## Repository posture checks

The repository also runs supply-chain posture checks outside the release flow:

- OpenSSF Scorecard publishes the public posture badge and SARIF results.
- CodeQL runs on pull requests targeting `main`, on a weekly schedule, and on
  demand. The pull-request event supplies pre-merge analysis; the schedule keeps
  a full default-branch scan independent of change traffic.
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
  or PowerShell installers. Each reviewed tag installs its exact `recon-tool`
  version, preserves a sole existing `uv` or `pipx` owner, refuses ambiguous or
  unmanaged ownership, and exposes manager failures.
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
- Remote release readiness checks PyPI's exact current-version record and the
  exact GitHub Release asset set for the current version. It first requires the
  remote and local current version tag plus `HEAD` to resolve to the same full
  commit, then validates the completed SBOM and verifies the policy-required
  GitHub subjects against the downloaded bundle, exact release workflow, exact
  source tag and commit digest, and hosted-runner boundary. The exact v2.6.3
  historical exception covers its wheel and sdist; every later release also
  requires the SBOM subject. The gate
  requires the PyPI and GitHub wheel and sdist digests to match. It also verifies
  public Scorecard API freshness for `HEAD`, code-owned Scorecard controls, the
  documented SAST floor, and both PyPI PEP 740 attestations.
- Checkout steps set `persist-credentials: false`, so the workflow token is not
  left in the local Git config after source checkout.
- Every workflow job has an explicit timeout so CI and release automation fail
  closed instead of hanging indefinitely.
- Secret scanning and push protection are enabled for the repository. The
  gitleaks workflow runs on pull requests, pushes to `main`, and a weekly
  full-history schedule with read-only repository permissions.
- `.github/CODEOWNERS` routes all repository paths to the maintainer account so
  external pull requests have a clear review owner.

The 2026-07-18 Scorecard recheck for the exact v2.6.4 `HEAD` commit reports
score `8.2`. The non-SAST measured code-owned controls are at `10`; SAST is `7`
because all 17 sampled merged pull requests predate PR-scoped CodeQL. Remote
release readiness requires an overall score of at least `8.0`, keeps the other
required code-owned controls at `10`, and enforces the current SAST floor of
`7`. New pull requests targeting `main` run CodeQL, and the weekly and manual
default-branch scans remain. The SAST requirement can return to `10` only after
the public API reports successful supported SAST checks for every merged pull
request in its sampled window. The dated `8.2` value is a snapshot, not a
permanent promise.
The June 28 review found one code-owned gap and several repository-process gaps.
The code-owned gap was an
unpinned installer download-and-run path; the installer now refuses to execute
remote tool installers. The Scorecard SARIF upload step also uses CodeQL Action
v4 to avoid the scheduled v3 deprecation. Live repository settings now enforce
full-SHA GitHub Action pins, enable dependency security updates, and protect
`main` with an active repository ruleset that requires the CI matrix, gitleaks,
and CodeQL checks, blocks deletion and non-fast-forward updates, and requires
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
