#!/usr/bin/env python3
"""Verify the human-published release against this original run's sealed files."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

try:
    from scripts import release_readiness
    from scripts.check_release_channel_parity import ParityError, RetryPolicy, _local_digest, check_channel_parity
    from scripts.check_release_recovery import (
        RELEASE_REPOSITORY,
        RecoveryError,
        Runner,
        expected_release_assets,
        load_release_metadata,
        release_signer_repository,
        validate_release_recovery,
    )
    from scripts.finalize_sbom import SbomError, validate_completed_sbom
except ImportError:
    import release_readiness  # type: ignore[no-redef]
    from check_release_channel_parity import (  # type: ignore[no-redef]
        ParityError,
        RetryPolicy,
        _local_digest,
        check_channel_parity,
    )
    from check_release_recovery import (  # type: ignore[no-redef]
        RELEASE_REPOSITORY,
        RecoveryError,
        Runner,
        expected_release_assets,
        load_release_metadata,
        release_signer_repository,
        validate_release_recovery,
    )
    from finalize_sbom import SbomError, validate_completed_sbom  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
HANDOFF = (
    "Human handoff: follow docs/release-process.md using the sealed dist, sbom and provenance artifacts "
    "from this original run and the maintainer's existing authenticated session. "
    "Publish the matching human-owned release, then rerun only this original failed github-release job. "
    "No release or asset was changed."
)


@dataclass(frozen=True)
class ArtifactDirectories:
    """The original run's three separate sealed artifact downloads."""

    dist: Path
    sbom: Path
    provenance: Path


def _require_source_binding(version: str, source_sha: str, runner: Runner) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise RecoveryError("source SHA must be the original run's full commit SHA")
    head = runner(["git", "rev-parse", "HEAD"])
    if head.returncode != 0 or head.stdout.strip() != source_sha:
        raise RecoveryError("HEAD does not match the original run's source SHA")
    # The remote ref must be lightweight and exact, including on an original-job rerun.
    if release_readiness._remote_release_tag_sha(runner, version) != source_sha:
        raise RecoveryError("remote release tag does not match the original run's source SHA")
    if release_readiness._release_tag_sha(runner, version) != source_sha:
        raise RecoveryError("local release tag does not match the original run's source SHA")


def _sealed_files(version: str, dist_dir: Path, sbom_dir: Path, provenance_dir: Path) -> dict[str, Path]:
    wheel, sdist, sbom, bundle = expected_release_assets(version)
    files: dict[str, Path] = {}
    for directory, names in ((dist_dir, (wheel, sdist)), (sbom_dir, (sbom,)), (provenance_dir, (bundle,))):
        if directory.is_symlink() or not directory.is_dir():
            raise RecoveryError(f"sealed artifact directory must be a regular directory: {directory}")
        if {path.name for path in directory.iterdir()} != set(names):
            raise RecoveryError(f"sealed artifact directory has missing or unexpected files: {directory}")
        for name in names:
            path = directory / name
            _local_digest(path)
            files[name] = path
    validate_completed_sbom(files[sbom], version)
    return files


def _verify_provenance(version: str, source_sha: str, sealed: dict[str, Path], runner: Runner) -> None:
    wheel, sdist, sbom, bundle = expected_release_assets(version)
    signer = release_signer_repository(version, source_sha)
    for subject in (wheel, sdist, sbom):
        result = runner(
            [
                "gh",
                "attestation",
                "verify",
                str(sealed[subject]),
                "--bundle",
                str(sealed[bundle]),
                "--repo",
                signer,
                "--signer-workflow",
                f"{signer}/.github/workflows/release.yml",
                "--source-ref",
                f"refs/tags/v{version}",
                "--source-digest",
                source_sha,
                "--deny-self-hosted-runners",
            ]
        )
        if result.returncode != 0:
            raise RecoveryError(f"sealed provenance verification failed for {subject}")


def _verify_remote_bytes(
    version: str,
    sealed: dict[str, Path],
    runner: Runner,
    *,
    draft_release_id: int | None,
) -> None:
    before = load_release_metadata(runner, version, release_id=draft_release_id)
    validate_release_recovery(version, before, draft=draft_release_id is not None)
    with tempfile.TemporaryDirectory(prefix="recon-human-release-") as temporary:
        assets = release_readiness._ReleaseAssetClient(runner, RELEASE_REPOSITORY, version, Path(temporary))
        if draft_release_id is None:
            assets.require_safe_inventory(tuple(sealed))
        records = cast(list[dict[str, object]], before["assets"])
        admitted = {cast(str, record["name"]): record for record in records}
        for name, local in sealed.items():
            downloaded = (
                assets.download(name)
                if draft_release_id is None
                else assets.download(name, asset_id=cast(int, admitted[name]["id"]))
            )
            if downloaded.stat().st_size != admitted[name]["size"]:
                raise RecoveryError(f"GitHub asset size differs from its admitted metadata: {name}")
            digest = _local_digest(downloaded)
            if digest != _local_digest(local):
                raise RecoveryError(f"GitHub asset differs from the original run's sealed file: {name}")
            if admitted[name]["digest"] != f"sha256:{digest}":
                raise RecoveryError(f"GitHub asset digest differs from its admitted metadata: {name}")
    after = load_release_metadata(runner, version, release_id=draft_release_id)
    validate_release_recovery(version, after, draft=draft_release_id is not None)
    if _release_snapshot(after) != _release_snapshot(before):
        raise RecoveryError("release metadata changed during verification; inspect before retrying")


def _release_snapshot(payload: dict[str, object]) -> str:
    # Download counts change during our own reads. Bind publication identity and
    # artifact identities instead of treating those counters as a source change.
    fields = ("id", "tag_name", "name", "draft", "prerelease", "author")
    snapshot = {key: payload.get(key) for key in fields}
    assets = payload["assets"]
    if not isinstance(assets, list):
        raise RecoveryError("release assets must be a JSON list")
    asset_fields = ("id", "name", "state", "size", "uploader", "digest")
    snapshot["assets"] = [
        {key: asset.get(key) for key in asset_fields} for asset in sorted(assets, key=lambda item: item["name"])
    ]
    return json.dumps(snapshot, sort_keys=True)


def verify_release(
    version: str,
    source_sha: str,
    artifacts: ArtifactDirectories,
    *,
    runner: Runner | None = None,
    draft_release_id: int | None = None,
) -> dict[str, str]:
    """Read and verify exact release evidence; perform no publication writes."""
    actual_runner = runner or release_readiness._make_runner(ROOT)
    expected_release_assets(version)
    _require_source_binding(version, source_sha, actual_runner)
    sealed = _sealed_files(version, artifacts.dist, artifacts.sbom, artifacts.provenance)
    _verify_remote_bytes(version, sealed, actual_runner, draft_release_id=draft_release_id)
    _verify_provenance(version, source_sha, sealed, actual_runner)
    # This is the same canonical checker used by the unchanged upstream parity job.
    check_channel_parity(version, artifacts.dist, retry=RetryPolicy(attempts=1, delay_seconds=0))
    return {name: _local_digest(path) for name, path in sealed.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--sbom-dir", type=Path, required=True)
    parser.add_argument("--provenance-dir", type=Path, required=True)
    parser.add_argument(
        "--check-draft", action="store_true", help="read-only maintainer check before publishing a draft"
    )
    parser.add_argument("--release-id", type=int, help="positive numeric draft release ID, required with --check-draft")
    args = parser.parse_args(argv)
    if args.check_draft != (args.release_id is not None) or (args.release_id is not None and args.release_id <= 0):
        parser.error("--check-draft and a positive --release-id must be supplied together")
    try:
        digests = verify_release(
            args.version,
            args.source_sha,
            ArtifactDirectories(args.dist_dir, args.sbom_dir, args.provenance_dir),
            draft_release_id=args.release_id,
        )
    except (RecoveryError, ParityError, SbomError, release_readiness._ReleaseEvidenceError, OSError) as exc:
        print(f"FAIL: {exc}\n{HANDOFF}", file=sys.stderr)
        return 1
    for name, digest in digests.items():
        print(f"PASS: {name} sha256={digest}")
    state = "draft" if args.check_draft else "published release"
    print(f"PASS: human {state} matches the original run, hosted provenance and PyPI; no publication writes performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
