#!/usr/bin/env python3
"""Validate a complete human-owned GitHub Release without repairing it."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path

MAX_RELEASE_JSON_BYTES = 1024 * 1024
MAX_RELEASE_ASSET_BYTES = 64 * 1024 * 1024
RELEASE_REPOSITORY = "pueo-labs/recon"
RELEASE_MAINTAINER = "blisspixel"
# Only these reviewed immutable releases retain the pre-transfer signer.
# Other historical releases must be verified from their reviewed source tags.
_HISTORICAL_SIGNERS = {
    "2.6.3": "2751dc11c64001272750df29477d6b9052407261",
    "2.27.0": "9c213f79cfa92eb2e40e76d605a2f9d6a341e4d9",
}
Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class RecoveryError(ValueError):
    """Release evidence is incomplete or conflicts with the human handoff."""


def release_signer_repository(version: str, source_sha: str) -> str:
    """Select a pinned historical signer, never retry with a weaker identity."""
    historical_sha = _HISTORICAL_SIGNERS.get(version)
    if historical_sha is not None:
        if source_sha != historical_sha:
            raise RecoveryError("release signer does not match the exact historical source digest")
        return "blisspixel/recon"
    return RELEASE_REPOSITORY


def expected_release_assets(version: str) -> tuple[str, ...]:
    if re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) is None:
        raise RecoveryError("release version must be stable X.Y.Z without leading zeroes")
    return (
        f"recon_tool-{version}-py3-none-any.whl",
        f"recon_tool-{version}.tar.gz",
        f"recon-tool-{version}.cdx.json",
        f"recon-tool-{version}.intoto.jsonl",
    )


def _require_maintainer(identity: object, label: str) -> None:
    if not isinstance(identity, dict) or identity.get("login") != RELEASE_MAINTAINER or identity.get("type") != "User":
        raise RecoveryError(f"{label} must be the human {RELEASE_MAINTAINER} account (type User)")


def _positive_int(value: object, label: str, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RecoveryError(f"{label} must be a positive integer")
    if maximum is not None and value > maximum:
        raise RecoveryError(f"{label} exceeds the {maximum}-byte safety limit")
    return value


def _asset_name(asset: object) -> str:
    if not isinstance(asset, dict) or not isinstance(asset.get("name"), str) or not asset["name"]:
        raise RecoveryError("release asset records must contain a nonempty name")
    name = asset["name"]
    _positive_int(asset.get("id"), f"asset ID for {name}")
    _positive_int(asset.get("size"), f"asset size for {name}", MAX_RELEASE_ASSET_BYTES)
    if asset.get("state") != "uploaded":
        raise RecoveryError(f"asset must be completely uploaded: {name}")
    digest = asset.get("digest")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise RecoveryError(f"asset must declare a canonical SHA-256 digest: {name}")
    _require_maintainer(asset.get("uploader"), f"asset uploader for {name}")
    return name


def validate_release_recovery(version: str, payload: object, *, draft: bool = False) -> tuple[str, ...]:
    """Require complete REST release evidence; never authorize replacement."""
    expected = expected_release_assets(version)
    tag = f"v{version}"
    if not isinstance(payload, dict):
        raise RecoveryError("GitHub Release metadata must be a JSON object")
    if payload.get("tag_name") != tag:
        raise RecoveryError(f"release tag must be exactly {tag}")
    if payload.get("name") != tag:
        raise RecoveryError(f"release title must be exactly {tag}")
    if payload.get("draft") is not draft:
        raise RecoveryError("release must be a draft" if draft else "release must not be a draft")
    if payload.get("prerelease") is not False:
        raise RecoveryError("release must not be a prerelease")
    _positive_int(payload.get("id"), "release ID")
    _require_maintainer(payload.get("author"), "release author")
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise RecoveryError("release assets must be a JSON list")
    names = [_asset_name(asset) for asset in assets]
    if len(names) != len(set(names)):
        raise RecoveryError("release contains duplicate asset names")
    unexpected = sorted(set(names) - set(expected))
    if unexpected:
        raise RecoveryError("release contains unexpected asset(s): " + ", ".join(unexpected))
    missing = sorted(set(expected) - set(names))
    if missing:
        raise RecoveryError("release is missing asset(s): " + ", ".join(missing))
    ids = [asset["id"] for asset in assets]
    if len(ids) != len(set(ids)):
        raise RecoveryError("release contains duplicate asset IDs")
    return ()


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryError(f"GitHub Release metadata repeats JSON key {key!r}")
        result[key] = value
    return result


def parse_release_metadata(raw: str | bytes) -> dict[str, object]:
    if len(raw.encode("utf-8") if isinstance(raw, str) else raw) > MAX_RELEASE_JSON_BYTES:
        raise RecoveryError(f"GitHub Release metadata exceeds the {MAX_RELEASE_JSON_BYTES}-byte safety limit")
    try:
        payload: object = json.loads(raw, object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"GitHub Release metadata is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RecoveryError("GitHub Release metadata must be a JSON object")
    return payload


def load_release_metadata(runner: Runner, version: str, *, release_id: int | None = None) -> dict[str, object]:
    expected_release_assets(version)
    selector = f"tags/v{version}" if release_id is None else str(_positive_int(release_id, "release ID"))
    result = runner(["gh", "api", "--hostname", "github.com", f"repos/{RELEASE_REPOSITORY}/releases/{selector}"])
    if result.returncode != 0:
        raise RecoveryError("no readable release metadata; inspect the original run and complete the human handoff")
    payload = parse_release_metadata(result.stdout)
    if release_id is not None and payload.get("id") != release_id:
        raise RecoveryError("release ID does not match the explicitly selected draft")
    return payload


def download_release_asset(subject: str, asset_id: int, directory: Path) -> Path:
    """Stream an admitted numeric asset with a hard byte cap and deadline."""
    _positive_int(asset_id, "asset ID")
    artifact = directory / subject
    command = [
        "gh",
        "api",
        "--hostname",
        "github.com",
        "--method",
        "GET",
        "--allow-escape-sequences",
        f"repos/{RELEASE_REPOSITORY}/releases/assets/{asset_id}",
        "--header",
        "Accept: application/octet-stream",
    ]
    expired = threading.Event()
    with (
        artifact.open("xb") as output,
        subprocess.Popen(  # noqa: S603 - fixed repository and admitted numeric ID
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as process,
    ):

        def expire() -> None:
            expired.set()
            if process.poll() is None:
                process.kill()

        deadline = threading.Timer(120, expire)
        deadline.daemon = True
        deadline.start()
        try:
            if process.stdout is None:
                raise RecoveryError("asset download did not open a binary stream")
            total = 0
            while block := process.stdout.read(min(1024 * 1024, MAX_RELEASE_ASSET_BYTES + 1 - total)):
                total += len(block)
                if total > MAX_RELEASE_ASSET_BYTES:
                    process.kill()
                    raise RecoveryError(
                        f"release asset exceeds the {MAX_RELEASE_ASSET_BYTES}-byte safety limit: {subject}"
                    )
                output.write(block)
            code = process.wait()
            if expired.is_set():
                raise RecoveryError(f"release asset download timed out: {subject}")
            if code != 0:
                raise RecoveryError(f"could not read admitted release asset: {subject}")
        finally:
            deadline.cancel()
            if process.poll() is None:
                process.kill()
                process.wait()
    return artifact


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        validate_release_recovery(
            args.version, parse_release_metadata(sys.stdin.buffer.read(MAX_RELEASE_JSON_BYTES + 1))
        )
    except RecoveryError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: v{args.version} has complete human-owned release metadata; no assets were changed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
