#!/usr/bin/env python3
"""Fail closed before replacing assets on an existing GitHub Release."""

from __future__ import annotations

import argparse
import json
import re
import sys

MAX_RELEASE_JSON_BYTES = 1024 * 1024
_STABLE_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")


class RecoveryError(RuntimeError):
    """An existing release is not safe for automated recovery."""


def expected_release_assets(version: str) -> tuple[str, str, str, str]:
    if _STABLE_VERSION.fullmatch(version) is None:
        raise RecoveryError("version must use stable X.Y.Z syntax")
    return (
        f"recon_tool-{version}-py3-none-any.whl",
        f"recon_tool-{version}.tar.gz",
        f"recon-tool-{version}.cdx.json",
        f"recon-tool-{version}.intoto.jsonl",
    )


def validate_release_recovery(version: str, payload: object) -> tuple[str, ...]:
    """Return missing expected assets when an existing release is safe to repair."""
    expected = expected_release_assets(version)
    tag = f"v{version}"
    if not isinstance(payload, dict):
        raise RecoveryError("GitHub Release metadata must be a JSON object")
    if payload.get("tagName") != tag:
        raise RecoveryError(f"release tag must be exactly {tag}")
    if payload.get("name") != tag:
        raise RecoveryError(f"release title must be exactly {tag}")
    if payload.get("isDraft") is not False:
        raise RecoveryError("existing release must not be a draft")
    if payload.get("isPrerelease") is not False:
        raise RecoveryError("existing release must not be a prerelease")
    if payload.get("isImmutable") is not False:
        raise RecoveryError("existing release must not be immutable")

    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise RecoveryError("existing release assets must be a JSON list")
    names: list[str] = []
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str) or not asset["name"]:
            raise RecoveryError("existing release asset records must contain a nonempty name")
        names.append(asset["name"])
    if len(names) != len(set(names)):
        raise RecoveryError("existing release contains duplicate asset names")
    unexpected = sorted(set(names) - set(expected))
    if unexpected:
        raise RecoveryError("existing release contains unexpected asset(s): " + ", ".join(unexpected))
    return tuple(name for name in expected if name not in names)


def _read_payload() -> object:
    raw = sys.stdin.buffer.read(MAX_RELEASE_JSON_BYTES + 1)
    if len(raw) > MAX_RELEASE_JSON_BYTES:
        raise RecoveryError(f"GitHub Release metadata exceeds the {MAX_RELEASE_JSON_BYTES}-byte safety limit")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"GitHub Release metadata is not valid JSON: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        missing = validate_release_recovery(args.version, _read_payload())
    except RecoveryError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    detail = "none" if not missing else ", ".join(missing)
    print(f"PASS: existing v{args.version} release is safe to recover; missing expected assets: {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
