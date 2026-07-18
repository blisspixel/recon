"""Existing GitHub Release recovery must fail closed before asset replacement."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import check_release_recovery as recovery

VERSION = "2.6.3"


def _payload(*assets: str, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "tagName": f"v{VERSION}",
        "name": f"v{VERSION}",
        "isDraft": False,
        "isPrerelease": False,
        "isImmutable": False,
        "assets": [{"name": asset} for asset in assets],
    }
    payload.update(overrides)
    return payload


def test_safe_partial_release_returns_only_missing_expected_assets() -> None:
    wheel, sdist, sbom, provenance = recovery.expected_release_assets(VERSION)

    missing = recovery.validate_release_recovery(VERSION, _payload(wheel, sbom))

    assert missing == (sdist, provenance)


def test_complete_exact_release_is_safe_to_recover() -> None:
    assets = recovery.expected_release_assets(VERSION)

    assert recovery.validate_release_recovery(VERSION, _payload(*assets)) == ()


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (_payload(tagName="v2.6.2"), "tag must be exactly"),
        (_payload(name="release 2.6.3"), "title must be exactly"),
        (_payload(isDraft=True), "must not be a draft"),
        (_payload(isPrerelease=True), "must not be a prerelease"),
        (_payload(isImmutable=True), "must not be immutable"),
        (_payload("unexpected.txt"), "unexpected asset"),
        (_payload("same.txt", "same.txt"), "duplicate asset"),
        (_payload(assets=[{"size": 1}]), "nonempty name"),
    ],
)
def test_unsafe_existing_release_state_is_rejected(payload: dict[str, object], message: str) -> None:
    with pytest.raises(recovery.RecoveryError, match=message):
        recovery.validate_release_recovery(VERSION, payload)


@pytest.mark.parametrize("version", ["2.6", "v2.6.3", "2.6.3rc1", "02.6.3"])
def test_version_must_be_stable_and_canonical(version: str) -> None:
    with pytest.raises(recovery.RecoveryError, match=r"stable X\.Y\.Z"):
        recovery.expected_release_assets(version)


def test_cli_accepts_bounded_json_and_reports_missing_assets() -> None:
    wheel = recovery.expected_release_assets(VERSION)[0]

    result = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [sys.executable, str(Path(recovery.__file__)), "--version", VERSION],
        input=json.dumps(_payload(wheel)),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.startswith(f"PASS: existing v{VERSION} release is safe to recover")
    assert f"recon_tool-{VERSION}.tar.gz" in result.stdout


def test_cli_rejects_oversized_json_before_parsing() -> None:
    result = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [sys.executable, str(Path(recovery.__file__)), "--version", VERSION],
        input=b"{" + b" " * recovery.MAX_RELEASE_JSON_BYTES,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert b"safety limit" in result.stderr
