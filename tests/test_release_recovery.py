"""Human release metadata must be complete before read-only verification."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

import pytest

from scripts import check_release_recovery as recovery

VERSION = "2.19.15"


def release_payload(version: str = VERSION) -> dict[str, object]:
    return {
        "id": 1,
        "tag_name": f"v{version}",
        "name": f"v{version}",
        "draft": False,
        "prerelease": False,
        "author": {"login": "blisspixel", "type": "User"},
        "assets": [
            {
                "id": index,
                "name": name,
                "size": 8,
                "digest": "sha256:" + hashlib.sha256(b"fixture").hexdigest(),
                "state": "uploaded",
                "uploader": {"login": "blisspixel", "type": "User"},
            }
            for index, name in enumerate(recovery.expected_release_assets(version), 2)
        ],
    }


def test_complete_human_release_including_immutable_can_verify() -> None:
    payload = release_payload()
    payload["immutable"] = True
    assert recovery.validate_release_recovery(VERSION, payload) == ()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("tag_name", "v2.6.2", "tag must be exactly"),
        ("name", "release", "title must be exactly"),
        ("draft", True, "must not be a draft"),
        ("draft", None, "must not be a draft"),
        ("prerelease", True, "must not be a prerelease"),
        ("id", True, "positive integer"),
        ("author", {"login": "github-actions[bot]", "type": "Bot"}, "release author"),
        ("author", {"login": "blisspixel", "type": "Bot"}, "release author"),
        ("author", {"login": "someone", "type": "User"}, "release author"),
        ("author", {"login": "blisspixel"}, "type User"),
        ("assets", [], "missing asset"),
        ("assets", None, "JSON list"),
    ],
)
def test_release_refusals(field: str, value: object, message: str) -> None:
    payload = release_payload()
    payload[field] = value
    with pytest.raises(recovery.RecoveryError, match=message):
        recovery.validate_release_recovery(VERSION, payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("name", "unexpected.txt", "unexpected asset"),
        ("name", "", "nonempty name"),
        ("id", True, "positive integer"),
        ("size", 0, "positive integer"),
        ("size", recovery.MAX_RELEASE_ASSET_BYTES + 1, "safety limit"),
        ("state", "starter", "completely uploaded"),
        ("digest", None, "canonical SHA-256"),
        ("digest", "sha256:xyz", "canonical SHA-256"),
        ("uploader", {"login": "github-actions[bot]", "type": "Bot"}, "asset uploader"),
        ("uploader", {"login": "blisspixel", "type": "Bot"}, "asset uploader"),
        ("uploader", None, "asset uploader"),
    ],
)
def test_asset_refusals(field: str, value: object, message: str) -> None:
    payload = release_payload()
    assets = payload["assets"]
    assert isinstance(assets, list)
    assets[0][field] = value
    with pytest.raises(recovery.RecoveryError, match=message):
        recovery.validate_release_recovery(VERSION, payload)


def test_duplicate_assets_are_rejected() -> None:
    payload = release_payload()
    assets = payload["assets"]
    assert isinstance(assets, list)
    assets.append(deepcopy(assets[0]))
    with pytest.raises(recovery.RecoveryError, match="duplicate asset names"):
        recovery.validate_release_recovery(VERSION, payload)
    assets.pop()
    assets[1]["id"] = assets[0]["id"]
    with pytest.raises(recovery.RecoveryError, match="duplicate asset IDs"):
        recovery.validate_release_recovery(VERSION, payload)


@pytest.mark.parametrize("version", ["2.6", "v2.6.3", "2.6.3rc1", "02.6.3"])
def test_version_must_be_stable_and_canonical(version: str) -> None:
    with pytest.raises(recovery.RecoveryError, match=r"stable X\.Y\.Z"):
        recovery.expected_release_assets(version)


@pytest.mark.parametrize(
    "raw",
    [b"{} " + b" " * recovery.MAX_RELEASE_JSON_BYTES, b"[]", b"{", b' {"id":1,"id":2}', b'"\xff"'],
    ids=("oversized", "non-object", "truncated", "duplicate-key", "invalid-utf8"),
)
def test_metadata_is_bounded_unambiguous_json(raw: bytes) -> None:
    with pytest.raises(recovery.RecoveryError):
        recovery.parse_release_metadata(raw)


def test_cli_complete_and_partial_have_truthful_status() -> None:
    payload = release_payload()
    for complete in (True, False):
        if not complete:
            payload["assets"] = []
        result = subprocess.run(  # noqa: S603 - fixed repository script
            [sys.executable, str(Path(recovery.__file__)), "--version", VERSION],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == (0 if complete else 1)
        assert ("no assets were changed" in result.stdout) if complete else ("missing asset" in result.stderr)


@pytest.mark.parametrize("release_id", [0, -1, True])
def test_numeric_release_id_must_be_positive_before_transport(release_id: int) -> None:
    def forbidden(_cmd: list[str]) -> subprocess.CompletedProcess[str]:
        raise AssertionError("invalid ID reached transport")

    with pytest.raises(recovery.RecoveryError, match="positive integer"):
        recovery.load_release_metadata(forbidden, VERSION, release_id=release_id)


def test_numeric_release_id_must_match_response() -> None:
    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        assert cmd[-1] == "repos/blisspixel/recon/releases/42"
        return subprocess.CompletedProcess(cmd, 0, json.dumps(release_payload()), "")

    with pytest.raises(recovery.RecoveryError, match="release ID does not match"):
        recovery.load_release_metadata(runner, VERSION, release_id=42)


@pytest.mark.parametrize("scenario", ["binary", "oversized", "timeout", "failure"])
def test_numeric_asset_transport_preserves_raw_bytes_and_stops_at_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
) -> None:
    payload = b"\x00\xff\x1b[31m!"
    killed: list[bool] = []

    class Process:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            assert command == [
                "gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "--allow-escape-sequences",
                "repos/blisspixel/recon/releases/assets/2",
                "--header",
                "Accept: application/octet-stream",
            ]
            assert kwargs == {"stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL}
            self.stdout = io.BytesIO(payload)
            self.code: int | None = None

        def __enter__(self) -> Process:
            return self

        def __exit__(self, *_args: object) -> None:
            self.stdout.close()

        def poll(self) -> int | None:
            return self.code

        def kill(self) -> None:
            killed.append(True)
            self.code = -9
            self.stdout = io.BytesIO()

        def wait(self) -> int:
            self.code = self.code if self.code is not None else (1 if scenario == "failure" else 0)
            return self.code

    monkeypatch.setattr(recovery.subprocess, "Popen", Process)
    if scenario == "oversized":
        monkeypatch.setattr(recovery, "MAX_RELEASE_ASSET_BYTES", len(payload) - 1)
    if scenario == "timeout":

        class ImmediateTimer:
            def __init__(self, interval: float, function: Callable[[], None]) -> None:
                assert interval == 120
                self.function = function
                self.daemon = False

            def start(self) -> None:
                self.function()

            def cancel(self) -> None:
                return None

        monkeypatch.setattr(recovery.threading, "Timer", ImmediateTimer)
    if scenario == "binary":
        result = recovery.download_release_asset("asset.bin", 2, tmp_path)
        assert result.read_bytes() == payload
        assert killed == []
    else:
        with pytest.raises(recovery.RecoveryError):
            recovery.download_release_asset("asset.bin", 2, tmp_path)
        assert (tmp_path / "asset.bin").stat().st_size <= len(payload)
        if scenario in {"timeout", "oversized"}:
            assert killed
