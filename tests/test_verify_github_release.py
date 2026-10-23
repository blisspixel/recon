# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportPrivateUsage=none, reportUnknownArgumentType=none, reportUnknownVariableType=none
"""Exercise original-run verification without release writes or live transport."""

from __future__ import annotations

import hashlib
import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from scripts import verify_github_release as verify
from scripts.check_release_recovery import RecoveryError, expected_release_assets
from tests.test_release_readiness import _completed_sbom
from tests.test_release_recovery import VERSION, release_payload

SHA = "a" * 40


@pytest.fixture
def sealed(tmp_path: Path) -> tuple[Path, Path, Path]:
    wheel, sdist, sbom, bundle = expected_release_assets(VERSION)
    for directory, names in (("dist", (wheel, sdist)), ("sbom", (sbom,)), ("provenance", (bundle,))):
        target = tmp_path / directory
        target.mkdir()
        for name in names:
            content = _completed_sbom(VERSION) if name == sbom else f"sealed {name}"
            (target / name).write_text(content, encoding="utf-8")
    return tmp_path / "dist", tmp_path / "sbom", tmp_path / "provenance"


class ReleaseTransport:
    def __init__(self, directories: tuple[Path, Path, Path], scenario: str = "complete") -> None:
        self.files = {path.name: path for directory in directories for path in directory.iterdir()}
        self.payload = release_payload()
        assets = self.payload["assets"]
        assert isinstance(assets, list)
        for asset in assets:
            asset["size"] = self.files[asset["name"]].stat().st_size
            asset["digest"] = "sha256:" + hashlib.sha256(self.files[asset["name"]].read_bytes()).hexdigest()
        self.scenario = scenario
        self.commands: list[list[str]] = []
        self.metadata_reads = 0

    def __call__(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(cmd)
        stdout = ""
        code = 0
        if cmd == ["git", "rev-parse", "HEAD"] or cmd[:3] == ["git", "rev-list", "-n"]:
            stdout = SHA
        elif cmd[:2] == ["git", "ls-remote"]:
            stdout = f"{'b' * 40 if self.scenario == 'moved-tag' else SHA}\trefs/tags/v{VERSION}\n"
        elif cmd[:2] == ["gh", "api"]:
            assert cmd[-1] in (f"repos/blisspixel/recon/releases/tags/v{VERSION}", "repos/blisspixel/recon/releases/1")
            self.metadata_reads += 1
            payload = deepcopy(self.payload)
            overrides: dict[str, dict[str, object]] = {
                "partial": {"assets": []},
                "draft": {"draft": True},
                "bot": {"author": {"login": "github-actions[bot]", "type": "Bot"}},
            }
            payload.update(overrides.get(self.scenario, {}))
            if self.scenario == "changed-metadata" and self.metadata_reads > 1:
                payload["id"] = 999
            payload["download_count"] = self.metadata_reads
            stdout = json.dumps(payload)
            code = 1 if self.scenario == "missing" or (self.scenario == "draft" and "/tags/" in cmd[-1]) else 0
        elif cmd[:3] == ["gh", "release", "view"]:
            stdout = json.dumps(self.payload)
        elif cmd[:3] == ["gh", "release", "download"]:
            name = cmd[cmd.index("--pattern") + 1]
            content = self.files[name].read_bytes()
            if self.scenario == "mismatch" or self.scenario == f"mismatch:{name}":
                content = bytes([content[0] ^ 1]) + content[1:]
            (Path(cmd[cmd.index("--dir") + 1]) / name).write_bytes(content)
        elif cmd[:3] == ["gh", "attestation", "verify"]:
            assert cmd[cmd.index("--source-digest") + 1] == SHA
            assert cmd[cmd.index("--source-ref") + 1] == f"refs/tags/v{VERSION}"
            assert cmd[cmd.index("--signer-workflow") + 1] == "blisspixel/recon/.github/workflows/release.yml"
            assert "--deny-self-hosted-runners" in cmd
            code = 1 if self.scenario == "provenance" else 0
        else:
            raise AssertionError(f"unexpected or mutating command: {cmd}")
        return subprocess.CompletedProcess(cmd, code, stdout, "unavailable" if code else "")


def _parity_probe(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Path]]:
    calls: list[tuple[str, Path]] = []

    def parity(version: str, dist_dir: Path, **kwargs: object) -> dict[str, str]:
        calls.append((version, dist_dir))
        assert kwargs["retry"] == verify.RetryPolicy(attempts=1, delay_seconds=0)
        return {}

    monkeypatch.setattr(verify, "check_channel_parity", parity)
    return calls


def test_complete_release_rerun_verifies_all_four_bytes_and_three_subjects(
    sealed: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = ReleaseTransport(sealed)
    transport.payload["immutable"] = True
    parity = _parity_probe(monkeypatch)
    before = {name: path.read_bytes() for name, path in transport.files.items()}
    digests = verify.verify_release(VERSION, SHA, verify.ArtifactDirectories(*sealed), runner=transport)
    assert digests == {name: hashlib.sha256(content).hexdigest() for name, content in before.items()}
    assert parity == [(VERSION, sealed[0])]
    assert sum(cmd[:3] == ["gh", "attestation", "verify"] for cmd in transport.commands) == 3
    assert sum(cmd[:3] == ["gh", "release", "download"] for cmd in transport.commands) == 4
    assert transport.metadata_reads == 2
    assert before == {name: path.read_bytes() for name, path in transport.files.items()}


@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("missing", "no readable release"),
        ("partial", "missing asset"),
        ("draft", "no readable release"),
        ("bot", "human blisspixel"),
        ("moved-tag", "remote release tag"),
        ("mismatch", "differs from"),
        ("changed-metadata", "changed during"),
        ("provenance", "provenance verification"),
    ],
)
def test_failed_recovery_never_mutates_or_calls_pypi(
    sealed: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    message: str,
) -> None:
    transport = ReleaseTransport(sealed, scenario)
    parity = _parity_probe(monkeypatch)
    with pytest.raises(RecoveryError, match=message):
        verify.verify_release(VERSION, SHA, verify.ArtifactDirectories(*sealed), runner=transport)
    assert parity == []
    assert not any(
        cmd[:3] in (["gh", "release", "create"], ["gh", "release", "upload"], ["gh", "release", "edit"])
        for cmd in transport.commands
    )


@pytest.mark.parametrize("name", expected_release_assets(VERSION))
def test_every_asset_including_provenance_must_match_original_bytes(
    sealed: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    parity = _parity_probe(monkeypatch)
    transport = ReleaseTransport(sealed, f"mismatch:{name}")
    with pytest.raises(RecoveryError, match="differs from"):
        verify.verify_release(VERSION, SHA, verify.ArtifactDirectories(*sealed), runner=transport)
    assert parity == []


def test_metadata_hash_and_size_must_match_actual_sealed_bytes(
    sealed: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _parity_probe(monkeypatch)
    for field, value, message in (("digest", "sha256:" + "0" * 64, "digest differs"), ("size", 1, "size differs")):
        transport = ReleaseTransport(sealed)
        assets = transport.payload["assets"]
        assert isinstance(assets, list)
        assets[0][field] = value
        with pytest.raises(RecoveryError, match=message):
            verify.verify_release(VERSION, SHA, verify.ArtifactDirectories(*sealed), runner=transport)


def test_draft_uses_numeric_id_even_when_by_tag_is_404(
    sealed: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = ReleaseTransport(sealed, "draft")
    _parity_probe(monkeypatch)
    with pytest.raises(RecoveryError, match="no readable release"):
        verify.verify_release(VERSION, SHA, verify.ArtifactDirectories(*sealed), runner=transport)
    downloads: list[int] = []

    def download(name: str, asset_id: int, directory: Path) -> Path:
        assets = transport.payload["assets"]
        assert isinstance(assets, list)
        assert any(record["id"] == asset_id and record["name"] == name for record in assets)
        downloads.append(asset_id)
        target = directory / name
        target.write_bytes(transport.files[name].read_bytes())
        return target

    monkeypatch.setattr(verify.release_readiness, "download_release_asset", download)
    assert (
        len(
            verify.verify_release(
                VERSION, SHA, verify.ArtifactDirectories(*sealed), runner=transport, draft_release_id=1
            )
        )
        == 4
    )
    assert downloads == [2, 3, 4, 5]
    assert not any(cmd[:3] == ["gh", "release", "download"] for cmd in transport.commands)
    with pytest.raises(RecoveryError, match="must be a draft"):
        verify.verify_release(
            VERSION, SHA, verify.ArtifactDirectories(*sealed), runner=ReleaseTransport(sealed), draft_release_id=1
        )


def test_pypi_mismatch_cannot_complete_the_final_job(
    sealed: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mismatch(*_args: object, **_kwargs: object) -> dict[str, str]:
        raise verify.ParityError("channel digest mismatch")

    monkeypatch.setattr(verify, "check_channel_parity", mismatch)
    with pytest.raises(verify.ParityError, match="channel digest mismatch"):
        verify.verify_release(VERSION, SHA, verify.ArtifactDirectories(*sealed), runner=ReleaseTransport(sealed))


@pytest.mark.parametrize("problem", ["extra", "symlink", "invalid-sbom", "empty"])
def test_sealed_artifact_refusal_precedes_remote_reads(
    sealed: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    problem: str,
) -> None:
    transport = ReleaseTransport(sealed)
    parity = _parity_probe(monkeypatch)
    wheel, _, sbom, _ = expected_release_assets(VERSION)
    if problem == "extra":
        (sealed[0] / "extra.txt").write_text("unexpected")
    elif problem == "symlink":
        source = sealed[0] / wheel
        source.rename(sealed[0] / "target")
        source.symlink_to("target")
        (sealed[0] / "target").rename(sealed[0].parent / "target")
    elif problem == "invalid-sbom":
        (sealed[1] / sbom).write_text("{}")
    else:
        (sealed[0] / wheel).write_bytes(b"")
    with pytest.raises((RecoveryError, verify.ParityError, verify.SbomError)):
        verify.verify_release(VERSION, SHA, verify.ArtifactDirectories(*sealed), runner=transport)
    assert parity == []
    assert transport.metadata_reads == 0


def test_cli_missing_release_returns_actionable_nonzero_handoff(
    sealed: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    transport = ReleaseTransport(sealed, "missing")

    def make_runner(_root: Path) -> ReleaseTransport:
        return transport

    monkeypatch.setattr(verify.release_readiness, "_make_runner", make_runner)
    code = verify.main(
        [
            "--version",
            VERSION,
            "--source-sha",
            SHA,
            "--dist-dir",
            str(sealed[0]),
            "--sbom-dir",
            str(sealed[1]),
            "--provenance-dir",
            str(sealed[2]),
        ]
    )
    output = capsys.readouterr()
    assert code == 1
    assert "Human handoff" in output.err
    assert "original failed github-release job" in output.err
    assert "No release or asset was changed" in output.err
