"""Fail-closed checks for PyPI and sealed release artifact parity."""

from __future__ import annotations

import hashlib
import io
import json
import urllib.error
from pathlib import Path

import pytest

from scripts import check_release_channel_parity as parity


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _names(version: str = "2.6.3") -> tuple[str, str]:
    return parity.expected_distribution_names(version)


def _payload(version: str, records: list[dict[str, object]]) -> bytes:
    return json.dumps({"info": {"version": version}, "urls": records}).encode()


def _record(filename: str) -> dict[str, str]:
    return {"filename": filename, "url": f"https://files.pythonhosted.org/{filename}"}


def _write_pair(directory: Path, wheel: bytes = b"wheel", sdist: bytes = b"sdist") -> dict[str, bytes]:
    directory.mkdir()
    names = _names()
    contents = {names[0]: wheel, names[1]: sdist}
    for filename, content in contents.items():
        (directory / filename).write_bytes(content)
    return contents


def _fail_on_retry(_delay: float) -> None:
    pytest.fail("unexpected retry")


def _opener_for(version: str, contents: dict[str, bytes], records: list[dict[str, object]] | None = None):
    release_records = records if records is not None else [_record(name) for name in _names(version)]

    def _open(url: str, **_kwargs: object) -> _Response:
        if url == parity._PYPI_RELEASE_URL.format(version=version):
            return _Response(_payload(version, release_records))
        filename = url.rsplit("/", 1)[-1]
        return _Response(contents[filename])

    return _open


def test_exact_pair_returns_shared_digests(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)

    digests = parity.check_channel_parity("2.6.3", dist, opener=_opener_for("2.6.3", contents))

    assert digests == {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()}


def test_metadata_request_is_scoped_to_the_exact_version(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    opened: list[str] = []
    good = _opener_for("2.6.3", contents)

    def _open(url: str, **kwargs: object) -> _Response:
        opened.append(url)
        return good(url, **kwargs)

    parity.check_channel_parity("2.6.3", dist, opener=_open)

    assert opened[0] == "https://pypi.org/pypi/recon-tool/2.6.3/json"


@pytest.mark.parametrize("extra", ["unexpected.whl", "notes.txt"])
def test_sealed_pair_rejects_unexpected_visible_files(tmp_path: Path, extra: str) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    (dist / extra).write_text("unexpected", encoding="utf-8")

    with pytest.raises(parity.ParityError, match="unexpected"):
        parity.check_channel_parity("2.6.3", dist, opener=_opener_for("2.6.3", contents))


def test_sealed_pair_ignores_uv_output_gitignore(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    (dist / ".gitignore").write_text("*", encoding="utf-8")

    parity.check_channel_parity("2.6.3", dist, opener=_opener_for("2.6.3", contents))


def test_sealed_pair_rejects_unexpected_directory(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    (dist / "nested").mkdir()

    with pytest.raises(parity.ParityError, match="unexpected"):
        parity.check_channel_parity("2.6.3", dist, opener=_opener_for("2.6.3", contents))


def test_validated_urls_are_created_only_after_parity_passes(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    output = tmp_path / "urls.txt"

    parity.check_channel_parity(
        "2.6.3",
        dist,
        url_file=output,
        opener=_opener_for("2.6.3", contents),
    )

    assert output.read_text(encoding="utf-8").splitlines() == [
        f"https://files.pythonhosted.org/{name}" for name in _names()
    ]


def test_url_output_is_not_replaced(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    output = tmp_path / "urls.txt"
    output.write_text("keep\n", encoding="utf-8")

    with pytest.raises(parity.ParityError, match="not replaced"):
        parity.check_channel_parity(
            "2.6.3",
            dist,
            url_file=output,
            opener=_opener_for("2.6.3", contents),
        )

    assert output.read_text(encoding="utf-8") == "keep\n"


@pytest.mark.parametrize(
    ("records", "message"),
    [
        ([], "missing distribution"),
        ([_record(_names()[0]), _record(_names()[0]), _record(_names()[1])], "repeats distribution"),
        ([_record(_names()[0]), _record(_names()[1]), _record("other.whl")], "unexpected distribution"),
        ([_record(_names()[0]), {"filename": _names()[1]}], "missing a file URL"),
        (
            [
                _record(_names()[0]),
                {"filename": _names()[1], "url": f"http://files.pythonhosted.org/{_names()[1]}"},
            ],
            "unexpected file URL",
        ),
    ],
)
def test_pypi_metadata_requires_exact_safe_pair(tmp_path: Path, records: list[dict[str, object]], message: str) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)

    with pytest.raises(parity.ParityError, match=message):
        parity.check_channel_parity("2.6.3", dist, opener=_opener_for("2.6.3", contents, records))


def test_digest_mismatch_names_both_hashes(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    remote = dict(contents)
    remote[_names()[0]] = b"different wheel"

    with pytest.raises(parity.ParityError, match=r"channel digest mismatch.*sealed=.*pypi="):
        parity.check_channel_parity("2.6.3", dist, opener=_opener_for("2.6.3", remote))


@pytest.mark.parametrize("remote", [False, True])
def test_artifact_size_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, remote: bool) -> None:
    monkeypatch.setattr(parity, "_MAX_ARTIFACT_BYTES", 4)
    dist = tmp_path / "dist"
    contents = _write_pair(dist, wheel=b"1234", sdist=b"1234")
    if remote:
        contents[_names()[0]] = b"12345"
    else:
        (dist / _names()[0]).write_bytes(b"12345")

    with pytest.raises(parity.ParityError, match="safety limit"):
        parity.check_channel_parity("2.6.3", dist, opener=_opener_for("2.6.3", contents))


def test_metadata_resolution_retries_then_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    good = _opener_for("2.6.3", contents)
    metadata_calls = 0
    sleeps: list[float] = []
    monkeypatch.setattr(parity.time, "sleep", sleeps.append)

    def _open(url: str, **kwargs: object) -> _Response:
        nonlocal metadata_calls
        if url == parity._PYPI_RELEASE_URL.format(version="2.6.3"):
            metadata_calls += 1
            if metadata_calls == 1:
                return _Response(_payload("2.6.3", []))
        return good(url, **kwargs)

    parity.check_channel_parity(
        "2.6.3",
        dist,
        retry=parity.RetryPolicy(2, 0.25),
        opener=_open,
    )

    assert metadata_calls == 2
    assert sleeps == [0.25]


def test_artifact_download_retries_then_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    good = _opener_for("2.6.3", contents)
    wheel_url = f"https://files.pythonhosted.org/{_names()[0]}"
    wheel_calls = 0
    sleeps: list[float] = []
    monkeypatch.setattr(parity.time, "sleep", sleeps.append)

    def _open(url: str, **kwargs: object) -> _Response:
        nonlocal wheel_calls
        if url == wheel_url:
            wheel_calls += 1
            if wheel_calls == 1:
                raise TimeoutError("CDN propagation")
        return good(url, **kwargs)

    parity.check_channel_parity(
        "2.6.3",
        dist,
        retry=parity.RetryPolicy(2, 0.25),
        opener=_open,
    )

    assert wheel_calls == 2
    assert sleeps == [0.25]


def test_malformed_metadata_fails_without_retrying_a_permanent_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dist = tmp_path / "dist"
    _write_pair(dist)
    calls = 0

    def _open(_url: str, **_kwargs: object) -> _Response:
        nonlocal calls
        calls += 1
        return _Response(b"not json")

    def _ignore_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(parity.time, "sleep", _ignore_sleep)

    with pytest.raises(parity.ParityError, match="not valid JSON"):
        parity.check_channel_parity("2.6.3", dist, retry=parity.RetryPolicy(2), opener=_open)

    assert calls == 1


def test_digest_mismatch_is_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dist = tmp_path / "dist"
    contents = _write_pair(dist)
    remote = dict(contents)
    remote[_names()[0]] = b"different wheel"
    good = _opener_for("2.6.3", remote)
    calls = 0
    monkeypatch.setattr(parity.time, "sleep", _fail_on_retry)

    def _open(url: str, **kwargs: object) -> _Response:
        nonlocal calls
        calls += 1
        return good(url, **kwargs)

    with pytest.raises(parity.ParityError, match="channel digest mismatch"):
        parity.check_channel_parity("2.6.3", dist, retry=parity.RetryPolicy(3, 0.25), opener=_open)

    assert calls == 2


def test_permanent_http_failure_is_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dist = tmp_path / "dist"
    _write_pair(dist)
    calls = 0
    monkeypatch.setattr(parity.time, "sleep", _fail_on_retry)

    def _open(url: str, **_kwargs: object) -> _Response:
        nonlocal calls
        calls += 1
        raise urllib.error.HTTPError(url, 403, "forbidden", hdrs=None, fp=None)

    with pytest.raises(parity.ParityError, match="permanently with HTTP 403"):
        parity.check_channel_parity("2.6.3", dist, retry=parity.RetryPolicy(3, 0.25), opener=_open)

    assert calls == 1
