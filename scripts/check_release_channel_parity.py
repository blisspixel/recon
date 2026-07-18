#!/usr/bin/env python3
"""Require PyPI and a sealed release directory to contain identical artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlparse

_PACKAGE = "recon-tool"
_PYPI_RELEASE_URL = f"https://pypi.org/pypi/{_PACKAGE}/{{version}}/json"
_MAX_METADATA_BYTES = 5 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024
_STABLE_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")


class ParityError(RuntimeError):
    """Published and sealed release state cannot be proven identical."""


class _RetryableParityError(ParityError):
    """The exact release may not be visible yet."""


class _Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


class _Response(_Readable, Protocol):
    def __enter__(self) -> _Response: ...

    def __exit__(self, *args: object) -> None: ...


_Opener = Callable[..., _Response]


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 1
    delay_seconds: float = 0


def expected_distribution_names(version: str) -> tuple[str, str]:
    if _STABLE_VERSION.fullmatch(version) is None:
        raise ParityError("version must use stable X.Y.Z syntax")
    return (f"recon_tool-{version}-py3-none-any.whl", f"recon_tool-{version}.tar.gz")


def _read_bounded(response: _Readable, limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(_CHUNK_BYTES, limit + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ParityError(f"{label} exceeds the {limit}-byte safety limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _load_release_payload(version: str, opener: _Opener) -> dict[str, object]:
    try:
        with opener(_PYPI_RELEASE_URL.format(version=version), timeout=30) as response:
            raw = _read_bounded(response, _MAX_METADATA_BYTES, "PyPI release metadata")
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParityError(f"PyPI release metadata is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ParityError("PyPI release metadata must be a JSON object")
    return payload


def _release_record(record: object, expected: set[str]) -> tuple[str, str | None]:
    if not isinstance(record, dict):
        raise ParityError("PyPI release file records must be objects")
    filename = record.get("filename")
    url = record.get("url")
    if not isinstance(filename, str) or not filename:
        raise ParityError("PyPI release file record is missing filename")
    if filename not in expected:
        return filename, None
    if not isinstance(url, str) or not url:
        raise ParityError(f"PyPI release is missing a file URL for {filename}")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
        raise ParityError(f"PyPI returned an unexpected file URL for {filename}")
    return filename, url


def _release_file_urls(version: str, opener: _Opener) -> dict[str, str]:
    payload = _load_release_payload(version, opener)
    info = payload.get("info")
    if not isinstance(info, dict) or info.get("version") != version:
        raise ParityError(f"PyPI release metadata does not describe {_PACKAGE} {version}")
    records = payload.get("urls")
    if not isinstance(records, list):
        raise _RetryableParityError(f"PyPI has no file list for {_PACKAGE} {version}")

    expected = set(expected_distribution_names(version))
    urls: dict[str, str] = {}
    observed: list[str] = []
    for record in records:
        filename, url = _release_record(record, expected)
        observed.append(filename)
        if filename in urls:
            raise ParityError(f"PyPI release repeats distribution filename {filename}")
        if url is not None:
            urls[filename] = url

    unexpected = sorted(set(observed) - expected)
    if unexpected:
        raise ParityError("PyPI release contains unexpected distribution file(s): " + ", ".join(unexpected))
    missing = sorted(expected - urls.keys())
    if missing:
        raise _RetryableParityError("PyPI release is missing distribution file(s): " + ", ".join(missing))
    if len(observed) != len(expected):
        raise ParityError(f"PyPI release must contain exactly {len(expected)} distribution files")
    return urls


def _sha256_stream(stream: _Readable, label: str) -> str:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_ARTIFACT_BYTES:
            raise ParityError(f"{label} exceeds the {_MAX_ARTIFACT_BYTES}-byte safety limit")
        digest.update(chunk)
    if total == 0:
        raise ParityError(f"{label} is empty")
    return digest.hexdigest()


def _local_digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ParityError(f"sealed artifact is missing or not a regular file: {path.name}")
    with path.open("rb") as stream:
        return _sha256_stream(stream, f"sealed artifact {path.name}")


def _remote_digest(url: str, filename: str, opener: _Opener) -> str:
    with opener(url, timeout=30) as response:
        return _sha256_stream(response, f"PyPI artifact {filename}")


def _visible_file_names(directory: Path) -> set[str]:
    try:
        return {path.name for path in directory.iterdir() if not path.name.startswith(".")}
    except OSError as exc:
        raise ParityError(f"cannot inspect sealed artifact directory {directory}: {exc}") from exc


def _write_url_file(path: Path, expected: tuple[str, str], urls: dict[str, str]) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            for filename in expected:
                stream.write(urls[filename] + "\n")
    except FileExistsError as exc:
        raise ParityError(f"URL output already exists and was not replaced: {path}") from exc
    except OSError as exc:
        raise ParityError(f"cannot write validated URL output {path}: {exc}") from exc


def _local_release_digests(version: str, dist_dir: Path) -> tuple[tuple[str, str], dict[str, str]]:
    expected = expected_distribution_names(version)
    visible = _visible_file_names(dist_dir)
    if visible != set(expected):
        missing = sorted(set(expected) - visible)
        unexpected = sorted(visible - set(expected))
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise ParityError("sealed artifact set is not the exact release pair: " + "; ".join(details))
    return expected, {filename: _local_digest(dist_dir / filename) for filename in expected}


def check_channel_parity(
    version: str,
    dist_dir: Path,
    *,
    retry: RetryPolicy | None = None,
    url_file: Path | None = None,
    opener: _Opener | None = None,
) -> dict[str, str]:
    """Return exact shared SHA-256 digests or raise a bounded parity failure."""
    actual_retry = retry or RetryPolicy()
    if actual_retry.attempts < 1:
        raise ParityError("attempts must be at least 1")
    if actual_retry.delay_seconds < 0:
        raise ParityError("delay-seconds must not be negative")
    expected, local_digests = _local_release_digests(version, dist_dir)
    actual_opener = opener or cast(_Opener, urllib.request.urlopen)
    urls: dict[str, str] | None = None
    last_error: Exception | None = None
    for attempt in range(1, actual_retry.attempts + 1):
        try:
            urls = _release_file_urls(version, actual_opener)
            for filename in expected:
                remote = _remote_digest(urls[filename], filename, actual_opener)
                local = local_digests[filename]
                if local != remote:
                    raise ParityError(f"channel digest mismatch for {filename}: sealed={local}, pypi={remote}")
            last_error = None
            break
        except (urllib.error.URLError, TimeoutError, OSError, _RetryableParityError) as exc:
            if isinstance(exc, urllib.error.HTTPError) and not (exc.code in {404, 408, 429} or exc.code >= 500):
                raise ParityError(f"PyPI request failed permanently with HTTP {exc.code}") from exc
            urls = None
            last_error = exc
            if attempt < actual_retry.attempts:
                time.sleep(actual_retry.delay_seconds)
    if urls is None:
        detail = str(last_error) if last_error is not None else "unknown PyPI release failure"
        raise ParityError(
            f"could not prove the exact PyPI release pair after {actual_retry.attempts} attempt(s): {detail}"
        )
    if url_file is not None:
        _write_url_file(url_file, expected, urls)
    return local_digests


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument("--delay-seconds", type=float, default=0)
    parser.add_argument(
        "--url-file",
        type=Path,
        help="create a new newline-delimited file containing the two validated PyPI artifact URLs",
    )
    args = parser.parse_args(argv)
    try:
        digests = check_channel_parity(
            args.version,
            args.dist_dir,
            retry=RetryPolicy(args.attempts, args.delay_seconds),
            url_file=args.url_file,
        )
    except ParityError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    for filename, digest in digests.items():
        print(f"PASS: {filename} is identical on PyPI and in the sealed release pair (sha256={digest}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
