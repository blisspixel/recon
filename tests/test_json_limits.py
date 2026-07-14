"""Tests for descriptor-bound JSON file admission."""

from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from recon_tool.json_limits import load_bounded_json_file


def test_load_bounded_json_file_returns_data_metadata_and_age(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text('{"ok": true}', encoding="utf-8")

    data, file_stat, age_seconds = load_bounded_json_file(path, maximum_bytes=1024)

    assert data == {"ok": True}
    assert file_stat.st_size == len(b'{"ok": true}')
    assert age_seconds >= 0.0


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"maximum_bytes": 0}, "maximum_bytes"),
        ({"maximum_bytes": 1, "maximum_age_seconds": -1.0}, "maximum_age_seconds"),
        ({"maximum_bytes": 1, "maximum_age_seconds": float("inf")}, "maximum_age_seconds"),
        ({"maximum_bytes": 1, "future_mtime_tolerance_seconds": -1.0}, "future_mtime"),
        ({"maximum_bytes": 1, "future_mtime_tolerance_seconds": float("nan")}, "future_mtime"),
    ],
)
def test_load_bounded_json_file_rejects_invalid_limits(
    tmp_path: Path, kwargs: dict[str, float | int], message: str
) -> None:
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_bounded_json_file(path, **kwargs)


def test_load_bounded_json_file_clamps_small_future_clock_skew(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    future = time.time() + 60.0
    os.utime(path, (future, future))

    _data, _file_stat, age_seconds = load_bounded_json_file(path, maximum_bytes=1024)

    assert age_seconds == 0.0


def test_load_bounded_json_file_rejects_material_future_mtime(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    future = time.time() + 3600.0
    os.utime(path, (future, future))

    with pytest.raises(ValueError, match="future modification time"):
        load_bounded_json_file(path, maximum_bytes=1024)


def test_load_bounded_json_file_rejects_expired_file(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    old = time.time() - 10.0
    os.utime(path, (old, old))

    with pytest.raises(ValueError, match="maximum age"):
        load_bounded_json_file(path, maximum_bytes=1024, maximum_age_seconds=1.0)


def test_load_bounded_json_file_rejects_stable_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "state.json"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symbolic link"):
        load_bounded_json_file(link, maximum_bytes=1024)


def test_load_bounded_json_file_rejects_change_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    original_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        observed = original_fstat(descriptor)
        if calls == 2:
            return SimpleNamespace(
                st_size=observed.st_size,
                st_mtime=observed.st_mtime,
                st_mtime_ns=observed.st_mtime_ns + 1,
                st_ctime_ns=observed.st_ctime_ns,
                st_mode=observed.st_mode,
                st_dev=observed.st_dev,
                st_ino=observed.st_ino,
            )
        return observed

    monkeypatch.setattr("recon_tool.json_limits.os.fstat", changing_fstat)

    with pytest.raises(ValueError, match="changed while"):
        load_bounded_json_file(path, maximum_bytes=1024)


def test_load_bounded_json_file_rejects_excessive_nesting(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(("[" * 101) + "0" + ("]" * 101), encoding="utf-8")

    with pytest.raises(ValueError, match="nesting"):
        load_bounded_json_file(path, maximum_bytes=1024)
