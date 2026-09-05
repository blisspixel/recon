"""Tests for descriptor-bound JSON file admission."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from recon_tool import json_limits
from recon_tool.json_limits import load_bounded_json_file


def test_load_bounded_json_file_returns_data_metadata_and_age(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text('{"ok": true}', encoding="utf-8")

    data, file_stat, age_seconds = load_bounded_json_file(path, maximum_bytes=1024)

    assert data == {"ok": True}
    assert file_stat.st_size == len(b'{"ok": true}')
    assert age_seconds >= 0.0


def test_default_decoder_is_resolved_at_call_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "state.json"
    path.write_text('{"ok": true}', encoding="utf-8")
    decoder = Mock(return_value={"decoded": "at call time"})
    monkeypatch.setattr(json_limits.json, "loads", decoder)

    data, _file_stat, _age_seconds = load_bounded_json_file(path, maximum_bytes=1024)

    assert data == {"decoded": "at call time"}
    decoder.assert_called_once_with('{"ok": true}')


def test_custom_decoder_receives_checked_text_and_preserves_metadata(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    raw = b'\xef\xbb\xbf{"key": 1, "key": 2}'
    path.write_bytes(raw)
    decoded = object()
    decoder = Mock(return_value=decoded)

    data, file_stat, age_seconds = load_bounded_json_file(path, maximum_bytes=1024, decoder=decoder)

    assert data is decoded
    assert file_stat.st_size == len(raw)
    assert age_seconds >= 0.0
    decoder.assert_called_once_with(raw.decode("utf-8"))


def test_custom_decoder_exception_propagates_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    failure = RuntimeError("custom admission failed")

    with pytest.raises(RuntimeError, match="custom admission failed") as caught:
        load_bounded_json_file(path, maximum_bytes=1024, decoder=Mock(side_effect=failure))

    assert caught.value is failure


@pytest.mark.parametrize(
    ("contents", "maximum_bytes", "age", "message"),
    [
        (b"{}", 1, 10.0, "byte limit"),
        (b"\xff", 1024, 10.0, "decode"),
        ((b"[" * 101) + b"0" + (b"]" * 101), 1024, 10.0, "nesting"),
        (b"{}", 1024, 0.0, "maximum age"),
    ],
)
def test_file_and_structure_checks_precede_custom_decoder(
    contents: bytes, maximum_bytes: int, age: float, message: str, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    path.write_bytes(contents)
    old = time.time() - 1.0
    os.utime(path, (old, old))
    decoder = Mock(side_effect=AssertionError("unadmitted text reached custom decoder"))

    with pytest.raises(ValueError, match=message):
        load_bounded_json_file(path, maximum_bytes=maximum_bytes, maximum_age_seconds=age, decoder=decoder)

    decoder.assert_not_called()


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


def test_load_bounded_json_file_rejects_change_during_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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


@pytest.mark.parametrize("custom_decoder", [False, True])
def test_non_regular_path_is_rejected_before_open(
    custom_decoder: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")

    def fifo_stat(_path: Path) -> SimpleNamespace:
        return SimpleNamespace(st_mode=stat.S_IFIFO)

    def unexpected_open(*_args: object, **_kwargs: object) -> int:
        pytest.fail("non-regular file reached a potentially blocking open")

    monkeypatch.setattr(Path, "lstat", fifo_stat)
    monkeypatch.setattr("recon_tool.json_limits.os.open", unexpected_open)
    decoder = Mock(side_effect=AssertionError("non-regular file reached decoder"))
    if not custom_decoder:
        monkeypatch.setattr(json_limits.json, "loads", decoder)
    with pytest.raises(ValueError, match="regular file"):
        load_bounded_json_file(path, maximum_bytes=1024, decoder=decoder if custom_decoder else None)
    decoder.assert_not_called()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO admission")
def test_regular_file_swapped_to_fifo_does_not_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    original_open = os.open

    def swapped_open(target: Path, flags: int) -> int:
        assert flags & os.O_NONBLOCK
        target.unlink()
        os.mkfifo(target)
        return original_open(target, flags)

    monkeypatch.setattr("recon_tool.json_limits.os.open", swapped_open)
    with pytest.raises(ValueError, match="regular file"):
        load_bounded_json_file(path, maximum_bytes=1024)
