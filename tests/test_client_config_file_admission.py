"""Client configuration reads reject special files and preserve dotfile setups."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

import pytest

from recon_tool import json_limits
from recon_tool.mcp_client.config_json import read_json_object


@pytest.mark.parametrize("payload", [b"\xef\xbb\xbf{}", b"{}", b" \t\n"])
def test_regular_config_preserves_bom_empty_and_future_mtime(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "config.json"
    path.write_bytes(payload)
    future = time.time() + 3600
    os.utime(path, (future, future))
    result = read_json_object(path)
    assert result.state == ("empty" if payload.isspace() else "ok")


def test_regular_config_symlink_remains_supported(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(path)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    assert read_json_object(link).state == "ok"
    with pytest.raises(ValueError, match="symbolic link"):
        json_limits.load_bounded_json_file(link, maximum_bytes=1024)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO support")
@pytest.mark.parametrize("symlink", [False, True])
def test_fifo_config_is_rejected_before_open(tmp_path: Path, symlink: bool) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    path = tmp_path / "config.json"
    if symlink:
        path.symlink_to(fifo)
    else:
        path = fifo
    result = read_json_object(path)
    assert result.state == "invalid"
    assert "regular file" in result.detail


def test_descriptor_type_is_checked_and_closed_before_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.json"
    path.write_text("{}", encoding="utf-8")
    original_open, original_close, original_fstat = os.open, os.close, os.fstat
    closed: list[int] = []

    def checked_open(target: Path, flags: int) -> int:
        assert flags & getattr(os, "O_NONBLOCK", 0) == getattr(os, "O_NONBLOCK", 0)
        return original_open(target, flags)

    def special_fstat(fd: int) -> os.stat_result:
        values = list(original_fstat(fd))
        values[0] = stat.S_IFIFO | 0o600
        return os.stat_result(values)

    def checked_close(fd: int) -> None:
        closed.append(fd)
        original_close(fd)

    monkeypatch.setattr(os, "open", checked_open)
    monkeypatch.setattr(os, "fstat", special_fstat)
    monkeypatch.setattr(os, "close", checked_close)
    result = read_json_object(path)
    assert result.state == "invalid"
    assert "regular file" in result.detail
    assert len(closed) == 1
