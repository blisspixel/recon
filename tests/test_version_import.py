"""Regression tests for import-time version resolution."""

from __future__ import annotations

from pathlib import Path

import recon_tool


def _path_exists(_path: Path) -> bool:
    return True


def test_source_tree_version_ignores_unreadable_pyproject(monkeypatch) -> None:
    def raise_oserror(_path: Path, encoding: str) -> str:
        raise OSError("denied")

    monkeypatch.setattr(Path, "exists", _path_exists)
    monkeypatch.setattr(Path, "read_text", raise_oserror)

    assert recon_tool._source_tree_version() is None


def test_source_tree_version_ignores_invalid_utf8_pyproject(monkeypatch) -> None:
    def raise_decode_error(_path: Path, encoding: str) -> str:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(Path, "exists", _path_exists)
    monkeypatch.setattr(Path, "read_text", raise_decode_error)

    assert recon_tool._source_tree_version() is None
