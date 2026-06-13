"""Config / cache / state directory resolution (recon_tool.paths).

Three precedence tiers, all pinned here: RECON_CONFIG_DIR override (single dir,
the test/CI seam), an existing ~/.recon legacy install (back-compat — data does
not move), and XDG base dirs for fresh installs. The XDG spec's
relative-path-is-invalid rule is also pinned.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from recon_tool.paths import cache_root, config_dir, state_dir


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    for var in ("RECON_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


class TestOverride:
    def test_recon_config_dir_wins_for_all_three(self, home: Path, monkeypatch, tmp_path) -> None:
        override = tmp_path / "override"
        monkeypatch.setenv("RECON_CONFIG_DIR", str(override))
        assert config_dir() == override
        assert cache_root() == override
        assert state_dir() == override

    def test_override_beats_existing_legacy_and_xdg(self, home: Path, monkeypatch, tmp_path) -> None:
        (home / ".recon").mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdgcfg"))
        override = tmp_path / "override"
        monkeypatch.setenv("RECON_CONFIG_DIR", str(override))
        assert config_dir() == override


class TestLegacy:
    def test_existing_recon_dir_used_for_all(self, home: Path) -> None:
        (home / ".recon").mkdir()
        assert config_dir() == home / ".recon"
        assert cache_root() == home / ".recon"
        assert state_dir() == home / ".recon"

    def test_legacy_beats_xdg(self, home: Path, monkeypatch, tmp_path) -> None:
        (home / ".recon").mkdir()
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdgcache"))
        assert cache_root() == home / ".recon"


class TestXdg:
    def test_defaults_when_no_legacy_and_no_xdg_env(self, home: Path) -> None:
        assert config_dir() == home / ".config" / "recon"
        assert cache_root() == home / ".cache" / "recon"
        assert state_dir() == home / ".local" / "state" / "recon"

    def test_honors_xdg_env_when_absolute(self, home: Path, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "c"))
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "k"))
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "s"))
        assert config_dir() == tmp_path / "c" / "recon"
        assert cache_root() == tmp_path / "k" / "recon"
        assert state_dir() == tmp_path / "s" / "recon"

    def test_relative_xdg_value_is_ignored_per_spec(self, home: Path, monkeypatch) -> None:
        # XDG spec: a relative path is invalid and must be ignored (use default).
        monkeypatch.setenv("XDG_CONFIG_HOME", "relative/path")
        assert config_dir() == home / ".config" / "recon"
