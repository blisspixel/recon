"""Tests for `recon update` (recon_tool.updater + the CLI command).

The version math, install-method detection, and upgrade-command mapping are
pure and pinned here; the CLI command is driven through CliRunner with the
PyPI lookup monkeypatched so no network is touched.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from recon_tool import updater
from recon_tool.cli import app

runner = CliRunner()


class TestCompareVersions:
    def test_equal(self) -> None:
        assert updater.compare_versions("2.1.18", "2.1.18") == 0

    def test_current_older(self) -> None:
        assert updater.compare_versions("2.1.18", "2.2.0") == -1
        assert updater.compare_versions("2.1.9", "2.1.18") == -1  # numeric, not lexical

    def test_current_newer(self) -> None:
        assert updater.compare_versions("2.3.0", "2.2.9") == 1

    def test_prerelease_suffix_tolerated(self) -> None:
        # Non-numeric trailers are truncated per component; no crash.
        assert updater.compare_versions("2.2.0", "2.2.0rc1") == 0


class TestUpgradeCommand:
    def test_pipx_uv_pip_argvs(self) -> None:
        assert updater.upgrade_command(updater.PIPX) == ["pipx", "upgrade", "recon-tool"]
        assert updater.upgrade_command(updater.UV) == ["uv", "tool", "upgrade", "recon-tool"]
        pip = updater.upgrade_command(updater.PIP)
        assert pip is not None
        assert pip[-3:] == ["install", "-U", "recon-tool"]

    def test_manual_methods_have_no_auto_command(self) -> None:
        assert updater.upgrade_command(updater.HOMEBREW) is None
        assert updater.upgrade_command(updater.EDITABLE) is None

    def test_manual_hints(self) -> None:
        assert "Homebrew install is retired" in updater.manual_hint(updater.HOMEBREW)
        assert "git" in updater.manual_hint(updater.EDITABLE)
        assert updater.manual_hint(updater.PIP) == "pip install -U recon-tool"


class TestDetectInstallMethod:
    def test_pipx_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater, "_is_editable", lambda: False)
        monkeypatch.setattr("sys.prefix", "/home/u/.local/pipx/venvs/recon-tool")
        assert updater.detect_install_method() == updater.PIPX

    def test_uv_tools_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater, "_is_editable", lambda: False)
        monkeypatch.setattr("sys.prefix", "/home/u/.local/share/uv/tools/recon-tool")
        assert updater.detect_install_method() == updater.UV

    def test_homebrew_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater, "_is_editable", lambda: False)
        monkeypatch.setattr("sys.prefix", "/opt/homebrew/Cellar/recon/2.1.18/libexec")
        assert updater.detect_install_method() == updater.HOMEBREW

    def test_pip_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater, "_is_editable", lambda: False)
        monkeypatch.setattr("sys.prefix", "/home/u/project/.venv")
        assert updater.detect_install_method() == updater.PIP

    def test_editable_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater, "_is_editable", lambda: True)
        assert updater.detect_install_method() == updater.EDITABLE


class TestFetchLatestVersion:
    def test_failure_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*a: object, **k: object) -> object:
            raise TimeoutError

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        assert updater.fetch_latest_version(timeout=0.1) is None


class TestUpdateCommand:
    def test_up_to_date(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater, "fetch_latest_version", updater.current_version)
        result = runner.invoke(app, ["update", "--check"])
        assert result.exit_code == 0
        assert "up to date" in result.output

    def test_check_reports_available_without_installing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater, "fetch_latest_version", lambda: "999.0.0")
        monkeypatch.setattr(updater, "detect_install_method", lambda: updater.PIPX)
        result = runner.invoke(app, ["update", "--check"])
        assert result.exit_code == 0
        assert "999.0.0" in result.output
        assert "pipx upgrade recon-tool" in result.output
        assert "or just: recon update" in result.output

    def test_check_manual_method_does_not_claim_self_upgrade(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater, "fetch_latest_version", lambda: "999.0.0")
        monkeypatch.setattr(updater, "detect_install_method", lambda: updater.HOMEBREW)
        result = runner.invoke(app, ["update", "--check"])
        assert result.exit_code == 0
        assert "Homebrew install is retired" in result.output
        assert "or just: recon update" not in result.output

    def test_network_failure_is_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater, "fetch_latest_version", lambda: None)
        result = runner.invoke(app, ["update", "--check"])
        assert result.exit_code == 1
