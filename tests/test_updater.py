"""Tests for `recon update` (recon_tool.updater + the CLI command).

The version math, install-method detection, and upgrade-command mapping are
pure and pinned here; the CLI command is driven through CliRunner with the
PyPI lookup monkeypatched so no network is touched.
"""

from __future__ import annotations

import http.client
import io
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from recon_tool import updater
from recon_tool.cli import app

runner = CliRunner()


def _resolvable_launcher(name: str) -> str:
    """A launcher that resolves outside the working directory."""
    return f"/opt/tools/{name}"


def _missing_launcher(name: str) -> str | None:
    """No launcher on PATH at all."""
    return None


class TestCompareVersions:
    def test_equal(self) -> None:
        assert updater.compare_versions("2.1.18", "2.1.18") == 0

    def test_current_older(self) -> None:
        assert updater.compare_versions("2.1.18", "2.2.0") == -1
        assert updater.compare_versions("2.1.9", "2.1.18") == -1  # numeric, not lexical

    def test_current_newer(self) -> None:
        assert updater.compare_versions("2.3.0", "2.2.9") == 1

    def test_prerelease_precedes_final_release(self) -> None:
        assert updater.compare_versions("2.2.0rc1", "2.2.0") == -1
        assert updater.compare_versions("2.2.0", "2.2.0rc1") == 1
        assert updater.compare_versions("2.2.0b2", "2.2.0rc1") == -1

    def test_release_tuple_ignores_insignificant_trailing_zeroes(self) -> None:
        assert updater.compare_versions("2.2", "2.2.0") == 0

    @pytest.mark.parametrize("current", ["2.5.10.dev1", "2.5.10+local"])
    def test_newer_local_release_does_not_offer_downgrade(self, current: str) -> None:
        assert updater.compare_versions(current, "2.5.9") == 1

    def test_same_release_development_build_precedes_final(self) -> None:
        assert updater.compare_versions("2.5.10.dev1", "2.5.10") == -1
        assert updater.compare_versions("2.5.10", "2.5.10.dev1") == 1

    def test_local_build_follows_same_public_release(self) -> None:
        assert updater.compare_versions("2.5.10+local", "2.5.10") == 1

    def test_distinct_local_build_labels_have_deterministic_order(self) -> None:
        assert updater.compare_versions("2.5.10+abc", "2.5.10+xyz") == -1
        assert updater.compare_versions("2.5.10+xyz", "2.5.10+abc") == 1
        assert updater.compare_versions("2.5.10+1", "2.5.10+abc") == 1

    def test_equivalent_local_build_labels_compare_equal(self) -> None:
        assert updater.compare_versions("2.5.10+ABC.01", "2.5.10+abc-1") == 0


class TestUpgradeCommand:
    def test_pipx_uv_pip_argvs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater.shutil, "which", _resolvable_launcher)

        pipx = updater.upgrade_command(updater.PIPX)
        uv = updater.upgrade_command(updater.UV)
        assert pipx is not None
        assert uv is not None
        assert pipx[1:] == ["upgrade", "recon-tool"]
        assert uv[1:] == ["tool", "upgrade", "recon-tool"]
        assert Path(pipx[0]).name.startswith("pipx")
        assert Path(uv[0]).name.startswith("uv")
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
        assert updater.manual_hint(updater.PIPX) == "pipx upgrade recon-tool"
        assert updater.manual_hint(updater.UV) == "uv tool upgrade recon-tool"

    def test_launcher_planted_in_the_working_directory_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A launcher found in the current directory must never be executed.

        Windows resolves a bare program name against the current directory
        before PATH, and shutil.which searches it first, so `recon update` run
        from an attacker-writable directory would have spawned a planted uv.exe
        or pipx.exe as the operator. Refusing degrades to the manual hint.
        """
        planted = tmp_path / ("uv.exe" if sys.platform == "win32" else "uv")
        planted.write_text("", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        def _planted(name: str) -> str:
            return str(tmp_path / name)

        monkeypatch.setattr(updater.shutil, "which", _planted)

        assert updater.upgrade_command(updater.UV) is None
        assert updater.upgrade_command(updater.PIPX) is None

    def test_missing_launcher_falls_back_to_the_manual_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(updater.shutil, "which", _missing_launcher)

        assert updater.upgrade_command(updater.UV) is None
        assert updater.upgrade_command(updater.PIPX) is None


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

    def test_truncated_response_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class TruncatedResponse:
            def __enter__(self) -> TruncatedResponse:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, _size: int = -1, /) -> bytes:
                raise http.client.IncompleteRead(b"{}", 10)

        def _response(*args: object, **kwargs: object) -> TruncatedResponse:
            return TruncatedResponse()

        monkeypatch.setattr("urllib.request.urlopen", _response)

        assert updater.fetch_latest_version(timeout=0.1) is None

    @pytest.mark.parametrize(
        "body",
        [
            b"[]",
            b"{}",
            b'{"info": null}',
            b'{"info": {"version": null}}',
            b'{"info": {"version": []}}',
            b'{"info": {"version": "  "}}',
            b'{"info": {"version": "not-a-version"}}',
            b"\xff",
        ],
    )
    def test_malformed_response_shape_returns_none(self, monkeypatch: pytest.MonkeyPatch, body: bytes) -> None:
        def _response(*args: object, **kwargs: object) -> io.BytesIO:
            return io.BytesIO(body)

        monkeypatch.setattr("urllib.request.urlopen", _response)

        assert updater.fetch_latest_version(timeout=0.1) is None

    def test_valid_response_returns_trimmed_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = io.BytesIO(b'{"info": {"version": " 2.5.8 "}}')

        def _response(*args: object, **kwargs: object) -> io.BytesIO:
            return body

        monkeypatch.setattr("urllib.request.urlopen", _response)

        assert updater.fetch_latest_version(timeout=0.1) == "2.5.8"

    def test_oversized_response_is_rejected_after_bounded_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class RecordingResponse(io.BytesIO):
            requested_sizes: list[int | None]

            def __init__(self) -> None:
                super().__init__(b"x" * (updater._MAX_PYPI_RESPONSE_BYTES + 1))
                self.requested_sizes = []

            def read(self, size: int | None = -1, /) -> bytes:
                self.requested_sizes.append(size)
                return super().read(size)

        body = RecordingResponse()

        def _response(*args: object, **kwargs: object) -> RecordingResponse:
            return body

        monkeypatch.setattr("urllib.request.urlopen", _response)

        assert updater.fetch_latest_version(timeout=0.1) is None
        assert body.requested_sizes == [updater._MAX_PYPI_RESPONSE_BYTES + 1]

    def test_excessively_nested_response_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = io.BytesIO((b"[" * 101) + b"0" + (b"]" * 101))

        def _response(*args: object, **kwargs: object) -> io.BytesIO:
            return body

        monkeypatch.setattr("urllib.request.urlopen", _response)

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
        # `recon update` only advertises self-upgrade when the launcher actually
        # resolves outside the working directory, so the check has to state that
        # precondition rather than depend on what the test machine has on PATH.
        monkeypatch.setattr(updater.shutil, "which", _resolvable_launcher)
        result = runner.invoke(app, ["update", "--check"])
        # The resolved launcher is an absolute path, so the rendered line can
        # wrap. Compare on collapsed whitespace rather than the raw output.
        rendered = " ".join(result.output.split())
        assert result.exit_code == 0
        assert "999.0.0" in rendered
        assert "pipx upgrade recon-tool" in rendered
        assert "or just: recon update" in rendered

    def test_check_does_not_advertise_self_upgrade_without_a_trusted_launcher(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(updater, "fetch_latest_version", lambda: "999.0.0")
        monkeypatch.setattr(updater, "detect_install_method", lambda: updater.PIPX)
        monkeypatch.setattr(updater.shutil, "which", _missing_launcher)
        result = runner.invoke(app, ["update", "--check"])
        assert result.exit_code == 0
        assert "pipx upgrade recon-tool" in result.output
        assert "or just: recon update" not in result.output

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
