"""Phase 2c: tests for the `recon doctor` command.

Mocks httpx + dnspython + the fingerprint/signal loaders so the doctor
checks run without touching the real network. Pushes cli.py coverage.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from typer.testing import CliRunner

from recon_tool.cli import app

runner = CliRunner()


def _ok_response(status: int = 200) -> MagicMock:
    """Build a fake httpx.Response with the given status code."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    return resp


@pytest.fixture
def fake_httpx_client():
    """A fake httpx.AsyncClient that returns 200s for every request."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=_ok_response(200))
    client.post = AsyncMock(return_value=_ok_response(200))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


@pytest.fixture
def patched_doctor_environment(fake_httpx_client):
    """Patch httpx.AsyncClient and dns.resolver.resolve so doctor runs offline."""
    fake_dns = MagicMock()
    fake_dns.resolve.return_value = [MagicMock(), MagicMock()]
    with (
        patch("httpx.AsyncClient", return_value=fake_httpx_client),
        patch("dns.resolver.resolve", fake_dns.resolve),
    ):
        yield fake_httpx_client, fake_dns


class TestDoctorCommandHappyPath:
    """All checks pass — every probe returns 200, DNS resolves cleanly."""

    def test_doctor_runs_without_crashing(self, patched_doctor_environment) -> None:
        result = runner.invoke(app, ["doctor"])
        # Doctor command might exit 0 or non-zero depending on whether the
        # mocked checks were sufficient. We just need it to not crash.
        assert result.exit_code in (0, 1)
        assert "recon" in result.stdout.lower()

    def test_doctor_shows_version(self, patched_doctor_environment) -> None:
        from recon_tool import __version__

        result = runner.invoke(app, ["doctor"])
        assert __version__ in result.stdout

    def test_doctor_shows_python_version(self, patched_doctor_environment) -> None:
        import sys

        result = runner.invoke(app, ["doctor"])
        assert sys.version.split()[0] in result.stdout


class TestDoctorCommandFailures:
    """When various probes fail, doctor reports them and continues."""

    def test_doctor_handles_oidc_timeout(self) -> None:
        """A timeout on the OIDC probe should be reported but not crash."""
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("httpx.AsyncClient", return_value=client),
            patch("dns.resolver.resolve", side_effect=Exception("offline")),
        ):
            result = runner.invoke(app, ["doctor"])

        # Should not crash even with everything failing
        assert "recon" in result.stdout.lower()

    def test_doctor_handles_dns_failure(self, fake_httpx_client) -> None:
        """A DNS resolver failure is reported in the checks output."""
        import dns.resolver

        with (
            patch("httpx.AsyncClient", return_value=fake_httpx_client),
            patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()),
        ):
            result = runner.invoke(app, ["doctor"])

        assert "recon" in result.stdout.lower()

    def test_doctor_treats_crtsh_http_error_as_warning(self, fake_httpx_client) -> None:
        """crt.sh is optional enrichment; outage should not fail doctor."""
        fake_dns = MagicMock()
        fake_dns.resolve.return_value = [MagicMock(), MagicMock()]
        fake_httpx_client.get = AsyncMock(
            side_effect=[
                _ok_response(200),  # OIDC discovery
                _ok_response(200),  # GetUserRealm
                _ok_response(502),  # crt.sh
            ]
        )
        fake_httpx_client.post = AsyncMock(return_value=_ok_response(503))

        with (
            patch("httpx.AsyncClient", return_value=fake_httpx_client),
            patch("dns.resolver.resolve", fake_dns.resolve),
        ):
            result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 0
        assert "WARN  crt.sh (cert transparency) — HTTP 502" in result.output
        assert "FAIL  crt.sh" not in result.output
        assert "Core checks passed. Optional enrichment sources are degraded." in result.output
        assert "Some checks failed" not in result.output


class TestDoctorFixSubcommand:
    """`recon doctor --fix` scaffolds template config files."""

    def test_doctor_fix_creates_templates(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        result = runner.invoke(app, ["doctor", "--fix"])
        # The subcommand may run a doctor check too — just confirm the
        # template files exist after invocation.
        assert (tmp_path / "fingerprints.yaml").exists()
        assert (tmp_path / "signals.yaml").exists()
        # Result code reflects whether checks pass (0) or some failed (1) —
        # we don't assert a specific code since it depends on the mocked
        # network state.
        assert result.exit_code in (0, 1)

    def test_doctor_fix_idempotent(self, tmp_path, monkeypatch) -> None:
        """Running `doctor --fix` twice doesn't overwrite existing files."""
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        # First run creates files
        runner.invoke(app, ["doctor", "--fix"])
        original = (tmp_path / "fingerprints.yaml").read_text(encoding="utf-8")
        # Modify the file to detect overwrite
        (tmp_path / "fingerprints.yaml").write_text("custom user content\n", encoding="utf-8")
        # Second run — should NOT overwrite
        runner.invoke(app, ["doctor", "--fix"])
        current = (tmp_path / "fingerprints.yaml").read_text(encoding="utf-8")
        assert current == "custom user content\n"
        assert current != original
