"""Tests for `recon delta <domain>` CLI command (v0.10.2).

The delta command reads the last cached TenantInfo from the main cache
(~/.recon/cache/) and diffs against a fresh lookup.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from recon_tool.cache import cache_put
from recon_tool.cli import app
from recon_tool.models import ConfidenceLevel, ReconLookupError, TenantInfo

runner = CliRunner()


@pytest.fixture
def tmp_recon_home(tmp_path: Path) -> Iterator[Path]:
    """Point RECON_CONFIG_DIR at a temp directory for isolated caching."""
    with patch.dict(os.environ, {"RECON_CONFIG_DIR": str(tmp_path)}):
        yield tmp_path


def _tenant(domain: str, services: tuple[str, ...] = (), slugs: tuple[str, ...] = ()) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.MEDIUM,
        services=services,
        slugs=slugs,
    )


class TestDeltaCLI:
    def test_delta_no_cache_returns_error(self, tmp_recon_home: Path) -> None:
        """Without a cached baseline, delta tells the user to run recon first."""
        result = runner.invoke(app, ["delta", "alpha.invalid"])
        assert result.exit_code != 0
        assert "No cached snapshot" in result.output
        assert "Run `recon alpha.invalid` first" in result.output

    def test_delta_no_cache_keeps_json_stdout_clean(self, tmp_recon_home: Path) -> None:
        result = runner.invoke(app, ["delta", "alpha.invalid", "--json"])
        assert result.exit_code == 3
        assert result.stdout == ""
        assert "No cached snapshot" in result.stderr

    def test_delta_invalid_domain(self, tmp_recon_home: Path) -> None:
        """Invalid domain input returns validation error."""
        result = runner.invoke(app, ["delta", "not a domain!!!"])
        assert result.exit_code != 0

    def test_delta_rejects_mismatched_cached_domain_before_resolution(self, tmp_recon_home: Path) -> None:
        resolver = AsyncMock()

        with (
            patch("recon_tool.cache.cache_get", return_value=_tenant("beta.invalid")),
            patch("recon_tool.resolver.resolve_tenant", new=resolver),
        ):
            result = runner.invoke(app, ["delta", "alpha.invalid"])

        assert result.exit_code == 2
        assert "does not match current domain" in result.stderr
        resolver.assert_not_awaited()

    def test_delta_compares_against_cache(self, tmp_recon_home: Path) -> None:
        """When cache exists, delta runs fresh lookup and diffs against it."""
        # Seed the cache with a baseline
        baseline = _tenant(
            "alpha.invalid",
            services=("Microsoft 365", "Google Workspace"),
            slugs=("microsoft365", "google-workspace"),
        )
        cache_put("alpha.invalid", baseline)

        # Fresh lookup returns a different set of services
        fresh = _tenant(
            "alpha.invalid",
            services=("Microsoft 365", "Slack"),
            slugs=("microsoft365", "slack"),
        )

        with patch(
            "recon_tool.resolver.resolve_tenant",
            new=AsyncMock(return_value=(fresh, [])),
        ):
            result = runner.invoke(app, ["delta", "alpha.invalid"])

        assert result.exit_code == 0
        # The delta panel should mention the added/removed services
        out = result.output.lower()
        assert "slack" in out or "google workspace" in out

    def test_delta_timeout_preserves_failure_and_exits_4(self, tmp_recon_home: Path) -> None:
        cache_put("alpha.invalid", _tenant("alpha.invalid"))
        error = ReconLookupError(
            domain="alpha.invalid",
            message="Resolution timed out after 5s for alpha.invalid",
            error_type="timeout",
        )

        with patch("recon_tool.resolver.resolve_tenant", new=AsyncMock(side_effect=error)):
            result = runner.invoke(app, ["delta", "alpha.invalid", "--timeout", "5"])

        assert result.exit_code == 4
        assert "Resolution timed out after 5s for alpha.invalid" in result.stderr
        assert "No information found" not in result.stderr

    @pytest.mark.parametrize("timeout", ["nan", "inf", "-1", "0"])
    def test_delta_rejects_nonpositive_or_nonfinite_timeout(self, tmp_recon_home: Path, timeout: str) -> None:
        cache_put("alpha.invalid", _tenant("alpha.invalid"))
        resolver = AsyncMock()
        with patch("recon_tool.resolver.resolve_tenant", new=resolver):
            result = runner.invoke(app, ["delta", "alpha.invalid", "--timeout", timeout, "--json"])
        assert result.exit_code == 2
        assert "finite positive number" in result.stderr
        resolver.assert_not_awaited()
