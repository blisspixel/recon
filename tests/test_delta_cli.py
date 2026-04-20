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
from recon_tool.models import ConfidenceLevel, TenantInfo

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
        result = runner.invoke(app, ["delta", "contoso.com"])
        assert result.exit_code != 0
        assert "No cached snapshot" in result.output
        assert "Run `recon contoso.com` first" in result.output

    def test_delta_invalid_domain(self, tmp_recon_home: Path) -> None:
        """Invalid domain input returns validation error."""
        result = runner.invoke(app, ["delta", "not a domain!!!"])
        assert result.exit_code != 0

    def test_delta_compares_against_cache(self, tmp_recon_home: Path) -> None:
        """When cache exists, delta runs fresh lookup and diffs against it."""
        # Seed the cache with a baseline
        baseline = _tenant(
            "contoso.com",
            services=("Microsoft 365", "Google Workspace"),
            slugs=("microsoft365", "google-workspace"),
        )
        cache_put("contoso.com", baseline)

        # Fresh lookup returns a different set of services
        fresh = _tenant(
            "contoso.com",
            services=("Microsoft 365", "Slack"),
            slugs=("microsoft365", "slack"),
        )

        with patch(
            "recon_tool.resolver.resolve_tenant",
            new=AsyncMock(return_value=(fresh, [])),
        ):
            result = runner.invoke(app, ["delta", "contoso.com"])

        assert result.exit_code == 0
        # The delta panel should mention the added/removed services
        out = result.output.lower()
        assert "slack" in out or "google workspace" in out
