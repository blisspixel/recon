"""Tests for `recon cache show` and `recon cache clear` CLI commands."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from recon_tool.cache import cache_dir, cache_put
from recon_tool.cli import app
from recon_tool.ct_cache import ct_cache_put
from recon_tool.models import ConfidenceLevel, TenantInfo

runner = CliRunner()


@pytest.fixture
def tmp_cache(tmp_path: Path) -> Iterator[Path]:
    """Point CT cache at a temp directory."""
    cache_path = tmp_path / "ct-cache"
    with patch.dict(os.environ, {"RECON_CONFIG_DIR": str(tmp_path)}):
        yield cache_path


class TestCacheShow:
    def test_show_empty(self, tmp_cache: Path) -> None:
        result = runner.invoke(app, ["cache", "show"])
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_show_domain_missing(self, tmp_cache: Path) -> None:
        result = runner.invoke(app, ["cache", "show", "nope.com"])
        assert result.exit_code == 0
        assert "No CT cache entry" in result.output

    def test_show_domain_present(self, tmp_cache: Path) -> None:
        ct_cache_put("example.com", ["a.example.com", "b.example.com"], None, "crt.sh")
        result = runner.invoke(app, ["cache", "show", "example.com"])
        assert result.exit_code == 0
        assert "example.com" in result.output
        assert "crt.sh" in result.output
        assert "2" in result.output  # subdomain count

    def test_show_rejects_traversal_and_preserves_sibling_json(self, tmp_cache: Path) -> None:
        sibling = tmp_cache.parent / "ct-cache-malice"
        sibling.mkdir()
        outside = sibling / "evil.json"
        outside.write_text('{"keep": true}', encoding="utf-8")

        result = runner.invoke(app, ["cache", "show", "../ct-cache-malice/evil"])

        assert result.exit_code == 2
        assert "Invalid domain format" in result.output
        assert outside.exists()

    def test_show_normalizes_domain_before_lookup(self, tmp_cache: Path) -> None:
        ct_cache_put("example.com", ["a.example.com"], None, "crt.sh")

        result = runner.invoke(app, ["cache", "show", "https://www.example.com/path"])

        assert result.exit_code == 0
        assert "example.com" in result.output
        assert "crt.sh" in result.output

    def test_show_list_all(self, tmp_cache: Path) -> None:
        ct_cache_put("a.com", ["x.a.com"], None, "crt.sh")
        ct_cache_put("b.com", ["x.b.com"], None, "certspotter")
        result = runner.invoke(app, ["cache", "show"])
        assert result.exit_code == 0
        assert "2 cached domains" in result.output
        assert "a.com" in result.output
        assert "b.com" in result.output


class TestCacheClear:
    def test_clear_domain(self, tmp_cache: Path) -> None:
        ct_cache_put("clear.com", ["a.clear.com"], None, "crt.sh")
        result = runner.invoke(app, ["cache", "clear", "clear.com"])
        assert result.exit_code == 0
        assert "Cleared" in result.output

    def test_clear_domain_missing(self, tmp_cache: Path) -> None:
        result = runner.invoke(app, ["cache", "clear", "nope.com"])
        assert result.exit_code == 0
        assert "No cache entry" in result.output

    def test_clear_all(self, tmp_cache: Path) -> None:
        ct_cache_put("a.com", ["x.a.com"], None, "crt.sh")
        ct_cache_put("b.com", ["x.b.com"], None, "crt.sh")
        result = runner.invoke(app, ["cache", "clear", "--all"])
        assert result.exit_code == 0
        assert "Cleared 2 CT cache" in result.output

    def test_clear_no_args(self, tmp_cache: Path) -> None:
        result = runner.invoke(app, ["cache", "clear"])
        assert result.exit_code == 2

    def test_clear_rejects_traversal_and_preserves_sibling_json(self, tmp_cache: Path) -> None:
        outside = tmp_cache.parent / "outside.json"
        outside.write_text('{"keep": true}', encoding="utf-8")

        result = runner.invoke(app, ["cache", "clear", "../outside"])

        assert result.exit_code == 2
        assert "Invalid domain format" in result.output
        assert outside.exists()

    def test_clear_normalizes_domain_before_clearing_result_cache(self, tmp_cache: Path) -> None:
        cache_put(
            "clear.com",
            TenantInfo(
                tenant_id=None,
                display_name="Clear Example",
                default_domain="clear.com",
                queried_domain="clear.com",
                confidence=ConfidenceLevel.HIGH,
                region=None,
                sources=("dns_records",),
                services=(),
                slugs=(),
                auth_type=None,
                dmarc_policy=None,
                domain_count=1,
            ),
        )

        result = runner.invoke(app, ["cache", "clear", "https://www.clear.com/path"])

        assert result.exit_code == 0
        assert "Cleared result cache" in result.output
        assert not (cache_dir() / "clear.com.json").exists()
