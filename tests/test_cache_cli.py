"""Tests for `recon cache show` and `recon cache clear` CLI commands."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from recon_tool.cache import cache_dir, cache_put
from recon_tool.cli import app
from recon_tool.ct_cache import ct_cache_put
from recon_tool.exit_codes import EXIT_INTERNAL
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
        assert "Result cache" in result.output
        assert "CT cache" in result.output
        assert result.output.count("Status:     no entry") == 2

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

    def test_show_exact_inspects_literal_subhost_cache_key(self, tmp_cache: Path) -> None:
        ct_cache_put("mail.example.com", ["a.mail.example.com"], None, "crt.sh")

        result = runner.invoke(app, ["cache", "show", "mail.example.com", "--exact"])

        assert result.exit_code == 0
        assert "mail.example.com" in result.output
        assert "crt.sh" in result.output

    def test_show_list_all(self, tmp_cache: Path) -> None:
        ct_cache_put("a.com", ["x.a.com"], None, "crt.sh")
        ct_cache_put("b.com", ["x.b.com"], None, "certspotter")
        result = runner.invoke(app, ["cache", "show"])
        assert result.exit_code == 0
        assert "Result cache (empty)" in result.output
        assert "CT cache (2 entries)" in result.output
        assert "a.com" in result.output
        assert "b.com" in result.output

    def test_show_list_surfaces_unreadable_entries_without_payload_details(self, tmp_cache: Path) -> None:
        tmp_cache.mkdir(parents=True)
        cache_dir().mkdir(parents=True)
        (tmp_cache / "broken-ct.com.json").write_text('{"private": "ct-marker"', encoding="utf-8")
        (cache_dir() / "broken-result.com.json").write_text(
            '{"private": "result-marker"',
            encoding="utf-8",
        )

        result = runner.invoke(app, ["cache", "show"])

        normalized = " ".join(result.output.split())
        assert result.exit_code == EXIT_INTERNAL
        assert "Result cache (0 readable entries)" in normalized
        assert "CT cache (0 readable entries)" in normalized
        assert normalized.count("Inspection failures: 1") == 2
        assert "ct-marker" not in result.output
        assert "result-marker" not in result.output
        assert "recon --debug cache show" in normalized

    def test_show_domain_reports_both_layers_without_result_payload(self, tmp_cache: Path) -> None:
        domain = "layered.com"
        private_marker = "PRIVATE-DISPLAY-MARKER"
        cache_put(
            domain,
            TenantInfo(
                tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                display_name=private_marker,
                default_domain=domain,
                queried_domain=domain,
                confidence=ConfidenceLevel.HIGH,
                sources=("dns_records",),
                services=("private-service-marker",),
            ),
        )
        ct_cache_put(domain, [f"a.{domain}"], None, "crt.sh")

        result = runner.invoke(app, ["cache", "show", domain])

        assert result.exit_code == 0
        assert "Result cache" in result.output
        assert "CT cache" in result.output
        assert result.output.count("Status:     reusable") == 2
        assert "TTL:        24 hours" in result.output
        assert "TTL:        30 days" in result.output
        assert private_marker not in result.output
        assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" not in result.output
        assert "private-service-marker" not in result.output

    def test_show_marks_expired_result_entry_as_not_reusable(self, tmp_cache: Path) -> None:
        domain = "expired.com"
        cache_put(
            domain,
            TenantInfo(
                tenant_id=None,
                display_name="Expired Example",
                default_domain=domain,
                queried_domain=domain,
                confidence=ConfidenceLevel.LOW,
            ),
        )
        old = time.time() - 90000
        os.utime(cache_dir() / f"{domain}.json", (old, old))

        result = runner.invoke(app, ["cache", "show", domain])

        assert result.exit_code == 0
        assert "Status:     expired; next lookup refreshes" in result.output
        assert "TTL:        24 hours" in result.output

    def test_show_corrupt_ct_entry_is_not_reported_as_absent(self, tmp_cache: Path) -> None:
        domain = "broken-ct.com"
        tmp_cache.mkdir(parents=True)
        (tmp_cache / f"{domain}.json").write_text('{"private": "do-not-print"', encoding="utf-8")

        result = runner.invoke(app, ["cache", "show", domain])

        assert result.exit_code == EXIT_INTERNAL
        assert "CT cache" in result.output
        assert "Status:     could not inspect" in result.output
        assert "No CT cache entry" not in result.output
        assert "do-not-print" not in result.output
        assert "recon --debug cache show" in result.output

    def test_show_corrupt_result_entry_is_not_reported_as_absent(self, tmp_cache: Path) -> None:
        domain = "broken-result.com"
        cache_dir().mkdir(parents=True)
        (cache_dir() / f"{domain}.json").write_text('{"private": "do-not-print"', encoding="utf-8")

        result = runner.invoke(app, ["cache", "show", domain])

        assert result.exit_code == EXIT_INTERNAL
        assert "Result cache" in result.output
        assert "Status:     could not inspect" in result.output
        assert "do-not-print" not in result.output
        assert "recon --debug cache show" in result.output

    def test_show_lists_result_and_ct_layers_independently(self, tmp_cache: Path) -> None:
        cache_put(
            "result-only.com",
            TenantInfo(
                tenant_id=None,
                display_name="Result Only",
                default_domain="result-only.com",
                queried_domain="result-only.com",
                confidence=ConfidenceLevel.LOW,
            ),
        )
        ct_cache_put("ct-only.com", ["a.ct-only.com"], None, "crt.sh")

        result = runner.invoke(app, ["cache", "show"])

        assert result.exit_code == 0
        assert "Result cache (1 entry)" in result.output
        assert "result-only.com" in result.output
        assert "CT cache (1 entry)" in result.output
        assert "ct-only.com" in result.output

    def test_show_exact_inspects_literal_result_cache_key(self, tmp_cache: Path) -> None:
        domain = "mail.exact-result.com"
        cache_put(
            domain,
            TenantInfo(
                tenant_id=None,
                display_name="Exact Result",
                default_domain="exact-result.com",
                queried_domain=domain,
                confidence=ConfidenceLevel.LOW,
            ),
        )

        result = runner.invoke(app, ["cache", "show", domain, "--exact"])

        assert result.exit_code == 0
        assert domain in result.output
        assert "Result cache" in result.output
        assert "Status:     reusable" in result.output


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
        result = runner.invoke(app, ["cache", "clear", "--all", "--force"])
        assert result.exit_code == 0
        assert "Cleared 2 CT cache" in result.output

    def test_clear_all_refuses_without_force_when_noninteractive(self, tmp_cache: Path) -> None:
        # CliRunner stdin is not a TTY, so --all must refuse (exit 2) without
        # --force rather than wipe everything unprompted (old behavior: exit 0).
        ct_cache_put("a.com", ["x.a.com"], None, "crt.sh")
        result = runner.invoke(app, ["cache", "clear", "--all"])
        assert result.exit_code == 2

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

    def test_clear_exact_removes_literal_subhost_from_both_caches(self, tmp_cache: Path) -> None:
        exact_domain = "mail.clear.com"
        ct_cache_put(exact_domain, ["a.mail.clear.com"], None, "crt.sh")
        cache_put(
            exact_domain,
            TenantInfo(
                tenant_id=None,
                display_name="Mail Clear Example",
                default_domain="clear.com",
                queried_domain=exact_domain,
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

        result = runner.invoke(app, ["cache", "clear", exact_domain, "--exact"])

        assert result.exit_code == 0
        assert "Cleared CT cache and result cache" in result.output
        assert not (tmp_cache / f"{exact_domain}.json").exists()
        assert not (cache_dir() / f"{exact_domain}.json").exists()

    def test_clear_domain_reports_partial_unlink_failure(self, tmp_cache: Path, caplog) -> None:
        domain = "partial-clear.com"
        ct_cache_put(domain, [f"a.{domain}"], None, "crt.sh")
        cache_put(
            domain,
            TenantInfo(
                tenant_id=None,
                display_name="Partial Clear",
                default_domain=domain,
                queried_domain=domain,
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
        original_unlink = Path.unlink

        def unlink_with_ct_failure(path: Path, *args: object, **kwargs: object) -> None:
            if path.parent.name == "ct-cache":
                raise PermissionError("secret-cache-path")
            original_unlink(path, *args, **kwargs)

        with (
            caplog.at_level(logging.DEBUG, logger="recon"),
            patch.object(Path, "unlink", unlink_with_ct_failure),
        ):
            result = runner.invoke(app, ["cache", "clear", domain])

        normalized = " ".join(result.output.split())
        assert result.exit_code == EXIT_INTERNAL
        assert "Cleared result cache" in normalized
        assert "CT cache clear failed" in normalized
        assert "Retry: recon --debug cache clear" in normalized
        assert "secret-cache-path" not in result.output
        assert "secret-cache-path" in caplog.text
        assert (tmp_cache / f"{domain}.json").exists()
        assert not (cache_dir() / f"{domain}.json").exists()

    def test_clear_all_reports_layer_failure_after_partial_success(self, tmp_cache: Path) -> None:
        domain = "partial-all.com"
        ct_cache_put(domain, [f"a.{domain}"], None, "crt.sh")
        cache_put(
            domain,
            TenantInfo(
                tenant_id=None,
                display_name="Partial All",
                default_domain=domain,
                queried_domain=domain,
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
        original_unlink = Path.unlink

        def unlink_with_result_failure(path: Path, *args: object, **kwargs: object) -> None:
            if path.parent.name == "cache":
                raise PermissionError("secret-result-path")
            original_unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", unlink_with_result_failure):
            result = runner.invoke(app, ["cache", "clear", "--all", "--force"])

        normalized = " ".join(result.output.split())
        assert result.exit_code == EXIT_INTERNAL
        assert "Cleared 1 CT cache entry" in normalized
        assert "Cleared 0 result cache entries" in normalized
        assert "Some result cache entries could not be cleared" in normalized
        assert "Retry: recon --debug cache clear" in normalized
        assert "secret-result-path" not in result.output
        assert not (tmp_cache / f"{domain}.json").exists()
        assert (cache_dir() / f"{domain}.json").exists()

    def test_clear_domain_never_reports_failures_as_absence(self, tmp_cache: Path) -> None:
        domain = "failed-clear.com"
        ct_cache_put(domain, [f"a.{domain}"], None, "crt.sh")
        cache_put(
            domain,
            TenantInfo(
                tenant_id=None,
                display_name="Failed Clear",
                default_domain=domain,
                queried_domain=domain,
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

        with patch.object(Path, "unlink", side_effect=PermissionError("private unlink detail")):
            result = runner.invoke(app, ["cache", "clear", domain])

        assert result.exit_code == EXIT_INTERNAL
        assert "No cache entry" not in result.output
        assert "CT cache clear failed" in result.output
        assert "result cache clear failed" in result.output
        assert "private unlink detail" not in result.output
