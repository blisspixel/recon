"""Read-only result-cache metadata inspection tests."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from recon_tool.cache import DEFAULT_TTL, cache_dir, cache_put
from recon_tool.cache_inspection import inspect_result_cache, list_result_cache
from recon_tool.models import ConfidenceLevel, TenantInfo


@pytest.fixture
def isolated_cache(tmp_path: Path) -> Iterator[Path]:
    with patch.dict(os.environ, {"RECON_CONFIG_DIR": str(tmp_path)}):
        yield tmp_path


def _info(domain: str) -> TenantInfo:
    return TenantInfo(
        tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        display_name="Private display value",
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.HIGH,
        sources=("dns_records",),
        services=("private-service",),
    )


def test_inspect_result_cache_returns_only_validated_metadata(isolated_cache: Path) -> None:
    cache_put("example.com", _info("example.com"))

    inspection = inspect_result_cache("example.com")

    assert not inspection.failed
    assert inspection.entry is not None
    assert inspection.entry.domain == "example.com"
    assert inspection.entry.cached_at != "unknown"
    assert inspection.entry.resolved_at != "unknown"
    assert inspection.entry.age_seconds >= 0.0
    assert inspection.entry.file_size_bytes > 0
    assert inspection.entry.reusable
    assert not hasattr(inspection.entry, "display_name")
    assert not hasattr(inspection.entry, "tenant_id")
    assert not hasattr(inspection.entry, "services")


def test_inspect_result_cache_reports_expired_entry_without_hiding_it(isolated_cache: Path) -> None:
    cache_put("expired.com", _info("expired.com"))
    old = time.time() - DEFAULT_TTL - 1
    os.utime(cache_dir() / "expired.com.json", (old, old))

    inspection = inspect_result_cache("expired.com")

    assert not inspection.failed
    assert inspection.entry is not None
    assert not inspection.entry.reusable
    assert inspection.entry.age_seconds > DEFAULT_TTL


def test_inspect_result_cache_distinguishes_missing_from_invalid(isolated_cache: Path) -> None:
    missing = inspect_result_cache("missing.com")
    cache_dir().mkdir(parents=True)
    (cache_dir() / "broken.com.json").write_text("NOT JSON", encoding="utf-8")
    broken = inspect_result_cache("broken.com")

    assert missing.entry is None
    assert not missing.failed
    assert broken.entry is None
    assert broken.failed


def test_list_result_cache_counts_invalid_entries(isolated_cache: Path) -> None:
    cache_put("valid.com", _info("valid.com"))
    (cache_dir() / "broken.com.json").write_text("NOT JSON", encoding="utf-8")

    listing = list_result_cache()

    assert [entry.domain for entry in listing.entries] == ["valid.com"]
    assert listing.failed == 1
