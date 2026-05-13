"""Tests for `resolved_at` / `cached_at` staleness metadata on TenantInfo.

Agents reading `--json` output need to distinguish freshly-resolved data
from a cache-served response. This is covered end-to-end:

- Fresh serialize includes a top-level `resolved_at` populated from now
  when the TenantInfo has no pre-existing timestamp.
- Round-trip through the on-disk cache preserves the original
  `resolved_at` value (i.e. it reflects when the data was *resolved*,
  not when the cache entry was *written*).
- `cache_get` stamps `cached_at` from the persisted `_cached_at` field
  so callers can see when the cache entry was produced.
- A TenantInfo built without timestamps does not leak a spurious
  `cached_at` when serialized directly (serialization never invents a
  cache-write timestamp for data that was not cached).
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

from recon_tool.cache import cache_get, cache_put, tenant_info_from_dict, tenant_info_to_dict
from recon_tool.models import ConfidenceLevel, TenantInfo


@pytest.fixture
def tmp_cache_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("RECON_CONFIG_DIR", tmp)
        yield Path(tmp)


def _minimal_info(**overrides: object) -> TenantInfo:
    base: dict[str, object] = {
        "tenant_id": None,
        "display_name": "Contoso Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": ConfidenceLevel.MEDIUM,
    }
    base.update(overrides)
    return TenantInfo(**base)  # type: ignore[arg-type]


def test_serialize_stamps_resolved_at_when_absent() -> None:
    info = _minimal_info()
    data = tenant_info_to_dict(info)

    assert "resolved_at" in data
    assert isinstance(data["resolved_at"], str)
    # ISO-8601 UTC, parseable
    datetime.fromisoformat(data["resolved_at"])


def test_serialize_preserves_explicit_resolved_at() -> None:
    fixed = "2026-04-21T12:34:56+00:00"
    info = _minimal_info(resolved_at=fixed)

    data = tenant_info_to_dict(info)

    assert data["resolved_at"] == fixed


def test_cache_roundtrip_preserves_resolved_at(tmp_cache_dir: Path) -> None:
    fixed = "2026-04-21T08:00:00+00:00"
    info = _minimal_info(resolved_at=fixed)

    cache_put("contoso.com", info)
    loaded = cache_get("contoso.com")

    assert loaded is not None
    assert loaded.resolved_at == fixed


def test_cache_get_stamps_cached_at(tmp_cache_dir: Path) -> None:
    info = _minimal_info(resolved_at=datetime(2026, 4, 21, 8, 0, 0, tzinfo=timezone.utc).isoformat())

    cache_put("contoso.com", info)
    loaded = cache_get("contoso.com")

    assert loaded is not None
    assert loaded.cached_at is not None
    # Value came from the persisted _cached_at — must be a valid ISO timestamp
    datetime.fromisoformat(loaded.cached_at)


def test_fresh_info_has_no_cached_at() -> None:
    info = _minimal_info()

    # A TenantInfo built directly from a resolve has no cached_at;
    # only cache_get should stamp it.
    assert info.cached_at is None


def test_deserialize_does_not_spuriously_set_cached_at() -> None:
    """tenant_info_from_dict ignores _cached_at — cache_get is the only
    path that should stamp cached_at, so ad-hoc round-trips through the
    serializer (e.g. MCP responses never written to disk) stay honest."""
    info = _minimal_info()
    data = tenant_info_to_dict(info)

    # Simulate a caller deserializing a blob that happens to have
    # _cached_at baked in. The resulting TenantInfo must not report
    # cached_at because it was not produced by cache_get.
    assert "_cached_at" in data
    restored = tenant_info_from_dict(data)

    assert restored.cached_at is None
    assert restored.resolved_at == data["resolved_at"]
