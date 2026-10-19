"""Tests for `resolved_at` / `cached_at` staleness metadata on TenantInfo.

Internal cache timestamps do not belong to the public lookup JSON contract.
These tests distinguish internal serialization from the public formatter:

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

import json
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from recon_tool.cache import cache_get, cache_put, tenant_info_from_dict, tenant_info_to_dict
from recon_tool.formatter import format_tenant_json
from recon_tool.models import ConfidenceLevel, TenantInfo


@pytest.fixture
def tmp_cache_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("RECON_CONFIG_DIR", tmp)
        yield Path(tmp)


def _minimal_info(**overrides: object) -> TenantInfo:
    base: dict[str, object] = {
        "tenant_id": None,
        "display_name": "Synthetic Alpha Ltd",
        "default_domain": "alpha.invalid",
        "queried_domain": "alpha.invalid",
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

    cache_put("alpha.invalid", info)
    loaded = cache_get("alpha.invalid")

    assert loaded is not None
    assert loaded.resolved_at == fixed


def test_cache_get_stamps_cached_at(tmp_cache_dir: Path) -> None:
    info = _minimal_info(resolved_at=datetime(2026, 4, 21, 8, 0, 0, tzinfo=UTC).isoformat())

    cache_put("alpha.invalid", info)
    loaded = cache_get("alpha.invalid")

    assert loaded is not None
    assert loaded.cached_at is not None
    # Value came from the persisted _cached_at; must be a valid ISO timestamp
    datetime.fromisoformat(loaded.cached_at)


def test_fresh_info_has_no_cached_at() -> None:
    info = _minimal_info()

    # A TenantInfo built directly from a resolve has no cached_at;
    # only cache_get should stamp it.
    assert info.cached_at is None


def test_deserialize_does_not_spuriously_set_cached_at() -> None:
    """tenant_info_from_dict ignores _cached_at; cache_get is the only
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


@pytest.mark.parametrize("cached", [False, True])
def test_public_lookup_json_does_not_expose_internal_timestamps(cached: bool) -> None:
    info = _minimal_info(
        resolved_at="2026-04-21T08:00:00+00:00",
        cached_at="2026-04-21T09:00:00+00:00" if cached else None,
    )

    public = json.loads(format_tenant_json(info))

    assert "resolved_at" not in public
    assert "cached_at" not in public
    assert "_cached_at" not in public
    assert tenant_info_to_dict(info)["resolved_at"] == info.resolved_at


_NOW = datetime(2026, 4, 21, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("resolved_at", "cached_at", "expected"),
    [
        ("2026-04-21T11:59:30+00:00", "2026-04-21T11:59:30+00:00", "under 1 minute ago"),
        ("2026-04-21T11:59:00+00:00", "2026-04-21T11:59:00+00:00", "1 minute ago"),
        ("2026-04-21T09:00:00+00:00", "2026-04-21T09:00:00+00:00", "3 hours ago"),
        ("2026-04-19T12:00:00+00:00", "2026-04-21T09:00:00+00:00", "2 days ago"),
        # Naive timestamps read as UTC; resolved_at wins over cached_at.
        ("2026-04-21T11:00:00", "2026-04-21T09:00:00+00:00", "1 hour ago"),
        # An unreadable collection time falls back to the cache-write time.
        ("not-a-time", "2026-04-21T10:00:00+00:00", "2 hours ago"),
        # A clock skewed into the future never yields a negative age.
        ("2026-04-21T12:30:00+00:00", "2026-04-21T12:30:00+00:00", "under 1 minute ago"),
        (None, "garbage", "an earlier collection"),
    ],
)
def test_cache_reuse_note_names_the_earlier_collection(resolved_at: str | None, cached_at: str, expected: str) -> None:
    from recon_tool.formatter.collection_status import cache_reuse_note

    info = _minimal_info(resolved_at=resolved_at, cached_at=cached_at)

    assert cache_reuse_note(info, now=_NOW) == f"Cached result from {expected}. Use --no-cache to collect again."


def test_fresh_result_has_no_cache_reuse_note_on_any_human_surface() -> None:
    from recon_tool.formatter import format_tenant_markdown, format_tenant_plain
    from recon_tool.formatter.collection_status import cache_reuse_note

    info = _minimal_info(resolved_at="2026-04-21T09:00:00+00:00")

    assert cache_reuse_note(info) is None
    assert "Cached result" not in format_tenant_plain(info)
    assert "Cached result" not in format_tenant_plain(info, full=True)
    assert "Cached result" not in format_tenant_markdown(info)


def test_cache_reuse_note_reaches_plain_full_and_markdown() -> None:
    from recon_tool.formatter import format_tenant_markdown, format_tenant_plain

    info = _minimal_info(resolved_at="2026-04-21T09:00:00+00:00", cached_at="2026-04-21T09:00:00+00:00")

    assert "cache_note: Cached result from " in format_tenant_plain(info, full=True)
    assert "*Cached result from " in format_tenant_markdown(info)
