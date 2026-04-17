"""Tests for CT per-domain cache (recon_tool/ct_cache.py).

Covers: get/put/clear/clear_all/show/list, TTL expiry, corruption
handling, missing directory creation, serialization round-trip.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from recon_tool.ct_cache import (
    CT_CACHE_TTL,
    CTCacheEntry,
    ct_cache_clear,
    ct_cache_clear_all,
    ct_cache_dir,
    ct_cache_get,
    ct_cache_list,
    ct_cache_put,
    ct_cache_show,
)
from recon_tool.models import CertSummary


@pytest.fixture
def tmp_cache(tmp_path: Path) -> Path:
    """Point CT cache at a temp directory."""
    cache_path = tmp_path / "ct-cache"
    with patch.dict(os.environ, {"RECON_CONFIG_DIR": str(tmp_path)}):
        yield cache_path


SAMPLE_SUBDOMAINS = ["auth.example.com", "api.example.com", "login.example.com"]

SAMPLE_CERT_SUMMARY = CertSummary(
    cert_count=42,
    issuer_diversity=3,
    issuance_velocity=7,
    newest_cert_age_days=2,
    oldest_cert_age_days=365,
    top_issuers=("Let's Encrypt", "DigiCert", "Sectigo"),
)


class TestCTCacheDir:
    def test_default_dir(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "RECON_CONFIG_DIR"}
        with patch.dict(os.environ, env, clear=True):
            d = ct_cache_dir()
            assert d.name == "ct-cache"
            assert d.parent == Path.home() / ".recon"

    def test_custom_dir(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {"RECON_CONFIG_DIR": str(tmp_path)}):
            d = ct_cache_dir()
            assert d == tmp_path / "ct-cache"


class TestCTCachePutGet:
    def test_put_creates_dir_and_file(self, tmp_cache: Path) -> None:
        ct_cache_put("example.com", SAMPLE_SUBDOMAINS, SAMPLE_CERT_SUMMARY, "crt.sh")
        path = tmp_cache / "example.com.json"
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["provider_used"] == "crt.sh"
        assert data["subdomains"] == SAMPLE_SUBDOMAINS
        assert data["cert_summary"]["cert_count"] == 42

    def test_round_trip(self, tmp_cache: Path) -> None:
        ct_cache_put("example.com", SAMPLE_SUBDOMAINS, SAMPLE_CERT_SUMMARY, "certspotter")
        entry = ct_cache_get("example.com")
        assert entry is not None
        assert isinstance(entry, CTCacheEntry)
        assert list(entry.subdomains) == SAMPLE_SUBDOMAINS
        assert entry.cert_summary is not None
        assert entry.cert_summary.cert_count == 42
        assert entry.cert_summary.top_issuers == ("Let's Encrypt", "DigiCert", "Sectigo")
        assert entry.provider_used == "certspotter"
        assert entry.age_days == 0

    def test_round_trip_no_cert_summary(self, tmp_cache: Path) -> None:
        ct_cache_put("bare.com", ["sub.bare.com"], None, "crt.sh")
        entry = ct_cache_get("bare.com")
        assert entry is not None
        assert entry.cert_summary is None
        assert entry.subdomains == ("sub.bare.com",)

    def test_get_missing_returns_none(self, tmp_cache: Path) -> None:
        assert ct_cache_get("nonexistent.com") is None

    def test_get_stale_returns_none(self, tmp_cache: Path) -> None:
        ct_cache_put("stale.com", ["s.stale.com"], None, "crt.sh")
        path = tmp_cache / "stale.com.json"
        # Backdate the file modification time beyond TTL
        old_time = time.time() - CT_CACHE_TTL - 100
        os.utime(path, (old_time, old_time))
        assert ct_cache_get("stale.com") is None

    def test_get_corrupt_returns_none(self, tmp_cache: Path) -> None:
        d = tmp_cache
        d.mkdir(parents=True, exist_ok=True)
        (d / "corrupt.com.json").write_text("NOT JSON", encoding="utf-8")
        assert ct_cache_get("corrupt.com") is None

    def test_custom_ttl(self, tmp_cache: Path) -> None:
        ct_cache_put("ttl.com", ["a.ttl.com"], None, "crt.sh")
        path = tmp_cache / "ttl.com.json"
        # 1 hour old
        old_time = time.time() - 3600
        os.utime(path, (old_time, old_time))
        # Still valid with default 7-day TTL
        assert ct_cache_get("ttl.com") is not None
        # Expired with 1-hour TTL
        assert ct_cache_get("ttl.com", ttl=3500) is None


class TestCTCacheClear:
    def test_clear_existing(self, tmp_cache: Path) -> None:
        ct_cache_put("clear.com", ["a.clear.com"], None, "crt.sh")
        assert ct_cache_clear("clear.com") is True
        assert ct_cache_get("clear.com") is None

    def test_clear_nonexistent(self, tmp_cache: Path) -> None:
        assert ct_cache_clear("nope.com") is False

    def test_clear_all(self, tmp_cache: Path) -> None:
        ct_cache_put("a.com", ["x.a.com"], None, "crt.sh")
        ct_cache_put("b.com", ["x.b.com"], None, "certspotter")
        ct_cache_put("c.com", ["x.c.com"], None, "crt.sh")
        count = ct_cache_clear_all()
        assert count == 3
        assert ct_cache_list() == []

    def test_clear_all_empty(self, tmp_cache: Path) -> None:
        assert ct_cache_clear_all() == 0


class TestCTCacheShow:
    def test_show_existing(self, tmp_cache: Path) -> None:
        ct_cache_put("show.com", SAMPLE_SUBDOMAINS, SAMPLE_CERT_SUMMARY, "crt.sh")
        info = ct_cache_show("show.com")
        assert info is not None
        assert info.domain == "show.com"
        assert info.provider_used == "crt.sh"
        assert info.subdomain_count == 3
        assert info.age_days == 0
        assert info.file_size_bytes > 0

    def test_show_missing(self, tmp_cache: Path) -> None:
        assert ct_cache_show("nope.com") is None


class TestCTCacheList:
    def test_list_multiple(self, tmp_cache: Path) -> None:
        ct_cache_put("alpha.com", ["a.alpha.com"], None, "crt.sh")
        ct_cache_put("beta.com", ["a.beta.com", "b.beta.com"], None, "certspotter")
        entries = ct_cache_list()
        assert len(entries) == 2
        domains = {e.domain for e in entries}
        assert domains == {"alpha.com", "beta.com"}

    def test_list_empty(self, tmp_cache: Path) -> None:
        assert ct_cache_list() == []
