"""Tests for CT per-domain cache (recon_tool/ct_cache.py).

Covers: get/put/clear/clear_all/show/list, TTL expiry, corruption
handling, missing directory creation, serialization round-trip.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from recon_tool.ct_cache import (
    CT_CACHE_TTL,
    CTCacheEntry,
    _safe_path,
    ct_cache_clear,
    ct_cache_clear_all,
    ct_cache_dir,
    ct_cache_get,
    ct_cache_list,
    ct_cache_put,
    ct_cache_show,
)
from recon_tool.models import (
    CertBurst,
    CertSummary,
    InfrastructureCluster,
    InfrastructureClusterReport,
    InfrastructureEdge,
)
from tests.cache_path_helpers import self_referencing_directory


@pytest.fixture
def tmp_cache(tmp_path: Path) -> Iterator[Path]:
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
    wildcard_sibling_clusters=(("api.example.com", "id.example.com"),),
    deployment_bursts=(
        CertBurst(
            window_start="2026-07-01T00:00:00Z",
            window_end="2026-07-01T00:00:10Z",
            span_seconds=10,
            names=("api.example.com", "id.example.com"),
        ),
    ),
)

SAMPLE_INFRASTRUCTURE = InfrastructureClusterReport(
    clusters=(
        InfrastructureCluster(
            cluster_id=0,
            members=("api.example.com", "id.example.com"),
            size=2,
            shared_cert_count=1,
            dominant_issuer="Let's Encrypt",
        ),
    ),
    modularity=0.5,
    algorithm="louvain",
    node_count=2,
    edge_count=1,
    edges=(InfrastructureEdge("api.example.com", "id.example.com", 1),),
    partition_stability=1.0,
    stability_runs=5,
)


class TestCTCacheDir:
    def test_legacy_recon_dir_when_present(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Back-compat: an existing ~/.recon keeps being used (no data moves).
        monkeypatch.delenv("RECON_CONFIG_DIR", raising=False)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".recon").mkdir()
        assert ct_cache_dir() == tmp_path / ".recon" / "ct-cache"

    def test_xdg_cache_when_no_legacy_dir(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Fresh install (no ~/.recon): XDG cache home.
        monkeypatch.delenv("RECON_CONFIG_DIR", raising=False)
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert ct_cache_dir() == tmp_path / ".cache" / "recon" / "ct-cache"

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
        assert data["domain"] == "example.com"
        assert data["provider_used"] == "crt.sh"
        assert data["subdomains"] == SAMPLE_SUBDOMAINS
        assert data["cert_summary"]["cert_count"] == 42

    def test_round_trip(self, tmp_cache: Path) -> None:
        ct_cache_put(
            "example.com",
            SAMPLE_SUBDOMAINS,
            SAMPLE_CERT_SUMMARY,
            "certspotter",
            infrastructure_clusters=SAMPLE_INFRASTRUCTURE,
        )
        entry = ct_cache_get("example.com")
        assert entry is not None
        assert isinstance(entry, CTCacheEntry)
        assert list(entry.subdomains) == SAMPLE_SUBDOMAINS
        assert entry.cert_summary is not None
        assert entry.cert_summary.cert_count == 42
        assert entry.cert_summary.top_issuers == ("Let's Encrypt", "DigiCert", "Sectigo")
        assert entry.cert_summary.wildcard_sibling_clusters == (("api.example.com", "id.example.com"),)
        assert entry.cert_summary.deployment_bursts == SAMPLE_CERT_SUMMARY.deployment_bursts
        assert entry.infrastructure_clusters == SAMPLE_INFRASTRUCTURE
        assert entry.provider_used == "certspotter"
        assert entry.age_days == 0

    def test_get_rejects_entry_bound_to_another_domain(self, tmp_cache: Path) -> None:
        ct_cache_put("example.com", SAMPLE_SUBDOMAINS, SAMPLE_CERT_SUMMARY, "crt.sh")
        source = tmp_cache / "example.com.json"
        target = tmp_cache / "fabrikam.com.json"
        target.write_bytes(source.read_bytes())

        assert ct_cache_get("fabrikam.com") is None

    def test_exact_subhost_has_an_independent_cache_key(self, tmp_cache: Path) -> None:
        ct_cache_put("mail.example.com", ["only.mail.example.com"], None, "crt.sh")

        assert (tmp_cache / "mail.example.com.json").exists()
        assert ct_cache_get("mail.example.com") is not None
        assert ct_cache_get("example.com") is None

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

    def test_future_mtime_is_rejected_without_negative_age(self, tmp_cache: Path) -> None:
        ct_cache_put("future.com", [], None, "crt.sh")
        path = tmp_cache / "future.com.json"
        future = time.time() + 365 * 86400
        os.utime(path, (future, future))

        assert ct_cache_get("future.com", ttl=0) is None
        assert ct_cache_show("future.com") is None

    def test_get_corrupt_returns_none(self, tmp_cache: Path) -> None:
        d = tmp_cache
        d.mkdir(parents=True, exist_ok=True)
        (d / "corrupt.com.json").write_text("NOT JSON", encoding="utf-8")
        assert ct_cache_get("corrupt.com") is None

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("subdomains", "api.example.com"),
            ("provider_used", ["crt.sh"]),
            ("cert_summary", {"cert_count": 1e999}),
        ],
    )
    def test_get_rejects_valid_json_with_invalid_shape(self, tmp_cache: Path, field: str, value: object) -> None:
        ct_cache_put("bad.com", [], None, "crt.sh")
        path = tmp_cache / "bad.com.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload[field] = value
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert ct_cache_get("bad.com") is None

    def test_get_rejects_legacy_unbound_entry(self, tmp_cache: Path) -> None:
        tmp_cache.mkdir(parents=True, exist_ok=True)
        (tmp_cache / "legacy.com.json").write_text(
            json.dumps(
                {
                    "cached_at": "2026-07-01T00:00:00Z",
                    "provider_used": "crt.sh",
                    "subdomains": [],
                    "cert_summary": None,
                }
            ),
            encoding="utf-8",
        )

        assert ct_cache_get("legacy.com") is None

    def test_write_binds_one_resolved_cache_directory(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        first = tmp_path / "first"
        second = tmp_path / "second"
        directories = iter((first, second))
        monkeypatch.setattr("recon_tool.paths.cache_root", lambda: next(directories))

        ct_cache_put("example.com", [], None, "crt.sh")

        assert (first / "ct-cache" / "example.com.json").exists()
        assert not (second / "ct-cache" / "example.com.json").exists()

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("algorithm", "unknown"),
            ("algorithm", 1),
            ("edges", [{"source": 1, "target": "id.example.com", "shared_cert_count": 1}]),
            ("edges", [{"source": "", "target": "id.example.com", "shared_cert_count": 1}]),
        ],
    )
    def test_get_rejects_malformed_infrastructure_cluster_data(
        self, tmp_cache: Path, field: str, value: object
    ) -> None:
        ct_cache_put(
            "bad.com",
            SAMPLE_SUBDOMAINS,
            SAMPLE_CERT_SUMMARY,
            "crt.sh",
            infrastructure_clusters=SAMPLE_INFRASTRUCTURE,
        )
        path = tmp_cache / "bad.com.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["infrastructure_clusters"][field] = value
        path.write_text(json.dumps(payload), encoding="utf-8")

        assert ct_cache_get("bad.com") is None

    def test_get_rejects_sibling_prefix_traversal(self, tmp_cache: Path) -> None:
        sibling = tmp_cache.parent / "ct-cache-malice"
        sibling.mkdir()
        outside = sibling / "evil.json"
        outside.write_text(
            json.dumps(
                {
                    "cached_at": "2026-01-01T00:00:00+00:00",
                    "provider_used": "malice",
                    "subdomains": ["evil.example.com"],
                    "cert_summary": None,
                }
            ),
            encoding="utf-8",
        )

        assert ct_cache_get("../ct-cache-malice/evil") is None
        assert outside.exists()

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

    def test_clear_rejects_sibling_prefix_traversal(self, tmp_cache: Path) -> None:
        sibling = tmp_cache.parent / "ct-cache-malice"
        sibling.mkdir()
        outside = sibling / "evil.json"
        outside.write_text('{"keep": true}', encoding="utf-8")

        assert ct_cache_clear("../ct-cache-malice/evil") is False
        assert outside.exists()

    def test_clear_all(self, tmp_cache: Path) -> None:
        ct_cache_put("a.com", ["x.a.com"], None, "crt.sh")
        ct_cache_put("b.com", ["x.b.com"], None, "certspotter")
        ct_cache_put("c.com", ["x.c.com"], None, "crt.sh")
        count = ct_cache_clear_all()
        assert count == 3
        assert ct_cache_list() == []

    def test_clear_all_empty(self, tmp_cache: Path) -> None:
        assert ct_cache_clear_all() == 0

    def test_redirected_cache_directory_cannot_escape_configured_root(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        configured_root = tmp_path / "configured"
        external = tmp_path / "external"
        configured_root.mkdir()
        external.mkdir()
        redirected = configured_root / "ct-cache"
        if os.name == "nt":
            command_processor = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
            subprocess.run(  # noqa: S603 - controlled test-only paths create a local junction
                [command_processor, "/d", "/c", "mklink", "/J", str(redirected), str(external)],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            redirected.symlink_to(external, target_is_directory=True)

        monkeypatch.setenv("RECON_CONFIG_DIR", str(configured_root))
        sentinel = external / "example.com.json"
        original = b'{"outside": true}'
        sentinel.write_bytes(original)

        with pytest.raises(ValueError, match="cache directory"):
            _safe_path("example.com")
        assert ct_cache_get("example.com") is None
        assert ct_cache_show("example.com") is None
        assert ct_cache_list() == []
        ct_cache_put("example.com", SAMPLE_SUBDOMAINS, None, "crt.sh")
        assert sentinel.read_bytes() == original
        assert ct_cache_clear("example.com") is False
        assert ct_cache_clear_all() == 0
        assert sentinel.read_bytes() == original

    def test_self_referencing_cache_directory_degrades_without_raising(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        configured_root = tmp_path / "configured-loop"
        configured_root.mkdir()
        redirected = configured_root / "ct-cache"
        monkeypatch.setenv("RECON_CONFIG_DIR", str(configured_root))

        with self_referencing_directory(redirected):
            with pytest.raises(ValueError, match="cache directory"):
                _safe_path("example.com")
            assert ct_cache_get("example.com") is None
            assert ct_cache_show("example.com") is None
            assert ct_cache_list() == []
            ct_cache_put("example.com", SAMPLE_SUBDOMAINS, None, "crt.sh")
            assert ct_cache_clear("example.com") is False
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

    def test_show_rejects_sibling_prefix_traversal(self, tmp_cache: Path) -> None:
        sibling = tmp_cache.parent / "ct-cache-malice"
        sibling.mkdir()
        outside = sibling / "evil.json"
        outside.write_text(
            json.dumps(
                {
                    "cached_at": "2026-01-01T00:00:00+00:00",
                    "provider_used": "malice",
                    "subdomains": ["evil.example.com"],
                    "cert_summary": None,
                }
            ),
            encoding="utf-8",
        )

        assert ct_cache_show("../ct-cache-malice/evil") is None
        assert outside.exists()


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
