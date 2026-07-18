"""Resilience hardening: confirmed gaps from the boundary fault-injection audit.

Four ingestion-boundary gaps that an attacker who controls a queried domain (or
a CT provider) could reach, each now degrading cleanly instead of crashing,
hanging, or consuming unbounded resources:

1. HTTP decompression bomb: the 10 MB body cap counts compressed transfer bytes,
   but httpx decodes Content-Encoding downstream, so a few MB of gzip could
   decode to many GB. recon now requests identity encoding and refuses a
   response that still carries a compressing Content-Encoding.
2. Deeply-nested JSON in a poisoned local cache file raises RecursionError (a
   RuntimeError, not ValueError) that the cache loaders did not catch.
3. The CT co-occurrence graph processed an unbounded CertSpotter entry count and
   accumulated one issuer sample per edge per entry (quadratic in entries).
4. The CT providers' ``resp.json()`` guard caught only ValueError, so a
   deeply-nested CT payload skipped the provider-local degrade path.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from recon_tool import cache as cache_mod
from recon_tool import ct_cache as ct_cache_mod
from recon_tool.http import (
    _COMPRESSING_ENCODINGS,
    _MAX_RESPONSE_BYTES,
    _MAX_TOTAL_RETRY_SLEEP,
    MAX_REDIRECTS,
    _MaxBytesStream,
    _RefusingStream,
    _RetryTransport,
    _SSRFSafeTransport,
    http_client,
)
from recon_tool.infra_graph import _MAX_EDGE_ISSUER_SAMPLES, _build_graph, build_infrastructure_clusters
from recon_tool.rate_limit import AdaptiveRateLimiter, rate_limit_state_dir
from recon_tool.resolver import RESOLVE_TIMEOUT
from recon_tool.sources import dns_base
from recon_tool.sources.cert_providers import CertSpotterProvider, CrtshProvider

# Part of the dedicated hostile-input fuzz gate (run with `-m hostile_input`).
pytestmark = pytest.mark.hostile_input

# A JSON document nested far past the interpreter recursion limit. json.loads
# raises RecursionError (a RuntimeError, not a ValueError) on it.
_DEEPLY_NESTED_JSON = "[" * 100_000 + "]" * 100_000


class _FakeStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.close_calls = 0

    async def __aiter__(self) -> AsyncGenerator[bytes]:
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        self.close_calls += 1


async def _consume_stream(stream: httpx.AsyncByteStream) -> None:
    async for _chunk in stream:
        continue


# ── 1. HTTP decompression bomb ───────────────────────────────────────────


class TestDecompressionBombGuard:
    @pytest.mark.asyncio
    async def test_refusing_stream_raises_on_read(self) -> None:
        stream = _RefusingStream("gzip")
        with pytest.raises(httpx.ReadError):
            await _consume_stream(stream)

    @pytest.mark.asyncio
    async def test_transport_refuses_compressed_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A compressing Content-Encoding (despite identity) is refused, not decoded."""
        from recon_tool import http as http_mod

        async def _not_private(_host: str) -> bool:
            return False

        raw_stream = _FakeStream([b"\x1f\x8b" + b"\x00" * 64])
        crafted = httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            stream=raw_stream,
            request=httpx.Request("GET", "https://cse.alpha.invalid/x"),
        )

        async def _fake_super(_self: Any, _request: httpx.Request) -> httpx.Response:
            return crafted

        monkeypatch.setattr(http_mod, "_is_private_ip_async", _not_private)
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _fake_super)

        resp = await _SSRFSafeTransport().handle_async_request(httpx.Request("GET", "https://cse.alpha.invalid/x"))
        assert isinstance(resp.stream, _RefusingStream)
        assert raw_stream.close_calls == 1
        with pytest.raises(httpx.ReadError):
            await _consume_stream(resp.stream)  # type: ignore[arg-type]
        await resp.aclose()
        assert raw_stream.close_calls == 1

    @pytest.mark.asyncio
    async def test_transport_caps_identity_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An uncompressed (identity) response is wrapped in the byte cap, not refused."""
        from recon_tool import http as http_mod

        async def _not_private(_host: str) -> bool:
            return False

        raw_stream = _FakeStream([b'{"ok": true}'])
        crafted = httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=raw_stream,
            request=httpx.Request("GET", "https://crt.sh/x"),
        )

        async def _fake_super(_self: Any, _request: httpx.Request) -> httpx.Response:
            return crafted

        monkeypatch.setattr(http_mod, "_is_private_ip_async", _not_private)
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _fake_super)

        resp = await _SSRFSafeTransport().handle_async_request(httpx.Request("GET", "https://crt.sh/x"))
        assert isinstance(resp.stream, _MaxBytesStream)
        assert raw_stream.close_calls == 0
        await resp.aclose()
        assert raw_stream.close_calls == 1

    @pytest.mark.asyncio
    async def test_client_requests_identity_encoding(self) -> None:
        async with http_client() as client:
            assert client.headers.get("accept-encoding") == "identity"

    def test_compressing_encodings_cover_the_common_codecs(self) -> None:
        assert {"gzip", "deflate", "br"} <= _COMPRESSING_ENCODINGS


# ── 2. Poisoned cache files degrade to a clean miss ──────────────────────


def _write_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Any, content: str) -> None:
    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    path = cache_mod._safe_cache_path("alpha.invalid")
    assert path is not None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_ct_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Any, content: str) -> None:
    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    path = ct_cache_mod._safe_path("alpha.invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class TestPoisonedCacheDegrades:
    def test_cache_get_deeply_nested_returns_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        # Sanity: this payload really does raise RecursionError, not ValueError.
        with pytest.raises(RecursionError):
            json.loads(_DEEPLY_NESTED_JSON)
        _write_cache(monkeypatch, tmp_path, _DEEPLY_NESTED_JSON)
        assert cache_mod.cache_get("alpha.invalid") is None

    def test_cache_get_oversized_returns_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        oversized = '{"display_name": "' + "a" * (6 * 1024 * 1024) + '"}'
        _write_cache(monkeypatch, tmp_path, oversized)
        assert cache_mod.cache_get("alpha.invalid") is None

    def test_cache_get_bounds_the_open_file_when_path_metadata_is_stale(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        oversized = '{"display_name": "' + "a" * (6 * 1024 * 1024) + '"}'
        _write_cache(monkeypatch, tmp_path, oversized)
        path = cache_mod._safe_cache_path("alpha.invalid")
        assert path is not None
        _make_path_metadata_stale(monkeypatch, path)

        assert cache_mod.cache_get("alpha.invalid") is None

    def test_ct_cache_get_deeply_nested_returns_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        _write_ct_cache(monkeypatch, tmp_path, _DEEPLY_NESTED_JSON)
        assert ct_cache_mod.ct_cache_get("alpha.invalid") is None

    def test_ct_cache_show_deeply_nested_returns_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        _write_ct_cache(monkeypatch, tmp_path, _DEEPLY_NESTED_JSON)
        assert ct_cache_mod.ct_cache_show("alpha.invalid") is None

    @pytest.mark.parametrize("operation", [ct_cache_mod.ct_cache_get, ct_cache_mod.ct_cache_show])
    def test_ct_cache_reads_bound_the_open_file_when_path_metadata_is_stale(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, operation: Any
    ) -> None:
        oversized = '{"subdomains": ["' + "a" * (6 * 1024 * 1024) + '"]}'
        _write_ct_cache(monkeypatch, tmp_path, oversized)
        path = ct_cache_mod._safe_path("alpha.invalid")
        _make_path_metadata_stale(monkeypatch, path)

        assert operation("alpha.invalid") is None

    @pytest.mark.parametrize("kind", ["tenant", "ct"])
    def test_stale_cache_is_rejected_before_json_decode(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, kind: str
    ) -> None:
        if kind == "tenant":
            _write_cache(monkeypatch, tmp_path, "{}")
            path = cache_mod._safe_cache_path("alpha.invalid")
            operation = cache_mod.cache_get
        else:
            _write_ct_cache(monkeypatch, tmp_path, "{}")
            path = ct_cache_mod._safe_path("alpha.invalid")
            operation = ct_cache_mod.ct_cache_get
        assert path is not None
        old = time.time() - 10 * 86400
        os.utime(path, (old, old))
        def _unexpected_decode(_text: str) -> object:
            raise AssertionError("stale cache body was decoded")

        monkeypatch.setattr("recon_tool.json_limits.json.loads", _unexpected_decode)

        assert operation("alpha.invalid", ttl=1) is None

    def test_rate_limit_load_persisted_degrades_on_poison(self) -> None:
        # A deeply-nested persisted limiter-state file must not crash limiter
        # construction: _load_persisted catches RecursionError and degrades to
        # fresh defaults. RECON_CONFIG_DIR is isolated by the autouse fixture.
        sd = rate_limit_state_dir()
        sd.mkdir(parents=True, exist_ok=True)
        (sd / "poison.json").write_text(_DEEPLY_NESTED_JSON, encoding="utf-8")
        lim = AdaptiveRateLimiter("poison", 0.1, 1.0, persist=True)
        assert lim.name == "poison"

    def test_rate_limit_load_bounds_the_open_file_when_path_metadata_is_stale(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state_path = rate_limit_state_dir() / "oversized.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text("{" + (" " * (6 * 1024 * 1024)) + "}", encoding="utf-8")
        _make_path_metadata_stale(monkeypatch, state_path)

        limiter = AdaptiveRateLimiter("oversized", 0.1, 1.0, persist=True)

        assert limiter.snapshot()["interval_s"] == 0.1

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("consecutive_failures", 1e999),
            ("breaker_remaining_s", 1e999),
            ("interval_s", "NaN"),
            ("interval_s", 10**400),
        ],
    )
    def test_rate_limit_load_rejects_non_finite_or_overflowing_state(self, field: str, value: object) -> None:
        state_path = rate_limit_state_dir() / "poison.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, object] = {
            "_state_version": 1,
            "name": "poison",
            "saved_at": datetime.now(UTC).isoformat(),
            "interval_s": 0.5,
            "current_cooldown_s": 1.0,
            "consecutive_failures": 1,
            "breaker_remaining_s": 0.0,
            field: value,
        }
        state_path.write_text(json.dumps(payload), encoding="utf-8")

        limiter = AdaptiveRateLimiter("poison", 0.1, 1.0, cooldown_s=1.0, persist=True)
        snapshot = limiter.snapshot()

        assert snapshot["interval_s"] == 0.1
        assert snapshot["consecutive_failures"] == 0
        assert snapshot["breaker_open"] is False

    def test_rate_limit_load_rejects_state_bound_to_another_provider(self) -> None:
        state_path = rate_limit_state_dir() / "certspotter.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps(
                {
                    "_state_version": 1,
                    "name": "crt.sh",
                    "saved_at": datetime.now(UTC).isoformat(),
                    "interval_s": 0.9,
                    "current_cooldown_s": 1.0,
                    "consecutive_failures": 1,
                    "breaker_remaining_s": 0.0,
                }
            ),
            encoding="utf-8",
        )

        limiter = AdaptiveRateLimiter("certspotter", 0.1, 1.0, cooldown_s=1.0, persist=True)

        assert limiter.snapshot()["interval_s"] == 0.1

    def test_rate_limit_rejects_traversal_shaped_provider_name(self) -> None:
        with pytest.raises(ValueError, match="name"):
            AdaptiveRateLimiter("../outside", 0.1, 1.0, persist=True)

    def test_rate_limit_persistence_avoids_predictable_temporary_path(self) -> None:
        state_directory = rate_limit_state_dir()
        state_directory.mkdir(parents=True, exist_ok=True)
        predictable = state_directory / "safe.json.tmp"
        predictable.write_text("SENTINEL", encoding="utf-8")

        limiter = AdaptiveRateLimiter("safe", 0.1, 1.0, persist=True)
        limiter._persist_state(force=True)

        assert predictable.read_text(encoding="utf-8") == "SENTINEL"
        payload = json.loads((state_directory / "safe.json").read_text(encoding="utf-8"))
        assert payload["_state_version"] == 1
        assert payload["name"] == "safe"


def _make_path_metadata_stale(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """Make path-level metadata and unbounded reads unsafe for the target."""
    original_stat = Path.stat
    original_read_text = Path.read_text

    def stale_stat(path: Path, *args: Any, **kwargs: Any) -> Any:
        result = original_stat(path, *args, **kwargs)
        if path == target:
            return SimpleNamespace(
                st_size=1,
                st_mtime=result.st_mtime,
                st_mode=result.st_mode,
                st_dev=result.st_dev,
                st_ino=result.st_ino,
            )
        return result

    def reject_unbounded_read(path: Path, *args: Any, **kwargs: Any) -> str:
        if path == target:
            raise AssertionError("cache reader used an unbounded path read after stale metadata")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", stale_stat)
    monkeypatch.setattr(Path, "read_text", reject_unbounded_read)


# ── 3. CT graph is bounded by entry count, not just node count ────────────


class TestInfraGraphEntryBound:
    @staticmethod
    def _reused_san_entries(n: int) -> list[dict[str, Any]]:
        # The same 60-name SAN set on every cert: node count freezes at 60, so
        # MAX_GRAPH_NODES never trips and the entry count is the only dimension.
        sans = [f"h{i}.beta.invalid" for i in range(60)]
        return [
            {"dns_names": list(sans), "issuer_name": "Synthetic Beta CA", "not_before": "2026-01-01T00:00:00Z"}
            for _ in range(n)
        ]

    def test_build_graph_bounds_edge_issuer_samples(self) -> None:
        entries = self._reused_san_entries(5000)
        g, edge_issuers, truncated = _build_graph(entries)
        assert truncated is True, "the entry-count cap should truncate"
        assert g.number_of_nodes() == 60
        # 60-name clique => C(60, 2) = 1770 edges, each capped at the sample bound.
        assert g.number_of_edges() == 1770
        for samples in edge_issuers.values():
            assert len(samples) <= _MAX_EDGE_ISSUER_SAMPLES

    def test_report_builds_on_reused_san_flood(self) -> None:
        report = build_infrastructure_clusters(self._reused_san_entries(5000))
        assert report.node_count == 60
        assert report.edge_count == 1770
        # Above the entry cap, construction is truncated, so it routes to the
        # deterministic connected-components fallback rather than Louvain.
        assert report.algorithm == "connected_components"


# ── 4. CT providers degrade on deeply-nested JSON ─────────────────────────


def _fake_ct_client(body: bytes) -> Any:
    @asynccontextmanager
    async def _cm(*_args: Any, **_kwargs: Any) -> AsyncGenerator[Any, None]:
        class _Client:
            async def get(self, url: str, **_kw: Any) -> httpx.Response:
                return httpx.Response(200, content=body, request=httpx.Request("GET", url))

        yield _Client()

    return _cm


class TestCtProviderRecursionError:
    @pytest.mark.asyncio
    async def test_crtsh_degrades_on_deeply_nested_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recon_tool.sources import cert_providers as cp

        monkeypatch.setattr(cp, "http_client", _fake_ct_client(_DEEPLY_NESTED_JSON.encode()))
        with pytest.raises(httpx.HTTPError):
            await CrtshProvider().query("alpha.invalid")

    @pytest.mark.asyncio
    async def test_certspotter_degrades_on_deeply_nested_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recon_tool.sources import cert_providers as cp

        monkeypatch.setattr(cp, "http_client", _fake_ct_client(_DEEPLY_NESTED_JSON.encode()))
        with pytest.raises(httpx.HTTPError):
            await CertSpotterProvider().query("alpha.invalid")


# ── HTTP retry / redirect bounds ──────────────────────────────────────────


class TestHttpBounds:
    def test_production_bound_constants_are_pinned(self) -> None:
        assert _MAX_RESPONSE_BYTES == 10 * 1024 * 1024
        assert MAX_REDIRECTS == 5
        assert _MAX_TOTAL_RETRY_SLEEP == 30.0
        assert RESOLVE_TIMEOUT == 120.0
        assert dns_base.DNS_QUERY_TIMEOUT == 5.0
        assert dns_base.DNS_QUERY_TIMEOUT < RESOLVE_TIMEOUT
        assert _MAX_TOTAL_RETRY_SLEEP < RESOLVE_TIMEOUT

    @pytest.mark.asyncio
    async def test_client_bounds_redirects(self) -> None:
        """The shared client caps redirects at MAX_REDIRECTS (5), so an
        attacker-influenced redirect chain cannot loop unbounded."""
        async with http_client() as client:
            assert MAX_REDIRECTS == 5
            assert client.max_redirects == MAX_REDIRECTS

    @pytest.mark.asyncio
    async def test_retry_cumulative_sleep_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Repeated 429s with a large Retry-After cannot stack retry sleep past
        _MAX_TOTAL_RETRY_SLEEP (30s), so an attacker-influenced endpoint cannot
        burn the aggregate resolve budget through rate-limit backoff."""
        slept: list[float] = []

        async def _record(seconds: float) -> None:
            slept.append(seconds)

        monkeypatch.setattr("recon_tool.http.asyncio.sleep", _record)

        class _Always429(httpx.AsyncHTTPTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(429, headers={"Retry-After": "30"}, content=b"", request=request)

        transport = _RetryTransport(wrapped=_Always429())
        resp = await transport.handle_async_request(httpx.Request("GET", "https://example.com/"))
        assert resp.status_code == 429  # last response returned after retries exhausted
        assert sum(slept) <= _MAX_TOTAL_RETRY_SLEEP + 1e-9


class TestDnsBounds:
    @pytest.mark.asyncio
    async def test_safe_resolve_uses_production_query_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import dns.exception

        class _TimeoutResolver:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, float]] = []

            async def resolve(self, domain: str, rdtype: str, *, lifetime: float) -> list[str]:
                self.calls.append((domain, rdtype, lifetime))
                raise dns.exception.Timeout

        resolver = _TimeoutResolver()
        monkeypatch.setattr(dns_base, "get_resolver", lambda: resolver)

        assert await dns_base.safe_resolve("alpha.invalid", "TXT") == []
        assert resolver.calls == [("alpha.invalid", "TXT", dns_base.DNS_QUERY_TIMEOUT)]
