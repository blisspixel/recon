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
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest

from recon_tool import cache as cache_mod
from recon_tool import ct_cache as ct_cache_mod
from recon_tool.http import (
    _COMPRESSING_ENCODINGS,
    _MaxBytesStream,
    _RefusingStream,
    _SSRFSafeTransport,
    http_client,
)
from recon_tool.infra_graph import _MAX_EDGE_ISSUER_SAMPLES, _build_graph, build_infrastructure_clusters
from recon_tool.sources.cert_providers import CertSpotterProvider, CrtshProvider

# Part of the dedicated hostile-input fuzz gate (run with `-m hostile_input`).
pytestmark = pytest.mark.hostile_input

# A JSON document nested far past the interpreter recursion limit. json.loads
# raises RecursionError (a RuntimeError, not a ValueError) on it.
_DEEPLY_NESTED_JSON = "[" * 100_000 + "]" * 100_000


class _FakeStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncGenerator[bytes]:
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        return None


# ── 1. HTTP decompression bomb ───────────────────────────────────────────


class TestDecompressionBombGuard:
    @pytest.mark.asyncio
    async def test_refusing_stream_raises_on_read(self) -> None:
        stream = _RefusingStream("gzip")
        with pytest.raises(httpx.ReadError):
            async for _chunk in stream:
                pass

    @pytest.mark.asyncio
    async def test_transport_refuses_compressed_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A compressing Content-Encoding (despite identity) is refused, not decoded."""
        from recon_tool import http as http_mod

        async def _not_private(_host: str) -> bool:
            return False

        crafted = httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            stream=_FakeStream([b"\x1f\x8b" + b"\x00" * 64]),
            request=httpx.Request("GET", "https://cse.contoso.com/x"),
        )

        async def _fake_super(_self: Any, _request: httpx.Request) -> httpx.Response:
            return crafted

        monkeypatch.setattr(http_mod, "_is_private_ip_async", _not_private)
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _fake_super)

        resp = await _SSRFSafeTransport().handle_async_request(httpx.Request("GET", "https://cse.contoso.com/x"))
        assert isinstance(resp.stream, _RefusingStream)
        with pytest.raises(httpx.ReadError):
            async for _chunk in resp.stream:  # type: ignore[union-attr]
                pass

    @pytest.mark.asyncio
    async def test_transport_caps_identity_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An uncompressed (identity) response is wrapped in the byte cap, not refused."""
        from recon_tool import http as http_mod

        async def _not_private(_host: str) -> bool:
            return False

        crafted = httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=_FakeStream([b'{"ok": true}']),
            request=httpx.Request("GET", "https://crt.sh/x"),
        )

        async def _fake_super(_self: Any, _request: httpx.Request) -> httpx.Response:
            return crafted

        monkeypatch.setattr(http_mod, "_is_private_ip_async", _not_private)
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _fake_super)

        resp = await _SSRFSafeTransport().handle_async_request(httpx.Request("GET", "https://crt.sh/x"))
        assert isinstance(resp.stream, _MaxBytesStream)

    @pytest.mark.asyncio
    async def test_client_requests_identity_encoding(self) -> None:
        async with http_client() as client:
            assert client.headers.get("accept-encoding") == "identity"

    def test_compressing_encodings_cover_the_common_codecs(self) -> None:
        assert {"gzip", "deflate", "br"} <= _COMPRESSING_ENCODINGS


# ── 2. Poisoned cache files degrade to a clean miss ──────────────────────


def _write_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Any, content: str) -> None:
    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    path = cache_mod._safe_cache_path("contoso.com")
    assert path is not None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_ct_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Any, content: str) -> None:
    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    path = ct_cache_mod._safe_path("contoso.com")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class TestPoisonedCacheDegrades:
    def test_cache_get_deeply_nested_returns_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        # Sanity: this payload really does raise RecursionError, not ValueError.
        with pytest.raises(RecursionError):
            json.loads(_DEEPLY_NESTED_JSON)
        _write_cache(monkeypatch, tmp_path, _DEEPLY_NESTED_JSON)
        assert cache_mod.cache_get("contoso.com") is None

    def test_cache_get_oversized_returns_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        oversized = '{"display_name": "' + "a" * (6 * 1024 * 1024) + '"}'
        _write_cache(monkeypatch, tmp_path, oversized)
        assert cache_mod.cache_get("contoso.com") is None

    def test_ct_cache_get_deeply_nested_returns_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        _write_ct_cache(monkeypatch, tmp_path, _DEEPLY_NESTED_JSON)
        assert ct_cache_mod.ct_cache_get("contoso.com") is None

    def test_ct_cache_show_deeply_nested_returns_none(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        _write_ct_cache(monkeypatch, tmp_path, _DEEPLY_NESTED_JSON)
        assert ct_cache_mod.ct_cache_show("contoso.com") is None


# ── 3. CT graph is bounded by entry count, not just node count ────────────


class TestInfraGraphEntryBound:
    @staticmethod
    def _reused_san_entries(n: int) -> list[dict[str, Any]]:
        # The same 60-name SAN set on every cert: node count freezes at 60, so
        # MAX_GRAPH_NODES never trips and the entry count is the only dimension.
        sans = [f"h{i}.fabrikam.com" for i in range(60)]
        return [
            {"dns_names": list(sans), "issuer_name": "Fabrikam CA", "not_before": "2026-01-01T00:00:00Z"}
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
            await CrtshProvider().query("contoso.com")

    @pytest.mark.asyncio
    async def test_certspotter_degrades_on_deeply_nested_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recon_tool.sources import cert_providers as cp

        monkeypatch.setattr(cp, "http_client", _fake_ct_client(_DEEPLY_NESTED_JSON.encode()))
        with pytest.raises(httpx.HTTPError):
            await CertSpotterProvider().query("contoso.com")
