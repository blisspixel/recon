"""Unit tests for CertIntelProvider protocol, CrtshProvider, CertSpotterProvider.

Covers: protocol conformance, provider names, HTTP error handling,
shared filtering helpers, CertSummary construction, CertSpotter request shape.

Requirements: 1.1, 1.2, 1.3, 2.1–2.7, 3.1–3.8, 11.5, 11.6
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from recon_tool.sources.cert_providers import (
    MAX_SUBDOMAINS,
    CertIntelProvider,
    CertSpotterProvider,
    CrtshProvider,
    build_cert_summary,
    filter_subdomains,
)

# ── Protocol conformance ────────────────────────────────────────────────


class TestProtocolConformance:
    def test_crtsh_implements_protocol(self):
        assert isinstance(CrtshProvider(), CertIntelProvider)

    def test_certspotter_implements_protocol(self):
        assert isinstance(CertSpotterProvider(), CertIntelProvider)


# ── Provider name properties ────────────────────────────────────────────


class TestProviderNames:
    def test_crtsh_name(self):
        assert CrtshProvider().name == "crt.sh"

    def test_certspotter_name(self):
        assert CertSpotterProvider().name == "certspotter"


# ── HTTP error handling ─────────────────────────────────────────────────


def _mock_http_context(mock_client):
    """Build a patched http_client context manager returning mock_client."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


@pytest.mark.usefixtures("_enable_crtsh")
class TestCrtshHttpErrors:
    @pytest.fixture
    def _enable_crtsh(self):
        """Override conftest auto-mock for these tests."""

    @pytest.mark.asyncio
    async def test_raises_on_400(self):
        provider = CrtshProvider()
        resp = MagicMock(status_code=400, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_500(self):
        provider = CrtshProvider()
        resp = MagicMock(status_code=500, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_503(self):
        provider = CrtshProvider()
        resp = MagicMock(status_code=503, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self):
        provider = CrtshProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.TimeoutException),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_connect_error(self):
        provider = CrtshProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.ConnectError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_invalid_json(self):
        provider = CrtshProvider()
        resp = MagicMock(status_code=200, request=MagicMock())
        resp.json.side_effect = ValueError("malformed json")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPError, match="invalid JSON"),
        ):
            await provider.query("example.com")


@pytest.mark.usefixtures("_enable_crtsh")
class TestCertSpotterHttpErrors:
    @pytest.fixture
    def _enable_crtsh(self):
        """Override conftest auto-mock for these tests."""

    @pytest.mark.asyncio
    async def test_raises_on_400(self):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=400, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_503(self):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=503, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self):
        provider = CertSpotterProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.TimeoutException),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_connect_error(self):
        provider = CertSpotterProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.ConnectError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_raises_on_invalid_json(self):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=200, request=MagicMock())
        resp.json.side_effect = ValueError("malformed json")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            pytest.raises(httpx.HTTPError, match="invalid JSON"),
        ):
            await provider.query("example.com")


# ── Shared filtering helpers ────────────────────────────────────────────


class TestFilterSubdomains:
    def test_removes_wildcards(self):
        raw = ["*.example.com", "app.example.com"]
        result = filter_subdomains(raw, "example.com")
        assert "app.example.com" in result
        assert all("*" not in r for r in result)

    def test_removes_noise_prefixes(self):
        raw = ["www.example.com", "mail.example.com", "ftp.example.com", "api.example.com"]
        result = filter_subdomains(raw, "example.com")
        assert "api.example.com" in result
        for prefix in ("www.", "mail.", "ftp."):
            assert not any(r.startswith(prefix) for r in result)

    def test_validates_subdomain_of_domain(self):
        raw = ["app.example.com", "app.other.com", "notexample.com"]
        result = filter_subdomains(raw, "example.com")
        assert "app.example.com" in result
        assert "app.other.com" not in result
        assert "notexample.com" not in result

    def test_excludes_domain_itself(self):
        raw = ["example.com", "sub.example.com"]
        result = filter_subdomains(raw, "example.com")
        assert "example.com" not in result
        assert "sub.example.com" in result

    def test_caps_at_max_subdomains(self):
        raw = [f"sub{i}.example.com" for i in range(200)]
        result = filter_subdomains(raw, "example.com")
        assert len(result) <= MAX_SUBDOMAINS

    def test_case_insensitive(self):
        raw = ["APP.EXAMPLE.COM", "Dev.Example.Com"]
        result = filter_subdomains(raw, "example.com")
        assert "app.example.com" in result
        assert "dev.example.com" in result

    def test_empty_input(self):
        assert filter_subdomains([], "example.com") == []

    def test_high_signal_prefixes_sorted_first(self):
        raw = ["zzz.example.com", "auth.example.com", "aaa.example.com"]
        result = filter_subdomains(raw, "example.com")
        auth_idx = result.index("auth.example.com")
        zzz_idx = result.index("zzz.example.com")
        assert auth_idx < zzz_idx


# ── CertSummary construction ────────────────────────────────────────────


class TestBuildCertSummary:
    def test_basic_construction(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            {
                "issuer_id": "1",
                "issuer_name": "Let's Encrypt",
                "not_before": "2024-03-01T00:00:00",
                "not_after": "2024-06-01T00:00:00",
            },
            {
                "issuer_id": "2",
                "issuer_name": "DigiCert",
                "not_before": "2024-01-01T00:00:00",
                "not_after": "2024-12-01T00:00:00",
            },
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert cs.cert_count == 2
        assert cs.issuer_diversity == 2
        assert cs.newest_cert_age_days >= 0
        assert cs.oldest_cert_age_days >= cs.newest_cert_age_days
        assert len(cs.top_issuers) <= 3

    def test_returns_none_for_empty(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        assert build_cert_summary([], now) is None

    def test_returns_none_for_invalid_entries(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [{"issuer_id": None, "issuer_name": None, "not_before": None, "not_after": None}]
        assert build_cert_summary(entries, now) is None

    def test_issuance_velocity_counts_recent(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            {
                "issuer_id": "1",
                "issuer_name": "LE",
                "not_before": "2024-05-01T00:00:00",
                "not_after": "2024-08-01T00:00:00",
            },
            {
                "issuer_id": "1",
                "issuer_name": "LE",
                "not_before": "2023-01-01T00:00:00",
                "not_after": "2024-01-01T00:00:00",
            },
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert cs.issuance_velocity == 1

    def test_top_issuers_capped_at_3(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            {
                "issuer_id": str(i),
                "issuer_name": f"CA{i}",
                "not_before": "2024-01-01T00:00:00",
                "not_after": "2025-01-01T00:00:00",
            }
            for i in range(10)
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert len(cs.top_issuers) <= 3

    def test_no_dns_names_means_no_clusters_or_bursts(self):
        """Pre-v1.7 entry shape (no dns_names key) must still build cleanly."""
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            {
                "issuer_id": "1",
                "issuer_name": "LE",
                "not_before": "2024-05-01T00:00:00",
                "not_after": "2024-08-01T00:00:00",
            },
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert cs.wildcard_sibling_clusters == ()
        assert cs.deployment_bursts == ()

    def test_certspotter_z_suffix_dates_parse(self):
        """Regression — Python 3.10's fromisoformat rejects 'Z' UTC marker.

        CertSpotter (and many CT log emitters) end timestamps in 'Z'.
        Without normalisation, every entry was silently skipped and
        cert_summary returned None — surfaced during the v1.8 validation
        run on a 105-domain corpus (0/105 had cert_summary populated
        before the fix).
        """
        now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        entries = [
            {
                "issuer_id": "DigiCert",
                "issuer_name": "DigiCert",
                "not_before": "2025-04-03T00:00:00Z",
                "not_after": "2026-05-04T23:59:59Z",
                "dns_names": ["a.example.com", "b.example.com"],
            },
            {
                "issuer_id": "LE",
                "issuer_name": "Let's Encrypt",
                "not_before": "2025-12-15T12:34:56.789Z",
                "not_after": "2026-03-15T12:34:56.789Z",
                "dns_names": ["c.example.com"],
            },
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert cs.cert_count == 2
        assert cs.issuer_diversity == 2
        assert "DigiCert" in cs.top_issuers
        assert "Let's Encrypt" in cs.top_issuers


# ── Wildcard SAN sibling clusters (v1.7) ─────────────────────────────────


class TestWildcardSiblingClusters:
    """A cert with ≥1 wildcard SAN exposes its concrete-name peers."""

    def _entry(self, names, when="2024-05-01T00:00:00"):
        return {
            "issuer_id": "le",
            "issuer_name": "Let's Encrypt",
            "not_before": when,
            "not_after": "2025-05-01T00:00:00",
            "dns_names": list(names),
        }

    def test_wildcard_with_concrete_siblings_emits_cluster(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        cs = build_cert_summary(
            [self._entry(["*.example.com", "example.com", "api.example.com"])],
            now,
        )
        assert cs is not None
        assert cs.wildcard_sibling_clusters == (("api.example.com", "example.com"),)

    def test_no_wildcard_means_no_cluster(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        cs = build_cert_summary([self._entry(["example.com", "api.example.com"])], now)
        assert cs is not None
        assert cs.wildcard_sibling_clusters == ()

    def test_only_wildcards_means_no_cluster(self):
        """A cert covering only wildcards has no concrete sibling to harvest."""
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        cs = build_cert_summary([self._entry(["*.example.com", "*.api.example.com"])], now)
        assert cs is not None
        assert cs.wildcard_sibling_clusters == ()

    def test_duplicate_clusters_deduped_across_renewals(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            self._entry(["*.example.com", "example.com", "api.example.com"], when="2024-01-01T00:00:00"),
            self._entry(["*.example.com", "example.com", "api.example.com"], when="2024-04-01T00:00:00"),
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert len(cs.wildcard_sibling_clusters) == 1

    def test_clusters_capped(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            self._entry(
                [f"*.zone{i}.example.com", f"node{i}.zone{i}.example.com"],
                when=f"2024-0{(i % 9) + 1}-01T00:00:00",
            )
            for i in range(15)
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert len(cs.wildcard_sibling_clusters) <= 10


# ── Temporal CT issuance bursts (v1.7) ───────────────────────────────────


class TestDeploymentBursts:
    """Co-issued certificates within a short window become a burst."""

    def _entry(self, when, names):
        return {
            "issuer_id": "le",
            "issuer_name": "Let's Encrypt",
            "not_before": when,
            "not_after": "2025-05-01T00:00:00",
            "dns_names": list(names),
        }

    def test_three_co_issued_names_form_burst(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            self._entry("2024-05-01T12:00:00", ["api.example.com"]),
            self._entry("2024-05-01T12:00:30", ["app.example.com"]),
            self._entry("2024-05-01T12:00:45", ["www.example.com"]),
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert len(cs.deployment_bursts) == 1
        burst = cs.deployment_bursts[0]
        assert burst.span_seconds <= 60
        assert set(burst.names) == {"api.example.com", "app.example.com", "www.example.com"}

    def test_two_names_does_not_form_burst(self):
        """Below the min_burst_names threshold."""
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            self._entry("2024-05-01T12:00:00", ["api.example.com"]),
            self._entry("2024-05-01T12:00:30", ["app.example.com"]),
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert cs.deployment_bursts == ()

    def test_separate_windows_yield_separate_bursts(self):
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            self._entry("2024-05-01T12:00:00", ["a.example.com"]),
            self._entry("2024-05-01T12:00:10", ["b.example.com"]),
            self._entry("2024-05-01T12:00:20", ["c.example.com"]),
            # Far outside the 60-second window:
            self._entry("2024-05-15T03:00:00", ["x.example.com"]),
            self._entry("2024-05-15T03:00:30", ["y.example.com"]),
            self._entry("2024-05-15T03:00:45", ["z.example.com"]),
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert len(cs.deployment_bursts) == 2

    def test_wildcards_excluded_from_burst_names(self):
        """Wildcards never count toward burst output (the wildcard fact is its own signal)."""
        now = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entries = [
            self._entry("2024-05-01T12:00:00", ["*.example.com", "a.example.com"]),
            self._entry("2024-05-01T12:00:10", ["b.example.com"]),
            self._entry("2024-05-01T12:00:20", ["c.example.com"]),
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert len(cs.deployment_bursts) == 1
        assert all(not n.startswith("*.") for n in cs.deployment_bursts[0].names)


# ── CertSpotter request shape ───────────────────────────────────────────


@pytest.mark.usefixtures("_enable_crtsh")
class TestCertSpotterRequestShape:
    @pytest.fixture
    def _enable_crtsh(self):
        """Override conftest auto-mock."""

    @pytest.mark.asyncio
    async def test_correct_url_and_params(self):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=200)
        resp.json.return_value = []
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            await provider.query("example.com")

        client.get.assert_called_once()
        call_args = client.get.call_args
        url = call_args[0][0]
        params = call_args[1].get("params")

        assert "api.certspotter.com" in url
        assert params["domain"] == "example.com"
        assert params["include_subdomains"] == "true"

    @pytest.mark.asyncio
    async def test_no_auth_headers(self):
        """CertSpotter requests must not include Authorization headers."""
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=200)
        resp.json.return_value = []
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            await provider.query("example.com")

        call_kwargs = client.get.call_args[1]
        headers = call_kwargs.get("headers", {})
        assert "Authorization" not in headers
        assert "authorization" not in headers


# ── R4 (v0.9.2): Pagination + rate-limit handling ───────────────────────


def _issuance(idx: int, dns_name: str) -> dict:
    """Build a minimal CertSpotter issuance record for tests."""
    return {
        "id": str(idx),
        "dns_names": [dns_name],
        "issuer": {"friendly_name": "Test CA"},
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
    }


class TestCertSpotterPagination:
    """v0.9.2 R4: CertSpotter pagination follows the after= cursor."""

    @pytest.mark.asyncio
    async def test_single_page_no_pagination_when_empty_next_page(self):
        """A full first page followed by an empty second page stops at 2 requests."""
        provider = CertSpotterProvider()
        page1 = [_issuance(i, f"host{i}.example.com") for i in range(5)]
        page2: list[dict] = []

        responses = [
            MagicMock(status_code=200, json=MagicMock(return_value=page1)),
            MagicMock(status_code=200, json=MagicMock(return_value=page2)),
        ]
        client = AsyncMock()
        client.get = AsyncMock(side_effect=responses)

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            subs, _summary, _clusters = await provider.query("example.com")

        assert client.get.call_count == 2
        assert len(subs) == 5

    @pytest.mark.asyncio
    async def test_pagination_advances_after_cursor(self):
        """Second request includes after=<last id from page 1>."""
        provider = CertSpotterProvider()
        page1 = [_issuance(i, f"host{i}.example.com") for i in range(3)]
        page2 = [_issuance(i, f"api{i}.example.com") for i in range(3, 6)]

        responses = [
            MagicMock(status_code=200, json=MagicMock(return_value=page1)),
            MagicMock(status_code=200, json=MagicMock(return_value=page2)),
        ]
        client = AsyncMock()
        client.get = AsyncMock(side_effect=responses)

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            subs, _summary, _clusters = await provider.query("example.com")

        # _MAX_PAGES=2 — we stop after page 2; no third call.
        assert client.get.call_count == 2
        # First call has no after=
        first_params = client.get.call_args_list[0][1]["params"]
        assert "after" not in first_params
        # Second call uses last id from page 1 ("2")
        second_params = client.get.call_args_list[1][1]["params"]
        assert second_params["after"] == "2"
        # All 6 subdomains from pages 1 and 2 collected
        assert len(subs) == 6

    @pytest.mark.asyncio
    async def test_pagination_respects_max_pages_cap(self):
        """Never fetches more than _MAX_PAGES pages even with endless data."""
        provider = CertSpotterProvider()
        # Each page returns 3 unique subdomains; _MAX_PAGES cap should stop us.
        calls = {"n": 0}

        def make_response(*args, **kwargs):
            calls["n"] += 1
            idx = calls["n"]
            page = [_issuance(idx * 10 + j, f"host-p{idx}-{j}.example.com") for j in range(3)]
            return MagicMock(status_code=200, json=MagicMock(return_value=page))

        client = AsyncMock()
        client.get = AsyncMock(side_effect=make_response)

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            subs, _summary, _clusters = await provider.query("example.com")

        assert client.get.call_count == provider._MAX_PAGES
        assert len(subs) == provider._MAX_PAGES * 3

    @pytest.mark.asyncio
    async def test_429_stops_pagination_returns_partial_data(self):
        """A 429 response stops pagination and returns what's been collected."""
        provider = CertSpotterProvider()
        page1 = [_issuance(i, f"host{i}.example.com") for i in range(4)]
        page2_rate_limited = MagicMock(status_code=429)

        responses = [
            MagicMock(status_code=200, json=MagicMock(return_value=page1)),
            page2_rate_limited,
        ]
        client = AsyncMock()
        client.get = AsyncMock(side_effect=responses)

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            subs, _summary, _clusters = await provider.query("example.com")

        # Pagination stopped at 429, but page 1 data is still returned
        assert client.get.call_count == 2
        assert len(subs) == 4  # from page 1

    @pytest.mark.asyncio
    async def test_non_429_error_still_raises(self):
        """A 500 on the second page raises — only 429 is handled gracefully."""
        provider = CertSpotterProvider()
        page1 = [_issuance(i, f"host{i}.example.com") for i in range(3)]
        page2_server_error = MagicMock(status_code=500, request=MagicMock())

        responses = [
            MagicMock(status_code=200, json=MagicMock(return_value=page1)),
            page2_server_error,
        ]
        client = AsyncMock()
        client.get = AsyncMock(side_effect=responses)

        with (
            patch(
                "recon_tool.sources.cert_providers.http_client",
                return_value=_mock_http_context(client),
            ),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")

    @pytest.mark.asyncio
    async def test_empty_first_page_returns_empty(self):
        """When the first page is empty, pagination stops immediately."""
        provider = CertSpotterProvider()
        client = AsyncMock()
        client.get = AsyncMock(return_value=MagicMock(status_code=200, json=MagicMock(return_value=[])))

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            subs, summary, clusters = await provider.query("example.com")

        assert client.get.call_count == 1
        assert subs == []
        assert summary is None
        assert clusters is None

    @pytest.mark.asyncio
    async def test_missing_issuance_id_stops_pagination(self):
        """If an issuance lacks an id field, we can't advance — stop cleanly."""
        provider = CertSpotterProvider()
        page1 = [
            {
                "dns_names": ["host.example.com"],
                "issuer": {"friendly_name": "Test CA"},
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            }
        ]
        client = AsyncMock()
        client.get = AsyncMock(return_value=MagicMock(status_code=200, json=MagicMock(return_value=page1)))

        with patch(
            "recon_tool.sources.cert_providers.http_client",
            return_value=_mock_http_context(client),
        ):
            subs, _summary, _clusters = await provider.query("example.com")

        # Without an id, we cannot advance the cursor — so only one call.
        assert client.get.call_count == 1
        assert len(subs) == 1

    @pytest.mark.asyncio
    async def test_transient_failure_propagates_without_retry(self):
        """Page-level retries on transient httpx errors were removed: three 8s
        ReadTimeouts per page accumulated >25s of pure delay on slow-CT targets,
        blowing the aggregate resolve budget. On a transient failure, the
        exception now propagates out of query() so the fallback chain can
        mark the provider degraded and move on."""
        provider = CertSpotterProvider()
        page1 = [_issuance(i, f"a{i}.example.com") for i in range(3)]

        # Page 1 succeeds; page 2 hits a ConnectError. With retry removed,
        # the exception propagates — caller sees the failure, NOT partial data.
        responses = [
            MagicMock(status_code=200, json=MagicMock(return_value=page1)),
            httpx.ConnectError("transient"),
        ]
        client = AsyncMock()
        client.get = AsyncMock(side_effect=responses)

        with (
            patch(
                "recon_tool.sources.cert_providers.http_client",
                return_value=_mock_http_context(client),
            ),
            pytest.raises(httpx.ConnectError),
        ):
            await provider.query("example.com")

        # Exactly 2 calls: page 1 ok, page 2 raised, no retry.
        assert client.get.call_count == 2

    @pytest.mark.asyncio
    async def test_persistent_transient_failure_eventually_propagates(self):
        """When transient failures persist past the retry budget, the error
        propagates out so the fallback chain can record the failure. Used
        by _detect_cert_intel to mark the provider as degraded."""
        provider = CertSpotterProvider()
        page1 = [_issuance(i, f"a{i}.example.com") for i in range(3)]

        # Page 1 ok, page 2 fails 3 times in a row (initial + 2 retries)
        responses = [
            MagicMock(status_code=200, json=MagicMock(return_value=page1)),
            httpx.ConnectError("persistent"),
            httpx.ConnectError("persistent"),
            httpx.ConnectError("persistent"),
        ]
        client = AsyncMock()
        client.get = AsyncMock(side_effect=responses)

        with (
            patch(
                "recon_tool.sources.cert_providers.http_client",
                return_value=_mock_http_context(client),
            ),
            pytest.raises(httpx.ConnectError),
        ):
            await provider.query("example.com")
