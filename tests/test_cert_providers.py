"""Unit tests for CertIntelProvider protocol, CrtshProvider, CertSpotterProvider.

Covers: protocol conformance, provider names, HTTP error handling,
shared filtering helpers, CertSummary construction, CertSpotter request shape.

Requirements: 1.1, 1.2, 1.3, 2.1–2.7, 3.1–3.8, 11.5, 11.6
"""

from __future__ import annotations

from datetime import UTC, datetime
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

    @pytest.fixture
    def limiter(self) -> MagicMock:
        limiter = MagicMock()
        limiter.acquire = AsyncMock()
        return limiter

    @pytest.mark.asyncio
    async def test_raises_on_400(self, limiter: MagicMock):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=400, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            patch("recon_tool.sources.cert_providers.ct_rate_limiter_certspotter", return_value=limiter),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")
        limiter.on_other_failure.assert_called_once_with()
        limiter.on_rate_limited.assert_not_called()

    @pytest.mark.asyncio
    async def test_raises_on_503(self, limiter: MagicMock):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=503, request=MagicMock())
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            patch("recon_tool.sources.cert_providers.ct_rate_limiter_certspotter", return_value=limiter),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await provider.query("example.com")
        limiter.on_other_failure.assert_called_once_with()
        limiter.on_rate_limited.assert_not_called()

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self, limiter: MagicMock):
        provider = CertSpotterProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            patch("recon_tool.sources.cert_providers.ct_rate_limiter_certspotter", return_value=limiter),
            pytest.raises(httpx.TimeoutException),
        ):
            await provider.query("example.com")
        limiter.on_other_failure.assert_called_once_with()
        limiter.on_rate_limited.assert_not_called()

    @pytest.mark.asyncio
    async def test_raises_on_connect_error(self, limiter: MagicMock):
        provider = CertSpotterProvider()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            patch("recon_tool.sources.cert_providers.ct_rate_limiter_certspotter", return_value=limiter),
            pytest.raises(httpx.ConnectError),
        ):
            await provider.query("example.com")
        limiter.on_other_failure.assert_called_once_with()
        limiter.on_rate_limited.assert_not_called()

    @pytest.mark.asyncio
    async def test_raises_on_invalid_json(self, limiter: MagicMock):
        provider = CertSpotterProvider()
        resp = MagicMock(status_code=200, request=MagicMock())
        resp.json.side_effect = ValueError("malformed json")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            patch("recon_tool.sources.cert_providers.ct_rate_limiter_certspotter", return_value=limiter),
            pytest.raises(httpx.HTTPError, match="invalid JSON"),
        ):
            await provider.query("example.com")
        limiter.on_other_failure.assert_called_once_with()
        limiter.on_rate_limited.assert_not_called()

    @pytest.mark.asyncio
    async def test_429_uses_only_rate_limit_accounting(self, limiter: MagicMock):
        provider = CertSpotterProvider()
        response = httpx.Response(
            429,
            request=httpx.Request("GET", "https://api.certspotter.com/v1/issuances"),
        )
        client = AsyncMock()
        client.get = AsyncMock(return_value=response)

        with (
            patch("recon_tool.sources.cert_providers.http_client", return_value=_mock_http_context(client)),
            patch("recon_tool.sources.cert_providers.ct_rate_limiter_certspotter", return_value=limiter),
            pytest.raises(httpx.HTTPError, match="rate-limited"),
        ):
            await provider.query("example.com")

        limiter.on_rate_limited.assert_called_once_with(retry_after_s=None)
        limiter.on_other_failure.assert_not_called()


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
        raw = ["app.example.com", "app.other.invalid", "notexample.invalid"]
        result = filter_subdomains(raw, "example.com")
        assert "app.example.com" in result
        assert "app.other.invalid" not in result
        assert "notexample.invalid" not in result

    def test_suffix_match_is_not_high_signal(self):
        # "webapp" ends with the high-signal prefix "app" but is not itself a
        # high-signal prefix, so it must not be ordered ahead of an
        # alphabetically earlier plain subdomain. Regression: the sort key used
        # endswith, which matched prefixes as suffixes.
        result = filter_subdomains(["webapp.example.com", "aaa.example.com"], "example.com")
        assert result.index("aaa.example.com") < result.index("webapp.example.com")

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
        now = datetime(2024, 6, 1, tzinfo=UTC)
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
        now = datetime(2024, 6, 1, tzinfo=UTC)
        assert build_cert_summary([], now) is None

    def test_returns_none_for_invalid_entries(self):
        now = datetime(2024, 6, 1, tzinfo=UTC)
        entries = [{"issuer_id": None, "issuer_name": None, "not_before": None, "not_after": None}]
        assert build_cert_summary(entries, now) is None

    def test_issuance_velocity_counts_recent(self):
        now = datetime(2024, 6, 1, tzinfo=UTC)
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
        now = datetime(2024, 6, 1, tzinfo=UTC)
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
        now = datetime(2024, 6, 1, tzinfo=UTC)
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
        now = datetime(2026, 6, 1, tzinfo=UTC)
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


# ── Wildcard SAN sibling clusters ────────────────────────────────────────


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
        now = datetime(2024, 6, 1, tzinfo=UTC)
        cs = build_cert_summary(
            [self._entry(["*.example.com", "example.com", "api.example.com"])],
            now,
        )
        assert cs is not None
        assert cs.wildcard_sibling_clusters == (("api.example.com", "example.com"),)

    def test_no_wildcard_means_no_cluster(self):
        now = datetime(2024, 6, 1, tzinfo=UTC)
        cs = build_cert_summary([self._entry(["example.com", "api.example.com"])], now)
        assert cs is not None
        assert cs.wildcard_sibling_clusters == ()

    def test_only_wildcards_means_no_cluster(self):
        """A cert covering only wildcards has no concrete sibling to harvest."""
        now = datetime(2024, 6, 1, tzinfo=UTC)
        cs = build_cert_summary([self._entry(["*.example.com", "*.api.example.com"])], now)
        assert cs is not None
        assert cs.wildcard_sibling_clusters == ()

    def test_duplicate_clusters_deduped_across_renewals(self):
        now = datetime(2024, 6, 1, tzinfo=UTC)
        entries = [
            self._entry(["*.example.com", "example.com", "api.example.com"], when="2024-01-01T00:00:00"),
            self._entry(["*.example.com", "example.com", "api.example.com"], when="2024-04-01T00:00:00"),
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert len(cs.wildcard_sibling_clusters) == 1

    def test_clusters_capped(self):
        now = datetime(2024, 6, 1, tzinfo=UTC)
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


# ── Temporal CT issuance bursts ──────────────────────────────────────────


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
        now = datetime(2024, 6, 1, tzinfo=UTC)
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
        now = datetime(2024, 6, 1, tzinfo=UTC)
        entries = [
            self._entry("2024-05-01T12:00:00", ["api.example.com"]),
            self._entry("2024-05-01T12:00:30", ["app.example.com"]),
        ]
        cs = build_cert_summary(entries, now)
        assert cs is not None
        assert cs.deployment_bursts == ()

    def test_separate_windows_yield_separate_bursts(self):
        now = datetime(2024, 6, 1, tzinfo=UTC)
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
        now = datetime(2024, 6, 1, tzinfo=UTC)
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


# ── R4: Pagination + rate-limit handling ────────────────────────────────


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
    """R4: CertSpotter pagination follows the after= cursor."""

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
    async def test_429_stops_pagination_returns_partial_data(self, monkeypatch: pytest.MonkeyPatch):
        """A 429 response stops pagination and returns what's been collected."""
        provider = CertSpotterProvider()
        page1 = [_issuance(i, f"host{i}.example.com") for i in range(4)]
        page2_rate_limited = httpx.Response(
            429,
            headers={"Retry-After": "1"},
            request=httpx.Request("GET", "https://api.certspotter.com/v1/issuances"),
        )
        retry_delays: list[float] = []

        async def capture_sleep(delay: float) -> None:
            retry_delays.append(delay)

        monkeypatch.setattr("recon_tool.sources.cert_providers.asyncio.sleep", capture_sleep)

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
        assert retry_delays == [1.0]

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


class TestCertSpotterAggregateBounds:
    def test_total_retained_sans_are_capped_across_entries(self) -> None:
        from recon_tool.sources.cert_providers import (
            _MAX_CRTSH_CERT_SUMMARY_ENTRIES,
            _MAX_CRTSH_RAW_NAMES,
            _MAX_SANS_PER_CERT,
        )

        issuance = _issuance(1, "same.example.com")
        issuance["dns_names"] = ["same.example.com"] * _MAX_SANS_PER_CERT
        raw_names: list[str] = []
        cert_entries: list[dict[str, str | int | list[str] | None]] = []

        CertSpotterProvider._accumulate_issuances(
            [issuance] * _MAX_CRTSH_CERT_SUMMARY_ENTRIES,
            raw_names,
            cert_entries,
        )

        retained_entry_names = sum(
            len(names)
            for entry in cert_entries
            if isinstance((names := entry.get("dns_names")), list)
        )
        assert len(raw_names) == _MAX_CRTSH_RAW_NAMES
        assert retained_entry_names == _MAX_CRTSH_RAW_NAMES
        assert len(cert_entries) == _MAX_CRTSH_CERT_SUMMARY_ENTRIES


# ── Attacker-controlled CT data sanitization ────────────────────────────


class TestCertDataSanitization:
    """CT SAN values and issuer names are attacker-influenceable (anyone
    can log a cert for a domain they own to a public CT log). These pin
    that control bytes and non-DNS characters cannot flow into
    related_domains or top_issuers, where they would be an ANSI-escape /
    newline injection vector in the rendered panel and MCP output."""

    def test_is_safe_san_name_allows_dns_chars(self):
        from recon_tool.sources.cert_providers import _is_safe_san_name

        assert _is_safe_san_name("app.example.com")
        assert _is_safe_san_name("sel._domainkey.example.com")  # underscore
        assert _is_safe_san_name("*.example.com")  # wildcard label
        assert _is_safe_san_name("App.Example.Com")  # case-insensitive

    def test_is_safe_san_name_rejects_control_and_non_dns(self):
        from recon_tool.sources.cert_providers import _is_safe_san_name

        assert not _is_safe_san_name("evil\x1b[2Kx.example.com")  # ESC
        assert not _is_safe_san_name("a\nb.example.com")  # newline
        assert not _is_safe_san_name("a\x00b.example.com")  # NUL
        assert not _is_safe_san_name("a b.example.com")  # space
        assert not _is_safe_san_name("")

    def test_filter_subdomains_drops_ansi_escape_san(self):
        raw = ["good.example.com", "evil\x1b[2Kx.example.com"]
        result = filter_subdomains(raw, "example.com")
        assert "good.example.com" in result
        assert all("\x1b" not in r for r in result)
        assert not any("evil" in r for r in result)

    def test_filter_subdomains_drops_newline_san(self):
        raw = ["ok.example.com", "a\nb.example.com"]
        result = filter_subdomains(raw, "example.com")
        assert result == ["ok.example.com"]

    def test_build_cert_summary_strips_issuer_control_chars(self):
        now = datetime(2024, 6, 1, tzinfo=UTC)
        entries: list[dict[str, str | int | list[str] | None]] = [
            {
                "issuer_id": "1",
                "issuer_name": "Evil\x1b[31m CA\x00",
                "not_before": "2024-03-01T00:00:00",
                "not_after": "2024-06-01T00:00:00",
            },
        ]
        summary = build_cert_summary(entries, now)
        assert summary is not None
        assert all("\x1b" not in name and "\x00" not in name for name in summary.top_issuers)
        assert "Evil[31m CA" in summary.top_issuers
