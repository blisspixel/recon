"""Server-tool coverage for the Bayesian + token-clustering MCP tools (Track B, B4).

`get_posteriors`, `explain_dag`, and `cluster_verification_tokens` were the
largest untested blocks in `server.py`. These tests drive them through the same
pattern the other server-tool tests use: patch `resolve_tenant` so the
cache-miss resolve path runs without network, plus the cache-hit, validation-
error, lookup-error, and unexpected-error branches. This lifts `server.py`
branch coverage (B4).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from recon_tool.models import (
    ConfidenceLevel,
    EvidenceRecord,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)
from recon_tool.server import (
    _cache_clear,
    _rate_limit,
    cluster_verification_tokens,
    explain_dag,
    get_posteriors,
)

RESOLVE_PATH = "recon_tool.server_app.resolve_tenant"


def _info(queried: str, *, tokens: tuple[str, ...] = ()) -> TenantInfo:
    """A TenantInfo rich enough that the Bayesian layer fires on the M365 cluster."""
    return TenantInfo(
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        display_name="Northwind Traders",
        default_domain=f"{queried.split('.')[0]}.onmicrosoft.com",
        queried_domain=queried,
        confidence=ConfidenceLevel.HIGH,
        region="NA",
        sources=("oidc_discovery", "dns_records"),
        services=("Microsoft 365", "Exchange Online", "DMARC"),
        slugs=("microsoft365", "exchange-online", "dmarc"),
        dmarc_policy="reject",
        site_verification_tokens=tokens,
        evidence=(
            EvidenceRecord(source_type="HTTP", raw_value="tenant_id=...", rule_name="OIDC", slug="microsoft365"),
            EvidenceRecord(source_type="TXT", raw_value="v=DMARC1; p=reject", rule_name="dmarc", slug="dmarc"),
        ),
    )


SAMPLE_RESULTS = [SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]


@pytest.fixture(autouse=True)
def _clear_server_caches():
    _cache_clear()
    _rate_limit.clear()
    yield
    _cache_clear()
    _rate_limit.clear()


class TestGetPosteriors:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_returns_posterior_block(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("northwindtraders.com"), SAMPLE_RESULTS)
        data = await get_posteriors("northwindtraders.com")
        assert data["domain"] == "northwindtraders.com"
        assert "entropy_reduction_nats" in data
        assert "evidence_count" in data
        assert isinstance(data["posteriors"], list)
        assert data["posteriors"], "expected at least one posterior node"
        first = data["posteriors"][0]
        assert {"name", "posterior", "interval_low", "interval_high", "n_eff", "sparse"} <= set(first)
        # Tool-level uncertainty summary: how many nodes the passive channel
        # could not resolve, agreeing with the per-node sparse flags.
        assert data["sparse_count"] == sum(1 for p in data["posteriors"] if p["sparse"])

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_cache_hit_avoids_second_resolve(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("northwindtraders.com"), SAMPLE_RESULTS)
        await get_posteriors("northwindtraders.com")
        await get_posteriors("northwindtraders.com")
        assert mock_resolve.call_count == 1  # second call served from cache

    @pytest.mark.asyncio
    async def test_validation_failure(self) -> None:
        with pytest.raises(ToolError):
            await get_posteriors("not a domain")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_recon_lookup_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(domain="x.com", message="No data", error_type="all_sources_failed")
        with pytest.raises(ToolError, match="No information found"):
            await get_posteriors("x.com")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_unexpected_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = RuntimeError("boom")
        with pytest.raises(ToolError, match="internal error"):
            await get_posteriors("example.com")


class TestExplainDag:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_text_format(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("northwindtraders.com"), SAMPLE_RESULTS)
        result = await explain_dag("northwindtraders.com", "text")
        assert result
        assert not result.startswith("Error")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_dot_format_differs_from_text(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("northwindtraders.com"), SAMPLE_RESULTS)
        text = await explain_dag("northwindtraders.com", "text")
        dot = await explain_dag("northwindtraders.com", "dot")
        assert dot
        assert not dot.startswith("Error")
        assert dot != text  # the two renderers produce different output

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_invalid_format_rejected(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("northwindtraders.com"), SAMPLE_RESULTS)
        result = await explain_dag("northwindtraders.com", "svg")
        assert "output_format must be" in result

    @pytest.mark.asyncio
    async def test_validation_failure(self) -> None:
        assert (await explain_dag("not a domain")).startswith("Error:")


class TestClusterVerificationTokens:
    @pytest.mark.asyncio
    async def test_empty_input_errors(self) -> None:
        with pytest.raises(ToolError, match="At least one domain"):
            await cluster_verification_tokens([])

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_shared_token_clusters_two_domains(self, mock_resolve: AsyncMock) -> None:
        shared = ("google-site-verification=sharedtoken123",)
        mock_resolve.side_effect = [
            (_info("contoso.com", tokens=shared), SAMPLE_RESULTS),
            (_info("northwindtraders.com", tokens=shared), SAMPLE_RESULTS),
        ]
        data = await cluster_verification_tokens(["contoso.com", "northwindtraders.com"])
        assert data["errors"] == []
        assert "disclaimer" in data
        assert data["peer_limit_per_domain"] == 0
        assert data["peers_omitted"] == {
            "contoso.com": 0,
            "northwindtraders.com": 0,
        }
        assert "peer_limit_per_domain=0" in data["raw_request"]
        # Both domains share the token, so each lists the other as a peer.
        assert data["clusters"] == {
            "contoso.com": [
                {
                    "token": "google-site-verification=sharedtoken123",
                    "peer": "northwindtraders.com",
                }
            ],
            "northwindtraders.com": [
                {
                    "token": "google-site-verification=sharedtoken123",
                    "peer": "contoso.com",
                }
            ],
        }

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_peer_limit_returns_omitted_counts(self, mock_resolve: AsyncMock) -> None:
        shared = ("MS=sharedtoken123",)
        mock_resolve.side_effect = [
            (_info("adatum.com", tokens=shared), SAMPLE_RESULTS),
            (_info("contoso.com", tokens=shared), SAMPLE_RESULTS),
            (_info("northwindtraders.com", tokens=shared), SAMPLE_RESULTS),
        ]
        data = await cluster_verification_tokens(
            ["northwindtraders.com", "contoso.com", "adatum.com"],
            peer_limit_per_domain=1,
        )
        assert data["peer_limit_per_domain"] == 1
        assert set(data["clusters"]) == {"adatum.com", "contoso.com", "northwindtraders.com"}
        assert all(len(peers) == 1 for peers in data["clusters"].values())
        assert data["clusters"]["adatum.com"] == [{"token": "ms=sharedtoken123", "peer": "contoso.com"}]
        assert data["peers_omitted"] == {
            "adatum.com": 1,
            "contoso.com": 1,
            "northwindtraders.com": 1,
        }
        assert "token then peer" in data["selection_rule"]

    @pytest.mark.asyncio
    async def test_negative_peer_limit_rejected(self) -> None:
        with pytest.raises(ToolError, match="peer_limit_per_domain"):
            await cluster_verification_tokens(["contoso.com"], peer_limit_per_domain=-1)

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_too_many_domains_rejected(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("example.com"), SAMPLE_RESULTS)
        many = [f"d{i}.com" for i in range(101)]
        with pytest.raises(ToolError, match="Too many domains"):
            await cluster_verification_tokens(many)
