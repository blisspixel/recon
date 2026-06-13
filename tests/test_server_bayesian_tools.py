"""Server-tool coverage for the Bayesian + token-clustering MCP tools (Track B, B4).

`get_posteriors`, `explain_dag`, and `cluster_verification_tokens` were the
largest untested blocks in `server.py`. These tests drive them through the same
pattern the other server-tool tests use: patch `resolve_tenant` so the
cache-miss resolve path runs without network, plus the cache-hit, validation-
error, lookup-error, and unexpected-error branches. This lifts `server.py`
branch coverage (B4).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

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

RESOLVE_PATH = "recon_tool.server.resolve_tenant"


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
        result = await get_posteriors("northwindtraders.com")
        data = json.loads(result)
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
        assert (await get_posteriors("not a domain")).startswith("Error:")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_recon_lookup_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(domain="x.com", message="No data", error_type="all_sources_failed")
        assert (await get_posteriors("x.com")).startswith("Error:")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_unexpected_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = RuntimeError("boom")
        result = await get_posteriors("example.com")
        assert "internal error" in result


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
        data = json.loads(await cluster_verification_tokens([]))
        assert "error" in data

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_shared_token_clusters_two_domains(self, mock_resolve: AsyncMock) -> None:
        shared = ("google-site-verification=sharedtoken123",)
        mock_resolve.side_effect = [
            (_info("contoso.com", tokens=shared), SAMPLE_RESULTS),
            (_info("northwindtraders.com", tokens=shared), SAMPLE_RESULTS),
        ]
        data = json.loads(await cluster_verification_tokens(["contoso.com", "northwindtraders.com"]))
        assert data["errors"] == []
        assert "disclaimer" in data
        # Both domains share the token, so each lists the other as a peer.
        assert data["clusters"], "expected a non-empty cluster for the shared token"

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_too_many_domains_rejected(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("example.com"), SAMPLE_RESULTS)
        many = [f"d{i}.com" for i in range(101)]
        data = json.loads(await cluster_verification_tokens(many))
        assert "Too many domains" in data["error"]
