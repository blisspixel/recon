"""Server-tool coverage for the Bayesian + token-clustering MCP tools (Track B, B4).

`get_posteriors`, `explain_dag`, and `cluster_verification_tokens` were the
largest untested blocks in `server.py`. These tests drive them through the same
pattern the other server-tool tests use: patch `resolve_tenant` so the
cache-miss resolve path runs without network, plus the cache-hit, validation-
error, lookup-error, and unexpected-error branches. This lifts `server.py`
branch coverage (B4).
"""

from __future__ import annotations

from dataclasses import replace
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
        display_name="Synthetic Gamma",
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
        mock_resolve.return_value = (_info("gamma.invalid"), SAMPLE_RESULTS)
        data = await get_posteriors("gamma.invalid")
        assert data["domain"] == "gamma.invalid"
        assert "entropy_reduction_nats" in data
        assert "evidence_count" in data
        assert data["degraded_sources"] == []
        assert data["collection_masked_units"] == []
        assert isinstance(data["posteriors"], list)
        assert data["posteriors"], "expected at least one posterior node"
        first = data["posteriors"][0]
        assert {"name", "posterior", "interval_low", "interval_high", "n_eff", "sparse"} <= set(first)
        # Tool-level uncertainty summary: how many nodes the passive channel
        # could not resolve, agreeing with the per-node sparse flags.
        assert data["sparse_count"] == sum(1 for p in data["posteriors"] if p["sparse"])

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_returns_collection_provenance_for_masked_units(self, mock_resolve: AsyncMock) -> None:
        degraded = replace(
            _info("gamma.invalid"),
            degraded_sources=("http:mta_sts_policy", "dns:dmarc"),
        )
        mock_resolve.return_value = (degraded, SAMPLE_RESULTS)

        data = await get_posteriors("gamma.invalid")

        assert data["degraded_sources"] == ["dns:dmarc", "http:mta_sts_policy"]
        assert data["collection_masked_units"] == ["dmarc_policy", "mta_sts_enforce"]

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_cache_hit_avoids_second_resolve(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("gamma.invalid"), SAMPLE_RESULTS)
        await get_posteriors("gamma.invalid")
        await get_posteriors("gamma.invalid")
        assert mock_resolve.call_count == 1  # second call served from cache

    @pytest.mark.asyncio
    async def test_validation_failure(self) -> None:
        with pytest.raises(ToolError):
            await get_posteriors("not a domain")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_recon_lookup_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="x.invalid",
            message="No data",
            error_type="all_sources_failed",
        )
        with pytest.raises(ToolError, match="Lookup failed"):
            await get_posteriors("x.invalid")

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
        mock_resolve.return_value = (_info("gamma.invalid"), SAMPLE_RESULTS)
        result = await explain_dag("gamma.invalid", "text")
        assert result
        assert not result.startswith("Error")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_dot_format_differs_from_text(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("gamma.invalid"), SAMPLE_RESULTS)
        text = await explain_dag("gamma.invalid", "text")
        dot = await explain_dag("gamma.invalid", "dot")
        assert dot
        assert not dot.startswith("Error")
        assert dot != text  # the two renderers produce different output

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_collection_provenance_prefixes_standalone_dag(self, mock_resolve: AsyncMock) -> None:
        degraded = replace(
            _info("gamma.invalid"),
            degraded_sources=("http:mta_sts_policy", "dns:dmarc"),
        )
        mock_resolve.return_value = (degraded, SAMPLE_RESULTS)

        text = await explain_dag("gamma.invalid", "text")
        dot = await explain_dag("gamma.invalid", "dot")

        assert text.startswith("Collection provenance:")
        assert "degraded_sources: dns:dmarc, http:mta_sts_policy" in text
        assert "collection-masked units: dmarc_policy, mta_sts_enforce" in text
        assert dot.startswith("// degraded_sources: dns:dmarc, http:mta_sts_policy")
        assert "// collection_masked_units: dmarc_policy, mta_sts_enforce" in dot

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_invalid_format_rejected(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("gamma.invalid"), SAMPLE_RESULTS)
        result = await explain_dag("gamma.invalid", "svg")
        assert "output_format must be" in result

    @pytest.mark.asyncio
    async def test_validation_failure(self) -> None:
        assert (await explain_dag("not a domain")).startswith("Error:")

    @pytest.mark.asyncio
    async def test_rate_limit_message_uses_only_normalized_domain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import recon_tool.server.introspection as server_introspection

        acquired: list[str] = []

        def deny(domain: str) -> bool:
            acquired.append(domain)
            return False

        monkeypatch.setattr(server_introspection, "rate_limit_try_acquire", deny)
        raw = "https://www.gamma.invalid/private/path?token=secret"

        result = await explain_dag(raw)

        assert acquired == ["gamma.invalid"]
        assert "Rate limited: gamma.invalid" in result
        assert raw not in result
        assert "/private/path" not in result

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_internal_error_and_log_use_only_normalized_domain(
        self,
        mock_resolve: AsyncMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        mock_resolve.side_effect = RuntimeError("boom")
        raw = "https://www.gamma.invalid/private/path?token=secret"

        with caplog.at_level("ERROR", logger="recon"):
            result = await explain_dag(raw)

        assert "Error rendering DAG for gamma.invalid" in result
        assert raw not in result
        assert "/private/path" not in result
        assert "explain_dag for gamma.invalid" in caplog.text
        assert raw not in caplog.text
        assert "/private/path" not in caplog.text


class TestClusterVerificationTokens:
    @pytest.mark.asyncio
    async def test_empty_input_errors(self) -> None:
        with pytest.raises(ToolError, match="At least one domain"):
            await cluster_verification_tokens([])

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_error_entry_uses_only_normalized_domain(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="alpha.invalid",
            message="No data",
            error_type="all_sources_failed",
        )
        raw = "https://www.alpha.invalid/private/path?token=secret"

        data = await cluster_verification_tokens([raw])

        assert data["errors"][0]["domain"] == "alpha.invalid"
        assert "alpha.invalid" in data["errors"][0]["error"]
        assert raw not in str(data["errors"])
        assert "/private/path" not in str(data["errors"])

    @pytest.mark.asyncio
    async def test_invalid_domain_error_contract_is_preserved(self) -> None:
        raw = "not a valid domain"

        data = await cluster_verification_tokens([raw])

        assert data["errors"][0]["domain"] == raw
        assert data["errors"][0]["error"].startswith("Error:")

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_shared_token_clusters_two_domains(self, mock_resolve: AsyncMock) -> None:
        shared = ("google-site-verification=sharedtoken123",)
        mock_resolve.side_effect = [
            (_info("alpha.invalid", tokens=shared), SAMPLE_RESULTS),
            (_info("gamma.invalid", tokens=shared), SAMPLE_RESULTS),
        ]
        data = await cluster_verification_tokens(["alpha.invalid", "gamma.invalid"])
        assert data["errors"] == []
        assert "disclaimer" in data
        assert data["peer_limit_per_domain"] == 0
        assert data["peers_omitted"] == {
            "alpha.invalid": 0,
            "gamma.invalid": 0,
        }
        assert "peer_limit_per_domain=0" in data["raw_request"]
        # Both domains share the token, so each lists the other as a peer.
        assert data["clusters"] == {
            "alpha.invalid": [
                {
                    "token": "google-site-verification=sharedtoken123",
                    "peer": "gamma.invalid",
                }
            ],
            "gamma.invalid": [
                {
                    "token": "google-site-verification=sharedtoken123",
                    "peer": "alpha.invalid",
                }
            ],
        }

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_unavailable_apex_txt_cannot_form_a_shared_token_cluster(self, mock_resolve: AsyncMock) -> None:
        shared = ("google-site-verification=sharedtoken123",)
        mock_resolve.side_effect = [
            (replace(_info("alpha.invalid", tokens=shared), degraded_sources=("dns:apex_txt",)), SAMPLE_RESULTS),
            (
                replace(
                    _info("gamma.invalid", tokens=shared),
                    degraded_sources=("dns:apex_txt",),
                ),
                SAMPLE_RESULTS,
            ),
        ]

        data = await cluster_verification_tokens(["alpha.invalid", "gamma.invalid"])

        assert data["clusters"] == {}

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_peer_limit_returns_omitted_counts(self, mock_resolve: AsyncMock) -> None:
        shared = ("MS=sharedtoken123",)
        mock_resolve.side_effect = [
            (_info("delta.invalid", tokens=shared), SAMPLE_RESULTS),
            (_info("alpha.invalid", tokens=shared), SAMPLE_RESULTS),
            (_info("gamma.invalid", tokens=shared), SAMPLE_RESULTS),
        ]
        data = await cluster_verification_tokens(
            ["gamma.invalid", "alpha.invalid", "delta.invalid"],
            peer_limit_per_domain=1,
        )
        assert data["peer_limit_per_domain"] == 1
        assert set(data["clusters"]) == {"alpha.invalid", "delta.invalid", "gamma.invalid"}
        assert all(len(peers) == 1 for peers in data["clusters"].values())
        assert data["clusters"]["delta.invalid"] == [{"token": "ms=sharedtoken123", "peer": "alpha.invalid"}]
        assert data["peers_omitted"] == {
            "delta.invalid": 1,
            "alpha.invalid": 1,
            "gamma.invalid": 1,
        }
        assert "token then peer" in data["selection_rule"]

    @pytest.mark.asyncio
    async def test_negative_peer_limit_rejected(self) -> None:
        with pytest.raises(ToolError, match="peer_limit_per_domain"):
            await cluster_verification_tokens(["alpha.invalid"], peer_limit_per_domain=-1)

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_too_many_domains_rejected(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (_info("example.com"), SAMPLE_RESULTS)
        many = [f"d{i}.invalid" for i in range(101)]
        with pytest.raises(ToolError, match="Too many domains"):
            await cluster_verification_tokens(many)
