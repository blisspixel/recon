"""Integration tests for MCP server."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from recon_tool.models import (
    ConfidenceLevel,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)
from recon_tool.server import _cache_clear, _rate_limit, lookup_tenant

RESOLVE_PATH = "recon_tool.server.resolve_tenant"

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Contoso Ltd",
    default_domain="contoso.onmicrosoft.com",
    queried_domain="contoso.com",
    confidence=ConfidenceLevel.HIGH,
    region="NA",
    sources=("oidc_discovery", "azure_ad_metadata"),
    services=("Exchange Online", "Microsoft 365"),
    slugs=("microsoft365",),
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
    SourceResult(source_name="azure_ad_metadata", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
]


@pytest.fixture(autouse=True)
def _clear_server_caches():
    """Clear server caches and rate limits between tests."""
    _cache_clear()
    _rate_limit.clear()
    yield
    _cache_clear()
    _rate_limit.clear()


class TestLookupText:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_text_contains_company(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com")
        assert "Company: Contoso Ltd" in result
        assert "Provider: Microsoft 365" in result
        assert "Tenant ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in result
        assert "Region: NA" in result

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_text_not_json(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com")
        with pytest.raises(json.JSONDecodeError):
            json.loads(result)

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_omits_region_when_none(self, mock_resolve: AsyncMock) -> None:
        info = TenantInfo(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            display_name="Contoso Ltd",
            default_domain="contoso.onmicrosoft.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.MEDIUM,
            region=None,
            sources=("oidc_discovery",),
        )
        mock_resolve.return_value = (info, SAMPLE_RESULTS[:1])
        result = await lookup_tenant("contoso.com")
        assert "Region:" not in result


class TestLookupJson:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_json_format(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="json")
        data = json.loads(result)
        assert data["display_name"] == "Contoso Ltd"
        assert data["provider"] == "Microsoft 365"
        assert data["tenant_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert data["confidence"] == "high"


class TestLookupMarkdown:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_markdown_format(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = await lookup_tenant("contoso.com", format="markdown")
        assert "# " in result
        assert "Contoso Ltd" in result


class TestErrors:
    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_not_found(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com",
            message="No data",
            error_type="all_sources_failed",
        )
        result = await lookup_tenant("unknown.com")
        assert "No information found for unknown.com" in result

    @pytest.mark.asyncio
    async def test_empty_domain(self) -> None:
        result = await lookup_tenant("   ")
        assert "error" in result.lower()

    @pytest.mark.asyncio
    async def test_invalid_domain(self) -> None:
        result = await lookup_tenant("not a domain")
        assert "error" in result.lower()

    @pytest.mark.asyncio
    async def test_invalid_format(self) -> None:
        result = await lookup_tenant("example.com", format="xml")
        assert "invalid format" in result.lower()

    @pytest.mark.asyncio
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    async def test_unexpected_error(self, mock_resolve: AsyncMock) -> None:
        mock_resolve.side_effect = RuntimeError("timeout")
        result = await lookup_tenant("example.com")
        assert "Error looking up example.com" in result
        assert "internal error" in result


class TestMCPMetadata:
    def test_server_name(self) -> None:
        from recon_tool.server import mcp

        assert mcp.name == "recon-tool"

    def test_tool_description(self) -> None:
        assert lookup_tenant.__doc__ is not None
        doc = lookup_tenant.__doc__.lower()
        assert "domain" in doc

    def test_prompt_exists(self) -> None:
        from recon_tool.server import domain_report

        result = domain_report("contoso.com")
        assert "contoso.com" in result
        assert "lookup_tenant" in result
