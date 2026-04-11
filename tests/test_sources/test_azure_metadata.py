"""Unit tests for the Azure AD metadata lookup source."""

import httpx
import pytest

from recon_tool.sources.azure_metadata import (
    METADATA_URL_TEMPLATE,
    AzureMetadataSource,
)
from recon_tool.sources.base import LookupSource

SAMPLE_TENANT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


class TestAzureMetadataSourceName:
    def test_name_property_returns_expected_value(self):
        source = AzureMetadataSource()
        assert source.name == "azure_ad_metadata"

    def test_implements_lookup_source_protocol(self):
        source = AzureMetadataSource()
        assert isinstance(source, LookupSource)


class TestAzureMetadataSourceLookup:
    @pytest.mark.asyncio
    async def test_successful_lookup_extracts_region(self):
        response_json = {
            "authorization_endpoint": f"https://login.microsoftonline.com/{SAMPLE_TENANT_ID}/oauth2/v2.0/authorize",
            "tenant_region_scope": "NA",
        }
        transport = httpx.MockTransport(
            lambda request: httpx.Response(200, json=response_json)
        )
        async with httpx.AsyncClient(transport=transport) as client:
            source = AzureMetadataSource()
            result = await source.lookup(
                "example.com", tenant_id=SAMPLE_TENANT_ID, client=client
            )

        assert result.source_name == "azure_ad_metadata"
        assert result.tenant_id == SAMPLE_TENANT_ID
        assert result.region == "NA"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_successful_lookup_constructs_correct_url(self):
        captured_url = None

        def capture_request(request):
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200, json={"tenant_region_scope": "EU"}
            )

        transport = httpx.MockTransport(capture_request)
        async with httpx.AsyncClient(transport=transport) as client:
            source = AzureMetadataSource()
            await source.lookup(
                "example.com", tenant_id=SAMPLE_TENANT_ID, client=client
            )

        assert captured_url == METADATA_URL_TEMPLATE.format(
            tenant_id=SAMPLE_TENANT_ID
        )

    @pytest.mark.asyncio
    async def test_region_is_none_when_not_in_response(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(200, json={})
        )
        async with httpx.AsyncClient(transport=transport) as client:
            source = AzureMetadataSource()
            result = await source.lookup(
                "example.com", tenant_id=SAMPLE_TENANT_ID, client=client
            )

        assert result.tenant_id == SAMPLE_TENANT_ID
        assert result.region is None
        assert result.error is None

    @pytest.mark.asyncio
    async def test_missing_tenant_id_returns_empty_result(self):
        source = AzureMetadataSource()
        result = await source.lookup("example.com")

        assert result.source_name == "azure_ad_metadata"
        assert result.tenant_id is None
        assert result.region is None
        assert result.error is None

    @pytest.mark.asyncio
    async def test_http_error_returns_source_result_with_error(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(404)
        )
        async with httpx.AsyncClient(transport=transport) as client:
            source = AzureMetadataSource()
            result = await source.lookup(
                "example.com", tenant_id=SAMPLE_TENANT_ID, client=client
            )

        assert result.error is not None
        assert "404" in result.error
        assert result.tenant_id is None

    @pytest.mark.asyncio
    async def test_network_error_returns_source_result_with_error(self):
        def raise_timeout(request):
            raise httpx.ConnectTimeout("Connection timed out")

        transport = httpx.MockTransport(raise_timeout)
        async with httpx.AsyncClient(transport=transport) as client:
            source = AzureMetadataSource()
            result = await source.lookup(
                "example.com", tenant_id=SAMPLE_TENANT_ID, client=client
            )

        assert result.error is not None
        assert result.tenant_id is None
