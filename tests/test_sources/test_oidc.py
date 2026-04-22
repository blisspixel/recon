"""Unit tests for the OIDC discovery lookup source."""

import httpx
import pytest

from recon_tool.models import ReconLookupError
from recon_tool.sources.oidc import (
    DISCOVERY_URL_TEMPLATE,
    OIDCSource,
    parse_tenant_info_from_oidc,
)

# --- parse_tenant_info_from_oidc tests ---


class TestParseTenantInfoFromOIDC:
    def test_extracts_tenant_id_from_authorization_endpoint(self):
        data = {
            "authorization_endpoint": "https://login.microsoftonline.com/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth2/v2.0/authorize",
        }
        result = parse_tenant_info_from_oidc(data)
        assert result.tenant_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert result.source_name == "oidc_discovery"

    def test_extracts_region_from_tenant_region_scope(self):
        data = {
            "authorization_endpoint": "https://login.microsoftonline.com/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth2/v2.0/authorize",
            "tenant_region_scope": "NA",
        }
        result = parse_tenant_info_from_oidc(data)
        assert result.region == "NA"

    def test_region_is_none_when_not_present(self):
        data = {
            "authorization_endpoint": "https://login.microsoftonline.com/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth2/v2.0/authorize",
        }
        result = parse_tenant_info_from_oidc(data)
        assert result.region is None

    def test_display_name_and_default_domain_are_none(self):
        data = {
            "authorization_endpoint": "https://login.microsoftonline.com/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth2/v2.0/authorize",
        }
        result = parse_tenant_info_from_oidc(data)
        assert result.display_name is None
        assert result.default_domain is None

    def test_raises_lookup_error_when_no_authorization_endpoint(self):
        with pytest.raises(ReconLookupError) as exc_info:
            parse_tenant_info_from_oidc({})
        assert exc_info.value.error_type == "parse_error"

    def test_raises_lookup_error_when_tenant_id_not_uuid(self):
        data = {
            "authorization_endpoint": "https://login.microsoftonline.com/not-a-uuid/oauth2/v2.0/authorize",
        }
        with pytest.raises(ReconLookupError) as exc_info:
            parse_tenant_info_from_oidc(data)
        assert exc_info.value.error_type == "parse_error"

    def test_tenant_id_is_lowercased(self):
        data = {
            "authorization_endpoint": "https://login.microsoftonline.com/A1B2C3D4-E5F6-7890-ABCD-EF1234567890/oauth2/v2.0/authorize",
        }
        result = parse_tenant_info_from_oidc(data)
        assert result.tenant_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


# --- OIDCSource tests ---


class TestOIDCSource:
    def test_name_property(self):
        source = OIDCSource()
        assert source.name == "oidc_discovery"

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        response_json = {
            "authorization_endpoint": "https://login.microsoftonline.com/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth2/v2.0/authorize",
            "tenant_region_scope": "NA",
        }
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json=response_json))
        async with httpx.AsyncClient(transport=transport) as client:
            source = OIDCSource()
            result = await source.lookup("example.com", client=client)
        assert result.tenant_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert result.region == "NA"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_http_error_returns_source_result_with_error(self):
        transport = httpx.MockTransport(lambda request: httpx.Response(404))
        async with httpx.AsyncClient(transport=transport) as client:
            source = OIDCSource()
            result = await source.lookup("nonexistent.com", client=client)
        assert result.error is not None
        assert "404" in result.error
        assert result.tenant_id is None

    @pytest.mark.asyncio
    async def test_unparseable_response_returns_error(self):
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"foo": "bar"}))
        async with httpx.AsyncClient(transport=transport) as client:
            source = OIDCSource()
            result = await source.lookup("example.com", client=client)
        assert result.error is not None
        assert result.tenant_id is None

    @pytest.mark.asyncio
    async def test_network_error_returns_source_result_with_error(self):
        def raise_timeout(request):
            raise httpx.ConnectTimeout("Connection timed out")

        transport = httpx.MockTransport(raise_timeout)
        async with httpx.AsyncClient(transport=transport) as client:
            source = OIDCSource()
            result = await source.lookup("example.com", client=client)
        assert result.error is not None
        assert result.tenant_id is None

    @pytest.mark.asyncio
    async def test_invalid_json_returns_error(self):
        request = httpx.Request("GET", DISCOVERY_URL_TEMPLATE.format(domain="example.com"))
        transport = httpx.MockTransport(lambda _: httpx.Response(200, request=request, content=b"{not json"))
        async with httpx.AsyncClient(transport=transport) as client:
            source = OIDCSource()
            result = await source.lookup("example.com", client=client)
        assert result.error == "Invalid JSON from OIDC discovery endpoint"
        assert result.tenant_id is None

    @pytest.mark.asyncio
    async def test_non_object_json_returns_error(self):
        transport = httpx.MockTransport(lambda _: httpx.Response(200, json=["not", "an", "object"]))
        async with httpx.AsyncClient(transport=transport) as client:
            source = OIDCSource()
            result = await source.lookup("example.com", client=client)
        assert result.error == "Invalid JSON response shape from OIDC discovery endpoint"
        assert result.tenant_id is None

    @pytest.mark.asyncio
    async def test_constructs_correct_url(self):
        """Verify the source hits the correct discovery URL."""
        captured_url = None

        def capture_request(request):
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "authorization_endpoint": "https://login.microsoftonline.com/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth2/v2.0/authorize",
                },
            )

        transport = httpx.MockTransport(capture_request)
        async with httpx.AsyncClient(transport=transport) as client:
            source = OIDCSource()
            await source.lookup("contoso.com", client=client)
        assert captured_url == DISCOVERY_URL_TEMPLATE.format(domain="contoso.com")


# --- Property-based tests (Hypothesis) ---

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from recon_tool.sources.base import LookupSource


def valid_domain_labels():
    """Strategy for valid domain label characters."""
    return st.text(
        alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789"),
        min_size=2,
        max_size=12,
    )


def valid_domains():
    """Strategy for valid domain strings like 'example.com'."""
    return st.tuples(valid_domain_labels(), valid_domain_labels()).map(lambda parts: f"{parts[0]}.{parts[1]}")


class TestProperty4DiscoveryURLConstruction:
    """Property 4: Discovery URL construction.

    **Validates: Requirements 2.1**
    """

    @given(domain=valid_domains())
    @settings(max_examples=100)
    def test_discovery_url_matches_expected_format(self, domain: str):
        """For any valid domain d, DISCOVERY_URL_TEMPLATE.format(domain=d) should equal
        'https://login.microsoftonline.com/' + d + '/.well-known/openid-configuration'."""
        url = DISCOVERY_URL_TEMPLATE.format(domain=domain)
        expected = "https://login.microsoftonline.com/" + domain + "/.well-known/openid-configuration"
        assert url == expected


class TestProperty5TenantInfoParsingRoundTrip:
    """Property 5: Tenant info parsing round-trip.

    **Validates: Requirements 2.2, 2.3, 4.1**
    """

    @given(uuid=st.uuids())
    @settings(max_examples=100)
    def test_parsing_extracts_correct_tenant_id(self, uuid):
        """For any valid UUID u, constructing a mock discovery JSON with authorization_endpoint
        containing u, then parsing with parse_tenant_info_from_oidc, should produce a
        SourceResult where tenant_id == u (lowercased)."""
        uuid_str = str(uuid)
        response_json = {
            "authorization_endpoint": f"https://login.microsoftonline.com/{uuid_str}/oauth2/v2.0/authorize",
        }
        result = parse_tenant_info_from_oidc(response_json)
        assert result.tenant_id == uuid_str.lower()


_UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class TestProperty6TenantIDUUIDFormatInvariant:
    """Property 6: Tenant ID UUID format invariant.

    **Validates: Requirements 4.2**
    """

    @given(uuid=st.uuids())
    @settings(max_examples=100)
    def test_tenant_id_matches_uuid_format(self, uuid):
        """For any valid discovery endpoint JSON response that is successfully parsed,
        the tenant_id field should match the UUID format pattern."""
        uuid_str = str(uuid)
        response_json = {
            "authorization_endpoint": f"https://login.microsoftonline.com/{uuid_str}/oauth2/v2.0/authorize",
        }
        result = parse_tenant_info_from_oidc(response_json)
        assert result.tenant_id is not None
        assert _UUID_PATTERN.match(result.tenant_id), f"tenant_id '{result.tenant_id}' does not match UUID format"


class TestProperty17LookupSourceProtocolCompliance:
    """Property 17: LookupSource protocol compliance.

    **Validates: Requirements 7.1, 7.2**
    """

    def test_oidc_source_is_lookup_source_instance(self):
        """OIDCSource should be a runtime-checkable instance of LookupSource protocol."""
        source = OIDCSource()
        assert isinstance(source, LookupSource)

    def test_oidc_source_name_is_non_empty_string(self):
        """OIDCSource.name should return a non-empty string."""
        source = OIDCSource()
        assert isinstance(source.name, str)
        assert len(source.name) > 0
