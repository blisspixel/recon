"""Unit tests for the UserRealm lookup source."""

from __future__ import annotations

import httpx
import pytest

from recon_tool.models import SourceResult
from recon_tool.sources.base import LookupSource
from recon_tool.sources.userrealm import UserRealmSource

USERREALM_JSON = {
    "State": 4,
    "UserState": 2,
    "Login": "user@contoso.com",
    "NameSpaceType": "Managed",
    "DomainName": "contoso.com",
    "FederationBrandName": "Contoso Ltd",
    "CloudInstanceName": "microsoftonline.com",
}

AUTODISCOVER_XML = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <GetFederationInformationResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Response>
        <Domains>
          <Domain>contoso.com</Domain>
          <Domain>contoso.onmicrosoft.com</Domain>
          <Domain>contosoltd.onmicrosoft.com</Domain>
        </Domains>
      </Response>
    </GetFederationInformationResponseMessage>
  </s:Body>
</s:Envelope>"""


class TestUserRealmSourceName:
    def test_name_property(self):
        source = UserRealmSource()
        assert source.name == "user_realm"

    def test_implements_lookup_source_protocol(self):
        source = UserRealmSource()
        assert isinstance(source, LookupSource)


class TestUserRealmSourceLookup:
    @pytest.mark.asyncio
    async def test_extracts_display_name_and_default_domain(self):
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if "GetUserRealm" in str(request.url):
                return httpx.Response(200, json=USERREALM_JSON)
            if "autodiscover" in str(request.url):
                return httpx.Response(200, text=AUTODISCOVER_XML)
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            source = UserRealmSource()
            result = await source.lookup("contoso.com", client=client)

        assert result.display_name == "Contoso Ltd"
        assert result.default_domain == "contoso.onmicrosoft.com"
        assert result.m365_detected is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_display_name_only_when_autodiscover_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "GetUserRealm" in str(request.url):
                return httpx.Response(200, json=USERREALM_JSON)
            return httpx.Response(500)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            source = UserRealmSource()
            result = await source.lookup("contoso.com", client=client)

        assert result.display_name == "Contoso Ltd"
        assert result.default_domain is None
        assert result.m365_detected is True

    @pytest.mark.asyncio
    async def test_default_domain_only_when_userrealm_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "GetUserRealm" in str(request.url):
                return httpx.Response(500)
            if "autodiscover" in str(request.url):
                return httpx.Response(200, text=AUTODISCOVER_XML)
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            source = UserRealmSource()
            result = await source.lookup("contoso.com", client=client)

        assert result.display_name is None
        assert result.default_domain == "contoso.onmicrosoft.com"
        assert result.m365_detected is True

    @pytest.mark.asyncio
    async def test_both_fail_returns_error(self):
        transport = httpx.MockTransport(lambda r: httpx.Response(500))
        async with httpx.AsyncClient(transport=transport) as client:
            source = UserRealmSource()
            result = await source.lookup("contoso.com", client=client)

        assert result.error is not None
        assert result.display_name is None
        assert result.default_domain is None

    @pytest.mark.asyncio
    async def test_empty_brand_name_ignored(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "GetUserRealm" in str(request.url):
                return httpx.Response(200, json={"FederationBrandName": ""})
            return httpx.Response(500)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            source = UserRealmSource()
            result = await source.lookup("contoso.com", client=client)

        assert result.error is not None
        assert result.display_name is None

    @pytest.mark.asyncio
    async def test_network_error_returns_error_result(self):
        def raise_error(request: httpx.Request):
            raise httpx.ConnectTimeout("timeout")

        transport = httpx.MockTransport(raise_error)
        async with httpx.AsyncClient(transport=transport) as client:
            source = UserRealmSource()
            result = await source.lookup("contoso.com", client=client)

        assert result.error is not None
        assert isinstance(result, SourceResult)
