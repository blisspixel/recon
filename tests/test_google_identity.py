"""Tests for GoogleIdentitySource — Google Workspace identity routing detection.

Covers: lookup(), _classify_response(), _is_federated_redirect(),
_is_workspace_domain(), _extract_idp_name().
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from recon_tool.sources.google_identity import (
    GoogleIdentitySource,
    _extract_idp_name,
)

# ── _extract_idp_name unit tests ────────────────────────────────────────


class TestExtractIdpName:
    def test_okta(self):
        assert _extract_idp_name("https://acme.okta.com/sso/saml") == "Okta"

    def test_ping_identity(self):
        assert _extract_idp_name("https://sso.pingidentity.com/idp") == "Ping Identity"

    def test_pingone(self):
        assert _extract_idp_name("https://auth.pingone.com/env/as/authorize") == "Ping Identity"

    def test_microsoft_entra(self):
        assert _extract_idp_name("https://login.microsoftonline.com/tenant/saml2") == "Microsoft Entra"

    def test_microsoft_com(self):
        assert _extract_idp_name("https://sts.microsoft.com/adfs/ls") == "Microsoft Entra"

    def test_google(self):
        assert _extract_idp_name("https://accounts.google.com/o/saml2") == "Google"

    def test_auth0(self):
        assert _extract_idp_name("https://acme.auth0.com/samlp/abc") == "Auth0"

    def test_onelogin(self):
        assert _extract_idp_name("https://acme.onelogin.com/trust/saml2") == "OneLogin"

    def test_duo(self):
        assert _extract_idp_name("https://sso.duo.com/saml2/sp/abc") == "Duo Security"

    def test_jumpcloud(self):
        assert _extract_idp_name("https://sso.jumpcloud.com/saml2/app") == "JumpCloud"

    def test_unknown_falls_back_to_hostname(self):
        assert _extract_idp_name("https://idp.customcorp.net/sso") == "idp.customcorp.net"

    def test_unparseable_returns_raw(self):
        assert _extract_idp_name("not-a-url") == "not-a-url"


# ── _is_federated_redirect unit tests ───────────────────────────────────


class TestIsFederatedRedirect:
    def test_non_google_domain_is_federated(self):
        assert GoogleIdentitySource._is_federated_redirect("https://acme.okta.com/sso") is True

    def test_google_accounts_not_federated(self):
        assert (
            GoogleIdentitySource._is_federated_redirect("https://accounts.google.com/servicelogin?hd=example.com")
            is False
        )

    def test_google_with_saml_indicator(self):
        assert GoogleIdentitySource._is_federated_redirect("https://accounts.google.com/saml/redirect?idp=okta") is True

    def test_google_with_sso_indicator(self):
        assert GoogleIdentitySource._is_federated_redirect("https://accounts.google.com/sso/redirect") is True

    def test_plain_google_com(self):
        assert GoogleIdentitySource._is_federated_redirect("https://www.google.com/accounts/servicelogin") is False

    def test_adfs_indicator(self):
        assert GoogleIdentitySource._is_federated_redirect("https://accounts.google.com/adfs/ls") is True


# ── _is_workspace_domain unit tests ────────────────────────────────────


class TestIsWorkspaceDomain:
    def test_hd_json_match(self):
        body = 'some content "hd":"example.com" more content'
        assert GoogleIdentitySource._is_workspace_domain(body, "example.com") is True

    def test_hd_param_match(self):
        body = "some content hd=example.com more content"
        assert GoogleIdentitySource._is_workspace_domain(body, "example.com") is True

    def test_identifier_with_domain(self):
        body = "identifier flow page for example.com login"
        assert GoogleIdentitySource._is_workspace_domain(body, "example.com") is True

    def test_identifier_without_domain(self):
        body = "identifier flow page for other.com login"
        assert GoogleIdentitySource._is_workspace_domain(body, "example.com") is False

    def test_no_markers(self):
        body = "generic google login page with no domain info"
        assert GoogleIdentitySource._is_workspace_domain(body, "example.com") is False

    def test_case_insensitive(self):
        body = '"hd":"EXAMPLE.COM" content'
        assert GoogleIdentitySource._is_workspace_domain(body, "Example.Com") is True


# ── _classify_response unit tests ──────────────────────────────────────


class TestClassifyResponse:
    def _make_response(self, url: str, body: str, status_code: int = 200) -> httpx.Response:
        resp = httpx.Response(
            status_code=status_code,
            request=httpx.Request("GET", url),
            content=body.encode(),
        )
        return resp

    def test_federated_redirect_to_okta(self):
        resp = self._make_response(
            "https://acme.okta.com/sso/saml2?SAMLRequest=abc",
            "<html>Okta login</html>",
        )
        source = GoogleIdentitySource()
        result = source._classify_response(resp, "example.com")
        assert result.google_auth_type == "Federated"
        assert result.google_idp_name == "Okta"
        assert "google-federated" in result.detected_slugs
        assert "google-workspace" in result.detected_slugs
        assert "Google Workspace" in result.detected_services

    def test_managed_workspace_domain(self):
        resp = self._make_response(
            "https://accounts.google.com/ServiceLogin",
            'page content "hd":"example.com" identifier shown',
        )
        source = GoogleIdentitySource()
        result = source._classify_response(resp, "example.com")
        assert result.google_auth_type == "Managed"
        assert "google-managed" in result.detected_slugs
        assert "google-workspace" in result.detected_slugs

    def test_not_workspace_domain(self):
        resp = self._make_response(
            "https://accounts.google.com/ServiceLogin",
            "<html>Generic Google login page</html>",
        )
        source = GoogleIdentitySource()
        result = source._classify_response(resp, "example.com")
        assert result.error == "Not a Google Workspace domain"
        assert result.google_auth_type is None


# ── GoogleIdentitySource.lookup integration tests ──────────────────────


class TestGoogleIdentityLookup:
    @pytest.mark.asyncio
    async def test_invalid_domain_format(self):
        source = GoogleIdentitySource()
        result = await source.lookup("example.com/path")
        assert "Invalid domain" in result.error

    @pytest.mark.asyncio
    async def test_invalid_domain_backslash(self):
        source = GoogleIdentitySource()
        result = await source.lookup("example.com\\bad")
        assert "Invalid domain" in result.error

    @pytest.mark.asyncio
    async def test_invalid_domain_dotdot(self):
        source = GoogleIdentitySource()
        result = await source.lookup("example..com")
        assert "Invalid domain" in result.error

    @pytest.mark.asyncio
    async def test_federated_lookup(self):
        mock_resp = httpx.Response(
            status_code=200,
            request=httpx.Request("GET", "https://acme.okta.com/sso"),
            content=b"<html>Okta SSO</html>",
        )

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google_identity.http_client") as mock_hc:
            mock_hc.return_value = mock_client
            source = GoogleIdentitySource()
            result = await source.lookup("example.com")

        assert result.google_auth_type == "Federated"
        assert result.google_idp_name == "Okta"

    @pytest.mark.asyncio
    async def test_managed_lookup(self):
        mock_resp = httpx.Response(
            status_code=200,
            request=httpx.Request("GET", "https://accounts.google.com/ServiceLogin"),
            content=b'"hd":"example.com" identifier page',
        )

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google_identity.http_client") as mock_hc:
            mock_hc.return_value = mock_client
            source = GoogleIdentitySource()
            result = await source.lookup("example.com")

        assert result.google_auth_type == "Managed"

    @pytest.mark.asyncio
    async def test_timeout_error(self):
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google_identity.http_client") as mock_hc:
            mock_hc.return_value = mock_client
            source = GoogleIdentitySource()
            result = await source.lookup("example.com")

        assert "Network error" in result.error

    @pytest.mark.asyncio
    async def test_connect_error(self):
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google_identity.http_client") as mock_hc:
            mock_hc.return_value = mock_client
            source = GoogleIdentitySource()
            result = await source.lookup("example.com")

        assert "Network error" in result.error

    @pytest.mark.asyncio
    async def test_unexpected_error(self):
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(side_effect=RuntimeError("boom"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google_identity.http_client") as mock_hc:
            mock_hc.return_value = mock_client
            source = GoogleIdentitySource()
            result = await source.lookup("example.com")

        assert "Unexpected error" in result.error

    def test_source_name(self):
        assert GoogleIdentitySource().name == "google_identity"
