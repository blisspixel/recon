"""Tests for GoogleIdentitySource — Google Workspace identity routing detection.

Covers: lookup(), _classify_response(), _is_federated_redirect(),
_extract_idp_name(). The managed-body heuristic was removed because
Google's ServiceLogin page false-positively matches every queryable
domain (the `hd=` URL parameter is echoed verbatim into the response
body); managed-auth customers are detected via DNS fingerprint rules
instead.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from recon_tool.sources.google_identity import (
    MAX_REDIRECTS,
    GoogleIdentitySource,
    _extract_idp_name,
)


@pytest.fixture
def retry_delays(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Capture source-level retry backoff without waiting on a real clock."""
    delays: list[float] = []

    async def capture_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("recon_tool.retry.asyncio.sleep", capture_sleep)
    return delays


# ── _extract_idp_name unit tests ────────────────────────────────────────


class TestExtractIdpName:
    def test_okta(self):
        assert _extract_idp_name("https://synthetic-delta.okta.com/sso/saml") == "Okta"

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
        assert _extract_idp_name("https://synthetic-delta.auth0.com/samlp/abc") == "Auth0"

    def test_onelogin(self):
        assert _extract_idp_name("https://synthetic-delta.onelogin.com/trust/saml2") == "OneLogin"

    def test_duo(self):
        assert _extract_idp_name("https://sso.duo.com/saml2/sp/abc") == "Duo Security"

    def test_jumpcloud(self):
        assert _extract_idp_name("https://sso.jumpcloud.com/saml2/app") == "JumpCloud"

    def test_unknown_falls_back_to_hostname(self):
        assert _extract_idp_name("https://idp.synthetic-idp.invalid/sso") == "idp.synthetic-idp.invalid"

    def test_unparseable_returns_raw(self):
        assert _extract_idp_name("not-a-url") == "not-a-url"

    def test_lookalike_host_does_not_match(self):
        # A vendor name as a non-suffix part of the hostname must not match.
        assert _extract_idp_name("https://notokta.invalid/login") == "notokta.invalid"
        assert _extract_idp_name("https://oktatest.example/sso") == "oktatest.example"

    def test_pattern_only_in_path_or_query_does_not_match(self):
        # The IdP is the redirect host, not a string anywhere in the URL.
        assert _extract_idp_name("https://accounts.google.com/o/saml2?continue=https://x.okta.com") == "Google"
        assert _extract_idp_name("https://sso.delta.invalid/auth?idp=okta.com") == "sso.delta.invalid"

    def test_bare_vendor_host_matches(self):
        assert _extract_idp_name("https://okta.com/") == "Okta"


# ── _is_federated_redirect unit tests ───────────────────────────────────


class TestIsFederatedRedirect:
    @pytest.mark.parametrize(
        "url",
        [
            "not-a-url",
            "javascript:alert(1)",
            "https:///idp.synthetic.invalid/login",
            "https://user:password@idp.synthetic.invalid/login",
            "https://idp.synthetic.invalid:invalid/login",
            "https://[broken/login",
        ],
    )
    def test_malformed_url_is_not_federation(self, url: str):
        assert GoogleIdentitySource._is_federated_redirect(url) is False

    def test_non_google_domain_is_federated(self):
        assert GoogleIdentitySource._is_federated_redirect("https://synthetic-delta.okta.com/sso") is True

    def test_google_accounts_not_federated(self):
        assert (
            GoogleIdentitySource._is_federated_redirect("https://accounts.google.com/servicelogin?hd=example.com")
            is False
        )

    def test_google_saml_path_is_not_external_routing(self):
        assert (
            GoogleIdentitySource._is_federated_redirect("https://accounts.google.com/saml/redirect?idp=okta") is False
        )

    def test_google_sso_path_is_not_external_routing(self):
        assert GoogleIdentitySource._is_federated_redirect("https://accounts.google.com/sso/redirect") is False

    def test_plain_google_com(self):
        assert GoogleIdentitySource._is_federated_redirect("https://www.google.com/accounts/servicelogin") is False

    def test_google_adfs_path_is_not_external_routing(self):
        assert GoogleIdentitySource._is_federated_redirect("https://accounts.google.com/adfs/ls") is False

    def test_google_lookalike_host_is_federated(self):
        assert GoogleIdentitySource._is_federated_redirect("https://evilgoogle.invalid/accounts/servicelogin") is True
        assert GoogleIdentitySource._is_federated_redirect("https://google.com.example.net/accounts") is True

    def test_google_string_in_path_or_query_does_not_define_host(self):
        assert (
            GoogleIdentitySource._is_federated_redirect("https://idp.example.net/login?next=accounts.google.com")
            is True
        )

    def test_sso_indicator_in_query_is_not_external_routing(self):
        assert GoogleIdentitySource._is_federated_redirect("https://accounts.google.com/signin?continue=saml") is False


# ── _classify_response unit tests ──────────────────────────────────────


class TestClassifyResponse:
    def _make_response(self, url: str, body: str, status_code: int = 200) -> httpx.Response:
        return httpx.Response(
            status_code=status_code,
            request=httpx.Request("GET", url),
            content=body.encode(),
        )

    def test_federated_redirect_to_okta(self):
        resp = self._make_response(
            "https://synthetic-delta.okta.com/sso/saml2?SAMLRequest=abc",
            "<html>Okta login</html>",
        )
        source = GoogleIdentitySource()
        result = source._classify_response(resp, "example.com")
        assert result.google_auth_type == "Federated"
        assert result.google_idp_name == "Okta"
        assert "google-federated" in result.detected_slugs
        assert "google-workspace" in result.detected_slugs
        assert "Google Workspace" in result.detected_services

    def test_no_federated_redirect_returns_error(self):
        # When we stay on accounts.google.com with no SSO indicators, the
        # source now returns an error. Managed-Workspace detection via the
        # response body was removed because it false-positived on every
        # queryable domain (the `hd=` URL param is embedded in the page).
        resp = self._make_response(
            "https://accounts.google.com/ServiceLogin",
            'page content "hd":"example.com" identifier shown',
        )
        source = GoogleIdentitySource()
        result = source._classify_response(resp, "example.com")
        assert result.google_auth_type is None
        assert result.detected_slugs == ()
        assert result.detected_services == ()
        assert "No federated IdP redirect" in (result.error or "")

    def test_generic_login_page_returns_error(self):
        resp = self._make_response(
            "https://accounts.google.com/ServiceLogin",
            "<html>Generic Google login page</html>",
        )
        source = GoogleIdentitySource()
        result = source._classify_response(resp, "example.com")
        assert result.google_auth_type is None
        assert "No federated IdP redirect" in (result.error or "")


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
            request=httpx.Request("GET", "https://synthetic-delta.okta.com/sso"),
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
    async def test_no_federated_redirect_lookup(self):
        # Response stays on accounts.google.com with no SSO indicators →
        # the source returns an error (no Workspace claim without DNS evidence).
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

        assert result.google_auth_type is None
        assert result.detected_slugs == ()

    @pytest.mark.asyncio
    async def test_timeout_error(self, retry_delays: list[float]):
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google_identity.http_client") as mock_hc:
            mock_hc.return_value = mock_client
            source = GoogleIdentitySource()
            result = await source.lookup("example.com")

        assert "Network error" in result.error
        assert mock_client.get.await_count == 3
        assert retry_delays == [0.5, 1.5]

    @pytest.mark.asyncio
    async def test_connect_error(self, retry_delays: list[float]):
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google_identity.http_client") as mock_hc:
            mock_hc.return_value = mock_client
            source = GoogleIdentitySource()
            result = await source.lookup("example.com")

        assert "Network error" in result.error
        assert mock_client.get.await_count == 3
        assert retry_delays == [0.5, 1.5]

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


class TestGoogleIdentityRequestBoundary:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("marker", ["saml", "sso", "adfs", "okta", "pingone", "auth0"])
    async def test_domain_keywords_on_a_normal_google_page_do_not_establish_federation(self, marker: str):
        requests: list[httpx.Request] = []
        domain = f"{marker}.synthetic.invalid"

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            assert request.url.host == "accounts.google.com"
            assert request.url.params["hd"] == domain
            return httpx.Response(200, text=f"Sign in for {domain}; identifier; SAML SSO Okta")

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await GoogleIdentitySource().lookup(domain, client=client)

        assert len(requests) == 1
        assert result.source_unavailable is False
        assert result.google_auth_type is None
        assert result.google_idp_name is None
        assert result.detected_slugs == ()
        assert result.detected_services == ()
        assert result.evidence == ()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "location",
        [
            "/signin?continue=saml",
            "/signin?continue=https://idp.synthetic.invalid/sso",
            "/saml/redirect?idp=okta",
            "/sso/redirect",
            "/adfs/ls",
        ],
    )
    async def test_google_hosted_handoff_text_is_not_federation(self, location: str):
        requests: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            assert request.url.host == "accounts.google.com"
            if len(requests) == 1:
                return httpx.Response(302, headers={"Location": location})
            return httpx.Response(200, text="Google sign-in page")

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await GoogleIdentitySource().lookup("synthetic.invalid", client=client)

        assert len(requests) == 2
        assert result.source_unavailable is False
        assert result.google_auth_type is None
        assert result.detected_slugs == ()
        assert result.detected_services == ()
        assert result.evidence == ()

    @pytest.mark.asyncio
    async def test_external_redirect_after_google_handoff_establishes_federation(self):
        requests: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            assert request.url.host == "accounts.google.com"
            location = "/saml/redirect" if len(requests) == 1 else "https://idp.synthetic.invalid/login"
            return httpx.Response(302, headers={"Location": location})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=True) as client:
            result = await GoogleIdentitySource().lookup("synthetic.invalid", client=client)

        assert len(requests) == 2
        assert result.source_unavailable is False
        assert result.google_auth_type == "Federated"
        assert result.google_idp_name == "idp.synthetic.invalid"
        assert result.detected_slugs == ("google-federated", "google-workspace")
        assert any(item.raw_value == "Federated redirect to idp.synthetic.invalid" for item in result.evidence)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    @pytest.mark.parametrize("scheme", ["http", "https"])
    async def test_external_routing_is_observed_without_an_idp_request(self, status: int, scheme: str):
        requests: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            assert request.url.host == "accounts.google.com"
            return httpx.Response(status, headers={"Location": f"{scheme}://idp.synthetic.invalid/saml"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=True) as client:
            result = await GoogleIdentitySource().lookup("synthetic.invalid", client=client)

        assert len(requests) == 1
        assert requests[0].url.params["hd"] == "synthetic.invalid"
        assert result.google_auth_type == "Federated"
        assert result.google_idp_name == "idp.synthetic.invalid"
        assert result.detected_slugs == ("google-federated", "google-workspace")
        assert result.source_unavailable is False
        assert any(item.raw_value == "Federated redirect to idp.synthetic.invalid" for item in result.evidence)

    @pytest.mark.asyncio
    async def test_relative_google_chain_keeps_the_same_https_origin(self):
        requests: list[httpx.Request] = []
        destinations = [
            "/signin/step-one?flow=1",
            "step-two?flow=2",
            "https://accounts.google.com:443/signin/complete",
        ]

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            assert request.url.scheme == "https"
            assert request.url.host == "accounts.google.com"
            assert request.url.port in {None, 443}
            if len(requests) <= len(destinations):
                return httpx.Response(302, headers={"Location": destinations[len(requests) - 1]})
            return httpx.Response(200, text="Generic Google sign-in page")

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=True) as client:
            result = await GoogleIdentitySource().lookup("synthetic.invalid", client=client)

        assert [request.url.path for request in requests] == [
            "/ServiceLogin",
            "/signin/step-one",
            "/signin/step-two",
            "/signin/complete",
        ]
        assert result.google_auth_type is None
        assert result.source_unavailable is False
        assert "No federated IdP redirect" in (result.error or "")

    @pytest.mark.asyncio
    async def test_google_chain_stops_before_protocol_relative_external_idp(self):
        requests: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            assert request.url.host == "accounts.google.com"
            location = "/signin/next" if len(requests) == 1 else "//idp.synthetic.invalid/saml"
            return httpx.Response(302, headers={"Location": location})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await GoogleIdentitySource().lookup("synthetic.invalid", client=client)

        assert len(requests) == 2
        assert result.google_auth_type == "Federated"
        assert result.google_idp_name == "idp.synthetic.invalid"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "location",
        [
            "",
            "javascript:alert(1)",
            "ftp://idp.synthetic.invalid/login",
            "https:///idp.synthetic.invalid/login",
            "https:relative-path",
            "///idp.synthetic.invalid/login",
            "//",
            "https://./login",
            "https://idp..synthetic.invalid/login",
            "https://_idp.synthetic.invalid/login",
            "https://-idp.synthetic.invalid/login",
            "https://user:password@idp.synthetic.invalid/login",
            "https://@idp.synthetic.invalid/login",
            "https://idp.synthetic.invalid:invalid/login",
            "https://idp.synthetic.invalid:65536/login",
            "https://idp.synthetic.invalid:0/login",
            "https://idp.synthetic.invalid:/login",
            "https://[broken/login",
            "https://accounts.google.com\\@idp.synthetic.invalid/login",
            "https://%61ccounts.google.com/login",
            " https://idp.synthetic.invalid/login",
            "https://idp.synthetic.invalid/a b",
            "https://idp.synthetic.invalid/\tlogin",
            "https://idp.synthetic.invalid/\x00login",
            "http://accounts.google.com/login",
            "https://accounts.google.com:8443/login",
            "/" + "a" * 8192,
        ],
    )
    async def test_invalid_redirect_is_unavailable_and_never_fetched(self, location: str):
        requests: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            assert len(requests) == 1
            return httpx.Response(302, headers={"Location": location})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=True) as client:
            result = await GoogleIdentitySource().lookup("synthetic.invalid", client=client)

        assert len(requests) == 1
        assert result.source_unavailable is True
        assert result.google_auth_type is None
        assert result.detected_slugs == ()
        assert result.evidence == ()
        assert "Google identity routing unavailable" in (result.error or "")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "headers",
        [[], [("Location", "/first"), ("Location", "https://idp.synthetic.invalid/saml")]],
    )
    async def test_missing_or_duplicate_location_is_unavailable(self, headers: list[tuple[str, str]]):
        requests: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(302, headers=headers)

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await GoogleIdentitySource().lookup("synthetic.invalid", client=client)

        assert len(requests) == 1
        assert result.source_unavailable is True
        assert result.detected_slugs == ()

    @pytest.mark.asyncio
    async def test_redirect_loop_is_bounded_and_unavailable(self):
        requests: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(302, headers={"Location": "/loop"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await GoogleIdentitySource().lookup("synthetic.invalid", client=client)

        assert len(requests) == MAX_REDIRECTS + 1
        assert result.source_unavailable is True
        assert result.error == "Google identity routing unavailable: redirect limit exceeded"
        assert result.detected_slugs == ()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("status", "location"), [(304, "/signin"), (302, "https://www.google.com/signin")])
    async def test_unsupported_routing_is_unavailable(self, status: int, location: str):
        requests: list[httpx.Request] = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(status, headers={"Location": location})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await GoogleIdentitySource().lookup("synthetic.invalid", client=client)

        assert len(requests) == 1
        assert result.source_unavailable is True
        assert result.detected_slugs == ()
