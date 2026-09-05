"""Google Workspace identity routing detection source.

Queries Google's public login flow to determine whether a domain uses
Google Workspace and whether authentication is managed (Google-native)
or federated (external IdP like Okta, Ping, Entra).

This is the Google equivalent of Microsoft's GetUserRealm endpoint.
The probe is passive — it mimics the first step of the Google login
flow by requesting the ServiceLogin page with an hd= (hosted domain)
parameter. Google's response reveals the authentication routing.

All probes are passive, unauthenticated HTTP GETs. No credentials,
no login attempts, no API keys.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse, urlsplit

import httpx

from recon_tool.http import MAX_REDIRECTS, http_client
from recon_tool.models import EvidenceRecord, SourceResult
from recon_tool.retry import retry_on_transient
from recon_tool.validator import host_has_suffix

logger = logging.getLogger("recon")

# Google's ServiceLogin endpoint with hosted domain parameter.
# When hd= is set, Google routes to the domain's auth configuration.
_GOOGLE_LOGIN_URL = "https://accounts.google.com/ServiceLogin"

# Timeout for the identity routing probe.
_IDENTITY_TIMEOUT = 5.0
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_MAX_LOCATION_LENGTH = 8192
_HOST_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

# Known IdP patterns for human-readable name extraction.
_IDP_PATTERNS: tuple[tuple[str, str], ...] = (
    ("okta.com", "Okta"),
    ("pingidentity.com", "Ping Identity"),
    ("pingone.com", "Ping Identity"),
    ("microsoftonline.com", "Microsoft Entra"),
    ("microsoft.com", "Microsoft Entra"),
    ("accounts.google.com", "Google"),
    ("auth0.com", "Auth0"),
    ("onelogin.com", "OneLogin"),
    ("duo.com", "Duo Security"),
    ("jumpcloud.com", "JumpCloud"),
)


def _extract_idp_name(url: str) -> str:
    """Extract a human-readable IdP name from a URL.

    Matches the URL hostname against known IdP domains by suffix, so an
    unrelated host such as ``notokta.com`` does not match ``okta.com`` and a
    pattern that appears only in the path or query does not match either.
    Falls back to the hostname (or the raw input when there is none) if no
    pattern matches.
    """
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        host = ""
    for pattern, name in _IDP_PATTERNS:
        if host_has_suffix(host, pattern):
            return name
    return host or url


def _routing_url(value: str, base: httpx.URL | None = None) -> httpx.URL:
    """Parse one unambiguous HTTP routing URL without trusting URL cleanup."""
    if (
        not value
        or len(value) > _MAX_LOCATION_LENGTH
        or value.startswith("///")
        or "\\" in value
        or any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError("Invalid redirect location")
    try:
        raw = urlsplit(value)
        if raw.scheme and (raw.scheme.lower() not in {"http", "https"} or not raw.netloc):
            raise ValueError("Invalid redirect scheme or authority")
        if value.startswith("//") and not raw.netloc:
            raise ValueError("Invalid redirect authority")
        if not base and not raw.netloc:
            raise ValueError("Redirect destination must be absolute")
        if "@" in raw.netloc or "%" in raw.netloc or raw.netloc.endswith(":"):
            raise ValueError("Ambiguous redirect authority")
        destination = base.join(value) if base is not None else httpx.URL(value)
        parsed = urlsplit(str(destination))
        host = destination.raw_host.decode("ascii")
        if (
            destination.scheme not in {"http", "https"}
            or not destination.host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port == 0
        ):
            raise ValueError("Invalid redirect destination")
        if ":" not in host and (
            len(host) > 253
            or any(_HOST_LABEL_RE.fullmatch(label) is None for label in host.removesuffix(".").split("."))
        ):
            raise ValueError("Invalid redirect hostname")
    except (ValueError, httpx.InvalidURL) as exc:
        raise ValueError("Invalid redirect destination") from exc
    return destination


def _routing_unavailable(detail: str) -> SourceResult:
    return SourceResult(
        source_name="google_identity",
        error=f"Google identity routing unavailable: {detail}",
        source_unavailable=True,
    )


def _redirect_target(response: httpx.Response, current_url: httpx.URL, redirects: int) -> httpx.URL:
    """Admit one redirect before the collector decides whether to follow it."""
    if response.status_code not in _REDIRECT_STATUS_CODES:
        raise ValueError("unsupported redirect response")
    if redirects == MAX_REDIRECTS:
        raise ValueError("redirect limit exceeded")
    locations = response.headers.get_list("location")
    if len(locations) != 1:
        raise ValueError("redirect requires one Location header")
    try:
        destination = _routing_url(locations[0], current_url)
    except ValueError as exc:
        raise ValueError("invalid redirect destination") from exc
    if destination.host == "accounts.google.com" and (
        destination.scheme != "https" or destination.port not in {None, 443}
    ):
        raise ValueError("unsafe Google identity redirect destination")
    return destination


class GoogleIdentitySource:
    """Lookup source: Google Workspace identity routing detection.

    Observes external identity-provider routing from Google's login endpoint.
    A Google-hosted page alone does not establish Workspace membership or an
    authentication type. An external redirect destination is mapped to a
    human-readable identity-provider name without requesting that destination.
    """

    @property
    def name(self) -> str:
        """Unique string identifier for this source."""
        return "google_identity"

    @retry_on_transient()
    async def _fetch(self, domain: str, client: httpx.AsyncClient | None) -> SourceResult:
        """Inner fetch that raises on transient failures so the retry
        decorator can re-attempt."""
        async with http_client(client, timeout=_IDENTITY_TIMEOUT) as c:
            url = httpx.URL(_GOOGLE_LOGIN_URL).copy_add_param("hd", domain)
            for redirects in range(MAX_REDIRECTS + 1):
                try:
                    resp = await c.get(url, follow_redirects=False)
                except (httpx.InvalidURL, httpx.RemoteProtocolError, ValueError):
                    # httpx prepares next_request even when redirect following
                    # is disabled, so malformed Locations may fail before the
                    # response reaches our explicit redirect admission below.
                    return _routing_unavailable("invalid redirect destination or response")
                if resp.status_code == 429 or resp.status_code >= 500:
                    resp.raise_for_status()
                if not 300 <= resp.status_code < 400:
                    return self._classify_response(resp, domain)
                try:
                    destination = _redirect_target(resp, url, redirects)
                except ValueError as exc:
                    return _routing_unavailable(str(exc))
                if destination.host != "accounts.google.com":
                    if self._is_federated_redirect(str(destination)):
                        return self._federated_result(str(destination))
                    return _routing_unavailable("redirect left the permitted Google identity endpoint")
                url = destination
        return _routing_unavailable("redirect limit exceeded")  # pragma: no cover

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        """Query Google's login flow to detect Workspace auth routing.

        Flow:
        1. GET accounts.google.com/ServiceLogin?hd={domain}
        2. Follow bounded HTTPS redirects within accounts.google.com
        3. Record third-party IdP routing without requesting the IdP
        4. If routing stays on Google, leave authentication unresolved
        5. Report malformed or incomplete routing as unavailable

        Returns SourceResult with google-workspace + auth type slugs.
        Never raises — always returns a SourceResult. Transient network
        failures are retried via the ``retry_on_transient`` decorator on
        ``_fetch``.
        """
        if "/" in domain or "\\" in domain or ".." in domain:
            return SourceResult(
                source_name="google_identity",
                error=f"Invalid domain format: {domain!r}",
            )

        try:
            return await self._fetch(domain, kwargs.get("client"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout) as exc:
            return SourceResult(
                source_name="google_identity",
                error=f"Network error querying Google identity after retries: {exc}",
                source_unavailable=True,
            )
        except Exception as exc:
            logger.debug("Google identity probe failed for %s: %s", domain, exc)
            return SourceResult(
                source_name="google_identity",
                error=f"Unexpected error: {exc}",
                source_unavailable=True,
            )

    def _classify_response(self, resp: httpx.Response, domain: str) -> SourceResult:
        """Classify the Google login response to determine auth routing."""
        final_url = str(resp.url).lower()
        body = resp.text

        # Check if we were redirected to a third-party IdP (federated)
        if self._is_federated_redirect(final_url):
            return self._federated_result(final_url)

        # No managed-domain detection via response body. Google's ServiceLogin
        # page embeds the `hd=` URL parameter and always contains the word
        # "identifier" (it's a sign-in identifier form), so body-text heuristics
        # false-positive on every queryable domain. Managed Workspace detection
        # remains the responsibility of the DNS fingerprint rules.
        _ = body, domain
        return SourceResult(
            source_name="google_identity",
            error="No federated IdP redirect observed (managed detection requires DNS evidence)",
        )

    @staticmethod
    def _federated_result(url: str) -> SourceResult:
        """Retain routing evidence without requiring an IdP response body."""
        idp_name = _extract_idp_name(url)
        return SourceResult(
            source_name="google_identity",
            detected_services=("Google Workspace",),
            detected_slugs=("google-federated", "google-workspace"),
            google_auth_type="Federated",
            google_idp_name=idp_name,
            evidence=(
                EvidenceRecord(
                    source_type="HTTP",
                    raw_value=f"Federated redirect to {idp_name}",
                    rule_name="Google Identity Routing",
                    slug="google-federated",
                ),
                EvidenceRecord(
                    source_type="HTTP",
                    raw_value=f"Federated Google Workspace tenant (IdP: {idp_name})",
                    rule_name="Google Identity Routing",
                    slug="google-workspace",
                ),
            ),
        )

    @staticmethod
    def _is_federated_redirect(final_url: str) -> bool:
        """Identify an external routing destination, never Google URL text."""
        try:
            parsed = urlparse(str(_routing_url(final_url)))
        except ValueError:
            return False

        host = (parsed.hostname or "").lower()
        # Google echoes caller-controlled values such as hd and continue in
        # its URLs. SSO markers there, or in a Google-hosted path, do not prove
        # that an external IdP was selected. Only the routing host carries that
        # evidence; _fetch stops before making any request to an external host.
        return not host_has_suffix(host, "google.com")
