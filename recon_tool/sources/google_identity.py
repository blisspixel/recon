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
from typing import Any
from urllib.parse import urlparse

import httpx

from recon_tool.http import http_client
from recon_tool.models import EvidenceRecord, SourceResult
from recon_tool.retry import retry_on_transient

logger = logging.getLogger("recon")

# Google's ServiceLogin endpoint with hosted domain parameter.
# When hd= is set, Google routes to the domain's auth configuration.
_GOOGLE_LOGIN_URL = "https://accounts.google.com/ServiceLogin"

# Timeout for the identity routing probe.
_IDENTITY_TIMEOUT = 5.0

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

    Checks against known IdP domain patterns. Falls back to the hostname
    portion of the URL if no pattern matches.
    """
    url_lower = url.lower()
    for pattern, name in _IDP_PATTERNS:
        if pattern in url_lower:
            return name
    # Fallback: extract hostname
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


class GoogleIdentitySource:
    """Lookup source: Google Workspace identity routing detection.

    Detects whether a domain uses Google Workspace and determines the
    authentication type (managed vs. federated). For federated domains,
    extracts the external Identity Provider URL and maps it to a
    human-readable name.
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
            resp = await c.get(
                _GOOGLE_LOGIN_URL,
                params={"hd": domain},
                follow_redirects=True,
            )
            return self._classify_response(resp, domain)

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        """Query Google's login flow to detect Workspace auth routing.

        Flow:
        1. GET accounts.google.com/ServiceLogin?hd={domain}
        2. Follow redirects (max 3) to detect auth routing
        3. If redirected to a third-party IdP → federated
        4. If stays on accounts.google.com with domain recognition → managed
        5. If generic login page / error → not a Google Workspace domain

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
            )
        except Exception as exc:
            logger.debug("Google identity probe failed for %s: %s", domain, exc)
            return SourceResult(
                    source_name="google_identity",
                    error=f"Unexpected error: {exc}",
                )

    def _classify_response(self, resp: httpx.Response, domain: str) -> SourceResult:
        """Classify the Google login response to determine auth routing."""
        final_url = str(resp.url).lower()
        body = resp.text

        # Check if we were redirected to a third-party IdP (federated)
        if self._is_federated_redirect(final_url):
            idp_name = _extract_idp_name(final_url)
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

        # No managed-domain detection via response body. Google's ServiceLogin
        # page embeds the `hd=` URL parameter and always contains the word
        # "identifier" (it's a sign-in identifier form), so body-text heuristics
        # false-positive on every queryable domain — including fabricated ones.
        # Workspace-managed customers are still detected via the DNS fingerprint
        # path (MX aspmx.l.google.com, SPF _spf.google.com, DKIM google._domainkey,
        # GWS module CNAMEs to ghs.googlehosted.com). Those paths are
        # evidence-based; this source now only claims Workspace when a genuine
        # third-party IdP redirect is observed.
        _ = body, domain  # kept for future use if a reliable marker is found
        return SourceResult(
            source_name="google_identity",
            error="No federated IdP redirect observed (managed detection requires DNS evidence)",
        )

    @staticmethod
    def _is_federated_redirect(final_url: str) -> bool:
        """Check if the final URL is a third-party IdP (not Google)."""
        # If we ended up on a non-Google domain, it's federated
        if "accounts.google.com" not in final_url and "google.com" not in final_url:
            return True
        # Some federated setups redirect through Google first then to the IdP
        # Check for SAML/SSO redirect indicators in the URL
        sso_indicators = ("saml", "sso", "adfs", "okta", "pingone", "auth0")
        return any(indicator in final_url for indicator in sso_indicators)

