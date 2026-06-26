"""Google Workspace passive discovery source.

Queries public, unauthenticated endpoints to detect Google Workspace
configuration and security posture:

1. Client-Side Encryption (CSE) discovery — checks for
   https://cse.{domain}/.well-known/cse-configuration which reveals
   that the org uses Google Workspace CSE with an external key manager.
   This is a high-security signal (data sovereignty, compliance).

2. Google Workspace SMTP relay check — probes for the presence of
   aspmx.l.google.com in MX records (already handled by DNS source,
   but this source adds the "google_workspace" flag for confidence
   scoring when DNS confirms Google MX).

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

logger = logging.getLogger("recon")

CSE_URL_TEMPLATE = "https://cse.{domain}/.well-known/cse-configuration"

# Short timeout — CSE endpoints either respond fast or don't exist.
CSE_TIMEOUT = 5.0


def parse_cse_config(data: dict[str, Any], domain: str) -> dict[str, Any]:
    """Extract intelligence from a CSE configuration response.

    Returns a dict with:
        - cse_enabled: True
        - cse_idp: the external IdP discovery URI (if present)
        - cse_client_id: the OAuth client ID (if present)
        - cse_kacls: the KACLS (Key Access Control List Service) URL (if present)
        - cse_key_providers: sorted list of distinct key service provider names (if present)
    """
    result: dict[str, Any] = {"cse_enabled": True}

    # The CSE config typically contains discovery_uri pointing to the
    # external IdP that controls encryption keys.
    discovery_uri = data.get("discovery_uri") or data.get("discoveryUri")
    if discovery_uri and isinstance(discovery_uri, str):
        result["cse_idp"] = discovery_uri

    client_id = data.get("client_id") or data.get("clientId")
    if client_id and isinstance(client_id, str):
        result["cse_client_id"] = client_id

    # KACLS URL extraction
    kacls_url = data.get("kacls_url") or data.get("kaclsUrl")
    if kacls_url and isinstance(kacls_url, str):
        result["cse_kacls"] = kacls_url

    # Multiple key service entries
    key_services = data.get("key_services") or data.get("keyServices") or []
    if isinstance(key_services, list):
        providers: set[str] = set()
        for ks in key_services:
            if isinstance(ks, dict):
                provider = ks.get("provider") or ks.get("name")
                if provider and isinstance(provider, str):
                    providers.add(provider)
        if providers:
            result["cse_key_providers"] = sorted(providers)

    return result


class GoogleSource:
    """Lookup source: Google Workspace passive discovery (CSE, metadata)."""

    @property
    def name(self) -> str:
        return "google_workspace"

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        """Probe Google Workspace-specific public endpoints.

        Currently checks:
        - CSE configuration endpoint (high-security signal)

        The CSE check is a direct HTTPS GET to ``cse.<domain>``, a host the
        looked-up party controls, so it is gated behind the opt-in
        ``active_probes`` kwarg. Without it (the default) this source makes no
        network call and returns an empty result, keeping collection passive.

        Returns SourceResult with detected services and slugs.
        Never raises — always returns a SourceResult.
        """
        if "/" in domain or "\\" in domain or ".." in domain:
            return SourceResult(
                source_name="google_workspace",
                error=f"Invalid domain format: {domain!r}",
            )

        # Passive by default: the CSE discovery probe is a direct request to a
        # target-controlled subdomain, so skip it unless the operator opted in
        # via --direct-probes (active_probes). No error, just no contribution.
        if not bool(kwargs.get("active_probes", False)):
            return SourceResult(source_name="google_workspace")

        services: list[str] = []
        slugs: list[str] = []
        evidence: list[EvidenceRecord] = []

        # Probe CSE configuration
        cse_result = await self._probe_cse(domain, kwargs.get("client"))
        if cse_result:
            services.append("Google Workspace CSE")
            slugs.append("google-cse")
            evidence.append(
                EvidenceRecord(
                    source_type="HTTP",
                    raw_value="CSE configuration found",
                    rule_name="Google Workspace CSE",
                    slug="google-cse",
                )
            )
            idp = cse_result.get("cse_idp")
            if idp:
                services.append(f"CSE Key Manager: {_extract_idp_name(idp)}")

        if services:
            return SourceResult(
                source_name="google_workspace",
                detected_services=tuple(sorted(services)),
                detected_slugs=tuple(sorted(slugs)),
                evidence=tuple(evidence),
            )

        return SourceResult(
            source_name="google_workspace",
            error="No Google Workspace-specific configuration found",
        )

    @staticmethod
    async def _probe_cse(
        domain: str,
        provided_client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any] | None:
        """Check for CSE configuration at cse.{domain}."""
        url = CSE_URL_TEMPLATE.format(domain=domain)
        async with http_client(provided_client, timeout=CSE_TIMEOUT) as client:
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return None
                data = resp.json()
                if isinstance(data, dict):
                    return parse_cse_config(data, domain)
            except (
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.ConnectTimeout,
                httpx.HTTPError,
                ValueError,
            ):
                pass
            except Exception as exc:
                logger.debug("CSE probe failed for %s: %s", domain, exc)
        return None


def _extract_idp_name(discovery_uri: str) -> str:
    """Extract a human-readable IdP name from a discovery URI.

    Examples:
        https://login.okta.com/... → Okta
        https://sso.pingidentity.com/... → Ping Identity
        https://accounts.google.com/... → Google
        https://login.microsoftonline.com/... → Microsoft Entra
    """
    try:
        host = (urlparse(discovery_uri).hostname or "").lower()
    except ValueError:
        host = ""

    def _host_matches(domain: str) -> bool:
        return host == domain or host.endswith(f".{domain}")

    if _host_matches("okta.com"):
        return "Okta"
    if _host_matches("pingidentity.com") or _host_matches("pingone.com"):
        return "Ping Identity"
    if _host_matches("microsoftonline.com") or _host_matches("microsoft.com"):
        return "Microsoft Entra"
    if _host_matches("accounts.google.com"):
        return "Google"
    if _host_matches("auth0.com"):
        return "Auth0"
    return host or discovery_uri
