"""OIDC discovery endpoint lookup source for M365 tenant resolution."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from recon_tool.http import http_client
from recon_tool.models import EvidenceRecord, ReconLookupError, SourceResult
from recon_tool.retry import retry_on_transient
from recon_tool.validator import UUID_RE

DISCOVERY_URL_TEMPLATE = "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"


def parse_tenant_info_from_oidc(response_json: dict[str, Any]) -> SourceResult:
    """
    Pure function: extracts tenant data from a discovery endpoint JSON response.

    Extracts:
    - tenant_id from the authorization_endpoint URL path
    - region from tenant_region_scope
    - cloud_instance from cloud_instance_name (Microsoft extension) —
      distinguishes commercial (microsoftonline.com), US Government
      (microsoftonline.us), and China 21Vianet
      (partner.microsoftonline.cn) tenants. Added in v0.9.3.
    - tenant_region_sub_scope from the same-named Microsoft extension
      (GCC, DOD, USGov, etc.) when present. Added in v0.9.3.
    - msgraph_host from msgraph_host (Microsoft extension) — the
      authoritative Graph API host for the tenant, which sometimes
      reveals a sovereign cloud. Added in v0.9.3.

    Args:
        response_json: Parsed JSON dict from the discovery endpoint.

    Returns:
        SourceResult with extracted fields.

    Raises:
        ReconLookupError: If tenant_id cannot be extracted or is not a valid UUID.
    """
    auth_endpoint = response_json.get("authorization_endpoint", "")
    tenant_id: str | None = None

    if auth_endpoint:
        parsed = urlparse(auth_endpoint)
        # Path looks like /{tenant_id}/oauth2/v2.0/authorize
        parts = [p for p in parsed.path.split("/") if p]
        if parts:
            candidate = parts[0]
            if UUID_RE.match(candidate):
                tenant_id = candidate.lower()

    if tenant_id is None:
        raise ReconLookupError(
            domain="",
            message="Could not extract a valid tenant ID from OIDC discovery response",
            error_type="parse_error",
        )

    region = response_json.get("tenant_region_scope") or None

    # v0.9.3: tenant metadata enrichment — parse the Microsoft-specific
    # OIDC extensions that disambiguate sovereign clouds. All three are
    # optional in the response; None when the discovery doc doesn't
    # carry them.
    cloud_instance_raw = response_json.get("cloud_instance_name")
    cloud_instance: str | None = (
        str(cloud_instance_raw).strip() or None
        if cloud_instance_raw is not None
        else None
    )

    sub_scope_raw = response_json.get("tenant_region_sub_scope")
    tenant_region_sub_scope: str | None = (
        str(sub_scope_raw).strip() or None if sub_scope_raw is not None else None
    )

    msgraph_raw = response_json.get("msgraph_host")
    msgraph_host: str | None = (
        str(msgraph_raw).strip() or None if msgraph_raw is not None else None
    )

    return SourceResult(
        source_name="oidc_discovery",
        tenant_id=tenant_id,
        region=region,
        cloud_instance=cloud_instance,
        tenant_region_sub_scope=tenant_region_sub_scope,
        msgraph_host=msgraph_host,
        evidence=(
            EvidenceRecord(
                source_type="HTTP",
                raw_value=f"tenant_id={tenant_id}",
                rule_name="OIDC Discovery",
                slug="microsoft365",
            ),
        ),
    )


class OIDCSource:
    """Primary lookup source: Microsoft OIDC discovery endpoint."""

    @property
    def name(self) -> str:
        """Unique string identifier for this source."""
        return "oidc_discovery"

    @retry_on_transient()
    async def _fetch(self, domain: str, client: httpx.AsyncClient | None) -> SourceResult:
        """Inner fetch that raises on transient failures so the retry
        decorator can re-attempt. Semantic failures (HTTP 4xx other than
        429/503 — which the transport layer handles — and parse errors)
        are returned as SourceResult so they don't retry."""
        url = DISCOVERY_URL_TEMPLATE.format(domain=domain)
        async with http_client(client) as c:
            try:
                response = await c.get(url)
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPStatusError as exc:
                return SourceResult(
                    source_name="oidc_discovery",
                    error=f"HTTP {exc.response.status_code} from OIDC discovery endpoint",
                )
        try:
            return parse_tenant_info_from_oidc(data)
        except ReconLookupError as exc:
            return SourceResult(source_name="oidc_discovery", error=exc.message)

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        """Queries the OIDC discovery endpoint and extracts tenant information.

        Returns SourceResult with tenant_id, and optionally region.
        Never raises exceptions — always returns a SourceResult.

        Transient network failures (timeout, connection reset) are retried
        automatically via the ``retry_on_transient`` decorator on ``_fetch``.
        """
        # Guard: reject domains that would produce malformed URLs.
        # The validator catches this upstream, but defend in depth for
        # direct callers (tests, library usage).
        if "/" in domain or "\\" in domain or ".." in domain:
            return SourceResult(
                source_name="oidc_discovery",
                error=f"Invalid domain format: {domain!r}",
            )

        try:
            return await self._fetch(domain, kwargs.get("client"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout) as exc:
            return SourceResult(
                source_name="oidc_discovery",
                error=f"Network error querying OIDC discovery endpoint after retries: {exc}",
            )
        except Exception as exc:
            return SourceResult(
                source_name="oidc_discovery",
                error=f"Unexpected error: {exc}",
            )
