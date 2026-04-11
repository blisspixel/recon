"""Azure AD tenant metadata endpoint lookup source.

NOTE: This source requires a tenant_id from a prior source to construct
the request URL. In the current parallel resolution architecture, it cannot
receive data from other sources. It is retained for use in sequential
pipelines or direct invocation, but is NOT included in the default pool.
"""

from __future__ import annotations

from typing import Any

import httpx

from recon_tool.http import http_client
from recon_tool.models import SourceResult
from recon_tool.validator import UUID_RE

METADATA_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"


class AzureMetadataSource:
    """Fallback source: Azure AD tenant metadata endpoint.

    Requires a tenant_id from a prior source to construct the request URL.
    """

    @property
    def name(self) -> str:
        """Unique string identifier for this source."""
        return "azure_ad_metadata"

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        """Queries the Azure AD metadata endpoint using a previously resolved tenant_id.

        Extracts tenant_region_scope and passes through the tenant_id.
        If no tenant_id is provided in kwargs, returns an empty SourceResult.
        Validates tenant_id is a proper UUID before interpolating into URL.
        Never raises exceptions — always returns a SourceResult.
        """
        tenant_id: str | None = kwargs.get("tenant_id")

        if not tenant_id:
            return SourceResult(source_name="azure_ad_metadata")

        # Validate UUID format before interpolating into URL to prevent
        # path traversal or query parameter injection.
        if not UUID_RE.match(tenant_id):
            return SourceResult(
                source_name="azure_ad_metadata",
                error=f"Invalid tenant_id format: {tenant_id!r}",
            )

        url = METADATA_URL_TEMPLATE.format(tenant_id=tenant_id)

        async with http_client(kwargs.get("client")) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                region = data.get("tenant_region_scope") or None

                return SourceResult(
                    source_name="azure_ad_metadata",
                    tenant_id=tenant_id,
                    region=region,
                )
            except httpx.HTTPStatusError as exc:
                return SourceResult(
                    source_name="azure_ad_metadata",
                    error=f"HTTP {exc.response.status_code} from Azure AD metadata endpoint",
                )
            except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout) as exc:
                return SourceResult(
                    source_name="azure_ad_metadata",
                    error=f"Network error querying Azure AD metadata endpoint: {exc}",
                )
            except Exception as exc:
                return SourceResult(
                    source_name="azure_ad_metadata",
                    error=f"Unexpected error: {exc}",
                )
