"""User Realm discovery source for tenant display name, auth type, and domains.

Queries two public Microsoft endpoints (no auth required):
1. GetUserRealm — returns FederationBrandName + NameSpaceType (Federated/Managed)
2. Autodiscover GetFederationInformation — returns all tenant domains
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any
from xml.sax.saxutils import escape as xml_escape

import defusedxml.ElementTree as DefusedET

from recon_tool.http import http_client
from recon_tool.models import EvidenceRecord, SourceResult

logger = logging.getLogger("recon")

USERREALM_URL = "https://login.microsoftonline.com/GetUserRealm.srf"

AUTODISCOVER_URL = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"

# Template uses {domain} placeholder — callers MUST xml-escape the value.
AUTODISCOVER_BODY = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:ext="http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"
  xmlns:a="http://www.w3.org/2005/08/addressing"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Request><Domain>{domain}</Domain></Request>
    </GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>"""


def _parse_autodiscover_domains(xml_text: str) -> tuple[list[str], str | None]:
    """Parse domain list and default domain from Autodiscover SOAP XML.

    Uses ElementTree for proper XML parsing instead of regex. Handles
    namespaced elements, CDATA, and encoded entities correctly.

    Returns:
        Tuple of (all_domains sorted lowercase, default_onmicrosoft_domain or None).
    """
    all_domains: list[str] = []
    default_domain: str | None = None

    try:
        root = DefusedET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.debug("Failed to parse Autodiscover XML: %s", exc)
        return [], None

    # Find all <Domain> elements regardless of namespace.
    # The Autodiscover response uses multiple namespaces, so we search
    # with a wildcard namespace prefix to catch them all.
    for elem in root.iter():
        # Match any element whose local name is "Domain"
        tag = elem.tag
        # Strip namespace: "{http://...}Domain" -> "Domain"
        local_name = tag.split("}")[-1] if "}" in tag else tag
        if local_name == "Domain" and elem.text:
            domain_val = elem.text.strip().lower()
            if domain_val:
                all_domains.append(domain_val)
                if domain_val.endswith(".onmicrosoft.com") and default_domain is None:
                    default_domain = domain_val

    return sorted(set(all_domains)), default_domain


class UserRealmSource:
    """Lookup source: GetUserRealm + Autodiscover for display name, auth type, and domains."""

    @property
    def name(self) -> str:
        return "user_realm"

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        """Query GetUserRealm and Autodiscover."""
        # Guard: reject domains that would produce malformed URLs/XML.
        if "/" in domain or "\\" in domain or ".." in domain:
            return SourceResult(
                source_name="user_realm",
                error=f"Invalid domain format: {domain!r}",
            )

        display_name: str | None = None
        default_domain: str | None = None
        auth_type: str | None = None
        tenant_domains: list[str] = []

        async with http_client(kwargs.get("client")) as client:
            # 1. GetUserRealm
            # The "user@" prefix is arbitrary — Microsoft's endpoint only cares
            # about the domain part after @. Any local-part works. We use "user"
            # because it's innocuous and doesn't look like a real probe.
            try:
                resp = await client.get(
                    USERREALM_URL,
                    params={"login": f"user@{domain}", "json": "1"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    brand = data.get("FederationBrandName")
                    if brand and isinstance(brand, str) and brand.strip():
                        display_name = brand.strip()
                    ns_type = data.get("NameSpaceType")
                    if ns_type and isinstance(ns_type, str):
                        auth_type = ns_type
            except Exception as exc:
                logger.debug("GetUserRealm failed for %s: %s", domain, exc)

            # 2. Autodiscover for domains — proper XML parsing via ElementTree
            try:
                body = AUTODISCOVER_BODY.format(domain=xml_escape(domain))
                resp = await client.post(
                    AUTODISCOVER_URL,
                    content=body,
                    headers={
                        "Content-Type": "text/xml; charset=utf-8",
                        "SOAPAction": "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation",
                        "User-Agent": "AutodiscoverClient",
                    },
                )
                if resp.status_code == 200:
                    tenant_domains, default_domain = _parse_autodiscover_domains(resp.text)
            except Exception as exc:
                logger.debug("Autodiscover failed for %s: %s", domain, exc)

            has_data = display_name or default_domain or auth_type or tenant_domains
            if has_data:
                evidence: list[EvidenceRecord] = []
                if display_name:
                    evidence.append(
                        EvidenceRecord(
                            source_type="HTTP",
                            raw_value=f"FederationBrandName={display_name}",
                            rule_name="GetUserRealm",
                            slug="microsoft365",
                        )
                    )
                if auth_type:
                    evidence.append(
                        EvidenceRecord(
                            source_type="HTTP",
                            raw_value=f"NameSpaceType={auth_type}",
                            rule_name="GetUserRealm",
                            slug="microsoft365",
                        )
                    )
                return SourceResult(
                    source_name="user_realm",
                    display_name=display_name,
                    default_domain=default_domain,
                    m365_detected=True,
                    auth_type=auth_type,
                    tenant_domains=tuple(tenant_domains),
                    evidence=tuple(evidence),
                )

            return SourceResult(
                source_name="user_realm",
                error="Could not resolve display name or default domain",
            )
