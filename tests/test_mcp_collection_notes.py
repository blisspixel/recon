"""MCP text distinguishes unavailable CT from cache and provider recovery."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from recon_tool.formatter.collection_status import collection_note_parts, project_collection_status
from recon_tool.models import ConfidenceLevel, TenantInfo
from recon_tool.server.lookup import _lookup_tenant_text


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({}, None),
        ({"degraded_sources": ("dns:mx",)}, "Some sources unavailable (dns:mx)"),
        (
            {"degraded_sources": ("crt.sh", "certspotter")},
            "All CT providers unavailable (crt.sh, certspotter)",
        ),
        (
            {"degraded_sources": ("crt.sh",), "ct_provider_used": "certspotter", "ct_subdomain_count": 12},
            "CT recovered via certspotter",
        ),
        (
            {
                "degraded_sources": ("crt.sh", "certspotter"),
                "ct_provider_used": "crt.sh (cached)",
                "ct_subdomain_count": 12,
                "ct_cache_age_days": 2,
            },
            "CT: from local cache, 2 days old (12 subdomains)",
        ),
        (
            {
                "degraded_sources": ("dns:dmarc", "crt.sh"),
                "ct_provider_used": "crt.sh (cached)",
                "ct_subdomain_count": 4,
                "ct_cache_age_days": 0,
            },
            "Some sources unavailable (dns:dmarc); CT: from local cache, today (4 subdomains)",
        ),
        (
            {
                "degraded_sources": ("dns:mx", "crt.sh"),
                "ct_provider_used": "certspotter",
                "ct_subdomain_count": 0,
            },
            "Some sources unavailable (dns:mx); CT recovered via certspotter",
        ),
    ],
)
def test_mcp_collection_notes_reuse_shared_caveats_without_hiding_source_details(
    fields: dict[str, Any], expected: str | None
) -> None:
    info = replace(
        TenantInfo(
            tenant_id=None,
            display_name="Synthetic",
            default_domain="example.invalid",
            queried_domain="example.invalid",
            confidence=ConfidenceLevel.LOW,
        ),
        **fields,
    )

    output = _lookup_tenant_text(info)

    if expected is None:
        assert "Collection note:" not in output
        assert "Degraded sources:" not in output
    else:
        assert f"Collection note: {expected}." in output
        assert f"Degraded sources: {', '.join(info.degraded_sources)}" in output
    for note in collection_note_parts(project_collection_status(info)):
        assert note in output
    if info.ct_provider_used is not None:
        assert "All CT providers unavailable" not in output
