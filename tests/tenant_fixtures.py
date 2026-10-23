"""Typed overrides shared by legacy TenantInfo test factories."""

from __future__ import annotations

from typing import TypedDict

from recon_tool import models


class _TenantOptions(TypedDict, total=False):
    """Only the optional overrides exercised by these fixtures."""

    confidence: models.ConfidenceLevel
    region: str | None
    sources: tuple[str, ...]
    services: tuple[str, ...]
    slugs: tuple[str, ...]
    auth_type: str | None
    dmarc_policy: str | None
    domain_count: int
    tenant_domains: tuple[str, ...]
    related_domains: tuple[str, ...]
    insights: tuple[str, ...]
    insight_claims: tuple[models.InsightClaim, ...]
    degraded_sources: tuple[str, ...]
    cert_summary: models.CertSummary | None
    evidence: tuple[models.EvidenceRecord, ...]
    mta_sts_mode: str | None
    email_gateway: str | None
    dmarc_testing: bool
    ct_provider_used: str | None
    ct_subdomain_count: int
    ct_cache_age_days: int | None
    ct_attempt_outcome: str | None
    posterior_observations: tuple[models.PosteriorObservation, ...]
    cloud_instance: str | None
    tenant_region_sub_scope: str | None
    msgraph_host: str | None


class TenantInfoArguments(_TenantOptions):
    """Typed constructor inputs with explicit required-key semantics."""

    tenant_id: str | None
    display_name: str
    default_domain: str
    queried_domain: str


class TenantInfoOverrides(_TenantOptions, total=False):
    """Typed constructor inputs with explicit required-key semantics."""

    tenant_id: str | None
    display_name: str
    default_domain: str
    queried_domain: str
