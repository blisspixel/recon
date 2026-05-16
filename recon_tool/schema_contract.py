"""Runtime mirror of the v2.0 schema's required-field list.

Downstream consumers read ``docs/recon-schema.json`` to validate that
``recon <domain> --json`` emits the locked top-level fields. That file
is the source of truth at PR-review time. At runtime, however, the
schema JSON is not bundled inside the installed package, so a tool that
wants to verify the emitter still satisfies the contract (``recon
doctor``) needs an in-package mirror.

This module is that mirror. The list is kept in sync with
``docs/recon-schema.json#/required`` by ``tests/test_json_schema_file.py``,
which fails CI on any drift between this tuple and the schema file.

Importing this module has no side effects; it exposes a single sorted
tuple of strings.
"""

from __future__ import annotations

REQUIRED_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "auth_type",
    "bimi_identity",
    "cert_summary",
    "chain_motifs",
    "cloud_instance",
    "confidence",
    "ct_cache_age_days",
    "ct_provider_used",
    "ct_subdomain_count",
    "default_domain",
    "degraded_sources",
    "detection_scores",
    "display_name",
    "dmarc_pct",
    "dmarc_policy",
    "domain_count",
    "email_gateway",
    "email_security_score",
    "evidence_confidence",
    "evidence_conflicts",
    "fingerprint_metadata",
    "google_auth_type",
    "google_idp_name",
    "inference_confidence",
    "infrastructure_clusters",
    "insights",
    "lexical_observations",
    "likely_primary_email_provider",
    "msgraph_host",
    "mta_sts_mode",
    "partial",
    "posterior_observations",
    "primary_email_provider",
    "provider",
    "queried_domain",
    "region",
    "related_domains",
    "services",
    "site_verification_tokens",
    "slug_confidences",
    "slugs",
    "sources",
    "surface_attributions",
    "tenant_domains",
    "tenant_id",
    "tenant_region_sub_scope",
)
