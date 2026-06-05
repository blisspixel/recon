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

Importing this module has no side effects; it exposes a sorted tuple of
the required single-domain fields plus the deterministic batch-record
classifier the schema contract references.
"""

from __future__ import annotations

from importlib.resources import files
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


def packaged_schema_text() -> str:
    """Return the bundled recon JSON-output schema as text.

    ``docs/recon-schema.json`` is the source of truth, but the wheel does not
    ship ``docs/``. A byte-identical copy is bundled at
    ``recon_tool/data/recon-schema.json`` so the MCP schema-discovery resource
    can serve the contract without an external fetch. The two are kept in sync
    by ``tests/test_schema_resource.py``. The schema's own ``description``
    field states the contract version.
    """
    return (files("recon_tool") / "data" / "recon-schema.json").read_text(encoding="utf-8")

REQUIRED_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "auth_type",
    "bimi_identity",
    "cert_summary",
    "chain_motifs",
    "cloud_instance",
    "confidence",
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
    "fusion_enabled",
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
    "record_type",
    "region",
    "related_domains",
    "schema_version",
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

# Batch and NDJSON runs interleave two record shapes: a single-domain
# success object (carrying every field in REQUIRED_TOP_LEVEL_FIELDS) and an
# error record emitted when a domain fails validation or lookup. The error
# record is exactly these two keys, matching docs/recon-schema.json
# $defs/BatchErrorRecord. The two shapes are disjoint, so a consumer can
# classify any batch / NDJSON record by its key set alone.
BATCH_ERROR_RECORD_KEYS: frozenset[str] = frozenset({"domain", "error"})


def classify_batch_record(record: Mapping[str, object]) -> str:
    """Classify one batch or NDJSON record by the deterministic rule set.

    Returns:
        ``"error"`` when the record is a BatchErrorRecord (exactly the
        ``{domain, error}`` keys); ``"success"`` when it carries every
        field in REQUIRED_TOP_LEVEL_FIELDS (a single-domain success
        object, possibly with extra batch-only or flag-gated fields);
        ``"unknown"`` for anything else.

    The classification is unambiguous because the two valid shapes do not
    overlap: the error record has exactly two keys, the success object
    requires far more. A success object never matches the error rule, and
    an error record never matches the success rule. This mirrors the
    ``oneOf`` branch in docs/recon-schema.json $defs/BatchArray and
    $defs/BatchNdjsonRecord, so a pure-Python consumer can validate batch
    output without a JSON Schema library.
    """
    # SH7: a v2.0 record self-identifies via record_type. This is the primary,
    # unambiguous path; the key-set rules below are a legacy fallback for
    # pre-v2.0 records that predate the discriminator.
    rt = record.get("record_type")
    if rt == "error":
        return "error"
    if rt == "lookup":
        return "success"
    keys = set(record.keys())
    if keys == set(BATCH_ERROR_RECORD_KEYS):
        return "error"
    # Pre-v2.0 success records lack the v2.0-added required fields, so the
    # fallback checks the required set without them.
    if keys.issuperset(set(REQUIRED_TOP_LEVEL_FIELDS) - _V2_ADDED_REQUIRED_FIELDS):
        return "success"
    return "unknown"


# Fields added to the required set in the v2.0 schema-hardening pass; excluded
# from the legacy key-set classifier so pre-v2.0 records still classify.
_V2_ADDED_REQUIRED_FIELDS: frozenset[str] = frozenset({"record_type", "schema_version", "fusion_enabled"})
