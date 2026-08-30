"""Generated-schema support for the separate ReviewBundle v1 contract."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from functools import lru_cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from recon_tool.review_bundle import (
    EXPLAINED_BASELINE_SCHEMA_VERSION,
    REVIEW_BUNDLE_SCHEMA_VERSION,
    REVIEW_CANDIDATES_SCHEMA_VERSION,
    REVIEW_LIMITATIONS,
    REVIEW_SCOPE_STATEMENT,
)

REVIEW_BUNDLE_TOP_LEVEL_FIELDS = (
    "record_type",
    "schema_version",
    "generated_at",
    "generator",
    "interpretation_context",
    "scope",
    "collection",
    "source_opportunities",
    "workflow",
    "result",
    "scope_statement",
    "limitations",
    "content_digest",
)

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_DOMAIN_PATTERN = r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$"
_PRINTABLE_PATTERN = r"^[^\u0000-\u001f\u007f]+$"
_TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"

__all__ = [
    "REVIEW_BUNDLE_TOP_LEVEL_FIELDS",
    "build_review_bundle_schema",
    "packaged_review_bundle_schema",
    "packaged_review_bundle_schema_text",
    "validate_review_bundle_document",
]


def _closed(properties: dict[str, Any], *, required: tuple[str, ...] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(required or properties),
        "properties": properties,
    }


def _string(maximum: int, *, enum: tuple[str, ...] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "string",
        "minLength": 1,
        "maxLength": maximum,
        "pattern": _PRINTABLE_PATTERN,
    }
    if enum is not None:
        schema["enum"] = list(enum)
    return schema


def _string_array(maximum: int, *, nonempty: bool = False) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "array",
        "items": _string(maximum),
        "uniqueItems": True,
    }
    if nonempty:
        schema["minItems"] = 1
    return schema


def _localize_lookup_refs(value: Any) -> Any:
    if isinstance(value, dict):
        localized: dict[str, Any] = {}
        for key, item in value.items():
            if key in {"$schema", "$id"}:
                continue
            if key == "$ref" and isinstance(item, str):
                if item == "#":
                    localized[key] = "#/$defs/LookupResult"
                elif item.startswith("#/$defs/"):
                    localized[key] = f"#/$defs/LookupResult/$defs/{item.removeprefix('#/$defs/')}"
                else:
                    raise ValueError(f"lookup schema contains a non-local reference: {item}")
            else:
                localized[key] = _localize_lookup_refs(item)
        return localized
    if isinstance(value, list):
        return [_localize_lookup_refs(item) for item in value]
    return copy.deepcopy(value)


def build_review_bundle_schema(lookup_schema: dict[str, Any]) -> dict[str, Any]:
    """Build the self-contained ReviewBundle schema around the current lookup schema."""
    lookup = _localize_lookup_refs(lookup_schema)
    digest = {"type": "string", "pattern": _DIGEST_PATTERN}
    timestamp = {"type": "string", "format": "date-time", "pattern": _TIMESTAMP_PATTERN}
    domain = {"type": "string", "minLength": 1, "maxLength": 253, "pattern": _DOMAIN_PATTERN}
    evidence_body = _closed(
        {
            "source_type": _string(8192),
            "raw_value": _string(8192),
            "rule_name": _string(8192),
            "slug": _string(8192),
        }
    )
    evidence_ledger_entry = _closed({"evidence_id": digest, **evidence_body["properties"]})
    explanation = _closed(
        {
            "item_name": _string(16384),
            "item_type": _string(16384),
            "matched_evidence": {"type": "array", "items": {"$ref": "#/$defs/EvidenceBody"}},
            "evidence_ids": {"type": "array", "items": digest, "uniqueItems": True},
            "fired_rules": _string_array(16384),
            "confidence_derivation": {"type": "string", "maxLength": 16384},
            "weakening_conditions": _string_array(16384),
            "curated_explanation": {"type": "string", "maxLength": 16384},
            "lineage_status": _string(
                32,
                enum=("exact", "exact_rule_only", "reconstructed", "unsupported"),
            ),
            "lineage_rule_ids": _string_array(16384),
        }
    )
    evidence_node = _closed(
        {
            "id": _string(16384),
            "type": {"const": "evidence"},
            "name": _string(16384),
            "source_type": _string(8192),
            "raw_value": _string(8192),
            "rule_name": _string(8192),
            "slug": _string(8192),
        }
    )
    slug_node = _closed({"id": _string(16384), "type": {"const": "slug"}, "name": _string(16384)})
    rule_node = _closed(
        {
            "id": _string(16384),
            "type": {"const": "rule"},
            "name": _string(16384),
            "lineage_status": _string(
                32,
                enum=("exact", "exact_rule_only", "reconstructed", "unsupported"),
            ),
        }
    )
    terminal_node = _closed(
        {
            "id": _string(16384),
            "type": _string(32, enum=("signal", "insight", "observation", "confidence")),
            "name": _string(16384),
            "confidence_derivation": {"type": "string", "maxLength": 16384},
            "weakening_conditions": _string_array(16384),
            "curated_explanation": {"type": "string", "maxLength": 16384},
            "lineage_status": _string(
                32,
                enum=("exact", "exact_rule_only", "reconstructed", "unsupported"),
            ),
            "lineage_rule_ids": _string_array(16384),
        }
    )
    explanation_dag = _closed(
        {
            "nodes": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {"$ref": "#/$defs/ExplanationEvidenceNode"},
                        {"$ref": "#/$defs/ExplanationSlugNode"},
                        {"$ref": "#/$defs/ExplanationRuleNode"},
                        {"$ref": "#/$defs/ExplanationTerminalNode"},
                    ]
                },
            },
            "edges": {"type": "array", "items": {"$ref": "#/$defs/ExplanationEdge"}, "uniqueItems": True},
            "schema_version": {"const": 1},
            "provenance_complete": {"type": "boolean"},
            "disconnected_terminals": _string_array(16384),
            "exact_provenance_complete": {"type": "boolean"},
            "lineage_disconnected_terminals": _string_array(16384),
        }
    )
    metadata_dependency = _closed(
        {
            "field": _string(128),
            "operator": _string(32),
            "expected_value": {},
            "observed_value": {},
        }
    )
    candidate = _closed(
        {
            "candidate_id": digest,
            "category": _string(8192),
            "severity": _string(8192),
            "observation": _string(8192),
            "recommendation": _string(8192),
            "generator_rule_id": _string(8192),
            "observation_state": _string(8192),
            "observation_scope": _string_array(8192),
            "metadata_dependencies": {
                "type": "array",
                "items": {"$ref": "#/$defs/MetadataDependency"},
            },
            "absence_confirmable": {"type": "boolean"},
            "evidence": {"type": "array", "items": {"$ref": "#/$defs/EvidenceBody"}},
            "evidence_ids": {"type": "array", "items": digest, "uniqueItems": True},
        }
    )
    defs: dict[str, Any] = {
        "Generator": _closed({"name": {"const": "recon-tool"}, "version": _string(64)}),
        "InterpretationContext": _closed(
            {
                "recon_version": _string(64),
                "normalizer_version": _string(32),
                "catalog_digest": digest,
                "model_digest": digest,
            }
        ),
        "Scope": _closed(
            {
                "kind": {"const": "single_namespace"},
                "selection_basis": {"const": "caller_supplied"},
                "input_coordinate": _string(512),
                "queried_domain": {"oneOf": [domain, {"type": "null"}]},
            }
        ),
        "CollectionOptions": _closed(
            {
                "ct_enabled": {"type": "boolean"},
                "direct_probes": {"const": False},
                "timeout_seconds": {"type": "number", "exclusiveMinimum": 0},
            }
        ),
        "CollectionCache": _closed(
            {
                "result_cache": {"const": "bypassed"},
                "ct_provider_used": {"type": ["string", "null"]},
                "ct_cache_age_days": {"type": ["integer", "null"], "minimum": 0},
                "ct_attempt_outcome": {"type": ["string", "null"]},
            }
        ),
        "Collection": _closed(
            {
                "started_at": timestamp,
                "ended_at": timestamp,
                "as_of": timestamp,
                "options": {"$ref": "#/$defs/CollectionOptions"},
                "vantage": _string(128),
                "cache": {"$ref": "#/$defs/CollectionCache"},
            }
        ),
        "ObservationWindow": _closed({"started_at": timestamp, "ended_at": timestamp}),
        "SourceOpportunity": _closed(
            {
                "source_role": _string(128),
                "state": _string(
                    32,
                    enum=("observed_value", "observed_empty", "partial", "unavailable"),
                ),
                "instance_count": {"type": "integer", "minimum": 1},
                "degraded_markers": _string_array(1024),
                "observation_window": {"$ref": "#/$defs/ObservationWindow"},
            }
        ),
        "Workflow": _closed(
            {
                "status": _string(16, enum=("completed", "failed")),
                "collection_validity": _string(
                    64,
                    enum=(
                        "complete_for_recorded_opportunities",
                        "partial",
                        "unavailable",
                        "not_observed",
                    ),
                ),
                "freshness_assessment": {"const": "not_assigned"},
            }
        ),
        "EvidenceBody": evidence_body,
        "EvidenceLedgerEntry": evidence_ledger_entry,
        "ExplanationRecord": explanation,
        "ExplanationEvidenceNode": evidence_node,
        "ExplanationSlugNode": slug_node,
        "ExplanationRuleNode": rule_node,
        "ExplanationTerminalNode": terminal_node,
        "ExplanationEdge": _closed(
            {
                "source": _string(16384),
                "target": _string(16384),
                "relation": _string(
                    32,
                    enum=("detected-by", "matched-rule", "supports-rule", "contributes-to", "fired"),
                ),
            }
        ),
        "ExplanationDag": explanation_dag,
        "MetadataDependency": metadata_dependency,
        "ReviewCandidate": candidate,
        "ReviewCandidates": _closed(
            {
                "record_type": {"const": "review_candidates"},
                "schema_version": {"const": REVIEW_CANDIDATES_SCHEMA_VERSION},
                "domain": domain,
                "disclaimer": _string(4096),
                "unavailable_controls": _string_array(8192),
                "degraded_sources": _string_array(8192),
                "candidates": {"type": "array", "items": {"$ref": "#/$defs/ReviewCandidate"}},
            }
        ),
        "ExplainedBaseline": _closed(
            {
                "record_type": {"const": "explained_lookup_baseline"},
                "schema_version": {"const": EXPLAINED_BASELINE_SCHEMA_VERSION},
                "lookup": {"$ref": "#/$defs/LookupResult"},
                "explanations": {"type": "array", "items": {"$ref": "#/$defs/ExplanationRecord"}},
                "explanation_dag": {"$ref": "#/$defs/ExplanationDag"},
            }
        ),
        "ReviewSuccess": _closed(
            {
                "record_type": {"const": "review_success"},
                "queried_domain": domain,
                "explained_baseline": {"$ref": "#/$defs/ExplainedBaseline"},
                "evidence_ledger": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/EvidenceLedgerEntry"},
                },
                "review_candidates": {"$ref": "#/$defs/ReviewCandidates"},
            }
        ),
        "ReviewError": _closed(
            {
                "record_type": {"const": "review_error"},
                "error_kind": _string(16, enum=("validation", "lookup", "timeout")),
                "failed_source_roles": _string_array(128),
            }
        ),
        "LookupResult": lookup,
    }
    top_properties = {
        "record_type": {"const": "review_bundle"},
        "schema_version": {"const": REVIEW_BUNDLE_SCHEMA_VERSION},
        "generated_at": timestamp,
        "generator": {"$ref": "#/$defs/Generator"},
        "interpretation_context": {"$ref": "#/$defs/InterpretationContext"},
        "scope": {"$ref": "#/$defs/Scope"},
        "collection": {"$ref": "#/$defs/Collection"},
        "source_opportunities": {
            "type": "array",
            "items": {"$ref": "#/$defs/SourceOpportunity"},
        },
        "workflow": {"$ref": "#/$defs/Workflow"},
        "result": {"oneOf": [{"$ref": "#/$defs/ReviewSuccess"}, {"$ref": "#/$defs/ReviewError"}]},
        "scope_statement": {"const": REVIEW_SCOPE_STATEMENT},
        "limitations": {
            "type": "array",
            "prefixItems": [{"const": item} for item in REVIEW_LIMITATIONS],
            "minItems": len(REVIEW_LIMITATIONS),
            "maxItems": len(REVIEW_LIMITATIONS),
        },
        "content_digest": digest,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://raw.githubusercontent.com/blisspixel/recon/main/docs/review-bundle-schema.json",
        "title": "recon ReviewBundle v1",
        "description": "Self-contained schema for deterministic, caller-owned single-namespace review artifacts.",
        **_closed(top_properties, required=REVIEW_BUNDLE_TOP_LEVEL_FIELDS),
        "oneOf": [
            {
                "properties": {
                    "scope": {"properties": {"queried_domain": domain}},
                    "workflow": {"properties": {"status": {"const": "completed"}}},
                    "result": {"$ref": "#/$defs/ReviewSuccess"},
                }
            },
            {
                "properties": {
                    "scope": {"properties": {"queried_domain": {"type": "null"}}},
                    "workflow": {"properties": {"status": {"const": "failed"}}},
                    "result": {"$ref": "#/$defs/ReviewError"},
                }
            },
        ],
        "$defs": defs,
    }


def packaged_review_bundle_schema_text() -> str:
    """Return the exact packaged ReviewBundle schema bytes as UTF-8 text."""
    return resources.files("recon_tool").joinpath("data", "review-bundle-schema.json").read_text(encoding="utf-8")


def packaged_review_bundle_schema() -> dict[str, Any]:
    """Return the packaged ReviewBundle schema as a JSON object."""
    value = json.loads(packaged_review_bundle_schema_text())
    if not isinstance(value, dict):
        raise ValueError("packaged ReviewBundle schema must be a JSON object")
    return value


@lru_cache(maxsize=1)
def _published_schema_validator() -> Draft202012Validator:
    schema = packaged_review_bundle_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_review_bundle_document(bundle: Mapping[str, Any]) -> None:
    """Apply the exact packaged Draft 2020-12 contract to one bundle."""
    errors = sorted(
        _published_schema_validator().iter_errors(bundle),
        key=lambda error: "/".join(str(segment) for segment in error.absolute_path),
    )
    if not errors:
        return
    error = errors[0]
    path = ".".join(str(segment) for segment in error.absolute_path) or "root"
    raise ValueError(f"review bundle violates the published schema at {path}: {error.validator} constraint failed")
