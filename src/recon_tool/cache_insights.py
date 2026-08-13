"""Strict cache codec for internal generated-insight lineage."""

from __future__ import annotations

from typing import Any

from recon_tool.cache_values import cache_object_tuple, cache_string, cache_string_tuple
from recon_tool.insight_scopes import INSIGHT_OBSERVATION_SCOPES
from recon_tool.models import EvidenceRecord, InsightClaim, TenantInfo

__all__ = [
    "insight_claims_from_cache",
    "insight_claims_to_cache",
    "validate_insight_claim_coverage",
]

_CLAIM_FIELDS = frozenset(
    {
        "text",
        "generator_rule_id",
        "supporting_evidence",
        "observation_scope",
        "evidence_required",
    }
)


def _evidence_to_cache(record: EvidenceRecord) -> dict[str, str]:
    """Serialize one retained evidence occurrence."""
    return {
        "source_type": record.source_type,
        "raw_value": record.raw_value,
        "rule_name": record.rule_name,
        "slug": record.slug,
    }


def insight_claims_to_cache(claims: tuple[InsightClaim, ...]) -> list[dict[str, Any]]:
    """Serialize exact generated-insight associations for result caching."""
    return [
        {
            "text": claim.text,
            "generator_rule_id": claim.generator_rule_id,
            "supporting_evidence": [_evidence_to_cache(record) for record in claim.supporting_evidence],
            "observation_scope": list(claim.observation_scope),
            "evidence_required": claim.evidence_required,
        }
        for claim in claims
    ]


def _evidence_from_cache(raw: dict[str, Any], field: str) -> EvidenceRecord:
    """Parse one strict cached evidence object without coercing values."""
    return EvidenceRecord(
        source_type=cache_string(raw.get("source_type"), f"{field}.source_type", nonempty=True),
        raw_value=cache_string(raw.get("raw_value"), f"{field}.raw_value"),
        rule_name=cache_string(raw.get("rule_name"), f"{field}.rule_name", nonempty=True),
        # EvidenceRecord allows an empty slug for typed observations that do
        # not originate in the fingerprint catalog. Rule and source remain
        # mandatory, so exact evidence identity is still preserved.
        slug=cache_string(raw.get("slug"), f"{field}.slug"),
    )


def insight_claims_from_cache(
    raw: object,
    *,
    insights: tuple[str, ...],
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[InsightClaim, ...]:
    """Parse and validate cached generation-time insight associations."""
    from recon_tool.insights import INSIGHT_GENERATOR_RULE_IDS

    claims: list[InsightClaim] = []
    items = cache_object_tuple(raw if raw is not None else [], "insight_claims")
    for index, item in enumerate(items):
        field = f"insight_claims[{index}]"
        missing_fields = _CLAIM_FIELDS - item.keys()
        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            raise ValueError(f"Cache field {field!r} is missing required fields: {missing}")
        text = cache_string(item.get("text"), f"{field}.text", nonempty=True)
        if text not in insights:
            raise ValueError(f"Cache field {field!r} references an absent insight")
        generator_rule_id = cache_string(
            item.get("generator_rule_id"),
            f"{field}.generator_rule_id",
            nonempty=True,
        )
        if generator_rule_id not in INSIGHT_GENERATOR_RULE_IDS:
            raise ValueError(f"Cache field {field!r} has an unknown generator rule")
        supporting_evidence = tuple(
            _evidence_from_cache(record, f"{field}.supporting_evidence[{record_index}]")
            for record_index, record in enumerate(
                cache_object_tuple(item.get("supporting_evidence", []), f"{field}.supporting_evidence")
            )
        )
        if any(record not in evidence for record in supporting_evidence):
            raise ValueError(f"Cache field {field!r} references evidence absent from the canonical record set")
        observation_scope = cache_string_tuple(item.get("observation_scope", []), f"{field}.observation_scope")
        unknown_scopes = set(observation_scope) - INSIGHT_OBSERVATION_SCOPES
        if unknown_scopes:
            unknown = ", ".join(sorted(unknown_scopes))
            raise ValueError(f"Cache field {field!r} has unknown observation scopes: {unknown}")
        evidence_required = item["evidence_required"]
        if type(evidence_required) is not bool:
            raise ValueError(f"Cache field '{field}.evidence_required' must be a boolean")
        if evidence_required and not supporting_evidence:
            raise ValueError(f"Cache field {field!r} requires supporting evidence")
        if not supporting_evidence and not observation_scope:
            raise ValueError(f"Cache field {field!r} has no evidence or bounded observation scope")
        claims.append(
            InsightClaim(
                text=text,
                generator_rule_id=generator_rule_id,
                supporting_evidence=supporting_evidence,
                observation_scope=observation_scope,
                evidence_required=evidence_required,
            )
        )
    return tuple(claims)


def validate_insight_claim_coverage(info: TenantInfo) -> None:
    """Require exact, complete generated-insight lineage at the v4 boundary."""
    from recon_tool.collection_view import collection_observable_info

    for index, claim in enumerate(info.insight_claims):
        unknown_scopes = set(claim.observation_scope) - INSIGHT_OBSERVATION_SCOPES
        if unknown_scopes:
            unknown = ", ".join(sorted(unknown_scopes))
            raise ValueError(f"Insight claim {index} has unknown observation scopes: {unknown}")

    expected = collection_observable_info(info).insight_claims
    if info.insight_claims != expected:
        raise ValueError("Generated-insight lineage is incomplete or inconsistent")
