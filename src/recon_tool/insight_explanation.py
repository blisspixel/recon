"""Exact explanation records for generation-time insight claims."""

from __future__ import annotations

from dataclasses import dataclass

from recon_tool.models import ExplanationLineageStatus, ExplanationRecord, InsightClaim

DetectionScores = tuple[tuple[str, str], ...]

__all__ = [
    "InsightExplanationContext",
    "normalize_insight_explanation_context",
    "take_exact_insight_explanation",
]


@dataclass(frozen=True)
class InsightExplanationContext:
    """Optional exact lineage carried alongside legacy detection scores."""

    detection_scores: DetectionScores
    insight_claims: tuple[InsightClaim, ...] = ()


def normalize_insight_explanation_context(
    value: DetectionScores | InsightExplanationContext,
) -> tuple[DetectionScores, list[InsightClaim]]:
    """Normalize backward-compatible explanation input into mutable work state."""
    if isinstance(value, InsightExplanationContext):
        return value.detection_scores, list(value.insight_claims)
    return value, []


def take_exact_insight_explanation(
    insight: str,
    unmatched_claims: list[InsightClaim],
) -> ExplanationRecord | None:
    """Consume and explain the first exact claim matching one rendered insight."""
    exact_index = next(
        (index for index, claim in enumerate(unmatched_claims) if claim.text == insight),
        None,
    )
    if exact_index is None:
        return None
    claim = unmatched_claims.pop(exact_index)
    scope = ", ".join(claim.observation_scope) or "none"
    evidence_count = len(claim.supporting_evidence)
    lineage_status = (
        ExplanationLineageStatus.EXACT
        if claim.supporting_evidence and claim.evidence_required
        else ExplanationLineageStatus.EXACT_RULE_ONLY
    )
    return ExplanationRecord(
        item_name=insight,
        item_type="insight",
        matched_evidence=claim.supporting_evidence,
        fired_rules=(claim.generator_rule_id,),
        confidence_derivation=(
            "Exact generation-time association; "
            f"{evidence_count} supporting retained evidence occurrence(s); "
            f"bounded observation scope: {scope}"
        ),
        weakening_conditions=tuple(
            f"Claim must be withheld when observation scope is unavailable: {item}" for item in claim.observation_scope
        ),
        lineage_status=lineage_status,
        lineage_rule_ids=(claim.generator_rule_id,),
    )
