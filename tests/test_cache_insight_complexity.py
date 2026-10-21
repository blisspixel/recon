"""Evidence admission must not multiply two artifact-controlled list sizes."""

from __future__ import annotations

from recon_tool.cache_insights import insight_claims_from_cache
from recon_tool.insights import INSIGHT_GENERATOR_RULE_IDS
from recon_tool.models import EvidenceRecord


class CountedValue(str):
    comparisons = 0
    __hash__ = str.__hash__

    def __eq__(self, other: object) -> bool:
        type(self).comparisons += 1
        return super().__eq__(other)


def test_repeated_final_evidence_references_have_linear_membership_work() -> None:
    count = 300
    evidence = tuple(EvidenceRecord("TXT", CountedValue(str(i)), "synthetic", "synthetic") for i in range(count))
    raw = [
        {
            "text": "Synthetic observation",
            "generator_rule_id": next(iter(INSIGHT_GENERATOR_RULE_IDS)),
            "supporting_evidence": [
                {"source_type": "TXT", "raw_value": str(count - 1), "rule_name": "synthetic", "slug": "synthetic"}
            ]
            * count,
            "observation_scope": [],
            "evidence_required": True,
        }
    ]
    CountedValue.comparisons = 0
    result = insight_claims_from_cache(raw, insights=("Synthetic observation",), evidence=evidence)
    assert len(result[0].supporting_evidence) == count
    assert result[0].supporting_evidence == (evidence[-1],) * count
    assert CountedValue.comparisons <= count * 4
