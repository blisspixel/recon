"""QA Round 2 — Conflict Merge and Explanation Engine tests.

Unit tests and Hypothesis property-based tests for:
- Conflict-aware merge (6.1)
- ExplanationRecord serialization (6.2)
- PBT Property 1: ExplanationRecord Serialization Round-Trip (6.3)
- PBT Property 6: Conflict Detection Completeness (6.4)
- PBT Property 7: First-Wins Merge Preservation (6.5)
- PBT Property 8: explain Field Round-Trip Preservation (6.6)
- PBT Property 9: Signal Explanation Evidence Completeness (6.7)
- PBT Property 10: Weakening Conditions Completeness (6.8)

All examples use fictional companies (Contoso, Northwind, Fabrikam).
"""

from __future__ import annotations

from unittest.mock import patch

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recon_tool.explanation import (
    _weakening_conditions_for_signal,  # pyright: ignore[reportPrivateUsage]
    explain_signals,
    serialize_explanation,
)
from recon_tool.merger import merge_results
from recon_tool.models import (
    CandidateValue,
    EvidenceRecord,
    ExplanationRecord,
    MergeConflicts,
    SignalContext,
    SourceResult,
    serialize_conflicts,
)
from recon_tool.signals import (
    Signal,
    _evaluate_single_signal,  # pyright: ignore[reportPrivateUsage]
)

# ── Helpers ─────────────────────────────────────────────────────────────


def _ctx(slugs: set[str], **kwargs: object) -> SignalContext:
    """Helper to build a SignalContext from a slug set."""
    return SignalContext(detected_slugs=frozenset(slugs), **kwargs)  # pyright: ignore[reportCallIssue, reportArgumentType]


def _source(name: str, **kwargs: object) -> SourceResult:
    """Helper to build a SourceResult with sensible defaults."""
    return SourceResult(source_name=name, **kwargs)  # pyright: ignore[reportCallIssue, reportArgumentType]


# ── Hypothesis strategies ───────────────────────────────────────────────

_slug_alphabet = st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789")
_slug_st = st.text(alphabet=_slug_alphabet, min_size=2, max_size=12)

_safe_text_st = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."),
    min_size=1,
    max_size=40,
).filter(lambda s: s.strip() == s and len(s.strip()) > 0)

_source_type_st = st.sampled_from(["TXT", "MX", "CNAME", "NS", "SPF", "CAA", "SRV", "HTTP"])

_confidence_str_st = st.sampled_from(["high", "medium", "low"])

_item_type_st = st.sampled_from(["insight", "signal", "observation", "confidence"])


# ── 6.1 Unit tests for conflict-aware merge ─────────────────────────────


class TestConflictAwareMerge:
    """Task 6.1: Conflict-aware merge tests.

    Requirements: 16.1, 16.4, 16.5, 16.7, 22.11
    """

    def test_two_sources_different_display_name_conflict_recorded(self) -> None:
        """Two sources with different display_name → conflict recorded with both candidates."""
        results = [
            _source(
                "oidc_discovery",
                tenant_id="tid-1",
                display_name="Contoso Corp",
                default_domain="contoso.com",
                detected_services=("Microsoft 365",),
            ),
            _source(
                "user_realm",
                tenant_id="tid-1",
                display_name="Contoso Ltd",
                default_domain="contoso.com",
                m365_detected=True,
                detected_services=("Microsoft 365",),
            ),
        ]
        with patch("recon_tool.merger.build_insights_with_signals", return_value=[]):
            info = merge_results(results, "contoso.com")

        assert info.merge_conflicts is not None
        assert info.merge_conflicts.has_conflicts is True
        candidates = info.merge_conflicts.display_name
        assert len(candidates) == 2
        values = {c.value for c in candidates}
        assert "Contoso Corp" in values
        assert "Contoso Ltd" in values
        sources = {c.source for c in candidates}
        assert "oidc_discovery" in sources
        assert "user_realm" in sources

    def test_all_sources_agree_no_conflicts(self) -> None:
        """All sources agree → no conflicts, has_conflicts returns False."""
        results = [
            _source(
                "oidc_discovery",
                tenant_id="tid-1",
                display_name="Northwind Traders",
                default_domain="northwind.com",
                detected_services=("Microsoft 365",),
            ),
            _source(
                "user_realm",
                tenant_id="tid-1",
                display_name="Northwind Traders",
                default_domain="northwind.com",
                m365_detected=True,
                detected_services=("Microsoft 365",),
            ),
        ]
        with patch("recon_tool.merger.build_insights_with_signals", return_value=[]):
            info = merge_results(results, "northwind.com")

        # No conflicts when values agree
        assert info.merge_conflicts is None or info.merge_conflicts.has_conflicts is False

    def test_single_source_no_conflict(self) -> None:
        """Single source provides value → no conflict."""
        results = [
            _source(
                "oidc_discovery",
                tenant_id="tid-1",
                display_name="Fabrikam Inc",
                default_domain="fabrikam.com",
                detected_services=("Microsoft 365",),
            ),
        ]
        with patch("recon_tool.merger.build_insights_with_signals", return_value=[]):
            info = merge_results(results, "fabrikam.com")

        assert info.merge_conflicts is None or info.merge_conflicts.has_conflicts is False

    def test_serialize_conflicts_produces_correct_json(self) -> None:
        """serialize_conflicts() produces correct JSON structure."""
        conflicts = MergeConflicts(
            display_name=(
                CandidateValue(value="Contoso Corp", source="oidc_discovery", confidence="high"),
                CandidateValue(value="Contoso Ltd", source="user_realm", confidence="medium"),
            ),
        )
        result = serialize_conflicts(conflicts)
        assert "display_name" in result
        assert len(result["display_name"]) == 2
        assert result["display_name"][0]["value"] == "Contoso Corp"
        assert result["display_name"][0]["source"] == "oidc_discovery"
        assert result["display_name"][0]["confidence"] == "high"
        assert result["display_name"][1]["value"] == "Contoso Ltd"
        # Fields with no conflicts should be omitted
        assert "auth_type" not in result
        assert "region" not in result


# ── 6.2 Unit tests for ExplanationRecord serialization ──────────────────


class TestExplanationRecordSerialization:
    """Task 6.2: ExplanationRecord serialization tests.

    Requirements: 2.3, 22.2
    """

    def test_serialize_explanation_produces_json_safe_dict(self) -> None:
        """serialize_explanation() produces JSON-safe dict with all fields."""
        record = ExplanationRecord(
            item_name="Contoso AI Adoption",
            item_type="signal",
            matched_evidence=(
                EvidenceRecord(
                    source_type="TXT", raw_value="contoso-verify=abc", rule_name="Contoso AI", slug="contoso-ai"
                ),
            ),
            fired_rules=("Contoso AI Adoption (requires.any: contoso-ai; min_matches: 1)",),
            confidence_derivation="Signal confidence: high. 1 of 1 candidates matched.",
            weakening_conditions=(
                "Removing slug 'contoso-ai' would drop match count to 0 (below min_matches=1), suppressing this signal",
            ),
            curated_explanation="Contoso AI integration detected",
        )
        result = serialize_explanation(record)

        assert result["item_name"] == "Contoso AI Adoption"
        assert result["item_type"] == "signal"
        assert isinstance(result["matched_evidence"], list)
        assert len(result["matched_evidence"]) == 1
        assert result["matched_evidence"][0]["source_type"] == "TXT"
        assert result["matched_evidence"][0]["slug"] == "contoso-ai"
        assert isinstance(result["fired_rules"], list)
        assert isinstance(result["weakening_conditions"], list)
        assert result["confidence_derivation"] == "Signal confidence: high. 1 of 1 candidates matched."
        assert result["curated_explanation"] == "Contoso AI integration detected"

    def test_round_trip_create_serialize_verify(self) -> None:
        """Round-trip: create → serialize → verify all fields preserved."""
        evidence = (
            EvidenceRecord(
                source_type="CNAME", raw_value="login.northwind.com", rule_name="Northwind SSO", slug="northwind-sso"
            ),
            EvidenceRecord(
                source_type="TXT",
                raw_value="northwind-verify=xyz",
                rule_name="Northwind Platform",
                slug="northwind-platform",
            ),
        )
        record = ExplanationRecord(
            item_name="Northwind Enterprise Stack",
            item_type="signal",
            matched_evidence=evidence,
            fired_rules=("Rule A", "Rule B"),
            confidence_derivation="High confidence based on 2 evidence records",
            weakening_conditions=("Condition 1", "Condition 2"),
            curated_explanation="Northwind enterprise deployment detected",
        )
        serialized = serialize_explanation(record)

        assert serialized["item_name"] == record.item_name
        assert serialized["item_type"] == record.item_type
        assert len(serialized["matched_evidence"]) == len(record.matched_evidence)
        for i, ev in enumerate(record.matched_evidence):
            assert serialized["matched_evidence"][i]["source_type"] == ev.source_type
            assert serialized["matched_evidence"][i]["raw_value"] == ev.raw_value
            assert serialized["matched_evidence"][i]["rule_name"] == ev.rule_name
            assert serialized["matched_evidence"][i]["slug"] == ev.slug
        assert serialized["fired_rules"] == list(record.fired_rules)
        assert serialized["confidence_derivation"] == record.confidence_derivation
        assert serialized["weakening_conditions"] == list(record.weakening_conditions)
        assert serialized["curated_explanation"] == record.curated_explanation


# ── 6.3 PBT Property 1: ExplanationRecord Serialization Round-Trip ──────


# Strategy for generating random EvidenceRecords
_evidence_record_st = st.builds(
    EvidenceRecord,
    source_type=_source_type_st,
    raw_value=_safe_text_st,
    rule_name=_safe_text_st,
    slug=_slug_st,
)

# Strategy for generating random ExplanationRecords
_explanation_record_st = st.builds(
    ExplanationRecord,
    item_name=_safe_text_st,
    item_type=_item_type_st,
    matched_evidence=st.lists(_evidence_record_st, min_size=0, max_size=2).map(tuple),
    fired_rules=st.lists(_safe_text_st, min_size=0, max_size=2).map(tuple),
    confidence_derivation=_safe_text_st,
    weakening_conditions=st.lists(_safe_text_st, min_size=0, max_size=2).map(tuple),
    curated_explanation=st.sampled_from(["", "Contoso explanation", "Northwind context"]),
)


class TestPBTExplanationRecordRoundTrip:
    """PBT Property 1: ExplanationRecord Serialization Round-Trip.

    For any valid ExplanationRecord, serialize → verify all fields preserved.

    **Validates: Requirements 2.1, 2.3**
    """

    @given(record=_explanation_record_st)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_serialization_round_trip(self, record: ExplanationRecord) -> None:
        """For any valid ExplanationRecord, serialization preserves all fields."""
        serialized = serialize_explanation(record)

        # Verify all top-level fields
        assert serialized["item_name"] == record.item_name
        assert serialized["item_type"] == record.item_type
        assert serialized["confidence_derivation"] == record.confidence_derivation
        assert serialized["curated_explanation"] == record.curated_explanation
        assert serialized["fired_rules"] == list(record.fired_rules)
        assert serialized["weakening_conditions"] == list(record.weakening_conditions)

        # Verify evidence records
        assert len(serialized["matched_evidence"]) == len(record.matched_evidence)
        for i, ev in enumerate(record.matched_evidence):
            assert serialized["matched_evidence"][i]["source_type"] == ev.source_type
            assert serialized["matched_evidence"][i]["raw_value"] == ev.raw_value
            assert serialized["matched_evidence"][i]["rule_name"] == ev.rule_name
            assert serialized["matched_evidence"][i]["slug"] == ev.slug


# ── 6.4 PBT Property 6: Conflict Detection Completeness ─────────────────


# Tracked fields on SourceResult that map to MergeConflicts
_TRACKED_FIELDS = ["display_name", "auth_type", "region", "tenant_id", "dmarc_policy", "google_auth_type"]


class TestPBTConflictDetectionCompleteness:
    """PBT Property 6: Conflict Detection Completeness.

    For any SourceResults with conflicting fields, MergeConflicts contains
    a CandidateValue for every source that provided a value.

    **Validates: Requirements 14.1, 14.7**
    """

    @given(
        field_name=st.sampled_from(_TRACKED_FIELDS),
        value_a=_safe_text_st,
        value_b=_safe_text_st.filter(lambda s: len(s) > 1),
    )
    @settings(max_examples=100)
    def test_conflict_completeness(
        self,
        field_name: str,
        value_a: str,
        value_b: str,
    ) -> None:
        """Every source that provided a value appears in MergeConflicts."""
        # Ensure values are actually different
        if value_a == value_b:
            value_b = value_b + "x"

        # Build two SourceResults with conflicting values for the chosen field
        kwargs_a: dict[str, object] = {
            "detected_services": ("Contoso Service",),
            field_name: value_a,
        }
        kwargs_b: dict[str, object] = {
            "detected_services": ("Fabrikam Service",),
            field_name: value_b,
        }

        results = [
            _source("source_alpha", **kwargs_a),
            _source("source_beta", **kwargs_b),
        ]

        with patch("recon_tool.merger.build_insights_with_signals", return_value=[]):
            info = merge_results(results, "contoso.com")

        assert info.merge_conflicts is not None
        assert info.merge_conflicts.has_conflicts is True

        candidates: tuple[CandidateValue, ...] = getattr(info.merge_conflicts, field_name)
        assert len(candidates) >= 2

        # Every source that provided a value must appear
        candidate_sources = {c.source for c in candidates}
        assert "source_alpha" in candidate_sources
        assert "source_beta" in candidate_sources

        # Both values must appear
        candidate_values = {c.value for c in candidates}
        assert value_a in candidate_values
        assert value_b in candidate_values


# ── 6.5 PBT Property 7: First-Wins Merge Preservation ───────────────────


class TestPBTFirstWinsMergePreservation:
    """PBT Property 7: First-Wins Merge Preservation.

    Merged TenantInfo field values equal the first non-None value in source
    order; conflict tracking does not alter primary values.

    **Validates: Requirements 14.5, 19.6**
    """

    @given(
        field_name=st.sampled_from(_TRACKED_FIELDS),
        value_a=_safe_text_st,
        value_b=_safe_text_st.filter(lambda s: len(s) > 1),
    )
    @settings(max_examples=100)
    def test_first_wins_preserved(
        self,
        field_name: str,
        value_a: str,
        value_b: str,
    ) -> None:
        """First non-None value wins; conflict tracking doesn't alter primary values."""
        if value_a == value_b:
            value_b = value_b + "x"

        kwargs_a: dict[str, object] = {
            "detected_services": ("Contoso Service",),
            field_name: value_a,
        }
        kwargs_b: dict[str, object] = {
            "detected_services": ("Fabrikam Service",),
            field_name: value_b,
        }

        results = [
            _source("source_first", **kwargs_a),
            _source("source_second", **kwargs_b),
        ]

        with patch("recon_tool.merger.build_insights_with_signals", return_value=[]):
            info = merge_results(results, "contoso.com")

        # The merged field should equal the first source's value
        merged_value = getattr(info, field_name)
        assert merged_value == value_a

    @given(
        value_b=_safe_text_st,
    )
    @settings(max_examples=100)
    def test_first_none_skipped(
        self,
        value_b: str,
    ) -> None:
        """When first source has None, second source's value wins."""
        results = [
            _source("source_first", detected_services=("Contoso Service",)),
            _source("source_second", display_name=value_b, detected_services=("Fabrikam Service",)),
        ]

        with patch("recon_tool.merger.build_insights_with_signals", return_value=[]):
            info = merge_results(results, "contoso.com")

        assert info.display_name == value_b


# ── 6.6 PBT Property 8: explain Field Round-Trip Preservation ───────────


class TestPBTExplainFieldRoundTrip:
    """PBT Property 8: explain Field Round-Trip Preservation.

    Signal with explain → load → evaluate → serialize → curated_explanation
    preserved; omitted explain → empty string.

    **Validates: Requirements 18.1, 18.3, 18.4**
    """

    @given(
        explain_text=_safe_text_st,
        slug=_slug_st,
    )
    @settings(max_examples=100)
    def test_explain_preserved_through_pipeline(
        self,
        explain_text: str,
        slug: str,
    ) -> None:
        """Signal explain field is preserved through evaluate → explain → serialize."""
        signal = Signal(
            name="Contoso Explain Test",
            category="Test",
            confidence="high",
            description="Test signal with explain",
            candidates=(slug,),
            min_matches=1,
            explain=explain_text,
        )

        context = _ctx({slug})
        evidence = (
            EvidenceRecord(source_type="TXT", raw_value=f"{slug}-verify=abc", rule_name="Test Rule", slug=slug),
        )
        detection_scores = ((slug, "medium"),)

        # Evaluate the signal
        match = _evaluate_single_signal(signal, context)
        assert match is not None

        # Generate explanation
        records = explain_signals(
            signal_matches=[match],
            signals=(signal,),
            context_detected_slugs=frozenset({slug}),
            context_metadata={},
            evidence=evidence,
            detection_scores=detection_scores,
        )
        assert len(records) == 1

        # Serialize and verify
        serialized = serialize_explanation(records[0])
        assert serialized["curated_explanation"] == explain_text

    @given(
        slug=_slug_st,
    )
    @settings(max_examples=100)
    def test_omitted_explain_produces_empty_string(
        self,
        slug: str,
    ) -> None:
        """Signal without explain field → curated_explanation is empty string."""
        signal = Signal(
            name="Contoso No Explain",
            category="Test",
            confidence="medium",
            description="Test signal without explain",
            candidates=(slug,),
            min_matches=1,
            # explain omitted → defaults to ""
        )

        context = _ctx({slug})
        evidence = (
            EvidenceRecord(source_type="TXT", raw_value=f"{slug}-verify=xyz", rule_name="Test Rule", slug=slug),
        )
        detection_scores = ((slug, "low"),)

        match = _evaluate_single_signal(signal, context)
        assert match is not None

        records = explain_signals(
            signal_matches=[match],
            signals=(signal,),
            context_detected_slugs=frozenset({slug}),
            context_metadata={},
            evidence=evidence,
            detection_scores=detection_scores,
        )
        assert len(records) == 1

        serialized = serialize_explanation(records[0])
        assert serialized["curated_explanation"] == ""


# ── 6.7 PBT Property 9: Signal Explanation Evidence Completeness ─────────


class TestPBTSignalExplanationEvidenceCompleteness:
    """PBT Property 9: Signal Explanation Evidence Completeness.

    For any fired signal, ExplanationRecord references every matched slug
    from requires.any with its EvidenceRecords and detection_scores.

    **Validates: Requirements 4.1, 4.2**
    """

    @given(
        slugs=st.lists(_slug_st, min_size=1, max_size=5, unique=True),
        extra_slugs=st.lists(_slug_st, min_size=0, max_size=3, unique=True),
    )
    @settings(max_examples=100)
    def test_evidence_completeness(
        self,
        slugs: list[str],
        extra_slugs: list[str],
    ) -> None:
        """Every matched slug from requires.any is referenced with evidence and scores."""
        # Ensure extra_slugs don't overlap with slugs
        candidate_slugs = list(dict.fromkeys(slugs))  # deduplicate preserving order
        all_detected = set(candidate_slugs) | set(extra_slugs)

        signal = Signal(
            name="Contoso Evidence Test",
            category="Test",
            confidence="high",
            description="Test signal for evidence completeness",
            candidates=tuple(candidate_slugs),
            min_matches=1,
        )

        context = _ctx(all_detected)

        # Create evidence for each candidate slug
        evidence_list: list[EvidenceRecord] = []
        score_list: list[tuple[str, str]] = []
        for slug in candidate_slugs:
            evidence_list.append(
                EvidenceRecord(source_type="TXT", raw_value=f"{slug}-verify=abc", rule_name=f"Rule-{slug}", slug=slug)
            )
            score_list.append((slug, "medium"))

        match = _evaluate_single_signal(signal, context)
        assert match is not None

        records = explain_signals(
            signal_matches=[match],
            signals=(signal,),
            context_detected_slugs=frozenset(all_detected),
            context_metadata={},
            evidence=tuple(evidence_list),
            detection_scores=tuple(score_list),
        )
        assert len(records) == 1
        record = records[0]

        # Every matched slug must be referenced in evidence
        matched_slugs_in_context = [s for s in candidate_slugs if s in all_detected]
        evidence_slugs = {e.slug for e in record.matched_evidence}
        for slug in matched_slugs_in_context:
            assert slug in evidence_slugs, f"Slug '{slug}' not found in matched_evidence"

        # Every matched slug must have its detection_score referenced in confidence_derivation
        for slug in matched_slugs_in_context:
            assert slug in record.confidence_derivation, f"Slug '{slug}' not referenced in confidence_derivation"


# ── 6.8 PBT Property 10: Weakening Conditions Completeness ──────────────


class TestPBTWeakeningConditionsCompleteness:
    """PBT Property 10: Weakening Conditions Completeness.

    For any fired signal, weakening_conditions covers all matched slugs
    (removal below min_matches), metadata conditions, and contradicts slugs.

    **Validates: Requirements 2.4, 4.3, 4.4, 4.5**
    """

    @given(
        slugs=st.lists(_slug_st, min_size=1, max_size=4, unique=True),
        contradict_slugs=st.lists(_slug_st, min_size=0, max_size=3, unique=True),
    )
    @settings(max_examples=100)
    def test_weakening_slug_removal(
        self,
        slugs: list[str],
        contradict_slugs: list[str],
    ) -> None:
        """Weakening conditions include slug removal when it would drop below min_matches."""
        # Ensure contradicts don't overlap with candidates
        clean_contradicts = [s for s in contradict_slugs if s not in slugs]

        min_matches = len(slugs)  # All slugs needed → removing any one drops below

        signal = Signal(
            name="Contoso Weakening Test",
            category="Test",
            confidence="high",
            description="Test signal",
            candidates=tuple(slugs),
            min_matches=min_matches,
            contradicts=tuple(clean_contradicts),
        )

        matched_slugs = list(slugs)
        conditions = _weakening_conditions_for_signal(signal, matched_slugs, {})

        # Every matched slug should have a removal condition
        for slug in matched_slugs:
            remaining = len(matched_slugs) - 1
            if remaining < min_matches:
                found = any(f"Removing slug '{slug}'" in c for c in conditions)
                assert found, f"Missing removal condition for slug '{slug}'"

        # Every contradicts slug should have a presence condition
        for slug in clean_contradicts:
            found = any(f"Detecting slug '{slug}'" in c for c in conditions)
            assert found, f"Missing contradiction condition for slug '{slug}'"

    @given(
        slug=_slug_st,
        metadata_field=st.sampled_from(["dmarc_policy", "auth_type"]),
        metadata_value=_safe_text_st,
    )
    @settings(max_examples=100)
    def test_weakening_metadata_conditions(
        self,
        slug: str,
        metadata_field: str,
        metadata_value: str,
    ) -> None:
        """Weakening conditions include metadata change conditions."""
        from recon_tool.models import MetadataCondition

        signal = Signal(
            name="Contoso Metadata Weakening",
            category="Test",
            confidence="high",
            description="Test signal",
            candidates=(slug,),
            min_matches=1,
            metadata=(MetadataCondition(field=metadata_field, operator="eq", value=metadata_value),),
        )

        context_metadata = {metadata_field: metadata_value}
        conditions = _weakening_conditions_for_signal(signal, [slug], context_metadata)

        # Should have a metadata weakening condition
        found = any(metadata_field in c for c in conditions)
        assert found, f"Missing metadata weakening condition for field '{metadata_field}'"

    @given(
        slugs=st.lists(_slug_st, min_size=1, max_size=3, unique=True),
        contradict_slugs=st.lists(_slug_st, min_size=1, max_size=3, unique=True),
    )
    @settings(max_examples=100)
    def test_weakening_contradicts_completeness(
        self,
        slugs: list[str],
        contradict_slugs: list[str],
    ) -> None:
        """Every contradicts slug appears in weakening conditions."""
        # Ensure no overlap
        clean_contradicts = [s for s in contradict_slugs if s not in slugs]
        if not clean_contradicts:
            clean_contradicts = ["unique-contradict-slug"]

        signal = Signal(
            name="Contoso Contradicts Weakening",
            category="Test",
            confidence="high",
            description="Test signal",
            candidates=tuple(slugs),
            min_matches=1,
            contradicts=tuple(clean_contradicts),
        )

        conditions = _weakening_conditions_for_signal(signal, list(slugs), {})

        for slug in clean_contradicts:
            found = any(f"Detecting slug '{slug}'" in c for c in conditions)
            assert found, f"Missing contradiction weakening condition for slug '{slug}'"
