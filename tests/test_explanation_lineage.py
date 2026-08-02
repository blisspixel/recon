"""Exact-lineage diagnostics for flat and graph explanations."""

from __future__ import annotations

import pytest
from rich.console import Console

from recon_tool.explanation import (
    build_explanation_dag,
    explain_confidence,
    explain_insights,
    explain_observations,
    explain_signals,
    serialize_explanation,
)
from recon_tool.formatter import render_explanations_panel
from recon_tool.formatter.markdown import format_explanations_markdown
from recon_tool.insight_explanation import InsightExplanationContext
from recon_tool.models import (
    ConfidenceLevel,
    EvidenceRecord,
    ExplanationLineageStatus,
    ExplanationRecord,
    InsightClaim,
    Observation,
    PostureMetadataDependency,
    SourceResult,
    TenantInfo,
)
from recon_tool.posture import _MetadataCondition, _PostureRule, analyze_posture, load_posture_rules
from recon_tool.signals import Signal, SignalMatch


def _evidence(slug: str = "microsoft365") -> EvidenceRecord:
    return EvidenceRecord(
        source_type="TXT",
        raw_value=f"fixture={slug}",
        rule_name=f"{slug}-fingerprint",
        slug=slug,
    )


def _record(
    status: ExplanationLineageStatus,
    *,
    evidence: tuple[EvidenceRecord, ...] = (),
    rules: tuple[str, ...] = (),
) -> ExplanationRecord:
    lineage_rules = (
        rules if status in {ExplanationLineageStatus.EXACT, ExplanationLineageStatus.EXACT_RULE_ONLY} else ()
    )
    return ExplanationRecord(
        item_name=f"{status.value} terminal",
        item_type="insight",
        matched_evidence=evidence,
        fired_rules=rules,
        confidence_derivation="fixture derivation",
        weakening_conditions=(),
        lineage_status=status,
        lineage_rule_ids=lineage_rules,
    )


def test_exact_association_has_an_explicit_evidence_rule_terminal_path() -> None:
    evidence = _evidence()
    record = _record(ExplanationLineageStatus.EXACT, evidence=(evidence,), rules=("generator.rule",))

    graph = build_explanation_dag([record], (evidence,))

    terminal = next(node for node in graph["nodes"] if node["type"] == "insight")
    rule = next(node for node in graph["nodes"] if node["type"] == "rule" and node["name"] == "generator.rule")
    evidence_node = next(node for node in graph["nodes"] if node["type"] == "evidence")
    assert terminal["lineage_status"] == "exact"
    assert {"source": evidence_node["id"], "target": rule["id"], "relation": "supports-rule"} in graph["edges"]
    assert graph["exact_provenance_complete"] is True
    assert graph["lineage_disconnected_terminals"] == []


def test_reconstructed_association_stays_lineage_disconnected_despite_legacy_reachability() -> None:
    evidence = _evidence("okta")
    record = _record(ExplanationLineageStatus.RECONSTRUCTED, evidence=(evidence,), rules=("likely-rule",))

    graph = build_explanation_dag([record], (evidence,))

    terminal_id = "insight:reconstructed terminal"
    assert graph["provenance_complete"] is True
    assert graph["exact_provenance_complete"] is False
    assert graph["lineage_disconnected_terminals"] == [terminal_id]
    terminal = next(node for node in graph["nodes"] if node["id"] == terminal_id)
    assert terminal["lineage_status"] == "reconstructed"
    assert all(edge["relation"] != "supports-rule" for edge in graph["edges"])


def test_exact_rule_without_complete_support_is_lineage_disconnected() -> None:
    record = _record(ExplanationLineageStatus.EXACT_RULE_ONLY, rules=("scope.rule",))

    graph = build_explanation_dag([record])

    assert graph["exact_provenance_complete"] is False
    assert graph["lineage_disconnected_terminals"] == ["insight:exact_rule_only terminal"]


def test_unsupported_record_defaults_fail_closed() -> None:
    evidence = _evidence("cloudflare")
    record = ExplanationRecord(
        item_name="unattributed",
        item_type="signal",
        matched_evidence=(evidence,),
        fired_rules=("claimed rule",),
        confidence_derivation="",
        weakening_conditions=(),
    )

    graph = build_explanation_dag([record], (evidence,))

    assert record.lineage_status is ExplanationLineageStatus.UNSUPPORTED
    assert graph["lineage_disconnected_terminals"] == ["signal:unattributed"]


@pytest.mark.parametrize(
    ("status", "evidence", "rules", "error"),
    [
        (
            ExplanationLineageStatus.EXACT,
            (),
            ("rule",),
            "exact explanation lineage requires supporting evidence",
        ),
        (
            ExplanationLineageStatus.EXACT_RULE_ONLY,
            (),
            (),
            "exact lineage statuses require rule ids",
        ),
        (
            ExplanationLineageStatus.RECONSTRUCTED,
            (),
            ("rule",),
            "other statuses forbid them",
        ),
        (
            ExplanationLineageStatus.EXACT_RULE_ONLY,
            (),
            ("",),
            "lineage rule ids must not be empty",
        ),
        (
            ExplanationLineageStatus.EXACT_RULE_ONLY,
            (),
            ("rule", "rule"),
            "lineage rule ids must be unique",
        ),
        (
            ExplanationLineageStatus.EXACT_RULE_ONLY,
            (),
            ("rule-a", "rule-b"),
            "exact lineage currently requires exactly one rule id",
        ),
    ],
)
def test_contradictory_lineage_metadata_is_rejected(
    status: ExplanationLineageStatus,
    evidence: tuple[EvidenceRecord, ...],
    rules: tuple[str, ...],
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        ExplanationRecord(
            item_name="invalid",
            item_type="insight",
            matched_evidence=evidence,
            fired_rules=rules,
            confidence_derivation="",
            weakening_conditions=(),
            lineage_status=status,
            lineage_rule_ids=rules,
        )


def test_exact_insight_claim_projects_exact_or_rule_only_lineage() -> None:
    evidence = _evidence("proofpoint")
    claims = (
        InsightClaim(
            text="MX gateway observed: Proofpoint",
            generator_rule_id="insights.gateway",
            supporting_evidence=(evidence,),
        ),
        InsightClaim(
            text="No observable email infrastructure",
            generator_rule_id="insights.no_email",
            observation_scope=("dns.mx",),
            evidence_required=False,
        ),
        InsightClaim(
            text="Federated identity observed; external IdP not identified",
            generator_rule_id="insights.auth.unidentified_idp",
            supporting_evidence=(evidence,),
            observation_scope=("dns.apex_txt", "dns.cname"),
            evidence_required=False,
        ),
    )

    records = explain_insights(
        [claim.text for claim in claims],
        frozenset({"proofpoint"}),
        frozenset(),
        (evidence,),
        InsightExplanationContext((), claims),
    )

    assert [record.lineage_status for record in records] == [
        ExplanationLineageStatus.EXACT,
        ExplanationLineageStatus.EXACT_RULE_ONLY,
        ExplanationLineageStatus.EXACT_RULE_ONLY,
    ]
    assert [record.lineage_rule_ids for record in records] == [
        ("insights.gateway",),
        ("insights.no_email",),
        ("insights.auth.unidentified_idp",),
    ]
    graph = build_explanation_dag(records, (evidence,))
    assert "insight:Federated identity observed; external IdP not identified" in graph["lineage_disconnected_terminals"]


def test_legacy_insight_classifier_is_explicitly_reconstructed() -> None:
    evidence = _evidence("proofpoint")

    record = explain_insights(
        ["MX gateway observed: Proofpoint"],
        frozenset({"proofpoint"}),
        frozenset(),
        (evidence,),
        (),
    )[0]
    graph = build_explanation_dag([record], (evidence,))

    assert record.lineage_status is ExplanationLineageStatus.RECONSTRUCTED
    assert graph["lineage_disconnected_terminals"] == ["insight:MX gateway observed: Proofpoint"]


def test_signal_uses_generation_time_match_and_marks_unretained_conditions_incomplete() -> None:
    first = _evidence("okta")
    unrelated = _evidence("duo")
    simple = Signal(
        name="Exact identity signal",
        category="Identity",
        confidence="high",
        description="fixture",
        candidates=("okta", "duo"),
        min_matches=1,
    )
    match = SignalMatch("Exact identity signal", "Identity", "high", ("okta",))

    exact = explain_signals(
        [match],
        (simple,),
        frozenset({"okta", "duo"}),
        {},
        (first, unrelated),
        (),
    )[0]

    assert exact.matched_evidence == (first,)
    assert exact.lineage_status is ExplanationLineageStatus.EXACT
    assert exact.lineage_rule_ids == ("Exact identity signal",)

    metadata_rule = Signal(
        name="Metadata signal",
        category="Identity",
        confidence="medium",
        description="fixture",
        candidates=("okta",),
        min_matches=1,
        metadata=simple.metadata,
        contradicts=("google-workspace",),
    )
    metadata_match = SignalMatch("Metadata signal", "Identity", "medium", ("okta",))
    incomplete = explain_signals(
        [metadata_match],
        (metadata_rule,),
        frozenset({"okta"}),
        {},
        (first,),
        (),
    )[0]
    assert incomplete.lineage_status is ExplanationLineageStatus.EXACT_RULE_ONLY


def test_signal_with_too_few_or_duplicate_matches_is_unsupported() -> None:
    evidence = _evidence("okta")
    signal = Signal(
        name="Two-factor identity signal",
        category="Identity",
        confidence="high",
        description="fixture",
        candidates=("okta", "duo"),
        min_matches=2,
    )

    records = [
        explain_signals(
            [SignalMatch(signal.name, signal.category, signal.confidence, matched)],
            (signal,),
            frozenset({"okta"}),
            {},
            (evidence,),
            (),
        )[0]
        for matched in (("okta",), ("okta", "okta"))
    ]

    assert all(record.lineage_status is ExplanationLineageStatus.UNSUPPORTED for record in records)
    assert all(record.lineage_rule_ids == () for record in records)


def test_positive_absence_match_keeps_its_exact_evaluator_identity() -> None:
    parent = Signal(
        name="Operator comparison",
        category="Custom",
        confidence="low",
        description="fixture",
        candidates=("okta",),
        min_matches=1,
        positive_when_absent=("consumer",),
    )
    match = SignalMatch(
        "Operator comparison: Configured Indicators Not Observed",
        "Absence",
        "low",
        (),
        "bounded comparison",
    )
    parent_match = SignalMatch(parent.name, parent.category, parent.confidence, ("okta",))

    record = next(
        record
        for record in explain_signals([parent_match, match], (parent,), frozenset({"okta"}), {}, (), ())
        if record.lineage_rule_ids == ("evaluate_positive_absence:Operator comparison",)
    )

    assert record.lineage_status is ExplanationLineageStatus.EXACT_RULE_ONLY
    assert record.lineage_rule_ids == ("evaluate_positive_absence:Operator comparison",)


@pytest.mark.parametrize(
    "match",
    [
        SignalMatch(
            "Unknown comparison: Configured Indicators Not Observed",
            "Absence",
            "low",
            (),
            "fixture",
        ),
        SignalMatch("Operator comparison \u2014 Missing Counterparts", "Absence", "medium", ("consumer",), "fixture"),
    ],
)
def test_absence_match_without_matching_parent_configuration_is_omitted(match: SignalMatch) -> None:
    parent = Signal(
        name="Operator comparison",
        category="Custom",
        confidence="low",
        description="fixture",
        candidates=("okta",),
        min_matches=1,
        positive_when_absent=("consumer",),
    )
    parent_match = SignalMatch(parent.name, parent.category, parent.confidence, ("okta",))

    records = explain_signals([parent_match, match], (parent,), frozenset({"okta"}), {}, (), ())

    assert len(records) == 1
    assert records[0].item_name == "Operator comparison"


def test_absence_match_without_a_fired_parent_is_omitted() -> None:
    parent = Signal(
        name="Counterpart rule",
        category="Custom",
        confidence="medium",
        description="fixture",
        candidates=("anchor",),
        min_matches=1,
        expected_counterparts=("counterpart",),
    )
    derived = SignalMatch(
        "Counterpart rule \u2014 Missing Counterparts",
        "Absence",
        "medium",
        ("counterpart",),
        "fixture",
    )

    assert explain_signals([derived], (parent,), frozenset(), {}, (), ()) == []


def test_posture_lineage_distinguishes_exact_source_name_from_legacy_proxy_match() -> None:
    evidence = _evidence("dmarc")
    rule = _PostureRule(
        name="dmarc-observed",
        category="email",
        salience="high",
        template="DMARC observed",
        slugs_any=("dmarc",),
        slugs_min=1,
    )
    exact_observation = Observation(
        "email",
        "high",
        "DMARC observed",
        ("dmarc",),
        source_name=rule.name,
        supporting_evidence=(evidence,),
    )
    legacy_observation = Observation("email", "high", "Legacy DMARC observation", ("dmarc",))

    exact, reconstructed = explain_observations(
        (exact_observation, legacy_observation),
        (rule,),
        (evidence,),
        (),
    )

    assert exact.lineage_status is ExplanationLineageStatus.EXACT
    assert exact.lineage_rule_ids == (rule.name,)
    assert reconstructed.lineage_status is ExplanationLineageStatus.RECONSTRUCTED


def test_posture_explanation_does_not_borrow_global_evidence_for_exact_lineage() -> None:
    evidence = _evidence("dmarc")
    rule = _PostureRule(
        name="dmarc-observed",
        category="email",
        salience="high",
        template="DMARC observed",
        slugs_any=("dmarc",),
        slugs_min=1,
    )
    observation = Observation("email", "high", "DMARC observed", ("dmarc",), source_name=rule.name)

    record = explain_observations((observation,), (rule,), (evidence,), ())[0]

    assert record.matched_evidence == ()
    assert record.lineage_status is ExplanationLineageStatus.EXACT_RULE_ONLY
    assert record.lineage_rule_ids == (rule.name,)


def test_metadata_only_posture_explanation_retains_typed_generation_dependency() -> None:
    condition = _MetadataCondition("auth_type", "eq", "Federated")
    rule = _PostureRule(
        name="federated-identity",
        category="identity",
        salience="medium",
        template="Federated",
        metadata=(condition,),
    )
    observation = Observation(
        "identity",
        "medium",
        "Federated",
        (),
        source_name=rule.name,
        metadata_dependencies=(PostureMetadataDependency("auth_type", "eq", "Federated", "Federated"),),
    )

    record = explain_observations((observation,), (rule,), (), ())[0]

    assert record.lineage_status is ExplanationLineageStatus.EXACT_RULE_ONLY
    assert record.lineage_rule_ids == (rule.name,)
    assert "Metadata dependency 'auth_type': observed 'Federated'; rule requires eq 'Federated'" in (
        record.confidence_derivation
    )


def test_generated_hybrid_posture_observation_has_exact_evidence_and_metadata_lineage() -> None:
    evidence = EvidenceRecord(
        source_type="MX",
        raw_value="mx1.synthetic-proofpoint.invalid",
        rule_name="Synthetic Proofpoint MX",
        slug="proofpoint",
    )
    info = TenantInfo(
        tenant_id=None,
        display_name="Synthetic Example",
        default_domain="example.invalid",
        queried_domain="example.invalid",
        confidence=ConfidenceLevel.MEDIUM,
        slugs=("proofpoint",),
        services=("Proofpoint",),
        dmarc_policy="none",
        evidence=(evidence,),
    )

    observations = analyze_posture(info)
    target = next(
        observation for observation in observations if observation.source_name == "gateway_without_dmarc_enforcement"
    )
    record = explain_observations((target,), load_posture_rules(), info.evidence, ())[0]

    assert record.lineage_status is ExplanationLineageStatus.EXACT
    assert record.lineage_rule_ids == ("gateway_without_dmarc_enforcement",)
    assert record.matched_evidence == (evidence,)
    assert "Metadata dependency 'dmarc_effective_policy': observed 'none'; rule requires neq 'reject'" in (
        record.confidence_derivation
    )


def test_profile_expectation_does_not_proxy_match_an_unrelated_posture_rule() -> None:
    rule = _PostureRule(
        name="unrelated",
        category="consistency",
        salience="medium",
        template="Unrelated",
        slugs_any=("okta",),
        slugs_min=1,
    )
    source_name = "profile:strict:expected-category:Security"
    observation = Observation(
        "consistency",
        "medium",
        "Security category not observed",
        (),
        source_name=source_name,
        metadata_dependencies=(
            PostureMetadataDependency("observed_fingerprint_categories", "not_contains", "Security", ("Email",)),
        ),
        observation_scope=("profile:strict:expected_categories",),
    )

    record = explain_observations((observation,), (rule,), (), ())[0]

    assert record.lineage_status is ExplanationLineageStatus.EXACT_RULE_ONLY
    assert record.lineage_rule_ids == (source_name,)
    assert record.fired_rules == (f"Profile expectation: {source_name}",)


def test_confidence_reconstruction_does_not_claim_exact_terminal_lineage() -> None:
    evidence = _evidence()
    record = explain_confidence(
        [SourceResult(source_name="dns_records", detected_slugs=("microsoft365",), evidence=(evidence,))],
        ConfidenceLevel.LOW,
        ConfidenceLevel.LOW,
        ConfidenceLevel.LOW,
    )

    graph = build_explanation_dag([record], (evidence,))

    assert record.lineage_status is ExplanationLineageStatus.RECONSTRUCTED
    assert graph["lineage_disconnected_terminals"] == ["confidence:Overall Confidence"]


def test_flat_serializers_and_human_renderers_report_lineage_status() -> None:
    record = _record(ExplanationLineageStatus.RECONSTRUCTED, rules=("likely-rule",))

    serialized = serialize_explanation(record)
    assert serialized["lineage_status"] == "reconstructed"
    assert serialized["lineage_rule_ids"] == []

    console = Console(record=True, no_color=True, width=100)
    console.print(render_explanations_panel([record]))
    panel_text = console.export_text()
    markdown = format_explanations_markdown([record])
    assert "Lineage: Reconstructed after generation; not exact provenance" in panel_text
    assert "**Lineage:** Reconstructed after generation; not exact provenance" in markdown
