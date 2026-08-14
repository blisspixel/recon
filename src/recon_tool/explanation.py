"""Explanation engine — generates structured ExplanationRecords.

Pure functions that consume pipeline output (signals, insights, confidence,
observations) and produce ExplanationRecord instances tracing every conclusion
back to matched evidence, fired rules, confidence derivation, and weakening
conditions.

All generated text uses defensive, hedged language.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from recon_tool.confidence import (
    confidence_source_names,
    inference_confidence_basis,
    is_confidence_contributor,
    minimum_confidence,
)
from recon_tool.explanation_dag import (
    add_evidence_node,
    evidence_node_id,
    evidence_sort_key,
    finalize_dag,
    item_node_id,
    record_sort_key,
    rule_node_id,
    slug_node_id,
)
from recon_tool.explanation_insights import explain_insights
from recon_tool.models import (
    ConfidenceLevel,
    EvidenceRecord,
    ExplanationLineageStatus,
    ExplanationRecord,
    Observation,
    PostureMetadataDependency,
    SourceResult,
)
from recon_tool.posture_models import metadata_predicate_satisfied
from recon_tool.signals import (
    Signal,
    SignalMatch,
    signal_observation_label,
)

if TYPE_CHECKING:
    from recon_tool.posture import _PostureRule  # pyright: ignore[reportPrivateUsage]


@dataclass(frozen=True, slots=True)
class _SignalExplanationContext:
    """Read-only state shared while projecting evaluated signal matches."""

    detected_slugs: frozenset[str]
    metadata: dict[str, Any]
    evidence: tuple[EvidenceRecord, ...]
    detection_scores: tuple[tuple[str, str], ...]


__all__ = [
    "build_explanation_dag",
    "explain_confidence",
    "explain_insights",
    "explain_observations",
    "explain_signals",
    "serialize_explanation",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _evidence_for_slug(
    slug: str,
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[EvidenceRecord, ...]:
    """Return all evidence records that produced *slug*."""
    return tuple(e for e in evidence if e.slug == slug)


def _score_for_slug(
    slug: str,
    detection_scores: tuple[tuple[str, str], ...],
) -> str:
    """Return the detection score string for *slug*, or 'unknown'."""
    for s, score in detection_scores:
        if s == slug:
            return score
    return "unknown"


def _signal_lineage_status(
    signal: Signal,
    match: SignalMatch,
    context_detected_slugs: frozenset[str],
    matched_evidence: tuple[EvidenceRecord, ...],
) -> ExplanationLineageStatus:
    """Classify whether one retained signal match has complete raw support."""
    distinct_matches = frozenset(match.matched)
    match_shape_invalid = (
        len(distinct_matches) != len(match.matched)
        or len(distinct_matches) < signal.min_matches
        or any(slug not in signal.candidates or slug not in context_detected_slugs for slug in distinct_matches)
    )
    if match_shape_invalid:
        return ExplanationLineageStatus.UNSUPPORTED
    evidence_slugs = {item.slug for item in matched_evidence}
    positive_support_complete = bool(match.matched) and all(slug in evidence_slugs for slug in match.matched)
    has_unretained_dependency = bool(
        signal.metadata or signal.contradicts or signal.requires_signals or signal.exclude_matches_in_primary
    )
    if positive_support_complete and not has_unretained_dependency:
        return ExplanationLineageStatus.EXACT
    return ExplanationLineageStatus.EXACT_RULE_ONLY


def _absence_parent(match: SignalMatch) -> tuple[str, str] | None:
    """Return the parent rule and exact absence evaluator for a derived match."""
    missing_suffix = " \u2014 Missing Counterparts"
    positive_suffix = ": Configured Indicators Not Observed"
    if match.name.endswith(missing_suffix):
        return match.name.removesuffix(missing_suffix), "evaluate_absence_signals"
    if match.name.endswith(positive_suffix):
        return match.name.removesuffix(positive_suffix), "evaluate_positive_absence"
    return None


def _validated_absence_parent(
    match: SignalMatch,
    signal_by_name: dict[str, Signal],
    detected_slugs: frozenset[str],
    signal_matches: list[SignalMatch],
) -> tuple[str, str] | None:
    """Return a configured parent and evaluator for a valid derived absence match."""
    parsed = _absence_parent(match)
    if parsed is None:
        return None
    parent_name, evaluator = parsed
    parent = signal_by_name.get(parent_name)
    if parent is None:
        return None
    parent_matches = [
        candidate
        for candidate in signal_matches
        if candidate.name == parent.name
        and candidate.category == parent.category
        and candidate.confidence == parent.confidence
    ]
    if (
        len(parent_matches) != 1
        or _signal_lineage_status(parent, parent_matches[0], detected_slugs, ()) is ExplanationLineageStatus.UNSUPPORTED
    ):
        return None
    if evaluator == "evaluate_absence_signals":
        expected_missing = tuple(slug for slug in parent.expected_counterparts if slug not in detected_slugs)
        if not parent.expected_counterparts or match.matched != expected_missing:
            return None
    elif (
        not parent.positive_when_absent
        or match.matched
        or any(slug in detected_slugs for slug in parent.positive_when_absent)
    ):
        return None
    return parent_name, evaluator


def _explain_unresolved_signal_match(
    match: SignalMatch,
    signal_by_name: dict[str, Signal],
    detected_slugs: frozenset[str],
    signal_matches: list[SignalMatch],
) -> ExplanationRecord | None:
    """Explain an absence match or fail closed for a missing definition."""
    if match.category == "Absence":
        absence_parent = _validated_absence_parent(match, signal_by_name, detected_slugs, signal_matches)
        if absence_parent is None:
            return None
        parent_name, evaluator = absence_parent
        parent_label = signal_observation_label(parent_name)
        if parent_label is None:
            return None
        weakening = tuple(f"Detecting slug '{slug}' would suppress this absence signal" for slug in match.matched)
        return ExplanationRecord(
            item_name=f"{parent_label}: configured counterpart indicators not observed",
            item_type="signal",
            matched_evidence=(),
            fired_rules=(parent_name,),
            confidence_derivation="Absence observation: configured counterpart indicators were not observed",
            weakening_conditions=weakening,
            curated_explanation=match.description,
            lineage_status=ExplanationLineageStatus.EXACT_RULE_ONLY,
            lineage_rule_ids=(f"{evaluator}:{parent_name}",),
        )

    public_label = signal_observation_label(match.name)
    if public_label is None:
        return None
    return ExplanationRecord(
        item_name=public_label,
        item_type="signal",
        matched_evidence=(),
        fired_rules=(f"{match.name} (definition not found)",),
        confidence_derivation=f"Signal confidence: {match.confidence}",
        weakening_conditions=(),
    )


def _signal_rule_description(signal: Signal) -> str:
    """Render the evaluated signal conditions for human explanation output."""
    parts: list[str] = []
    if signal.candidates:
        parts.append(f"requires.any: {', '.join(signal.candidates)}; min_matches: {signal.min_matches}")
    if signal.metadata:
        metadata = "; ".join(
            f"{condition.field} {condition.operator} {condition.value}" for condition in signal.metadata
        )
        parts.append(f"metadata: {metadata}")
    if signal.contradicts:
        parts.append(f"contradicts: {', '.join(signal.contradicts)}")
    if signal.requires_signals:
        parts.append(f"requires_signals: {', '.join(signal.requires_signals)}")
    return f"{signal.name} ({'; '.join(parts)})" if parts else signal.name


def _signal_evidence_details(
    matched_slugs: tuple[str, ...],
    evidence: tuple[EvidenceRecord, ...],
    detection_scores: tuple[tuple[str, str], ...],
) -> tuple[tuple[EvidenceRecord, ...], tuple[str, ...]]:
    """Collect exact matched evidence and stable human-readable score details."""
    matched_evidence: list[EvidenceRecord] = []
    details: list[str] = []
    for slug in matched_slugs:
        slug_evidence = _evidence_for_slug(slug, evidence)
        matched_evidence.extend(slug_evidence)
        score = _score_for_slug(slug, detection_scores)
        details.append(
            f"Slug '{slug}' backed by {len(slug_evidence)} evidence record(s) with detection score '{score}'"
        )
    return tuple(matched_evidence), tuple(details)


def _explain_signal_match(
    signal: Signal,
    match: SignalMatch,
    context: _SignalExplanationContext,
) -> ExplanationRecord | None:
    """Project one generation-time signal match into a qualified record."""
    public_label = signal_observation_label(signal.name)
    if public_label is None:
        return None

    matched_slugs = tuple(match.matched)
    matched_evidence, slug_details = _signal_evidence_details(
        matched_slugs,
        context.evidence,
        context.detection_scores,
    )
    derivation = [f"Signal confidence: {signal.confidence}"]
    if signal.candidates:
        derivation.append(
            f"{len(matched_slugs)} of {len(signal.candidates)} candidates matched (min_matches={signal.min_matches})"
        )
    derivation.extend(slug_details)
    lineage_status = _signal_lineage_status(signal, match, context.detected_slugs, matched_evidence)
    lineage_rule_ids = (
        (signal.name,)
        if lineage_status in {ExplanationLineageStatus.EXACT, ExplanationLineageStatus.EXACT_RULE_ONLY}
        else ()
    )
    return ExplanationRecord(
        item_name=public_label,
        item_type="signal",
        matched_evidence=matched_evidence,
        fired_rules=(_signal_rule_description(signal),),
        confidence_derivation=". ".join(derivation),
        weakening_conditions=_weakening_conditions_for_signal(signal, list(matched_slugs), context.metadata),
        curated_explanation=signal.explain,
        lineage_status=lineage_status,
        lineage_rule_ids=lineage_rule_ids,
    )


# ---------------------------------------------------------------------------
# 5.2  Signal weakening condition generation
# ---------------------------------------------------------------------------


def _weakening_conditions_for_signal(
    signal: Signal,
    matched_slugs: list[str],
    context_metadata: dict[str, Any],
) -> tuple[str, ...]:
    """Generate weakening conditions for a fired signal.

    Three categories:
    1. Slug removal — if removing a matched slug drops count below min_matches.
    2. Metadata change — what value change would cause each satisfied condition
       to fail.
    3. Contradiction presence — each slug in ``contradicts`` would suppress the
       signal if detected.
    """
    conditions: list[str] = []

    # 1. Slug removal
    match_count = len(matched_slugs)
    for slug in matched_slugs:
        remaining = match_count - 1
        if remaining < signal.min_matches:
            conditions.append(
                f"Removing slug '{slug}' would drop match count to {remaining} "
                f"(below min_matches={signal.min_matches}), suppressing this signal"
            )

    # 2. Metadata conditions
    for cond in signal.metadata:
        actual = context_metadata.get(cond.field)
        actual_str = str(actual) if actual is not None else "None"
        if cond.operator == "eq":
            conditions.append(
                f"If '{cond.field}' changed from '{actual_str}' to any value "
                f"other than '{cond.value}', this condition would fail"
            )
        elif cond.operator == "neq":
            conditions.append(f"If '{cond.field}' changed to '{cond.value}', this condition would fail")
        elif cond.operator == "gte":
            conditions.append(
                f"If '{cond.field}' dropped below {cond.value} (currently {actual_str}), this condition would fail"
            )
        elif cond.operator == "lte":
            conditions.append(
                f"If '{cond.field}' rose above {cond.value} (currently {actual_str}), this condition would fail"
            )

    # 3. Contradiction slugs
    for slug in signal.contradicts:
        conditions.append(f"Detecting slug '{slug}' would suppress this signal (listed in contradicts)")

    return tuple(conditions)


# ---------------------------------------------------------------------------
# 5.1  Core explanation functions
# ---------------------------------------------------------------------------


def explain_signals(
    signal_matches: list[SignalMatch],
    signals: tuple[Signal, ...],
    context_detected_slugs: frozenset[str],
    context_metadata: dict[str, Any],
    evidence: tuple[EvidenceRecord, ...],
    detection_scores: tuple[tuple[str, str], ...],
) -> list[ExplanationRecord]:
    """Generate ExplanationRecords for all fired signals.

    For each SignalMatch:
    - Find the corresponding Signal definition.
    - List every slug from signal.candidates present in detected_slugs.
    - For each matched slug, find the EvidenceRecord(s) that produced it.
    - Include detection_scores for each referenced slug.
    - Include the signal's ``explain`` field as curated_explanation.
    - Generate weakening conditions (task 5.2).
    - Build fired_rules string showing the signal's conditions.
    """
    signal_by_name = {signal.name: signal for signal in signals}
    records: list[ExplanationRecord] = []
    context = _SignalExplanationContext(
        context_detected_slugs,
        context_metadata,
        evidence,
        detection_scores,
    )

    for match in signal_matches:
        signal = signal_by_name.get(match.name)
        record = (
            _explain_unresolved_signal_match(match, signal_by_name, context_detected_slugs, signal_matches)
            if signal is None
            else _explain_signal_match(signal, match, context)
        )
        if record is not None:
            records.append(record)

    return records


def explain_confidence(
    results: list[SourceResult],
    evidence_confidence: ConfidenceLevel,
    inference_confidence: ConfidenceLevel,
    final_confidence: ConfidenceLevel,
    *,
    identity_conflict: bool = False,
) -> ExplanationRecord:
    """Generate an ExplanationRecord for the confidence derivation.

    Shows evidence_confidence derivation, inference_confidence derivation,
    final combined confidence, and notes about degraded sources.
    """
    source_names = confidence_source_names(results)
    successful = len(source_names)

    # Evidence confidence derivation
    evidence_parts: list[str] = [
        f"Evidence confidence: {evidence_confidence.value}",
        f"{successful} successful source(s) (threshold: 3 for high, 2 for medium)",
        f"Contributing sources: {', '.join(source_names)}" if source_names else "No successful sources",
    ]

    basis = inference_confidence_basis(results)
    inference_rule = {
        "oidc_corroboration": (
            "The winning claim met the high corroboration rule through OIDC and an independent source"
        ),
        "three_record_types": "The winning claim met the high corroboration rule with at least three record types",
        "two_record_types": "The winning claim met the medium corroboration rule with at least two record types",
        "two_sources": "The winning claim met the medium corroboration rule through at least two sources",
        "repeated_tenant_id": "Independent sources reported the same tenant ID",
        "insufficient_corroboration": "No canonical claim met a multiple-record-type or multiple-source rule",
        "no_claim": "No canonical claim met a multiple-record-type or multiple-source rule",
    }[basis.rule]
    inference_parts: list[str] = [
        f"Inference confidence: {inference_confidence.value}",
        "Only error-free sources contribute; corroboration is evaluated per canonical claim; "
        "unrelated claims do not combine",
        inference_rule,
    ]
    if basis.claim:
        label = "Winning claim" if basis.level != ConfidenceLevel.LOW else "Strongest observed claim"
        inference_parts.append(f"{label}: {basis.claim}")
    if basis.source_types:
        inference_parts.append(f"Qualifying record types: {', '.join(basis.source_types)}")
    if basis.sources:
        inference_parts.append(f"Qualifying sources: {', '.join(basis.sources)}")

    # Final confidence. Merger takes min(identity-agreement, evidence, inference)
    # and then may apply a one-step degraded-collection downgrade. Saying only
    # "minimum of evidence and inference" contradicted LOW finals after a
    # tenant-ID conflict.
    dimensional_floor = minimum_confidence(evidence_confidence, inference_confidence)
    if identity_conflict and final_confidence != dimensional_floor:
        final_note = "identity sources disagreed on tenant ID"
    elif final_confidence == dimensional_floor:
        final_note = "minimum of evidence and inference dimensions"
    else:
        final_note = "combined identity, evidence, and inference dimensions"
    final_parts = [
        f"Final confidence: {final_confidence.value} ({final_note})",
    ]

    # Degraded sources
    degraded: set[str] = set()
    for r in results:
        degraded.update(r.degraded_sources)
    degraded_parts: list[str] = []
    if degraded:
        degraded_parts.append(f"Degraded sources that could have increased confidence: {', '.join(sorted(degraded))}")

    all_parts = evidence_parts + inference_parts + final_parts + degraded_parts
    derivation = ". ".join(all_parts)

    # Record one confidence-contribution status per source name.
    source_status: dict[str, bool] = {}
    for result in results:
        source_status[result.source_name] = source_status.get(result.source_name, False) or is_confidence_contributor(
            result
        )
    fired_rules = tuple(
        f"Source: {source_name} ({'success' if success else 'failed'})"
        for source_name, success in source_status.items()
    )

    # Weakening: note degraded sources
    weakening: list[str] = []
    for src in sorted(degraded):
        weakening.append(f"Source '{src}' was unavailable — its data could have changed the confidence assessment")

    return ExplanationRecord(
        item_name="Overall Confidence",
        item_type="confidence",
        matched_evidence=basis.evidence,
        fired_rules=fired_rules,
        confidence_derivation=derivation,
        weakening_conditions=tuple(weakening),
        lineage_status=ExplanationLineageStatus.RECONSTRUCTED,
    )


def _match_posture_rule(
    observation: Observation,
    posture_rules: tuple[_PostureRule, ...],
    rules_by_name: dict[str, _PostureRule],
) -> tuple[_PostureRule | None, _PostureRule | None]:
    """Return exact and best-effort compatibility rules for an observation."""
    exact_rule = rules_by_name.get(observation.source_name) if observation.source_name else None
    if exact_rule is not None or observation.source_name:
        return exact_rule, exact_rule

    for rule in posture_rules:
        same_surface = rule.category == observation.category and rule.salience == observation.salience
        slug_match = bool(rule.slugs_any) and set(observation.related_slugs).issubset(rule.slugs_any)
        metadata_only_match = not rule.slugs_any
        if same_surface and (slug_match or metadata_only_match):
            return None, rule
    return None, None


def _posture_rule_description(rule: _PostureRule | None) -> str:
    """Render a matched posture rule without implying stronger lineage."""
    if rule is None:
        return "Posture rule (could not be matched to definition)"
    parts = [f"Posture rule: {rule.name}"]
    if rule.slugs_any:
        parts.extend((f"slugs_any: {', '.join(rule.slugs_any)}", f"slugs_min: {rule.slugs_min}"))
    if rule.metadata:
        metadata = "; ".join(f"{condition.field} {condition.operator} {condition.value}" for condition in rule.metadata)
        parts.append(f"metadata: {metadata}")
    return "; ".join(parts)


def _retained_observation_evidence(
    observation: Observation,
    retained_evidence: tuple[EvidenceRecord, ...],
) -> tuple[EvidenceRecord, ...]:
    """Return claimed occurrences only when the retained multiset contains them."""
    available = Counter(retained_evidence)
    for item in observation.supporting_evidence:
        if available[item] == 0:
            return ()
        available[item] -= 1
    return observation.supporting_evidence


def _metadata_dependency_satisfies(dependency: PostureMetadataDependency) -> bool:
    """Validate one captured metadata predicate without re-reading live state."""
    return metadata_predicate_satisfied(
        dependency.operator,
        dependency.expected_value,
        dependency.observed_value,
    )


def _posture_dependencies_complete(
    observation: Observation,
    rule: _PostureRule,
    matched_evidence: tuple[EvidenceRecord, ...],
) -> bool:
    """Validate the generation-time dependency bundle against its named rule."""
    related = observation.related_slugs
    related_set = set(related)
    evidence_slugs = {item.slug for item in matched_evidence}
    maximum_valid = rule.slugs_max is None or len(related) <= rule.slugs_max
    slug_dependencies_valid = (
        len(related) == len(related_set)
        and related_set.issubset(rule.slugs_any)
        and len(related) >= rule.slugs_min
        and maximum_valid
        and evidence_slugs == related_set
    )
    dependencies = observation.metadata_dependencies
    metadata_dependencies_valid = len(dependencies) == len(rule.metadata) and all(
        dependency.field == condition.field
        and dependency.operator == condition.operator
        and dependency.expected_value == condition.value
        and _metadata_dependency_satisfies(dependency)
        for dependency, condition in zip(dependencies, rule.metadata, strict=True)
    )
    return slug_dependencies_valid and metadata_dependencies_valid


def _posture_lineage(
    observation: Observation,
    exact_rule: _PostureRule | None,
    matched_rule: _PostureRule | None,
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[ExplanationLineageStatus, tuple[str, ...]]:
    """Qualify a posture association against retained generation-time state."""
    if exact_rule is None:
        if (
            observation.source_name.startswith("profile:")
            and observation.metadata_dependencies
            and observation.observation_scope
            and all(_metadata_dependency_satisfies(item) for item in observation.metadata_dependencies)
        ):
            return ExplanationLineageStatus.EXACT_RULE_ONLY, (observation.source_name,)
        status = (
            ExplanationLineageStatus.RECONSTRUCTED
            if matched_rule is not None and not observation.source_name
            else ExplanationLineageStatus.UNSUPPORTED
        )
        return status, ()

    complete_dependencies = _posture_dependencies_complete(observation, exact_rule, evidence)
    status = (
        ExplanationLineageStatus.EXACT
        if complete_dependencies and bool(evidence)
        else ExplanationLineageStatus.EXACT_RULE_ONLY
    )
    return status, (exact_rule.name,)


def explain_observations(
    observations: tuple[Observation, ...],
    posture_rules: tuple[_PostureRule, ...],
    evidence: tuple[EvidenceRecord, ...],
    detection_scores: tuple[tuple[str, str], ...],
) -> list[ExplanationRecord]:
    """Generate ExplanationRecords for posture observations.

    For each Observation, find the matching _PostureRule by name,
    include the rule's ``explain`` field as curated_explanation,
    and list matched slugs and their evidence.
    """
    records: list[ExplanationRecord] = []
    rules_by_name = {rule.name: rule for rule in posture_rules}

    for obs in observations:
        exact_source_rule, matched_rule = _match_posture_rule(obs, posture_rules, rules_by_name)

        # Exact observations carry their own branch-local occurrences. Legacy
        # observations without a source rule retain the old reconstruction path.
        if obs.source_name:
            obs_evidence = list(_retained_observation_evidence(obs, evidence))
        else:
            obs_evidence = []
            for slug in obs.related_slugs:
                obs_evidence.extend(_evidence_for_slug(slug, evidence))

        slug_details: list[str] = []
        for slug in obs.related_slugs:
            slug_ev = tuple(item for item in obs_evidence if item.slug == slug)
            score = _score_for_slug(slug, detection_scores)
            slug_details.append(f"Slug '{slug}': {len(slug_ev)} evidence record(s), score '{score}'")

        # Confidence derivation
        derivation_parts = [f"Observation salience: {obs.salience}"]
        if slug_details:
            derivation_parts.extend(slug_details)
        if not slug_details and not obs.related_slugs:
            derivation_parts.append("Metadata-only observation (no slug evidence)")
        derivation_parts.extend(
            (
                f"Metadata dependency '{dependency.field}': observed {dependency.observed_value!r}; "
                f"rule requires {dependency.operator} {dependency.expected_value!r}"
            )
            for dependency in obs.metadata_dependencies
        )
        derivation_parts.extend(f"Observation scope: {scope}" for scope in obs.observation_scope)

        curated = matched_rule.explain if matched_rule is not None else ""
        lineage_status, lineage_rule_ids = _posture_lineage(
            obs,
            exact_source_rule,
            matched_rule,
            tuple(obs_evidence),
        )

        records.append(
            ExplanationRecord(
                item_name=obs.statement,
                item_type="observation",
                matched_evidence=tuple(obs_evidence),
                fired_rules=(
                    (
                        f"Profile expectation: {obs.source_name}"
                        if matched_rule is None and obs.source_name.startswith("profile:")
                        else _posture_rule_description(matched_rule)
                    ),
                ),
                confidence_derivation=". ".join(derivation_parts),
                weakening_conditions=(),
                curated_explanation=curated,
                lineage_status=lineage_status,
                lineage_rule_ids=lineage_rule_ids,
            )
        )

    return records


def serialize_explanation(record: ExplanationRecord) -> dict[str, Any]:
    """Serialize an ExplanationRecord to a JSON-safe dict.

    matched_evidence → list of dicts with source_type, raw_value, rule_name, slug.
    All other fields → strings or lists of strings.
    """
    return {
        "item_name": record.item_name,
        "item_type": record.item_type,
        "matched_evidence": [
            {
                "source_type": e.source_type,
                "raw_value": e.raw_value,
                "rule_name": e.rule_name,
                "slug": e.slug,
            }
            for e in record.matched_evidence
        ],
        "fired_rules": list(record.fired_rules),
        "confidence_derivation": record.confidence_derivation,
        "weakening_conditions": list(record.weakening_conditions),
        "curated_explanation": record.curated_explanation,
        "lineage_status": record.lineage_status.value,
        "lineage_rule_ids": list(record.lineage_rule_ids),
    }


# ── Explanation DAG (schema version 1) ───────────────────────────────────


def build_explanation_dag(
    records: list[ExplanationRecord],
    all_evidence: tuple[EvidenceRecord, ...] = (),
) -> dict[str, Any]:
    """Build a JSON-serialisable provenance DAG from ExplanationRecords.

    Schema version 1 node types:
        * ``evidence``  - one node per raw EvidenceRecord occurrence
        * ``slug``      - one node per detected fingerprint slug
        * ``rule``      - one occurrence-scoped node per fired rule and
                          explanation terminal
        * ``signal``    - one node per fired signal (incl. absence
                          and hardening observations)
        * ``insight``   - one node per generated insight string
        * ``observation`` - one node per posture observation
        * ``confidence`` - the overall confidence node (singleton)

    Edge types:
        * ``detected-by``        - evidence to slug
        * ``matched-rule``       - evidence to rule only when the retained
                                   evidence rule name exactly matches the label
        * ``supports-rule``      - exact generation-time evidence association
        * ``contributes-to``     - slug to signal | insight |
                                   observation | confidence
        * ``fired``              - rule to signal | insight |
                                   observation | confidence

    Diagnostics:
        * ``provenance_complete`` is true exactly when every terminal
          explanation node is reachable from at least one evidence node.
        * ``disconnected_terminals`` contains the sorted ids of any terminal
          explanation nodes for which that evidence path is unavailable.
        * ``exact_provenance_complete`` and
          ``lineage_disconnected_terminals`` apply the stronger requirement of
          an explicit generation-time evidence-to-rule association.

    The graph is acyclic: edges flow from evidence to slug or rule, then to
    terminal explanation nodes. Weakening conditions remain item-node metadata.

    The DAG is additive; the existing flat ``explanations`` list is
    still emitted alongside it for callers that prefer the old shape.
    Downstream tooling can pick whichever view fits.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    evidence_ids_by_identity: dict[int, list[str]] = {}
    evidence_ids_by_value: dict[EvidenceRecord, list[str]] = {}
    next_evidence_index = 0

    def register_evidence(ev: EvidenceRecord) -> str:
        """Register one occurrence and retain both exact and value lookups."""
        nonlocal next_evidence_index
        eid = evidence_node_id(ev, next_evidence_index)
        next_evidence_index += 1
        add_evidence_node(nodes, edges, ev, eid)
        evidence_ids_by_identity.setdefault(id(ev), []).append(eid)
        evidence_ids_by_value.setdefault(ev, []).append(eid)
        return eid

    ordered_records = sorted(records, key=record_sort_key)
    evidence_contexts: dict[int, list[tuple[tuple[Any, ...], int]]] = {}
    for record in ordered_records:
        record_key = record_sort_key(record)
        for occurrence, evidence in enumerate(record.matched_evidence):
            evidence_contexts.setdefault(id(evidence), []).append((record_key, occurrence))

    # Seed every occurrence in canonical authoritative order. The two
    # lookup maps let later ExplanationRecords reuse these ids without deriving
    # a new, record-local index that can collide with another occurrence.
    for ev in sorted(
        all_evidence,
        key=lambda evidence: (evidence_sort_key(evidence), tuple(evidence_contexts.get(id(evidence), ()))),
    ):
        register_evidence(ev)

    # Step 2: add one node per ExplanationRecord and link the evidence
    # it cites to it. For signal records, link via the slug node too
    # so the DAG walker can walk evidence → slug → signal either way.
    item_totals: dict[tuple[str, str], int] = {}
    for record in ordered_records:
        key = (record.item_type, record.item_name)
        item_totals[key] = item_totals.get(key, 0) + 1
    item_occurrences: dict[tuple[str, str], int] = {}

    for rec in ordered_records:
        used_evidence_ids: set[str] = set()
        item_key = (rec.item_type, rec.item_name)
        item_occurrence = item_occurrences.get(item_key, 0)
        item_occurrences[item_key] = item_occurrence + 1
        item_id = item_node_id(rec.item_type, rec.item_name, item_occurrence, item_totals[item_key])
        # If a signal and an observation happen to share the same
        # name, distinguish them by item_type in the id.
        nodes[item_id] = {
            "id": item_id,
            "type": rec.item_type,
            "name": rec.item_name,
            "confidence_derivation": rec.confidence_derivation,
            "weakening_conditions": sorted(rec.weakening_conditions),
            "curated_explanation": rec.curated_explanation,
            "lineage_status": rec.lineage_status.value,
            "lineage_rule_ids": sorted(rec.lineage_rule_ids),
        }

        # For each cited evidence, add (evidence) → slug → item via
        # contributes-to. If the evidence is also in all_evidence we
        # already seeded it; otherwise seed it now.
        record_evidence_occurrences: list[tuple[EvidenceRecord, str]] = []
        for ev in sorted(rec.matched_evidence, key=evidence_sort_key):
            candidates = [
                *evidence_ids_by_identity.get(id(ev), ()),
                *evidence_ids_by_value.get(ev, ()),
            ]
            eid = next((candidate for candidate in candidates if candidate not in used_evidence_ids), None)
            if eid is None:
                eid = register_evidence(ev)
            used_evidence_ids.add(eid)
            record_evidence_occurrences.append((ev, eid))
            sid = slug_node_id(ev.slug)
            # slug → item
            edges.append({"source": sid, "target": item_id, "relation": "contributes-to"})

        # Preserve the v1 exact-name edge and add a distinct generation-time
        # edge only for records that retained that stronger association.
        all_rules = sorted(set(rec.fired_rules) | set(rec.lineage_rule_ids))
        for occurrence, rule in enumerate(all_rules):
            rid = rule_node_id(rule, item_id, occurrence)
            rule_is_exact = rule in rec.lineage_rule_ids
            nodes[rid] = {
                "id": rid,
                "type": "rule",
                "name": rule,
                "lineage_status": "exact" if rule_is_exact else rec.lineage_status.value,
            }
            for evidence, eid in record_evidence_occurrences:
                if evidence.rule_name == rule:
                    edges.append({"source": eid, "target": rid, "relation": "matched-rule"})
                if rule_is_exact and rec.lineage_status is ExplanationLineageStatus.EXACT:
                    edges.append({"source": eid, "target": rid, "relation": "supports-rule"})
            edges.append({"source": rid, "target": item_id, "relation": "fired"})

    return finalize_dag(nodes, edges)
