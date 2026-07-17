"""Explanation engine — generates structured ExplanationRecords.

Pure functions that consume pipeline output (signals, insights, confidence,
observations) and produce ExplanationRecord instances tracing every conclusion
back to matched evidence, fired rules, confidence derivation, and weakening
conditions.

All generated text uses defensive, hedged language.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from recon_tool.confidence import (
    confidence_source_names,
    inference_confidence_basis,
    is_confidence_contributor,
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
from recon_tool.models import (
    ConfidenceLevel,
    EvidenceRecord,
    ExplanationRecord,
    Observation,
    SourceResult,
)
from recon_tool.signals import (
    Signal,
    SignalMatch,
    load_signals,
    signal_observation_label,
    signal_rule_names_from_observation,
)

if TYPE_CHECKING:
    from recon_tool.posture import _PostureRule  # pyright: ignore[reportPrivateUsage]

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
    signal_by_name: dict[str, Signal] = {s.name: s for s in signals}
    records: list[ExplanationRecord] = []

    for match in signal_matches:
        sig = signal_by_name.get(match.name)
        if sig is None:
            # Check if this is an absence signal (category="Absence")
            if match.category == "Absence":
                # Absence signals carry missing slugs in matched and the
                # parent signal name in the derived name.
                # Extract parent signal name for fired_rules.
                parent_name = match.name.replace(" \u2014 Missing Counterparts", "")
                parent_label = signal_observation_label(parent_name)
                if parent_label is None:
                    continue
                weakening_abs = tuple(
                    f"Detecting slug '{slug}' would suppress this absence signal" for slug in match.matched
                )
                records.append(
                    ExplanationRecord(
                        item_name=f"{parent_label}: configured counterpart indicators not observed",
                        item_type="signal",
                        matched_evidence=(),
                        fired_rules=(parent_name,),
                        confidence_derivation=(
                            "Absence observation: configured counterpart indicators were not observed"
                        ),
                        weakening_conditions=weakening_abs,
                        curated_explanation=match.description,
                    )
                )
                continue

            # Defensive: signal match without a definition — produce minimal record
            public_label = signal_observation_label(match.name)
            if public_label is None:
                continue
            records.append(
                ExplanationRecord(
                    item_name=public_label,
                    item_type="signal",
                    matched_evidence=(),
                    fired_rules=(f"{match.name} (definition not found)",),
                    confidence_derivation=f"Signal confidence: {match.confidence}",
                    weakening_conditions=(),
                )
            )
            continue

        public_label = signal_observation_label(sig.name)
        if public_label is None:
            continue

        # Matched slugs: candidates that are present in detected_slugs
        matched_slugs = [slug for slug in sig.candidates if slug in context_detected_slugs]

        # Collect evidence for all matched slugs
        all_evidence: list[EvidenceRecord] = []
        slug_details: list[str] = []
        for slug in matched_slugs:
            slug_ev = _evidence_for_slug(slug, evidence)
            all_evidence.extend(slug_ev)
            score = _score_for_slug(slug, detection_scores)
            slug_details.append(
                f"Slug '{slug}' backed by {len(slug_ev)} evidence record(s) with detection score '{score}'"
            )

        # Build fired_rules description
        rules_parts: list[str] = []
        if sig.candidates:
            candidates_str = ", ".join(sig.candidates)
            rules_parts.append(f"requires.any: {candidates_str}; min_matches: {sig.min_matches}")
        if sig.metadata:
            meta_strs = [f"{c.field} {c.operator} {c.value}" for c in sig.metadata]
            rules_parts.append(f"metadata: {'; '.join(meta_strs)}")
        if sig.contradicts:
            rules_parts.append(f"contradicts: {', '.join(sig.contradicts)}")
        if sig.requires_signals:
            rules_parts.append(f"requires_signals: {', '.join(sig.requires_signals)}")

        fired_rule = f"{sig.name} ({'; '.join(rules_parts)})" if rules_parts else sig.name

        # Confidence derivation
        derivation_parts = [f"Signal confidence: {sig.confidence}"]
        if sig.candidates:
            derivation_parts.append(
                f"{len(matched_slugs)} of {len(sig.candidates)} candidates matched (min_matches={sig.min_matches})"
            )
        if slug_details:
            derivation_parts.extend(slug_details)

        # Weakening conditions
        weakening = _weakening_conditions_for_signal(sig, matched_slugs, context_metadata)

        records.append(
            ExplanationRecord(
                item_name=public_label,
                item_type="signal",
                matched_evidence=tuple(all_evidence),
                fired_rules=(fired_rule,),
                confidence_derivation=". ".join(derivation_parts),
                weakening_conditions=weakening,
                curated_explanation=sig.explain,
            )
        )

    return records


# Generator-owned prefixes must bypass the generic ``Signal: matches`` parser.
# Keep this bounded to emitted formats; a colon alone is not enough to establish
# that an insight came from the declarative signal engine.
_GENERATOR_OWNED_INSIGHT_PREFIXES = (
    "email security",
    "dmarc",
    "no dmarc",
    "no dkim",
    "pki:",
    "caa issuer authorization observed:",
    "infrastructure:",
    "federated identity observed",
    "mx gateway observed:",
    "provider indicators co-observed:",
    "security-vendor indicator",
    "network-security vendor indicator",
    "device-management vendor indicator",
    "google workspace module indicators observed:",
    "google workspace:",
    "no observable email infrastructure",
    "next step:",
    "non-commercial microsoft cloud instance observed:",
    # Legacy-only cached formats. Their removed generators remain classifiable
    # for raw-cache diagnostics, but collection_view suppresses them from
    # current user-facing output.
    "email gateway:",
    "security stack:",
    "sase/ztna:",
    "dual provider:",
    "dual mdm:",
    "google workspace modules:",
)


# Keyword-driven insight classification. Each rule is
# (predicate over the lowercased insight, generator label, candidate slugs to
# attribute when present, confidence note). Order matters: the first matching
# rule wins, mirroring the original elif chain. The two special cases
# (signal-name parsing and the email-security all-slug scan) are handled before
# this table in _classify_insight.
_INSIGHT_RULES: list[tuple[Callable[[str], bool], str, tuple[str, ...], str]] = [
    (
        lambda low: (
            low.startswith(("federated identity observed", "federated identity indicators"))
            or "cloud-managed" in low
            or "entra id" in low
        ),
        "_auth_insights",
        ("okta", "duo", "microsoft365"),
        "Federation state plus separately observed identity-vendor indicators",
    ),
    (
        lambda low: low.startswith("mx gateway observed:"),
        "_gateway_insights",
        ("proofpoint", "mimecast", "barracuda", "cisco-ironport", "cisco-email", "trendmicro", "symantec", "trellix"),
        "MX-backed gateway observation",
    ),
    (
        lambda low: low.startswith("provider indicators co-observed:"),
        "_provider_overlap_insights",
        ("google-workspace", "microsoft365"),
        "Simultaneous Google and Microsoft public indicators",
    ),
    (
        lambda low: low.startswith("microsoft tenant discovery returned ") and low.endswith(" domains"),
        "_tenant_domain_insights",
        (),
        "Microsoft tenant-discovery domain count",
    ),
    (
        lambda low: low.startswith("security-vendor indicator"),
        "_security_vendor_insights",
        (
            "knowbe4",
            "crowdstrike",
            "sentinelone",
            "sophos",
            "duo",
            "okta",
            "1password",
            "paloalto",
            "zscaler",
            "netskope",
            "wiz",
            "imperva",
        ),
        "Public security-vendor indicator observation",
    ),
    (
        lambda low: low.startswith("network-security vendor indicator"),
        "_network_security_insights",
        ("zscaler", "netskope", "paloalto"),
        "Public network-security vendor indicator observation",
    ),
    (
        lambda low: low.startswith("device-management vendor indicator"),
        "_device_management_insights",
        ("jamf", "kandji"),
        "Public device-management vendor indicator observation",
    ),
    (
        lambda low: low.startswith("google workspace module indicators observed:"),
        "_google_modules_insights",
        (),
        "Google Workspace module indicators observed in public DNS",
    ),
    (
        lambda low: low.startswith("no observable email infrastructure"),
        "_no_email_infrastructure_insights",
        (),
        "Observed-empty email channels; no positive evidence edge is synthesized",
    ),
    (
        lambda low: low.startswith(("sparse public signal", "next step:")),
        "_sparse_signal_insights",
        (),
        "Sparse public-observation guidance; no positive evidence edge is synthesized",
    ),
    (
        lambda low: low.startswith(
            (
                "likely us government",
                "likely azure china",
                "azure ad b2c tenant",
                "non-commercial microsoft cloud instance observed:",
            )
        ),
        "_sovereignty_insights",
        (),
        "Microsoft cloud-instance metadata observation; exact lineage is not reconstructed here",
    ),
    (
        lambda low: low.startswith("email gateway") or "email gateway identified" in low,
        "_gateway_insights",
        ("proofpoint", "mimecast", "barracuda", "cisco-ironport", "cisco-email", "trendmicro", "symantec", "trellix"),
        "Legacy gateway insight format; current output uses the MX-backed gateway field",
    ),
    (
        lambda low: "security stack" in low,
        "legacy-only _security_stack_insights (removed)",
        (
            "knowbe4",
            "crowdstrike",
            "sentinelone",
            "sophos",
            "duo",
            "okta",
            "1password",
            "paloalto",
            "zscaler",
            "netskope",
            "wiz",
            "imperva",
        ),
        "Legacy-only active-stack wording; removed from current generation",
    ),
    (
        lambda low: "sase" in low or "ztna" in low,
        "legacy-only _sase_insights (removed)",
        ("zscaler", "netskope", "paloalto"),
        "Legacy-only deployment wording; removed from current generation",
    ),
    (
        lambda low: "dual provider" in low or "coexistence" in low,
        "legacy-only _migration_insights (removed)",
        ("google-workspace", "microsoft365"),
        "Legacy-only coexistence wording; removed from current generation",
    ),
    (
        lambda low: "domains" in low and ("enterprise" in low or "mid-size" in low or "in tenant" in low),
        "legacy-only _org_size_insights (removed)",
        (),
        "Legacy-only organization-size wording; removed from current generation",
    ),
    (
        lambda low: "m365" in low and ("e3" in low or "e5" in low or "proplus" in low or "apps for" in low),
        "legacy-only _license_insights (removed)",
        (),
        "Legacy-only license-tier wording; removed from current generation",
    ),
    (
        lambda low: "dual mdm" in low or "mac management" in low,
        "legacy-only _mdm_insights (removed)",
        ("jamf", "kandji"),
        "Legacy-only fleet wording; removed from current generation",
    ),
    (
        lambda low: low.startswith("caa issuer authorization observed:"),
        "_pki_insights",
        ("letsencrypt", "digicert", "sectigo", "aws-acm", "google-trust", "globalsign"),
        "CAA records authorize these issuers; issuance is not established",
    ),
    (
        lambda low: low.startswith("infrastructure:"),
        "_infrastructure_insights",
        (),
        "Infrastructure providers detected from DNS records",
    ),
    (
        lambda low: "google workspace" in low and ("federated" in low or "managed" in low),
        "_google_auth_insights",
        ("google-federated", "google-managed"),
        "Google Workspace identity type detected",
    ),
    (
        lambda low: "google workspace modules" in low,
        "_google_modules_insights",
        (),
        "Legacy module-label format from public DNS indicators",
    ),
    (
        lambda low: "dmarc" in low or "dkim" in low,
        "_email_security_insights",
        (),
        "Email security observation from DNS records",
    ),
    (
        lambda low: "conflicting tenant" in low,
        "merge_results (conflict detection)",
        (),
        "Multiple distinct tenant IDs found across sources",
    ),
    (
        lambda low: "large org signal" in low,
        "legacy-only _org_size_insights (removed)",
        (),
        "Legacy-only organization-size wording; removed from current generation",
    ),
]


def _evidence_for_insight_rule(
    rule: str,
    slug: str,
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[EvidenceRecord, ...]:
    """Return only evidence types that can support the classified observation."""
    matched = _evidence_for_slug(slug, evidence)
    if rule == "_gateway_insights":
        return tuple(item for item in matched if item.source_type.upper() == "MX")
    return matched


def _classify_structured_slug_insight(
    insight: str,
    slugs: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[list[str], list[EvidenceRecord], list[str], list[str]] | None:
    """Classify non-signal ``prefix: raw-slug`` insight text."""
    if ": " not in insight or insight.lower().startswith(_GENERATOR_OWNED_INSIGHT_PREFIXES):
        return None
    prefix, matched_text = insight.split(": ", 1)
    relevant_slugs = [
        slug for slug in (item.strip() for item in matched_text.split(",") if item.strip()) if slug in slugs
    ]
    relevant_evidence = [item for slug in relevant_slugs for item in _evidence_for_slug(slug, evidence)]
    return (
        relevant_slugs,
        relevant_evidence,
        [f"Structured insight: {prefix}"],
        [f"Structured insight referencing {len(relevant_slugs)} slug(s)"],
    )


def _classify_insight(
    insight: str,
    slugs: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[list[str], list[EvidenceRecord], list[str], list[str]]:
    """Map one insight string to (relevant slugs, evidence, fired rules, notes).

    Best-effort keyword matching back to the generator that likely produced the
    insight. The signal-name case and the email-security all-slug scan are
    handled explicitly; everything else is the ordered ``_INSIGHT_RULES`` table.
    """
    lower = insight.lower()
    relevant_slugs: list[str] = []
    relevant_evidence: list[EvidenceRecord] = []
    fired_rules: list[str] = []
    confidence_parts: list[str] = []

    # Signal-generated insights use a claim-safe label. Resolve that label to
    # stable rule IDs, then reconstruct matched slugs from the rule catalog
    # instead of attempting to reverse humanized display names.
    rule_names = signal_rule_names_from_observation(insight)
    if rule_names and not lower.startswith(_GENERATOR_OWNED_INSIGHT_PREFIXES):
        signal_by_name = {signal.name: signal for signal in load_signals()}
        for rule_name in rule_names:
            signal = signal_by_name.get(rule_name)
            if signal is None:
                continue
            fired_rules.append(f"Signal: {rule_name}")
            for slug in signal.candidates:
                if slug in slugs and slug not in relevant_slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
        confidence_parts.append(f"Signal-generated insight referencing {len(relevant_slugs)} slug(s)")
        return relevant_slugs, relevant_evidence, fired_rules, confidence_parts

    # Other structured insights may carry canonical raw slugs on the right
    # side even though their prefix is not a declarative signal label. Preserve
    # those evidence links without misclassifying the prefix as a signal rule.
    structured = _classify_structured_slug_insight(insight, slugs, evidence)
    if structured is not None:
        return structured

    # Email-control inventory insight scans slugs for parenthetical references.
    if lower.startswith("email security"):
        fired_rules.append("_email_security_insights")
        for slug in slugs:
            if slug in lower:
                relevant_slugs.append(slug)
                relevant_evidence.extend(_evidence_for_slug(slug, evidence))
        confidence_parts.append(
            "Email control count derived from observed DMARC, DKIM, SPF, MTA-STS, BIMI presence"
        )
        return relevant_slugs, relevant_evidence, fired_rules, confidence_parts

    for predicate, rule, candidate_slugs, note in _INSIGHT_RULES:
        if predicate(lower):
            fired_rules.append(rule)
            for slug in candidate_slugs:
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_insight_rule(rule, slug, evidence))
            confidence_parts.append(note)
            return relevant_slugs, relevant_evidence, fired_rules, confidence_parts

    fired_rules.append("unknown generator")
    confidence_parts.append("Unmapped insight — generator could not be determined")
    return relevant_slugs, relevant_evidence, fired_rules, confidence_parts


def explain_insights(
    insights: list[str],
    slugs: frozenset[str],
    services: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
    detection_scores: tuple[tuple[str, str], ...],
) -> list[ExplanationRecord]:
    """Generate ExplanationRecords for all generated insights.

    Maps each insight string back to the generator that likely produced it via
    keyword matching (see ``_classify_insight``). Approximate by design, since
    insights are free-form strings.
    """
    records: list[ExplanationRecord] = []
    for insight in insights:
        relevant_slugs, relevant_evidence, fired_rules, confidence_parts = _classify_insight(insight, slugs, evidence)

        for slug in relevant_slugs:
            score = _score_for_slug(slug, detection_scores)
            confidence_parts.append(f"Slug '{slug}' detection score: '{score}'")

        records.append(
            ExplanationRecord(
                item_name=insight,
                item_type="insight",
                matched_evidence=tuple(relevant_evidence),
                fired_rules=tuple(fired_rules),
                confidence_derivation=". ".join(confidence_parts) if confidence_parts else "No derivation available",
                weakening_conditions=(),
            )
        )

    return records


def explain_confidence(
    results: list[SourceResult],
    evidence_confidence: ConfidenceLevel,
    inference_confidence: ConfidenceLevel,
    final_confidence: ConfidenceLevel,
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

    # Final confidence
    final_parts = [
        f"Final confidence: {final_confidence.value} (minimum of evidence and inference dimensions)",
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
    )


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
        # New observations retain their exact source rule. The bounded heuristic
        # remains only for legacy callers that constructed Observation before
        # source_name was added.
        matched_rule = rules_by_name.get(obs.source_name) if obs.source_name else None
        for rule in posture_rules if matched_rule is None and not obs.source_name else ():
            # Match by slug overlap: if the observation's related_slugs are a
            # subset of the rule's slugs_any, it's likely the right rule.
            if (
                rule.slugs_any
                and set(obs.related_slugs).issubset(set(rule.slugs_any))
                and rule.category == obs.category
                and rule.salience == obs.salience
            ):
                matched_rule = rule
                break
            # For metadata-only rules (no slugs_any), match by category + salience
            if not rule.slugs_any and rule.category == obs.category and rule.salience == obs.salience:
                matched_rule = rule
                break

        # Collect evidence for related slugs
        obs_evidence: list[EvidenceRecord] = []
        slug_details: list[str] = []
        for slug in obs.related_slugs:
            slug_ev = _evidence_for_slug(slug, evidence)
            obs_evidence.extend(slug_ev)
            score = _score_for_slug(slug, detection_scores)
            slug_details.append(f"Slug '{slug}': {len(slug_ev)} evidence record(s), score '{score}'")

        # Build fired rules
        fired: list[str] = []
        if matched_rule is not None:
            rule_desc_parts: list[str] = [f"Posture rule: {matched_rule.name}"]
            if matched_rule.slugs_any:
                rule_desc_parts.append(f"slugs_any: {', '.join(matched_rule.slugs_any)}")
                rule_desc_parts.append(f"slugs_min: {matched_rule.slugs_min}")
            if matched_rule.metadata:
                meta_strs = [f"{c.field} {c.operator} {c.value}" for c in matched_rule.metadata]
                rule_desc_parts.append(f"metadata: {'; '.join(meta_strs)}")
            fired.append("; ".join(rule_desc_parts))
        else:
            fired.append("Posture rule (could not be matched to definition)")

        # Confidence derivation
        derivation_parts = [f"Observation salience: {obs.salience}"]
        if slug_details:
            derivation_parts.extend(slug_details)
        if not slug_details and not obs.related_slugs:
            derivation_parts.append("Metadata-only observation (no slug evidence)")

        curated = matched_rule.explain if matched_rule is not None else ""

        records.append(
            ExplanationRecord(
                item_name=obs.statement,
                item_type="observation",
                matched_evidence=tuple(obs_evidence),
                fired_rules=tuple(fired),
                confidence_derivation=". ".join(derivation_parts),
                weakening_conditions=(),
                curated_explanation=curated,
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
    }


# ── Explanation DAG (v0.9.3) ────────────────────────────────────────────


def build_explanation_dag(
    records: list[ExplanationRecord],
    all_evidence: tuple[EvidenceRecord, ...] = (),
) -> dict[str, Any]:
    """Build a JSON-serialisable provenance DAG from ExplanationRecords.

    v0.9.3. Node types:
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
        * ``contributes-to``     - slug to signal | insight |
                                   observation | confidence
        * ``fired``              - rule to signal | insight |
                                   observation | confidence

    Diagnostics:
        * ``provenance_complete`` is true exactly when every terminal
          explanation node is reachable from at least one evidence node.
        * ``disconnected_terminals`` contains the sorted ids of any terminal
          explanation nodes for which that evidence path is unavailable.

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

        # Rule labels can recur across independent explanation records, so
        # every fired rule gets an item-scoped occurrence node. ExplanationRecord
        # does not retain a general evidence-to-fired-rule mapping, so add the
        # matched-rule edge only for the defensible exact-name association.
        # Other cited evidence reaches the terminal through its slug without
        # inventing rule-specific lineage.
        for occurrence, rule in enumerate(sorted(rec.fired_rules)):
            rid = rule_node_id(rule, item_id, occurrence)
            nodes[rid] = {"id": rid, "type": "rule", "name": rule}
            for evidence, eid in record_evidence_occurrences:
                if evidence.rule_name == rule:
                    edges.append({"source": eid, "target": rid, "relation": "matched-rule"})
            edges.append({"source": rid, "target": item_id, "relation": "fired"})

    return finalize_dag(nodes, edges)
