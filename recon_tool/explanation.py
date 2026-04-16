"""Explanation engine — generates structured ExplanationRecords.

Pure functions that consume pipeline output (signals, insights, confidence,
observations) and produce ExplanationRecord instances tracing every conclusion
back to matched evidence, fired rules, confidence derivation, and weakening
conditions.

All generated text uses defensive, hedged language.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from recon_tool.models import (
    ConfidenceLevel,
    EvidenceRecord,
    ExplanationRecord,
    Observation,
    SourceResult,
)
from recon_tool.signals import Signal, SignalMatch

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
                # parent signal name in the name (e.g. "X — Missing Counterparts").
                # Extract parent signal name for fired_rules.
                parent_name = match.name.replace(" \u2014 Missing Counterparts", "")
                weakening_abs = tuple(
                    f"Detecting slug '{slug}' would suppress this absence signal" for slug in match.matched
                )
                records.append(
                    ExplanationRecord(
                        item_name=match.name,
                        item_type="signal",
                        matched_evidence=(),
                        fired_rules=(parent_name,),
                        confidence_derivation="Absence signal \u2014 expected counterparts not observed",
                        weakening_conditions=weakening_abs,
                        curated_explanation=match.description,
                    )
                )
                continue

            # Defensive: signal match without a definition — produce minimal record
            records.append(
                ExplanationRecord(
                    item_name=match.name,
                    item_type="signal",
                    matched_evidence=(),
                    fired_rules=(f"{match.name} (definition not found)",),
                    confidence_derivation=f"Signal confidence: {match.confidence}",
                    weakening_conditions=(),
                )
            )
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
                item_name=match.name,
                item_type="signal",
                matched_evidence=tuple(all_evidence),
                fired_rules=(fired_rule,),
                confidence_derivation=". ".join(derivation_parts),
                weakening_conditions=weakening,
                curated_explanation=sig.explain,
            )
        )

    return records


def explain_insights(
    insights: list[str],
    slugs: frozenset[str],
    services: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
    detection_scores: tuple[tuple[str, str], ...],
) -> list[ExplanationRecord]:
    """Generate ExplanationRecords for all generated insights.

    Maps each insight string back to the generator that likely produced it
    using keyword matching against known insight patterns. This is
    approximate — insights are free-form strings, so the mapping is
    best-effort.
    """
    records: list[ExplanationRecord] = []

    for insight in insights:
        lower = insight.lower()

        # Determine which slugs/services are relevant to this insight
        relevant_slugs: list[str] = []
        relevant_evidence: list[EvidenceRecord] = []
        fired_rules: list[str] = []
        confidence_parts: list[str] = []

        # Signal-generated insights have the pattern "SignalName: matched1, matched2"
        if ": " in insight and not lower.startswith(("email security", "dmarc", "no dmarc", "no dkim")):
            # Likely a signal insight — handled by explain_signals, but we
            # still produce a lightweight record for completeness.
            parts = insight.split(": ", 1)
            signal_name = parts[0]
            matched_str = parts[1] if len(parts) > 1 else ""
            matched_items = [s.strip() for s in matched_str.split(",") if s.strip()]
            for slug in matched_items:
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            fired_rules.append(f"Signal: {signal_name}")
            confidence_parts.append(f"Signal-generated insight referencing {len(relevant_slugs)} slug(s)")

        # Email security score insight
        elif lower.startswith("email security"):
            fired_rules.append("_email_security_insights")
            # Extract referenced components from the parenthetical
            for slug in slugs:
                if slug in lower:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            confidence_parts.append("Email security score derived from DMARC, DKIM, SPF, MTA-STS, BIMI presence")

        # Auth insights
        elif "federated" in lower or "cloud-managed" in lower or "entra id" in lower:
            fired_rules.append("_auth_insights")
            for slug in ("okta", "duo", "cisco-identity", "microsoft365"):
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            confidence_parts.append("Authentication type derived from identity provider detection")

        # Gateway insights
        elif "email gateway" in lower:
            fired_rules.append("_gateway_insights")
            _gw_slugs = (
                "proofpoint",
                "mimecast",
                "barracuda",
                "cisco-ironport",
                "cisco-email",
                "trendmicro",
                "symantec",
                "trellix",
            )
            for slug in _gw_slugs:
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            confidence_parts.append("Email gateway detected via DNS fingerprinting")

        # Security stack insights
        elif "security stack" in lower:
            fired_rules.append("_security_stack_insights")
            _sec_slugs = (
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
            )
            for slug in _sec_slugs:
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            confidence_parts.append("Security tools detected via DNS fingerprinting")

        # SASE insights
        elif "sase" in lower or "ztna" in lower:
            fired_rules.append("_sase_insights")
            for slug in ("zscaler", "netskope", "paloalto"):
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            confidence_parts.append("SASE/ZTNA provider detected via DNS fingerprinting")

        # Migration insights
        elif "dual provider" in lower or "coexistence" in lower:
            fired_rules.append("_migration_insights")
            for slug in ("google-workspace", "microsoft365"):
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            confidence_parts.append("Dual provider detected from simultaneous Google and Microsoft fingerprints")

        # Org size insights
        elif "domains" in lower and ("enterprise" in lower or "mid-size" in lower or "in tenant" in lower):
            fired_rules.append("_org_size_insights")
            confidence_parts.append("Organization size estimated from domain count and SPF complexity")

        # License insights
        elif "m365" in lower and ("e3" in lower or "e5" in lower or "proplus" in lower or "apps for" in lower):
            fired_rules.append("_license_insights")
            confidence_parts.append("License tier inferred from Intune enrollment and auth type")

        # MDM insights
        elif "dual mdm" in lower or "mac management" in lower:
            fired_rules.append("_mdm_insights")
            for slug in ("jamf", "kandji"):
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            confidence_parts.append("MDM detection from DNS fingerprinting")

        # PKI insights
        elif lower.startswith("pki:"):
            fired_rules.append("_pki_insights")
            _pki_slugs = ("letsencrypt", "digicert", "sectigo", "aws-acm", "google-trust", "globalsign")
            for slug in _pki_slugs:
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            confidence_parts.append("Certificate authority detected from CAA records")

        # Infrastructure insights
        elif lower.startswith("infrastructure:"):
            fired_rules.append("_infrastructure_insights")
            confidence_parts.append("Infrastructure providers detected from DNS records")

        # Google auth insights
        elif "google workspace" in lower and ("federated" in lower or "managed" in lower):
            fired_rules.append("_google_auth_insights")
            for slug in ("google-federated", "google-managed"):
                if slug in slugs:
                    relevant_slugs.append(slug)
                    relevant_evidence.extend(_evidence_for_slug(slug, evidence))
            confidence_parts.append("Google Workspace identity type detected")

        # Google modules insights
        elif "google workspace modules" in lower:
            fired_rules.append("_google_modules_insights")
            confidence_parts.append("Google Workspace modules detected from DNS records")

        # DMARC / DKIM standalone insights
        elif "dmarc" in lower or "dkim" in lower:
            fired_rules.append("_email_security_insights")
            confidence_parts.append("Email security observation from DNS records")

        # Conflicting tenant IDs
        elif "conflicting tenant" in lower:
            fired_rules.append("merge_results (conflict detection)")
            confidence_parts.append("Multiple distinct tenant IDs found across sources")

        # SPF complexity
        elif "large org signal" in lower:
            fired_rules.append("_org_size_insights")
            confidence_parts.append("Organization size estimated from SPF include count")

        else:
            # Unmapped insight — produce minimal record
            fired_rules.append("unknown generator")
            confidence_parts.append("Unmapped insight — generator could not be determined")

        # Add detection scores for relevant slugs
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
    successful = sum(1 for r in results if r.is_success)
    source_names = [r.source_name for r in results if r.is_success]

    # Evidence confidence derivation
    evidence_parts: list[str] = [
        f"Evidence confidence: {evidence_confidence.value}",
        f"{successful} successful source(s) (threshold: 3 for high, 2 for medium)",
        f"Contributing sources: {', '.join(source_names)}" if source_names else "No successful sources",
    ]

    # Inference confidence derivation
    has_tenant_id = any(r.tenant_id is not None for r in results)
    has_corroboration = any(
        r.is_success and r.source_name != "oidc_discovery" and (r.m365_detected or r.display_name or r.auth_type)
        for r in results
    )

    all_evidence: list[EvidenceRecord] = []
    for r in results:
        all_evidence.extend(r.evidence)
    source_types = {e.source_type for e in all_evidence}

    inference_parts: list[str] = [
        f"Inference confidence: {inference_confidence.value}",
    ]
    if has_tenant_id:
        inference_parts.append("Tenant ID present from at least one source")
    if has_corroboration:
        inference_parts.append("Corroborating data from independent source(s)")
    if len(source_types) >= 3:
        inference_parts.append(
            f"{len(source_types)} distinct evidence source types ({', '.join(sorted(source_types))})"
        )

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

    # Fired rules: list the source names
    fired_rules = tuple(f"Source: {r.source_name} ({'success' if r.is_success else 'failed'})" for r in results)

    # Weakening: note degraded sources
    weakening: list[str] = []
    for src in sorted(degraded):
        weakening.append(f"Source '{src}' was unavailable — its data could have changed the confidence assessment")

    return ExplanationRecord(
        item_name="Overall Confidence",
        item_type="confidence",
        matched_evidence=tuple(all_evidence),
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

    for obs in observations:
        # Find matching rule — observations don't carry the rule name directly,
        # so we match by checking which rule's template could have produced
        # this observation's statement. We use the rule name as a proxy by
        # looking at related_slugs overlap with rule.slugs_any.
        matched_rule: _PostureRule | None = None
        for rule in posture_rules:
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


def _evidence_node_id(ev: EvidenceRecord, idx: int) -> str:
    """Stable deterministic node id for an evidence record.

    Uses the (source_type, slug, rule_name, idx) tuple so two records
    with identical fields still get distinct ids when they co-occur.
    """
    return f"evidence:{ev.source_type}:{ev.slug}:{ev.rule_name}:{idx}"


def _slug_node_id(slug: str) -> str:
    return f"slug:{slug}"


def _rule_node_id(rule: str) -> str:
    return f"rule:{rule}"


def _item_node_id(item_type: str, name: str) -> str:
    return f"{item_type}:{name}"


def build_explanation_dag(
    records: list[ExplanationRecord],
    all_evidence: tuple[EvidenceRecord, ...] = (),
) -> dict[str, Any]:
    """Build a JSON-serialisable provenance DAG from ExplanationRecords.

    v0.9.3. Node types:
        * ``evidence``  — one node per raw EvidenceRecord
        * ``slug``      — one node per detected fingerprint slug
        * ``rule``      — one node per fingerprint / signal rule
                          that fired
        * ``signal``    — one node per fired signal (incl. absence
                          and hardening observations)
        * ``insight``   — one node per generated insight string
        * ``observation`` — one node per posture observation
        * ``confidence`` — the overall confidence node (singleton)

    Edge types:
        * ``detected-by``        — evidence → slug
        * ``matched-rule``       — evidence → rule
        * ``contributes-to``     — slug → signal | insight |
                                   observation | confidence
        * ``synthesized-into``   — signal → insight | observation
        * ``weakened-by``        — label-only attribute (no outgoing
                                   edge); each weakening condition
                                   hangs off the item node as metadata

    Invariants
        * Every terminal node (``signal``, ``insight``,
          ``observation``, ``confidence``) must be reachable from at
          least one ``evidence`` node via a path of length ≤ 3.
        * Every node carries ``item_type`` equal to its category,
          ``name`` equal to a human-readable label, and, when
          relevant, ``confidence_derivation`` and ``weakening``.
        * The DAG is acyclic: edges only flow from evidence →
          slug/rule → signal → insight/observation → confidence.

    The DAG is additive — the existing flat ``explanations`` list is
    still emitted alongside it for callers that prefer the old shape.
    Downstream tooling can pick whichever view fits.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    # Step 1: seed with every evidence record, regardless of whether
    # an explanation record references it. This ensures the DAG's
    # "every terminal reachable from evidence" invariant holds even
    # for terminal nodes whose explanation records failed to pin
    # down specific evidence.
    for idx, ev in enumerate(all_evidence):
        eid = _evidence_node_id(ev, idx)
        if eid in nodes:
            continue
        nodes[eid] = {
            "id": eid,
            "type": "evidence",
            "name": f"{ev.source_type}: {ev.rule_name}",
            "source_type": ev.source_type,
            "raw_value": ev.raw_value,
            "rule_name": ev.rule_name,
            "slug": ev.slug,
        }
        # evidence → slug edge
        sid = _slug_node_id(ev.slug)
        if sid not in nodes:
            nodes[sid] = {"id": sid, "type": "slug", "name": ev.slug}
        edges.append({"source": eid, "target": sid, "relation": "detected-by"})

    # Step 2: add one node per ExplanationRecord and link the evidence
    # it cites to it. For signal records, link via the slug node too
    # so the DAG walker can walk evidence → slug → signal either way.
    for rec in records:
        item_id = _item_node_id(rec.item_type, rec.item_name)
        # If a signal and an observation happen to share the same
        # name, distinguish them by item_type in the id.
        nodes[item_id] = {
            "id": item_id,
            "type": rec.item_type,
            "name": rec.item_name,
            "confidence_derivation": rec.confidence_derivation,
            "weakening_conditions": list(rec.weakening_conditions),
            "curated_explanation": rec.curated_explanation,
        }

        # Attach each fired_rules entry as its own node so the DAG
        # can show which rules contributed. Link evidence → rule →
        # item where possible.
        for rule in rec.fired_rules:
            rid = _rule_node_id(rule)
            if rid not in nodes:
                nodes[rid] = {"id": rid, "type": "rule", "name": rule}
            edges.append({"source": rid, "target": item_id, "relation": "fired"})

        # For each cited evidence, add (evidence) → slug → item via
        # contributes-to. If the evidence is also in all_evidence we
        # already seeded it; otherwise seed it now.
        for eidx, ev in enumerate(rec.matched_evidence):
            eid = _evidence_node_id(ev, eidx)
            if eid not in nodes:
                nodes[eid] = {
                    "id": eid,
                    "type": "evidence",
                    "name": f"{ev.source_type}: {ev.rule_name}",
                    "source_type": ev.source_type,
                    "raw_value": ev.raw_value,
                    "rule_name": ev.rule_name,
                    "slug": ev.slug,
                }
            sid = _slug_node_id(ev.slug)
            if sid not in nodes:
                nodes[sid] = {"id": sid, "type": "slug", "name": ev.slug}
            # evidence → slug (may already exist from step 1)
            edges.append({"source": eid, "target": sid, "relation": "detected-by"})
            # slug → item
            edges.append({"source": sid, "target": item_id, "relation": "contributes-to"})

    # Deduplicate edges while preserving order
    seen_edges: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for e in edges:
        key = (e["source"], e["target"], e["relation"])
        if key in seen_edges:
            continue
        seen_edges.add(key)
        deduped.append(e)

    return {
        "nodes": list(nodes.values()),
        "edges": deduped,
        "schema_version": 1,
    }
