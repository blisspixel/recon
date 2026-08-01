"""Exact and compatibility explanation records for generated insights."""

from __future__ import annotations

from collections.abc import Callable

from recon_tool.insight_explanation import (
    InsightExplanationContext,
    normalize_insight_explanation_context,
    take_exact_insight_explanation,
)
from recon_tool.models import EvidenceRecord, ExplanationLineageStatus, ExplanationRecord
from recon_tool.signals import load_signals, signal_rule_names_from_observation

InsightClassification = tuple[list[str], list[EvidenceRecord], list[str], list[str]]

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
    # Removed generator formats remain classifiable for raw-cache diagnostics.
    "email gateway:",
    "security stack:",
    "sase/ztna:",
    "dual provider:",
    "dual mdm:",
    "google workspace modules:",
)


# Post-generation compatibility classification. The first predicate wins.
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


def _evidence_for_slug(slug: str, evidence: tuple[EvidenceRecord, ...]) -> tuple[EvidenceRecord, ...]:
    return tuple(item for item in evidence if item.slug == slug)


def _score_for_slug(slug: str, scores: tuple[tuple[str, str], ...]) -> str:
    return next((score for candidate, score in scores if candidate == slug), "unknown")


def _evidence_for_insight_rule(
    rule: str,
    slug: str,
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[EvidenceRecord, ...]:
    matched = _evidence_for_slug(slug, evidence)
    if rule == "_gateway_insights":
        return tuple(item for item in matched if item.source_type.upper() == "MX")
    return matched


def _classify_structured_slug_insight(
    insight: str,
    slugs: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
) -> InsightClassification | None:
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


def _classify_signal_generated_insight(
    rule_names: tuple[str, ...],
    slugs: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
) -> InsightClassification:
    """Reconstruct a displayed declarative-signal insight from catalog rules."""
    relevant_slugs: list[str] = []
    relevant_evidence: list[EvidenceRecord] = []
    fired_rules: list[str] = []
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
    note = f"Signal-generated insight referencing {len(relevant_slugs)} slug(s)"
    return relevant_slugs, relevant_evidence, fired_rules, [note]


def _classify_email_security_insight(
    lower: str,
    slugs: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
) -> InsightClassification:
    """Reconstruct the legacy email-control inventory association."""
    relevant_slugs = [slug for slug in sorted(slugs) if slug in lower]
    relevant_evidence = [item for slug in relevant_slugs for item in _evidence_for_slug(slug, evidence)]
    return (
        relevant_slugs,
        relevant_evidence,
        ["_email_security_insights"],
        ["Email control count derived from observed DMARC, DKIM, SPF, MTA-STS, BIMI presence"],
    )


def _classify_compatibility_rule(
    lower: str,
    slugs: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
) -> InsightClassification | None:
    """Return the first matching bounded legacy-classifier association."""
    for predicate, rule, candidate_slugs, note in _INSIGHT_RULES:
        if not predicate(lower):
            continue
        relevant_slugs = [slug for slug in candidate_slugs if slug in slugs]
        relevant_evidence = [
            item for slug in relevant_slugs for item in _evidence_for_insight_rule(rule, slug, evidence)
        ]
        return relevant_slugs, relevant_evidence, [rule], [note]
    return None


def _classify_insight(
    insight: str,
    slugs: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
) -> InsightClassification:
    """Reconstruct a legacy insight association without presenting it as exact."""
    lower = insight.lower()

    rule_names = signal_rule_names_from_observation(insight)
    if rule_names and not lower.startswith(_GENERATOR_OWNED_INSIGHT_PREFIXES):
        return _classify_signal_generated_insight(rule_names, slugs, evidence)

    structured = _classify_structured_slug_insight(insight, slugs, evidence)
    if structured is not None:
        return structured

    if lower.startswith("email security"):
        return _classify_email_security_insight(lower, slugs, evidence)

    classified = _classify_compatibility_rule(lower, slugs, evidence)
    return classified or ([], [], ["unknown generator"], ["Unmapped insight; generator unavailable"])


def explain_insights(
    insights: list[str],
    slugs: frozenset[str],
    services: frozenset[str],
    evidence: tuple[EvidenceRecord, ...],
    detection_scores: tuple[tuple[str, str], ...] | InsightExplanationContext,
) -> list[ExplanationRecord]:
    """Explain current exact claims and label every compatibility path."""
    records: list[ExplanationRecord] = []
    detection_scores, unmatched_claims = normalize_insight_explanation_context(detection_scores)
    for insight in insights:
        exact_record = take_exact_insight_explanation(insight, unmatched_claims)
        if exact_record is not None:
            records.append(exact_record)
            continue

        relevant_slugs, relevant_evidence, fired_rules, confidence_parts = _classify_insight(insight, slugs, evidence)
        for slug in relevant_slugs:
            score = _score_for_slug(slug, detection_scores)
            confidence_parts.append(f"Slug '{slug}' detection score: '{score}'")
        status = (
            ExplanationLineageStatus.UNSUPPORTED
            if fired_rules == ["unknown generator"]
            else ExplanationLineageStatus.RECONSTRUCTED
        )
        records.append(
            ExplanationRecord(
                item_name=insight,
                item_type="insight",
                matched_evidence=tuple(relevant_evidence),
                fired_rules=tuple(fired_rules),
                confidence_derivation=". ".join(confidence_parts) if confidence_parts else "No derivation available",
                weakening_conditions=(),
                lineage_status=status,
            )
        )
    return records
