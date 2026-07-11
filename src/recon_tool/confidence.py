"""Deterministic confidence scoring and claim-level inference provenance."""

from __future__ import annotations

from typing import Literal, NamedTuple

from recon_tool.merger_tables import VARIANT_SLUG_PARENTS
from recon_tool.models import ConfidenceLevel, EvidenceRecord, SourceResult

InferenceRule = Literal[
    "insufficient_corroboration",
    "no_claim",
    "oidc_corroboration",
    "repeated_tenant_id",
    "three_record_types",
    "two_record_types",
    "two_sources",
]


class InferenceConfidenceBasis(NamedTuple):
    """The exact claim and observations that determine inference confidence."""

    level: ConfidenceLevel
    claim: str | None
    source_types: tuple[str, ...]
    sources: tuple[str, ...]
    evidence: tuple[EvidenceRecord, ...]
    rule: InferenceRule


_INFERENCE_CLAIM_PARENTS = {slug: parent for slug, parent in VARIANT_SLUG_PARENTS.items() if slug != "google-site"} | {
    "google-cse": "google-workspace",
    "microsoft365-gov": "microsoft365",
}


def minimum_confidence(a: ConfidenceLevel, b: ConfidenceLevel) -> ConfidenceLevel:
    """Return the lower of two confidence levels."""
    order = {ConfidenceLevel.HIGH: 2, ConfidenceLevel.MEDIUM: 1, ConfidenceLevel.LOW: 0}
    return a if order[a] <= order[b] else b


def is_confidence_contributor(result: SourceResult) -> bool:
    """Return whether a source supplied useful data without a source-level error."""
    return result.error is None and result.is_success


def confidence_contributors(results: list[SourceResult]) -> tuple[SourceResult, ...]:
    """Return error-free results that contain useful data."""
    return tuple(result for result in results if is_confidence_contributor(result))


def confidence_source_names(results: list[SourceResult]) -> tuple[str, ...]:
    """Return distinct contributing source names in first-observed order."""
    return tuple(dict.fromkeys(result.source_name for result in confidence_contributors(results)))


def compute_evidence_confidence(results: list[SourceResult]) -> ConfidenceLevel:
    """Compute evidence confidence from distinct, error-free source names."""
    successful = len(confidence_source_names(results))
    if successful >= 3:
        return ConfidenceLevel.HIGH
    if successful >= 2:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def _canonical_claim(slug: str) -> str:
    return _INFERENCE_CLAIM_PARENTS.get(slug, slug)


def _inference_claims(result: SourceResult) -> set[str]:
    slugs = set(result.detected_slugs) | {evidence.slug for evidence in result.evidence}
    if result.m365_detected or (result.source_name == "oidc_discovery" and result.tenant_id):
        slugs.add("microsoft365")
    return {_canonical_claim(slug) for raw_slug in slugs if (slug := raw_slug.strip())}


def _select_claim(
    candidates: set[str],
    claim_types: dict[str, set[str]],
    claim_sources: dict[str, set[str]],
) -> str:
    """Select the richest qualifying claim with a stable lexical tie-break."""
    return min(
        candidates,
        key=lambda claim: (-len(claim_types.get(claim, set())), -len(claim_sources.get(claim, set())), claim),
    )


def _claim_basis(
    level: ConfidenceLevel,
    claim: str,
    rule: InferenceRule,
    claim_types: dict[str, set[str]],
    claim_sources: dict[str, set[str]],
    claim_evidence: dict[str, list[EvidenceRecord]],
) -> InferenceConfidenceBasis:
    return InferenceConfidenceBasis(
        level=level,
        claim=claim,
        source_types=tuple(sorted(claim_types.get(claim, set()))),
        sources=tuple(sorted(claim_sources.get(claim, set()))),
        evidence=tuple(dict.fromkeys(claim_evidence.get(claim, ()))),
        rule=rule,
    )


def inference_confidence_basis(results: list[SourceResult]) -> InferenceConfidenceBasis:
    """Derive inference confidence and the exact canonical claim that sets it."""
    contributors = confidence_contributors(results)
    claim_types: dict[str, set[str]] = {}
    claim_sources: dict[str, set[str]] = {}
    claim_evidence: dict[str, list[EvidenceRecord]] = {}
    tenant_sources: dict[str, set[str]] = {}
    tenant_evidence: dict[str, list[EvidenceRecord]] = {}

    for result in contributors:
        for claim in _inference_claims(result):
            claim_sources.setdefault(claim, set()).add(result.source_name)
        if result.tenant_id:
            tenant_sources.setdefault(result.tenant_id, set()).add(result.source_name)
            tenant_evidence.setdefault(result.tenant_id, []).extend(
                evidence
                for evidence in result.evidence
                if evidence.slug.strip()
                and _canonical_claim(evidence.slug.strip()) == "microsoft365"
                and result.tenant_id in evidence.raw_value
            )
        for evidence in result.evidence:
            if not (slug := evidence.slug.strip()):
                continue
            claim = _canonical_claim(slug)
            claim_evidence.setdefault(claim, []).append(evidence)
            if source_type := evidence.source_type.strip().upper():
                claim_types.setdefault(claim, set()).add(source_type)

    m365_sources = claim_sources.get("microsoft365", set())
    has_oidc_tenant = any(result.source_name == "oidc_discovery" and result.tenant_id for result in contributors)
    if has_oidc_tenant and m365_sources - {"oidc_discovery"}:
        return _claim_basis(
            ConfidenceLevel.HIGH,
            "microsoft365",
            "oidc_corroboration",
            claim_types,
            claim_sources,
            claim_evidence,
        )

    high_claims = {claim for claim, source_types in claim_types.items() if len(source_types) >= 3}
    if high_claims:
        claim = _select_claim(high_claims, claim_types, claim_sources)
        return _claim_basis(
            ConfidenceLevel.HIGH,
            claim,
            "three_record_types",
            claim_types,
            claim_sources,
            claim_evidence,
        )

    medium_claims = {
        claim
        for claim in set(claim_sources) | set(claim_types)
        if len(claim_types.get(claim, set())) >= 2 or len(claim_sources.get(claim, set())) >= 2
    }
    if medium_claims:
        claim = _select_claim(medium_claims, claim_types, claim_sources)
        rule = "two_record_types" if len(claim_types.get(claim, set())) >= 2 else "two_sources"
        return _claim_basis(
            ConfidenceLevel.MEDIUM,
            claim,
            rule,
            claim_types,
            claim_sources,
            claim_evidence,
        )

    repeated_tenants = {tenant_id for tenant_id, sources in tenant_sources.items() if len(sources) >= 2}
    if repeated_tenants:
        tenant_id = min(repeated_tenants, key=lambda value: (-len(tenant_sources[value]), value))
        return InferenceConfidenceBasis(
            level=ConfidenceLevel.MEDIUM,
            claim="tenant-id",
            source_types=(),
            sources=tuple(sorted(tenant_sources[tenant_id])),
            evidence=tuple(dict.fromkeys(tenant_evidence.get(tenant_id, ()))),
            rule="repeated_tenant_id",
        )

    all_claims = set(claim_sources) | set(claim_types)
    if all_claims:
        claim = _select_claim(all_claims, claim_types, claim_sources)
        return _claim_basis(
            ConfidenceLevel.LOW,
            claim,
            "insufficient_corroboration",
            claim_types,
            claim_sources,
            claim_evidence,
        )
    return InferenceConfidenceBasis(ConfidenceLevel.LOW, None, (), (), (), "no_claim")


def compute_inference_confidence(results: list[SourceResult]) -> ConfidenceLevel:
    """Measure the strongest error-free, same-claim corroboration chain."""
    return inference_confidence_basis(results).level


def compute_confidence(results: list[SourceResult]) -> tuple[ConfidenceLevel, bool]:
    """Compute base confidence and whether error-free tenant IDs conflict."""
    contributors = confidence_contributors(results)
    tenant_ids = [result.tenant_id for result in contributors if result.tenant_id is not None]

    if tenant_ids:
        if len(set(tenant_ids)) > 1:
            return ConfidenceLevel.LOW, True
        tenant_id_sources = {result.source_name for result in contributors if result.tenant_id is not None}
        corroborating = [
            result
            for result in contributors
            if result.source_name not in tenant_id_sources and "microsoft365" in _inference_claims(result)
        ]
        if corroborating or len(tenant_id_sources) >= 2:
            return ConfidenceLevel.HIGH, False
        return ConfidenceLevel.MEDIUM, False

    services = {service for result in contributors for service in result.detected_services}
    successful_sources = len({result.source_name for result in contributors})
    if len(services) >= 8 and successful_sources >= 2:
        return ConfidenceLevel.HIGH, False
    if len(services) >= 3 or successful_sources >= 2:
        return ConfidenceLevel.MEDIUM, False
    return ConfidenceLevel.LOW, False
