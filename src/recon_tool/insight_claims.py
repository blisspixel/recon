"""Branch-local provenance primitives for generated insight text."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from recon_tool.models import EvidenceRecord


class InsightEvidenceContext(Protocol):
    """Minimum generator context needed by evidence-selection helpers."""

    @property
    def services(self) -> frozenset[str]: ...

    @property
    def slugs(self) -> frozenset[str]: ...

    @property
    def evidence(self) -> tuple[EvidenceRecord, ...]: ...

    @property
    def evidence_bound(self) -> bool: ...


class GeneratedInsight(str):
    """Rendered insight plus the lineage captured by its emitting branch.

    The ``str`` base preserves the small, independently testable generator
    contract. Claim assembly reads the attached immutable metadata instead of
    reconstructing dependencies from the rendered sentence.
    """

    supporting_evidence: tuple[EvidenceRecord, ...]
    observation_scope: tuple[str, ...]
    allows_scope_only: bool

    def __new__(
        cls,
        text: str,
        *,
        supporting_evidence: Iterable[EvidenceRecord] = (),
        observation_scope: tuple[str, ...] = (),
        allows_scope_only: bool = False,
    ) -> GeneratedInsight:
        instance = super().__new__(cls, text)
        instance.supporting_evidence = tuple(supporting_evidence)
        instance.observation_scope = observation_scope
        instance.allows_scope_only = allows_scope_only
        return instance


def claim_text(
    text: str,
    *,
    evidence: Iterable[EvidenceRecord] = (),
    scope: tuple[str, ...],
    allows_scope_only: bool = False,
) -> GeneratedInsight:
    """Create one generator result with its branch-local dependencies."""
    return GeneratedInsight(
        text,
        supporting_evidence=evidence,
        observation_scope=scope,
        allows_scope_only=allows_scope_only,
    )


def evidence_for_slugs(
    ctx: InsightEvidenceContext,
    slugs: frozenset[str],
    *,
    source_types: frozenset[str] | None = None,
) -> tuple[EvidenceRecord, ...]:
    """Select retained evidence occurrences for the requested active slugs."""
    return tuple(
        record
        for record in ctx.evidence
        if record.slug in slugs and (source_types is None or record.source_type.upper() in source_types)
    )


def evidence_for_rule_names(
    ctx: InsightEvidenceContext,
    rule_names: frozenset[str],
) -> tuple[EvidenceRecord, ...]:
    """Select retained evidence occurrences by their claim-safe rule names."""
    normalized = {name.casefold() for name in rule_names}
    return tuple(record for record in ctx.evidence if record.rule_name.casefold() in normalized)


def evidence_for_source_types(
    ctx: InsightEvidenceContext,
    source_types: frozenset[str],
) -> tuple[EvidenceRecord, ...]:
    """Select retained occurrences from the source families a branch read."""
    return tuple(record for record in ctx.evidence if record.source_type.upper() in source_types)


def combine_evidence(
    ctx: InsightEvidenceContext,
    *groups: Iterable[EvidenceRecord],
) -> tuple[EvidenceRecord, ...]:
    """Union selected occurrences in canonical retained-evidence order."""
    selected = {record for group in groups for record in group}
    return tuple(record for record in ctx.evidence if record in selected)


def claimable_slugs(ctx: InsightEvidenceContext, candidates: frozenset[str]) -> frozenset[str]:
    """Keep catalog inputs attributable to this context's retained evidence.

    Empty-evidence contexts remain useful for direct generator unit tests, but
    runtime contexts are explicitly evidence-bound even when they retained no
    occurrences. In an evidence-bound context, a slug without a matching
    occurrence is unscoped inventory, such as related-domain enrichment, and
    cannot affect rendered claim text.
    """
    active = ctx.slugs & candidates
    if not ctx.evidence and not ctx.evidence_bound:
        return active
    evidenced = {record.slug for record in ctx.evidence}
    return frozenset(slug for slug in active if slug in evidenced)


def claimable_services(ctx: InsightEvidenceContext, candidates: frozenset[str]) -> frozenset[str]:
    """Keep service inputs whose exact role-named occurrence is retained."""
    active = ctx.services & candidates
    if not ctx.evidence and not ctx.evidence_bound:
        return active
    evidenced = {record.rule_name.casefold() for record in ctx.evidence}
    return frozenset(service for service in active if service.casefold() in evidenced)
