"""Bounded sparse-signal observations and their generation-time lineage."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from recon_tool.insight_claims import (
    InsightEvidenceContext,
    claim_text,
    claimable_services,
    claimable_slugs,
    evidence_for_rule_names,
    evidence_for_source_types,
)
from recon_tool.models import EvidenceRecord

_NON_SUBSTANTIVE_PREFIXES = ("SPF complexity:",)
_EDGE_SERVICE_PREFIXES = ("DNS:", "CDN:", "WAF:")
_DOC_HINT = (
    "Next step: see docs/weak-areas.md for passive-only blind spots. "
    "For an operator-supplied domain set, run `recon batch <candidates.txt>`; "
    "for bounded related-host discovery, run `recon <domain> --chain --depth 2`."
)


class SparseInsightContext(InsightEvidenceContext, Protocol):
    """State consumed by the bounded sparse-result classifier."""

    @property
    def auth_type(self) -> str | None: ...

    @property
    def google_auth_type(self) -> str | None: ...

    @property
    def has_mx_records(self) -> bool: ...

    @property
    def primary_email_provider(self) -> str | None: ...

    @property
    def likely_primary_email_provider(self) -> str | None: ...

    @property
    def email_gateway(self) -> str | None: ...

    @property
    def role_scoped_services(self) -> frozenset[str]: ...


def _substantive_services(ctx: SparseInsightContext) -> list[str]:
    evidenced = claimable_services(ctx, frozenset(ctx.services))
    return [service for service in evidenced if not service.startswith(_NON_SUBSTANTIVE_PREFIXES)]


def _edge_services(ctx: SparseInsightContext) -> list[str]:
    """Return distinct, role-established edge-layer providers."""
    found: list[str] = []
    for service in sorted(ctx.role_scoped_services):
        if not service.startswith(_EDGE_SERVICE_PREFIXES):
            continue
        _, _, provider = service.partition(": ")
        if provider and provider not in found:
            found.append(provider)
    return found


def _guidance(
    ctx: SparseInsightContext,
    *,
    evidence: Iterable[EvidenceRecord] = (),
) -> str:
    return claim_text(
        _DOC_HINT,
        evidence=evidence,
        scope=("public_metadata:bounded_collection",),
        allows_scope_only=True,
    )


def sparse_signal_insights(ctx: SparseInsightContext) -> list[str]:
    """Explain thin public evidence without inferring why it is sparse."""
    substantive = _substantive_services(ctx)
    if len(substantive) >= 5:
        return []
    if ctx.auth_type in ("Federated", "Managed") and claimable_slugs(ctx, frozenset({"microsoft365"})):
        return []

    edge = _edge_services(ctx)
    claimable_mail_slugs = claimable_slugs(ctx, frozenset({"null-mx", "self-hosted-mail", "exchange-onprem"}))
    has_unclassified_mail = (
        ctx.has_mx_records
        and "null-mx" not in claimable_mail_slugs
        and (
            "self-hosted-mail" in claimable_mail_slugs
            or "exchange-onprem" in claimable_mail_slugs
            or (
                ctx.primary_email_provider is None
                and ctx.likely_primary_email_provider is None
                and ctx.email_gateway is None
            )
        )
    )
    if has_unclassified_mail:
        mx_evidence = evidence_for_source_types(ctx, frozenset({"MX"}))
        return [
            claim_text(
                "Sparse public signal: custom or unclassified MX. MX records exist, "
                "but the public evidence does not identify their operator or hosting "
                "model. Observation, not a verdict.",
                evidence=mx_evidence,
                scope=("dns:mx", "public_metadata:bounded_collection"),
                allows_scope_only=True,
            ),
            _guidance(ctx, evidence=mx_evidence),
        ]

    if edge and len(substantive) <= 3:
        visible_edge = ", ".join(edge[:2])
        if len(edge) > 2:
            visible_edge = f"{visible_edge}, and other edge services"
        edge_services = frozenset(
            service for service in ctx.role_scoped_services if service.startswith(_EDGE_SERVICE_PREFIXES)
        )
        edge_evidence = evidence_for_rule_names(ctx, edge_services)
        return [
            claim_text(
                f"Sparse public signal — edge-heavy footprint. {visible_edge} sits "
                "in front of the apex, which can hide origin and SaaS detail from "
                "passive public-source collection. Observation, not a verdict.",
                evidence=edge_evidence,
                scope=("dns:bounded_service_records", "public_metadata:bounded_collection"),
            ),
            _guidance(ctx, evidence=edge_evidence),
        ]

    if (
        not ctx.has_mx_records
        and ctx.auth_type is None
        and ctx.google_auth_type is None
        and not edge
        and len(substantive) <= 2
    ):
        return [
            claim_text(
                "Sparse public signal — minimal public DNS footprint. Very little is "
                "exposed beyond basic records, which is consistent with a "
                "web-only property, a parked or dormant domain, or services hosted "
                "on a different apex. Observation, not a verdict.",
                scope=("public_metadata:bounded_collection",),
                allows_scope_only=True,
            ),
            _guidance(ctx),
        ]

    return [
        claim_text(
            "Sparse public signal — few observable records beyond MX and "
            "identity. Consistent with a parked or dormant domain, a heavily "
            "proxied namespace, or services hosted on a different apex. "
            "Observation, not a verdict.",
            evidence=ctx.evidence,
            scope=("public_metadata:bounded_collection",),
            allows_scope_only=True,
        ),
        _guidance(ctx, evidence=ctx.evidence),
    ]
