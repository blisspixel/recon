"""Apply the Bayesian fusion layer onto a collected ``TenantInfo``.

Shared by the CLI and the MCP server so both populate ``slug_confidences`` and
``posterior_observations`` the same way. It was private to ``cli.lookup``, which
left the MCP JSON payload advertising those fields (the TypedDict and
``docs/mcp.md`` name them) while always emitting an empty list. Pure and
deterministic over an existing ``TenantInfo``: no network, no shared state, so it
is safe on the MCP worker thread.
"""

from __future__ import annotations

from dataclasses import replace

from recon_tool.models import TenantInfo


def apply_fusion(info: TenantInfo) -> TenantInfo:
    """Recompute slug posteriors and Bayesian marginals onto ``info``.

    Returns a copy with ``slug_confidences`` and ``posterior_observations``
    populated. Deterministic over the existing record, so it runs on both cache
    hits and misses.
    """
    from recon_tool.bayesian import infer_from_tenant_info
    from recon_tool.collection_view import collection_observable_evidence
    from recon_tool.fusion import compute_slug_posteriors
    from recon_tool.models import NodeConflict, NodeEvidence, NodeUnitCounterfactual, PosteriorObservation

    bayesian_result = infer_from_tenant_info(info)
    bayesian_observations = tuple(
        PosteriorObservation(
            name=p.name,
            description=p.description,
            posterior=p.posterior,
            interval_low=p.interval_low,
            interval_high=p.interval_high,
            evidence_used=p.evidence_used,
            n_eff=p.n_eff,
            sparse=p.sparse,
            conflict_provenance=tuple(
                NodeConflict(field=c.field, sources=c.sources, magnitude=c.magnitude) for c in p.conflict_provenance
            ),
            evidence_ranked=tuple(
                NodeEvidence(
                    kind=e.kind,
                    name=e.name,
                    llr=e.llr,
                    influence_pct=e.influence_pct,
                )
                for e in p.evidence_ranked
            ),
            entropy_reduction_nats=p.entropy_reduction_nats,
            unit_counterfactuals=tuple(
                NodeUnitCounterfactual(
                    unit=c.unit,
                    kind=c.kind,
                    observed=c.observed,
                    posterior_without=c.posterior_without,
                    delta=c.delta,
                )
                for c in p.unit_counterfactuals
            ),
        )
        for p in bayesian_result.posteriors
    )
    return replace(
        info,
        slug_confidences=compute_slug_posteriors(collection_observable_evidence(info)),
        posterior_observations=bayesian_observations,
    )
