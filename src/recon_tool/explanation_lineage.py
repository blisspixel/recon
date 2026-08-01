"""Shared labels and predicates for explanation-lineage diagnostics."""

from __future__ import annotations

from recon_tool.models import ExplanationLineageStatus

_LINEAGE_LABELS = {
    ExplanationLineageStatus.EXACT: "Exact generation-time evidence and rule association",
    ExplanationLineageStatus.EXACT_RULE_ONLY: ("Exact generation-time rule; complete evidence association unavailable"),
    ExplanationLineageStatus.RECONSTRUCTED: "Reconstructed after generation; not exact provenance",
    ExplanationLineageStatus.UNSUPPORTED: "Generator association unavailable",
}


def explanation_lineage_label(status: ExplanationLineageStatus) -> str:
    """Return the stable human-readable qualification for one terminal."""
    return _LINEAGE_LABELS[status]
