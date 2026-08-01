"""Structured projection for exact public-evidence comparisons."""

from __future__ import annotations

import json
from typing import Any

from recon_tool.exposure_models import ExposureIndex, PostureComparison
from recon_tool.formatter.exposure import format_index_observability


def format_comparison_dict(comparison: PostureComparison) -> dict[str, Any]:
    """Format a comparison with each namespace's exact index ledger."""
    payload: dict[str, Any] = {
        "domain_a": comparison.domain_a,
        "domain_b": comparison.domain_b,
        "metrics": [
            {
                "metric_name": metric.metric_name,
                "domain_a_value": metric.domain_a_value,
                "domain_b_value": metric.domain_b_value,
            }
            for metric in comparison.metrics
        ],
        "differences": [
            {
                "description": difference.description,
                "domain_a_has": difference.domain_a_has,
                "domain_b_has": difference.domain_b_has,
            }
            for difference in comparison.differences
        ],
        "relative_assessment": [
            {
                "dimension": assessment.dimension,
                "summary": assessment.summary,
            }
            for assessment in comparison.relative_assessment
        ],
        "disclaimer": comparison.disclaimer,
    }
    if comparison.domain_a_index_components and comparison.domain_b_index_components:
        payload["domain_a_observability"] = format_index_observability(
            ExposureIndex(comparison.domain_a_index_components),
            comparison.domain_a_unavailable_controls,
        )
        payload["domain_b_observability"] = format_index_observability(
            ExposureIndex(comparison.domain_b_index_components),
            comparison.domain_b_unavailable_controls,
        )
    return payload


def format_comparison_json(comparison: PostureComparison) -> str:
    """Format a comparison as deterministic indented JSON."""
    return json.dumps(format_comparison_dict(comparison), indent=2)


__all__ = ["format_comparison_dict", "format_comparison_json"]
