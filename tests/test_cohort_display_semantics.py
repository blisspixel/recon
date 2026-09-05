"""Human units and method labels must agree with unchanged cohort values."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from recon_tool.cohort_summary import build_summary_document, render_cohort_summary, wilson_interval


def _model_row(sparse: bool) -> dict[str, Any]:
    return {
        "posterior_observations": [
            {
                "name": "m365_tenant",
                "posterior": 0.9,
                "interval_low": 0.8,
                "interval_high": 0.95,
                "sparse": sparse,
                "evidence_used": ["synthetic-routing-record"],
            },
        ],
    }


def test_panel_labels_each_statistic_without_changing_denominators_or_values() -> None:
    rows = [
        {**_model_row(False), "mta_sts_mode": "enforce"},
        {**_model_row(True), "mta_sts_mode": "none"},
        {"degraded_sources": ["dns:mta_sts"]},
        {},
    ]
    document = build_summary_document(rows, schema_version="2.2")
    original = copy.deepcopy(document)
    public_rate = document["prevalence"]["mta_sts_enforce"]
    model_support = document["prevalence"]["m365_tenant"]
    assert public_rate["observable_n"] == 2
    assert public_rate["observed_rate"] == 0.5
    assert public_rate["observed_rate_interval_80"] == [round(endpoint, 4) for endpoint in wilson_interval(1, 2)]
    assert public_rate["observability_fraction"] == 0.5
    assert model_support["support_coverage"] == 0.25
    assert model_support["model_evidence_n"] == 1
    assert document["observability"]["mean_sparse_share"] == 0.5

    text = str(render_cohort_summary(document).renderable)
    assert "25% model support coverage" in text
    assert "mean sparse share 50%" in text
    assert "50% [16%-84%], seen for 50%" in text
    assert "80% Wilson score intervals under a binomial model" in text
    assert "Rates use eligible rows" in text
    assert "Model support uses all resolved rows" in text
    assert "among rows with model output" in text
    assert "Independence and population coverage are not established" in text
    assert document == original


@pytest.mark.parametrize(
    ("rows", "expected_support", "raw_support"),
    [([], "n/a model support coverage", None), ([{}], "0% model support coverage (no model-supported claims)", 0.0)],
)
def test_empty_and_zero_support_are_visually_distinct(
    rows: list[dict[str, Any]], expected_support: str, raw_support: float | None
) -> None:
    document = build_summary_document(rows, schema_version="2.2")
    original = copy.deepcopy(document)
    assert document["prevalence"]["m365_tenant"]["support_coverage"] == raw_support
    assert document["observability"]["mean_sparse_share"] is None
    text = str(render_cohort_summary(document).renderable)
    assert expected_support in text
    assert "mean sparse share n/a" in text
    assert "mean sparse share None" not in text
    assert document == original
