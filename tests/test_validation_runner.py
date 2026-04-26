from __future__ import annotations

from recon_tool.validation_runner import (
    compare_batch_results,
    compare_batch_summaries,
    render_summary_markdown,
    summarize_batch_results,
)


def _sample_results() -> list[dict[str, object]]:
    return [
        {
            "queried_domain": "alpha.com",
            "provider": "Microsoft 365",
            "confidence": "high",
            "services": ["Microsoft 365", "DMARC"],
            "slugs": ["microsoft365", "dmarc"],
            "insights": [
                "Email security: DMARC quarantine",
                "Sparse public signal — minimal public DNS footprint.",
            ],
            "degraded_sources": [],
            "partial": False,
        },
        {
            "queried_domain": "beta.com",
            "provider": "Google Workspace",
            "confidence": "medium",
            "services": ["Google Workspace"],
            "slugs": ["google-workspace"],
            "insights": [
                "Google-native identity indicators",
                "Sparse public signal — edge-heavy footprint.",
            ],
            "degraded_sources": ["crt.sh"],
            "partial": True,
        },
        {
            "domain": "gamma.com",
            "error": "No information found for gamma.com",
        },
    ]


def test_summarize_batch_results_counts_and_top_lists() -> None:
    summary = summarize_batch_results(_sample_results())

    assert summary["total"] == 3
    assert summary["successes"] == 2
    assert summary["errors"] == 1
    assert summary["partials"] == 1
    assert summary["degraded"] == 1
    assert summary["top_services"][0] == ("Microsoft 365", 1)
    assert summary["error_domains"] == ["gamma.com"]
    assert summary["partial_domains"] == ["beta.com"]
    assert summary["top_sparse_diagnoses"] == [
        ("Sparse public signal — minimal public DNS footprint.", 1),
        ("Sparse public signal — edge-heavy footprint.", 1),
    ]


def test_compare_batch_summaries_returns_deltas() -> None:
    before = {"total": 3, "successes": 2, "errors": 1, "partials": 1, "degraded": 1}
    after = {"total": 4, "successes": 4, "errors": 0, "partials": 0, "degraded": 2}

    comparison = compare_batch_summaries(before, after)

    assert comparison == {
        "total_delta": 1,
        "successes_delta": 2,
        "errors_delta": -1,
        "partials_delta": -1,
        "degraded_delta": 1,
    }


def test_compare_batch_results_reports_semantic_domain_changes() -> None:
    before = [
        {
            "queried_domain": "alpha.com",
            "provider": "Microsoft 365",
            "confidence": "high",
            "services": ["Microsoft 365", "DMARC"],
            "slugs": ["microsoft365", "dmarc"],
            "insights": ["Sparse public signal — minimal public DNS footprint."],
            "degraded_sources": [],
            "partial": False,
        },
        {
            "queried_domain": "beta.com",
            "provider": "Google Workspace",
            "confidence": "medium",
            "services": ["Google Workspace"],
            "slugs": ["google-workspace"],
            "insights": [],
            "degraded_sources": ["crt.sh"],
            "partial": True,
        },
    ]
    after = [
        {
            "queried_domain": "alpha.com",
            "provider": "Microsoft 365",
            "confidence": "medium",
            "services": ["Microsoft 365", "DMARC", "Cloudflare"],
            "slugs": ["microsoft365", "dmarc", "cloudflare"],
            "insights": ["Sparse public signal — edge-heavy footprint."],
            "degraded_sources": ["crt.sh"],
            "partial": True,
        },
        {
            "queried_domain": "gamma.com",
            "provider": "Unknown",
            "confidence": "low",
            "services": [],
            "slugs": [],
            "insights": [],
            "degraded_sources": [],
            "partial": False,
        },
    ]

    comparison = compare_batch_results(before, after)

    assert comparison["added_domains"] == ["gamma.com"]
    assert comparison["removed_domains"] == ["beta.com"]
    assert comparison["changed_domain_count"] == 1
    assert comparison["change_counts"]["confidence_changes"] == 1
    assert comparison["change_counts"]["partial_changes"] == 1
    assert comparison["change_counts"]["degraded_changes"] == 1
    assert comparison["change_counts"]["service_changes"] == 1
    assert comparison["change_counts"]["slug_changes"] == 1
    assert comparison["change_counts"]["sparse_diagnosis_changes"] == 1
    assert comparison["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 1,
        "low": 0,
    }
    assert comparison["change_type_counts"] == {
        "regression": 1,
        "improvement": 0,
        "mixed": 0,
        "review": 0,
        "neutral": 0,
    }

    changed = comparison["changed_domains"][0]
    assert changed["domain"] == "alpha.com"
    assert changed["severity"] == "medium"
    assert changed["change_type"] == "regression"
    assert changed["confidence_change"] == {"from": "high", "to": "medium"}
    assert changed["partial_change"] == {"from": False, "to": True}
    assert changed["degraded_sources_added"] == ["crt.sh"]
    assert changed["added_services"] == ["Cloudflare"]
    assert changed["added_slugs"] == ["cloudflare"]
    assert changed["sparse_diagnosis_change"] == {
        "from": "Sparse public signal — minimal public DNS footprint.",
        "to": "Sparse public signal — edge-heavy footprint.",
    }


def test_render_summary_markdown_includes_attention_sections() -> None:
    results = _sample_results()
    summary = summarize_batch_results(results)

    rendered = render_summary_markdown("Sample Run", summary, results)

    assert "# Sample Run" in rendered
    assert "## Headline counts" in rendered
    assert "## Top sparse diagnoses" in rendered
    assert "`gamma.com`: ERROR" in rendered
    assert "degraded: `beta.com` via crt.sh" in rendered


def test_render_summary_markdown_includes_regression_detail() -> None:
    results = _sample_results()
    summary = summarize_batch_results(results)
    detailed = {
        "shared_domains": 1,
        "added_domains": ["delta.com"],
        "removed_domains": [],
        "changed_domain_count": 1,
        "change_counts": {
            "status_changes": 0,
            "provider_changes": 1,
            "confidence_changes": 1,
            "partial_changes": 0,
            "degraded_changes": 1,
            "service_changes": 1,
            "slug_changes": 1,
            "sparse_diagnosis_changes": 1,
        },
        "severity_counts": {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
        },
        "change_type_counts": {
            "regression": 0,
            "improvement": 0,
            "mixed": 0,
            "review": 1,
            "neutral": 0,
        },
        "changed_domains": [
            {
                "domain": "alpha.com",
                "severity": "high",
                "change_type": "review",
                "provider_change": {"from": "Microsoft 365", "to": "Google Workspace"},
                "confidence_change": {"from": "high", "to": "medium"},
                "degraded_sources_added": ["crt.sh"],
                "degraded_sources_removed": [],
                "added_services": ["Google Workspace"],
                "removed_services": ["Microsoft 365"],
                "added_slugs": ["google-workspace"],
                "removed_slugs": ["microsoft365"],
                "sparse_diagnosis_change": {
                    "from": "Sparse public signal — minimal public DNS footprint.",
                    "to": "Sparse public signal — edge-heavy footprint.",
                },
            }
        ],
    }

    rendered = render_summary_markdown(
        "Sample Run",
        summary,
        results,
        comparison={"total_delta": 0},
        detailed_comparison=detailed,
    )

    assert "## Regression Detail" in rendered
    assert "- changed domains: 1" in rendered
    assert "- high regressions: 1" in rendered
    assert "- review changes: 1" in rendered
    assert "Added domains: `delta.com`" in rendered
    assert "## Changed domains" in rendered
    assert "- `alpha.com` (high, review)" in rendered
    assert "provider: `Microsoft 365` -> `Google Workspace`" in rendered
    assert "sparse diagnosis:" in rendered


def test_compare_batch_results_sorts_by_severity() -> None:
    before = [
        {"queried_domain": "alpha.com", "provider": "Microsoft 365"},
        {"queried_domain": "beta.com", "provider": "Google Workspace"},
        {"queried_domain": "gamma.com", "provider": "Unknown", "confidence": "low"},
    ]
    after = [
        {"queried_domain": "alpha.com", "error": "timeout"},
        {"queried_domain": "beta.com", "provider": "Microsoft 365"},
        {"queried_domain": "gamma.com", "provider": "Unknown", "confidence": "medium", "services": ["Cloudflare"]},
    ]

    comparison = compare_batch_results(before, after)

    assert [entry["domain"] for entry in comparison["changed_domains"]] == [
        "alpha.com",
        "beta.com",
        "gamma.com",
    ]
    assert [entry["severity"] for entry in comparison["changed_domains"]] == [
        "critical",
        "high",
        "medium",
    ]
    assert [entry["change_type"] for entry in comparison["changed_domains"]] == [
        "regression",
        "review",
        "improvement",
    ]
