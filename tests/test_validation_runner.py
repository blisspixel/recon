from __future__ import annotations

from recon_tool.validation_runner import (
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
            "insights": ["Email security: DMARC quarantine"],
            "degraded_sources": [],
            "partial": False,
        },
        {
            "queried_domain": "beta.com",
            "provider": "Google Workspace",
            "confidence": "medium",
            "services": ["Google Workspace"],
            "slugs": ["google-workspace"],
            "insights": ["Google-native identity indicators"],
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


def test_render_summary_markdown_includes_attention_sections() -> None:
    results = _sample_results()
    summary = summarize_batch_results(results)

    rendered = render_summary_markdown("Sample Run", summary, results)

    assert "# Sample Run" in rendered
    assert "## Headline counts" in rendered
    assert "`gamma.com`: ERROR" in rendered
    assert "degraded: `beta.com` via crt.sh" in rendered
