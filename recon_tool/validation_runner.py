"""Helpers for repeatable live-corpus validation runs.

These utilities wrap the existing batch JSON workflow so validation can be
rerun against a real-domain corpus and summarized into artifacts that are easy
to diff and triage.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def summarize_batch_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize a batch JSON result set for quick triage."""
    total = len(results)
    successes = [entry for entry in results if "error" not in entry]
    errors = [entry for entry in results if "error" in entry]
    partials = [entry for entry in successes if bool(entry.get("partial"))]
    degraded = [entry for entry in successes if entry.get("degraded_sources")]

    provider_counter = Counter(str(entry.get("provider") or "(none)") for entry in successes)
    service_counter = Counter(
        str(service) for entry in successes for service in (entry.get("services") or []) if service
    )
    slug_counter = Counter(str(slug) for entry in successes for slug in (entry.get("slugs") or []) if slug)
    degraded_counter = Counter(
        str(source) for entry in successes for source in (entry.get("degraded_sources") or []) if source
    )
    insight_counter = Counter(
        str(insight) for entry in successes for insight in (entry.get("insights") or []) if insight
    )

    return {
        "total": total,
        "successes": len(successes),
        "errors": len(errors),
        "partials": len(partials),
        "degraded": len(degraded),
        "top_providers": provider_counter.most_common(10),
        "top_services": service_counter.most_common(15),
        "top_slugs": slug_counter.most_common(15),
        "top_degraded_sources": degraded_counter.most_common(10),
        "top_insights": insight_counter.most_common(15),
        "error_domains": [str(entry.get("domain") or "?") for entry in errors],
        "partial_domains": [str(entry.get("queried_domain") or "?") for entry in partials],
        "degraded_domains": [
            {
                "domain": str(entry.get("queried_domain") or "?"),
                "degraded_sources": [str(source) for source in (entry.get("degraded_sources") or [])],
            }
            for entry in degraded
        ],
    }


def compare_batch_summaries(before: dict[str, Any], after: dict[str, Any]) -> dict[str, int]:
    """Compare two batch summaries on the core triage counters."""
    keys = ("total", "successes", "errors", "partials", "degraded")
    return {
        f"{key}_delta": int(after.get(key, 0)) - int(before.get(key, 0))
        for key in keys
    }


def render_summary_markdown(
    label: str,
    summary: dict[str, Any],
    results: list[dict[str, Any]],
    comparison: dict[str, int] | None = None,
) -> str:
    """Render a human-readable Markdown summary for a validation run."""
    lines = [
        f"# {label}",
        "",
        "## Headline counts",
        "",
        f"- total: {summary['total']}",
        f"- successes: {summary['successes']}",
        f"- errors: {summary['errors']}",
        f"- partials: {summary['partials']}",
        f"- degraded: {summary['degraded']}",
        "",
    ]

    if comparison is not None:
        lines.extend(
            [
                "## Comparison",
                "",
                *(f"- {key}: {value:+d}" for key, value in comparison.items()),
                "",
            ]
        )

    def _append_counter_section(title: str, items: list[list[Any]] | list[tuple[Any, Any]]) -> None:
        lines.extend([f"## {title}", ""])
        if not items:
            lines.append("- none")
        else:
            for name, count in items:
                lines.append(f"- `{name}`: {count}")
        lines.append("")

    _append_counter_section("Top providers", summary["top_providers"])
    _append_counter_section("Top services", summary["top_services"])
    _append_counter_section("Top slugs", summary["top_slugs"])
    _append_counter_section("Top degraded sources", summary["top_degraded_sources"])
    _append_counter_section("Top insights", summary["top_insights"])

    lines.extend(["## Domains needing attention", ""])
    if not summary["error_domains"] and not summary["partial_domains"] and not summary["degraded_domains"]:
        lines.append("- none")
    else:
        for domain in summary["error_domains"]:
            lines.append(f"- error: `{domain}`")
        for domain in summary["partial_domains"]:
            lines.append(f"- partial: `{domain}`")
        for entry in summary["degraded_domains"]:
            sources = ", ".join(entry["degraded_sources"])
            lines.append(f"- degraded: `{entry['domain']}` via {sources}")
    lines.append("")

    lines.extend(["## Per-domain snapshot", ""])
    for entry in results:
        if "error" in entry:
            lines.append(f"- `{entry.get('domain', '?')}`: ERROR — {entry['error']}")
            continue
        domain = str(entry.get("queried_domain") or "?")
        provider = str(entry.get("provider") or "-")
        confidence = str(entry.get("confidence") or "-")
        partial = bool(entry.get("partial"))
        degraded_sources = entry.get("degraded_sources") or []
        degraded_text = ", ".join(str(source) for source in degraded_sources) if degraded_sources else "-"
        lines.append(
            f"- `{domain}`: provider=`{provider}` "
            f"confidence=`{confidence}` partial={partial} degraded=`{degraded_text}`"
        )

    return "\n".join(lines) + "\n"


def run_batch_validation_sync(corpus_path: Path, concurrency: int = 5) -> list[dict[str, Any]]:
    """Run the public batch CLI in-process and return its JSON payload."""
    from typer.testing import CliRunner

    from recon_tool.cli import app

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["batch", str(corpus_path), "--json", "--concurrency", str(concurrency)],
    )
    if result.exit_code != 0:
        msg = result.output.strip() or f"Batch validation failed for {corpus_path}"
        raise RuntimeError(msg)

    raw = result.output.strip()
    if not raw:
        msg = f"Batch run produced no JSON output for {corpus_path}"
        raise ValueError(msg)

    data = json.loads(raw)
    if not isinstance(data, list):
        msg = "Batch JSON output must be a list"
        raise ValueError(msg)
    if not all(isinstance(entry, dict) for entry in data):
        msg = "Batch JSON entries must be objects"
        raise ValueError(msg)
    return data
