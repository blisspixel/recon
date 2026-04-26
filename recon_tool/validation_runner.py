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

__all__ = [
    "compare_batch_results",
    "compare_batch_summaries",
    "render_summary_markdown",
    "run_batch_validation_sync",
    "summarize_batch_results",
]

_SPARSE_PREFIX = "Sparse public signal —"
_SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


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
    sparse_counter = Counter(
        sparse
        for entry in successes
        for sparse in [_first_sparse_insight(entry)]
        if sparse is not None
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
        "top_sparse_diagnoses": sparse_counter.most_common(10),
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


def _result_domain(entry: dict[str, Any]) -> str:
    """Return the canonical domain key for a batch result entry."""
    return str(entry.get("queried_domain") or entry.get("domain") or "?")


def _first_sparse_insight(entry: dict[str, Any]) -> str | None:
    """Return the first sparse-signal diagnosis insight from a result entry."""
    for insight in entry.get("insights") or []:
        text = str(insight)
        if text.startswith(_SPARSE_PREFIX):
            return text
    return None


def _classify_regression_severity(change: dict[str, Any]) -> str:
    """Assign a triage severity to a per-domain regression/change entry."""
    status = change.get("status_change")
    if isinstance(status, dict) and status.get("to") == "error":
        return "critical"
    if "provider_change" in change:
        return "high"
    if "confidence_change" in change or "partial_change" in change:
        return "medium"
    if (
        change.get("degraded_sources_added")
        or change.get("degraded_sources_removed")
        or "sparse_diagnosis_change" in change
    ):
        return "medium"
    return "low"


def _classify_change_type(change: dict[str, Any]) -> str:
    """Classify whether a domain change is good, bad, mixed, or review-only."""
    positive = 0
    negative = 0
    needs_review = False

    status = change.get("status_change")
    if isinstance(status, dict):
        if status.get("to") == "error":
            negative += 3
        elif status.get("from") == "error":
            positive += 3

    confidence = change.get("confidence_change")
    if isinstance(confidence, dict):
        before = _CONFIDENCE_ORDER.get(str(confidence.get("from") or ""))
        after = _CONFIDENCE_ORDER.get(str(confidence.get("to") or ""))
        if before is not None and after is not None:
            if after > before:
                positive += 2
            elif after < before:
                negative += 2

    partial = change.get("partial_change")
    if isinstance(partial, dict):
        if partial.get("to") is True and partial.get("from") is False:
            negative += 1
        elif partial.get("to") is False and partial.get("from") is True:
            positive += 1

    negative += len(change.get("degraded_sources_added") or [])
    positive += len(change.get("degraded_sources_removed") or [])

    if "provider_change" in change or "sparse_diagnosis_change" in change:
        needs_review = True
    if change.get("added_services") or change.get("removed_services"):
        needs_review = True
    if change.get("added_slugs") or change.get("removed_slugs"):
        needs_review = True

    if positive and negative:
        return "mixed"
    if negative:
        return "regression"
    if positive:
        return "improvement"
    if needs_review:
        return "review"
    return "neutral"


def compare_batch_results(before_results: list[dict[str, Any]], after_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare two batch result sets and report semantic per-domain changes."""
    before_index = {_result_domain(entry): entry for entry in before_results}
    after_index = {_result_domain(entry): entry for entry in after_results}

    before_domains = set(before_index)
    after_domains = set(after_index)
    shared_domains = sorted(before_domains & after_domains)

    changed_domains: list[dict[str, Any]] = []
    status_changes = provider_changes = confidence_changes = partial_changes = 0
    degraded_changes = service_changes = slug_changes = sparse_changes = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    change_type_counts = {"regression": 0, "improvement": 0, "mixed": 0, "review": 0, "neutral": 0}

    for domain in shared_domains:
        before = before_index[domain]
        after = after_index[domain]
        change: dict[str, Any] = {"domain": domain}

        before_error = str(before.get("error")) if "error" in before else None
        after_error = str(after.get("error")) if "error" in after else None
        if before_error != after_error:
            change["status_change"] = {
                "from": "error" if before_error is not None else "success",
                "to": "error" if after_error is not None else "success",
                "from_error": before_error,
                "to_error": after_error,
            }
            status_changes += 1

        before_provider = str(before.get("provider") or "")
        after_provider = str(after.get("provider") or "")
        if before_provider != after_provider:
            change["provider_change"] = {"from": before_provider or None, "to": after_provider or None}
            provider_changes += 1

        before_confidence = str(before.get("confidence") or "")
        after_confidence = str(after.get("confidence") or "")
        if before_confidence != after_confidence:
            change["confidence_change"] = {"from": before_confidence or None, "to": after_confidence or None}
            confidence_changes += 1

        before_partial = bool(before.get("partial"))
        after_partial = bool(after.get("partial"))
        if before_partial != after_partial:
            change["partial_change"] = {"from": before_partial, "to": after_partial}
            partial_changes += 1

        before_degraded = {str(source) for source in before.get("degraded_sources") or [] if source}
        after_degraded = {str(source) for source in after.get("degraded_sources") or [] if source}
        if before_degraded != after_degraded:
            change["degraded_sources_added"] = sorted(after_degraded - before_degraded)
            change["degraded_sources_removed"] = sorted(before_degraded - after_degraded)
            degraded_changes += 1

        before_services = {str(service) for service in before.get("services") or [] if service}
        after_services = {str(service) for service in after.get("services") or [] if service}
        if before_services != after_services:
            change["added_services"] = sorted(after_services - before_services)
            change["removed_services"] = sorted(before_services - after_services)
            service_changes += 1

        before_slugs = {str(slug) for slug in before.get("slugs") or [] if slug}
        after_slugs = {str(slug) for slug in after.get("slugs") or [] if slug}
        if before_slugs != after_slugs:
            change["added_slugs"] = sorted(after_slugs - before_slugs)
            change["removed_slugs"] = sorted(before_slugs - after_slugs)
            slug_changes += 1

        before_sparse = _first_sparse_insight(before)
        after_sparse = _first_sparse_insight(after)
        if before_sparse != after_sparse:
            change["sparse_diagnosis_change"] = {"from": before_sparse, "to": after_sparse}
            sparse_changes += 1

        if len(change) > 1:
            severity = _classify_regression_severity(change)
            change_type = _classify_change_type(change)
            change["severity"] = severity
            change["change_type"] = change_type
            severity_counts[severity] += 1
            change_type_counts[change_type] += 1
            changed_domains.append(change)

    changed_domains.sort(key=lambda entry: (-_SEVERITY_ORDER[entry["severity"]], entry["domain"]))

    return {
        "domains_before": len(before_domains),
        "domains_after": len(after_domains),
        "shared_domains": len(shared_domains),
        "added_domains": sorted(after_domains - before_domains),
        "removed_domains": sorted(before_domains - after_domains),
        "changed_domains": changed_domains,
        "changed_domain_count": len(changed_domains),
        "change_counts": {
            "status_changes": status_changes,
            "provider_changes": provider_changes,
            "confidence_changes": confidence_changes,
            "partial_changes": partial_changes,
            "degraded_changes": degraded_changes,
            "service_changes": service_changes,
            "slug_changes": slug_changes,
            "sparse_diagnosis_changes": sparse_changes,
        },
        "severity_counts": severity_counts,
        "change_type_counts": change_type_counts,
    }


def render_summary_markdown(
    label: str,
    summary: dict[str, Any],
    results: list[dict[str, Any]],
    comparison: dict[str, int] | None = None,
    detailed_comparison: dict[str, Any] | None = None,
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

    if detailed_comparison is not None:
        change_counts = detailed_comparison["change_counts"]
        severity_counts = detailed_comparison["severity_counts"]
        change_type_counts = detailed_comparison["change_type_counts"]
        lines.extend(
            [
                "## Regression Detail",
                "",
                f"- shared domains: {detailed_comparison['shared_domains']}",
                f"- added domains: {len(detailed_comparison['added_domains'])}",
                f"- removed domains: {len(detailed_comparison['removed_domains'])}",
                f"- changed domains: {detailed_comparison['changed_domain_count']}",
                f"- provider changes: {change_counts['provider_changes']}",
                f"- confidence changes: {change_counts['confidence_changes']}",
                f"- partial changes: {change_counts['partial_changes']}",
                f"- degraded-source changes: {change_counts['degraded_changes']}",
                f"- service changes: {change_counts['service_changes']}",
                f"- slug changes: {change_counts['slug_changes']}",
                f"- sparse-diagnosis changes: {change_counts['sparse_diagnosis_changes']}",
                f"- critical regressions: {severity_counts['critical']}",
                f"- high regressions: {severity_counts['high']}",
                f"- medium regressions: {severity_counts['medium']}",
                f"- low regressions: {severity_counts['low']}",
                f"- regression changes: {change_type_counts['regression']}",
                f"- improvement changes: {change_type_counts['improvement']}",
                f"- mixed changes: {change_type_counts['mixed']}",
                f"- review changes: {change_type_counts['review']}",
                f"- neutral changes: {change_type_counts['neutral']}",
                "",
            ]
        )
        if detailed_comparison["added_domains"]:
            added_domains = ", ".join(f"`{domain}`" for domain in detailed_comparison["added_domains"])
            lines.append(f"Added domains: {added_domains}")
            lines.append("")
        if detailed_comparison["removed_domains"]:
            removed_domains = ", ".join(f"`{domain}`" for domain in detailed_comparison["removed_domains"])
            lines.append(f"Removed domains: {removed_domains}")
            lines.append("")
        lines.extend(["## Changed domains", ""])
        if not detailed_comparison["changed_domains"]:
            lines.append("- none")
            lines.append("")
        else:
            for entry in detailed_comparison["changed_domains"]:
                lines.append(f"- `{entry['domain']}` ({entry['severity']}, {entry['change_type']})")
                if "status_change" in entry:
                    status = entry["status_change"]
                    lines.append(f"  status: `{status['from']}` -> `{status['to']}`")
                if "provider_change" in entry:
                    provider = entry["provider_change"]
                    lines.append(f"  provider: `{provider['from']}` -> `{provider['to']}`")
                if "confidence_change" in entry:
                    confidence = entry["confidence_change"]
                    lines.append(f"  confidence: `{confidence['from']}` -> `{confidence['to']}`")
                if "partial_change" in entry:
                    partial = entry["partial_change"]
                    lines.append(f"  partial: `{partial['from']}` -> `{partial['to']}`")
                if entry.get("degraded_sources_added") or entry.get("degraded_sources_removed"):
                    added = ", ".join(entry.get("degraded_sources_added", [])) or "-"
                    removed = ", ".join(entry.get("degraded_sources_removed", [])) or "-"
                    lines.append(f"  degraded sources: +[{added}] -[{removed}]")
                if entry.get("added_services") or entry.get("removed_services"):
                    added = ", ".join(entry.get("added_services", [])) or "-"
                    removed = ", ".join(entry.get("removed_services", [])) or "-"
                    lines.append(f"  services: +[{added}] -[{removed}]")
                if entry.get("added_slugs") or entry.get("removed_slugs"):
                    added = ", ".join(entry.get("added_slugs", [])) or "-"
                    removed = ", ".join(entry.get("removed_slugs", [])) or "-"
                    lines.append(f"  slugs: +[{added}] -[{removed}]")
                if "sparse_diagnosis_change" in entry:
                    sparse = entry["sparse_diagnosis_change"]
                    lines.append(f"  sparse diagnosis: `{sparse['from']}` -> `{sparse['to']}`")
            lines.append("")

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
    _append_counter_section("Top sparse diagnoses", summary["top_sparse_diagnoses"])
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
