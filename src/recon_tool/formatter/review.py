"""Deterministic Markdown projection for NamespaceReviewBundle v1."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from recon_tool.formatter.markdown import markdown_escape

_CANDIDATE_STATE_ORDER = (
    "observed_weak_configuration",
    "bounded_non_observation",
    "unresolved_hideable_state",
    "observed_configuration_inconsistency",
)


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _items(value: object) -> list[object]:
    if isinstance(value, list | tuple):
        return list(value)
    return []


def _safe(value: object) -> str:
    if value is None:
        return "not reported"
    return markdown_escape(str(value)) or "not reported"


def _safe_join(values: object) -> str:
    rendered = [_safe(value) for value in _items(values)]
    return ", ".join(rendered) if rendered else "none reported"


def _line(label: str, value: object) -> str:
    return f"- **{label}:** {_safe(value)}"


def _scope_domain(bundle: Mapping[str, Any], lookup: Mapping[str, Any]) -> str:
    scope = _mapping(bundle.get("scope"))
    for key in ("queried_domain", "input_coordinate"):
        value = scope.get(key)
        if isinstance(value, str) and value:
            return value
    value = lookup.get("queried_domain")
    return value if isinstance(value, str) and value else "namespace not reported"


def _baseline_succeeded(bundle: Mapping[str, Any]) -> bool:
    result = _mapping(bundle.get("result"))
    return bool(_mapping(result.get("explained_baseline")))


def _collection_lines(bundle: Mapping[str, Any], lookup: Mapping[str, Any]) -> list[str]:
    collection = _mapping(bundle.get("collection"))
    workflow = _mapping(bundle.get("workflow"))
    options = _mapping(collection.get("options"))
    cache = _mapping(collection.get("cache"))

    lines = ["## Collection validity", ""]
    lines.extend(
        (
            _line("Workflow status", workflow.get("status")),
            _line("Collection validity", workflow.get("collection_validity")),
            _line("Freshness assessment", workflow.get("freshness_assessment")),
            _line("Generated at", bundle.get("generated_at")),
            _line("Collection started", collection.get("started_at")),
            _line("Collection ended", collection.get("ended_at")),
            _line("As of", collection.get("as_of")),
            _line("Collection vantage", collection.get("vantage")),
            _line("Lookup-result cache", cache.get("result_cache")),
            _line("Certificate transparency enabled", options.get("ct_enabled")),
            _line("Certificate transparency provider", cache.get("ct_provider_used")),
            _line("Certificate transparency cache age in days", cache.get("ct_cache_age_days")),
            _line("Certificate transparency attempt", cache.get("ct_attempt_outcome")),
            _line("Direct probes", options.get("direct_probes")),
        )
    )
    if lookup:
        lines.extend(
            (
                _line("Confidence", lookup.get("confidence")),
                f"- **Degraded sources:** {_safe_join(lookup.get('degraded_sources'))}",
            )
        )
    lines.append(_line("Artifact digest", bundle.get("content_digest")))
    opportunities = _items(bundle.get("source_opportunities"))
    lines.extend(("", "### Recorded source opportunities", ""))
    if not opportunities:
        lines.append("No source opportunity was recorded.")
    for raw_opportunity in opportunities:
        opportunity = _mapping(raw_opportunity)
        window = _mapping(opportunity.get("observation_window"))
        lines.append(
            f"- **{_safe(opportunity.get('source_role'))}:** "
            f"state {_safe(opportunity.get('state'))}; "
            f"instances {_safe(opportunity.get('instance_count'))}; "
            f"window {_safe(window.get('started_at'))} to {_safe(window.get('ended_at'))}; "
            f"degraded markers {_safe_join(opportunity.get('degraded_markers'))}"
        )
    lines.extend(("", "The artifact digest detects content modification; it is not a signature or collector identity."))
    return lines


def _mail_identity_lines(lookup: Mapping[str, Any]) -> list[str]:
    lines = ["## Observed mail and identity configuration", ""]
    fields = (
        ("Provider observation", "provider"),
        ("Mail provider observation", "primary_email_provider"),
        ("Possible downstream mail provider", "likely_primary_email_provider"),
        ("Mail gateway observation", "email_gateway"),
        ("DMARC policy", "dmarc_policy"),
        ("MTA-STS mode", "mta_sts_mode"),
        ("Public email controls observed", "email_security_score"),
        ("Tenant identifier", "tenant_id"),
        ("Authentication type", "auth_type"),
        ("Google authentication type", "google_auth_type"),
        ("Identity-provider observation", "google_idp_name"),
        ("Cloud instance", "cloud_instance"),
        ("Region", "region"),
    )
    observed: list[tuple[str, object]] = []
    for label, key in fields:
        value = lookup.get(key)
        if value in (None, "", [], ()):
            continue
        if key == "email_security_score" and isinstance(value, int) and not isinstance(value, bool):
            value = f"{value} of 5"
        observed.append((label, value))
    if observed:
        lines.extend(_line(label, value) for label, value in observed)
    else:
        lines.append("No mail or identity configuration value was reported within the bounded baseline.")

    return lines


def _evidence_lines(baseline: Mapping[str, Any], evidence_ledger: list[object]) -> list[str]:
    lines = ["## Evidence and lineage", ""]
    explanations = [_mapping(item) for item in _items(baseline.get("explanations"))]
    if explanations:
        lines.extend(("### Explained baseline references", ""))
        for item in explanations:
            lines.append(
                f"- **{_safe(item.get('item_type'))}: {_safe(item.get('item_name'))}**; "
                f"lineage {_safe(item.get('lineage_status'))}; "
                f"evidence IDs {_safe_join(item.get('evidence_ids'))}"
            )
    else:
        lines.append("No explained baseline reference was reported.")

    if evidence_ledger:
        lines.extend(("", "### Retained evidence ledger", ""))
        for raw in evidence_ledger:
            item = _mapping(raw)
            evidence_id = item.get("evidence_id", "identifier not reported")
            kind = item.get("source_type", item.get("type", item.get("kind", "evidence")))
            rule = item.get("rule_name", item.get("rule_id", "rule not reported"))
            value = item.get("raw_value", item.get("value", "value retained in JSON artifact"))
            lines.append(f"- **{_safe(evidence_id)}** [{_safe(kind)}; {_safe(rule)}]: {_safe(value)}")
    else:
        lines.extend(("", "No retained evidence identifier was reported."))
    return lines


def _connection_lines(lookup: Mapping[str, Any]) -> list[str]:
    lines = ["## Public connection indicators", ""]
    connection_map = _mapping(lookup.get("connection_map"))
    emitted = False
    for raw_lane in _items(connection_map.get("lanes")):
        lane = _mapping(raw_lane)
        entries = _items(lane.get("entries"))
        if not entries:
            continue
        emitted = True
        lines.append(f"### {_safe(lane.get('label', lane.get('id', 'Connection lane')))}")
        lines.append("")
        for raw_entry in entries:
            entry = _mapping(raw_entry)
            role = entry.get("role", "role not reported")
            name = entry.get("name", "name not reported")
            hosts = _safe_join(entry.get("hosts"))
            lines.append(f"- {_safe(name)}; role: {_safe(role)}; related hosts: {hosts}")
        lines.append("")

    host_classes = _items(connection_map.get("related_host_classes"))
    if host_classes:
        emitted = True
        lines.extend(("### Related-host classes", ""))
        for raw_class in host_classes:
            host_class = _mapping(raw_class)
            lines.append(
                f"- {_safe(host_class.get('prefix', 'class not reported'))}: {_safe_join(host_class.get('hosts'))}"
            )

    if not emitted:
        lines.append("No public connection indicator was reported within the bounded baseline.")
    return lines


def _candidate_lines(review: Mapping[str, Any]) -> list[str]:
    lines = ["## Review candidates grouped by observation_state", ""]
    candidates = [_mapping(item) for item in _items(review.get("candidates"))]
    if not candidates:
        lines.append("The candidate stage succeeded and returned no review candidates.")
        return lines

    states = {str(candidate.get("observation_state", "unclassified")) for candidate in candidates}
    ordered_states = [state for state in _CANDIDATE_STATE_ORDER if state in states]
    ordered_states.extend(sorted(states - set(ordered_states)))
    for state in ordered_states:
        lines.append(f"### {_safe(state)}")
        lines.append("")
        for candidate in candidates:
            if str(candidate.get("observation_state", "unclassified")) != state:
                continue
            lines.append(f"- **Candidate ID:** {_safe(candidate.get('candidate_id'))}")
            lines.append(f"  - Category: {_safe(candidate.get('category'))}")
            lines.append(f"  - Severity: {_safe(candidate.get('severity'))}")
            lines.append(f"  - Observation: {_safe(candidate.get('observation'))}")
            lines.append(f"  - Consider: {_safe(candidate.get('recommendation'))}")
            lines.append(f"  - Generator: {_safe(candidate.get('generator_rule_id'))}")
            lines.append(f"  - Observation scope: {_safe_join(candidate.get('observation_scope'))}")
            dependencies: list[str] = []
            for raw_dependency in _items(candidate.get("metadata_dependencies")):
                dependency = _mapping(raw_dependency)
                dependencies.append(
                    f"{_safe(dependency.get('field'))} {_safe(dependency.get('operator'))}; "
                    f"expected {_safe(dependency.get('expected_value'))}; "
                    f"observed {_safe(dependency.get('observed_value'))}"
                )
            lines.append(f"  - Metadata dependencies: {' | '.join(dependencies) if dependencies else 'none reported'}")
            lines.append(f"  - Absence confirmable: {_safe(candidate.get('absence_confirmable'))}")
            lines.append(f"  - Evidence IDs: {_safe_join(candidate.get('evidence_ids'))}")
        lines.append("")
    return lines


def _unresolved_lines(lookup: Mapping[str, Any], review: Mapping[str, Any], baseline: Mapping[str, Any]) -> list[str]:
    lines = ["## Unresolved and unavailable evidence", ""]
    items: list[str] = []
    degraded = list(dict.fromkeys(str(item) for item in _items(lookup.get("degraded_sources"))))
    degraded.extend(
        item
        for item in dict.fromkeys(str(item) for item in _items(review.get("degraded_sources")))
        if item not in degraded
    )
    if degraded:
        items.append(f"- Degraded sources: {_safe_join(degraded)}")

    unavailable = _items(review.get("unavailable_controls"))
    if unavailable:
        items.append(f"- Unavailable controls: {_safe_join(unavailable)}")

    dag = _mapping(baseline.get("explanation_dag"))
    disconnected = dag.get("lineage_disconnected_terminals", dag.get("disconnected_terminals"))
    if _items(disconnected):
        items.append(f"- Unsupported or disconnected lineage: {_safe_join(disconnected)}")

    unresolved_candidates = [
        candidate.get("candidate_id")
        for candidate in (_mapping(item) for item in _items(review.get("candidates")))
        if candidate.get("observation_state") == "unresolved_hideable_state"
    ]
    if unresolved_candidates:
        items.append(f"- Hideable-state candidate IDs: {_safe_join(unresolved_candidates)}")

    lines.extend(items or ["No unresolved or unavailable item was reported within the bounded artifact."])
    return lines


def _scope_lines(bundle: Mapping[str, Any]) -> list[str]:
    return ["## Scope statement", "", _safe(bundle.get("scope_statement"))]


def _failed_lines(bundle: Mapping[str, Any]) -> list[str]:
    result = _mapping(bundle.get("result"))
    lines = _collection_lines(bundle, {})
    lines.extend(
        (
            "",
            _line("Baseline failure kind", result.get("error_kind")),
            _line("Failed source roles", result.get("failed_source_roles", ())),
            "",
        )
    )
    lines.extend(_scope_lines(bundle))
    return lines


def format_review_bundle_markdown(bundle: Mapping[str, Any]) -> str:
    """Render one validated NamespaceReviewBundle v1 as role-neutral Markdown.

    The function performs no collection and follows no retained links. Every
    dynamic value passes through the shared full-punctuation Markdown escape.
    """
    result = _mapping(bundle.get("result"))
    baseline = _mapping(result.get("explained_baseline"))
    lookup = _mapping(baseline.get("lookup"))
    domain = _scope_domain(bundle, lookup)
    lines = [f"# Namespace review: {_safe(domain)}", ""]

    if not _baseline_succeeded(bundle):
        lines.extend(_failed_lines(bundle))
        return "\n".join(lines).rstrip() + "\n"

    review = _mapping(result.get("review_candidates"))
    lines.extend(_collection_lines(bundle, lookup))
    lines.extend(("", *_mail_identity_lines(lookup), ""))
    lines.extend((*_connection_lines(lookup), ""))
    lines.extend((*_evidence_lines(baseline, _items(result.get("evidence_ledger"))), ""))
    lines.extend((*_candidate_lines(review), ""))
    lines.extend((*_unresolved_lines(lookup, review, baseline), ""))
    lines.extend(_scope_lines(bundle))
    return "\n".join(lines).rstrip() + "\n"


render_review_bundle_markdown = format_review_bundle_markdown


__all__ = ["format_review_bundle_markdown", "render_review_bundle_markdown"]
