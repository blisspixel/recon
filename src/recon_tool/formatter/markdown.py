"""Markdown rendering for the tenant report.

Split out of ``formatter.py`` so the markdown renderer lives beside the other
per-target renderers rather than inside the panel module. It depends only on the
models and the shared classification predicates; it does no Rich rendering and
imports nothing from ``formatter``. ``formatter`` re-exports
``format_tenant_markdown`` / ``format_explanations_markdown`` and aliases
``markdown_escape`` back to its historical ``_markdown_escape`` name, so the
public and test import paths are unchanged.
"""

from __future__ import annotations

import string

from recon_tool.formatter.classify import (
    categorize_services,
    google_workspace_cse_indicators,
    google_workspace_module_indicators,
    is_gws_service,
    is_m365_service,
)
from recon_tool.models import ExplanationRecord, TenantInfo
from recon_tool.validator import strip_control_chars

# CommonMark permits a backslash before every ASCII punctuation character.
# Escape that complete set, including existing backslashes, so dynamic text is
# literal in headings, list items, links, code spans, tables, and inline HTML.
# Control bytes are already removed upstream by strip_control_chars.
MARKDOWN_ESCAPE = str.maketrans({c: "\\" + c for c in string.punctuation})
MARKDOWN_HARD_BREAK = "\\"


def markdown_escape(value: str) -> str:
    """Neutralize Markdown structural characters in attacker-derived text."""
    cleaned = strip_control_chars(value, max_len=len(value)).strip()
    return cleaned.translate(MARKDOWN_ESCAPE)


def _markdown_identifier(value: str) -> str:
    """Render a simple ASCII identifier as code, otherwise as literal text."""
    if value.isascii() and value and all(c.isalnum() or c == "-" for c in value):
        return f"`{value}`"
    return markdown_escape(value)


def _md_header(info: TenantInfo) -> list[str]:
    """Title and key-facts block of the markdown report."""
    lines: list[str] = []
    lines.append(f"# Tenant Report: {markdown_escape(info.display_name)}")
    lines.append("")
    lines.append(f"**Domain:** {markdown_escape(info.queried_domain)}{MARKDOWN_HARD_BREAK}")
    if info.tenant_id:
        lines.append(f"**Tenant ID:** {_markdown_identifier(info.tenant_id)}{MARKDOWN_HARD_BREAK}")
    lines.append(f"**Default Domain:** {markdown_escape(info.default_domain)}{MARKDOWN_HARD_BREAK}")
    if info.region:
        lines.append(f"**Region:** {markdown_escape(info.region)}{MARKDOWN_HARD_BREAK}")
    if info.auth_type:
        lines.append(f"**Auth Type:** {markdown_escape(info.auth_type)}{MARKDOWN_HARD_BREAK}")
    lines.append(f"**Confidence:** {info.confidence.value} ({len(info.sources)} sources){MARKDOWN_HARD_BREAK}")
    lines.append(
        f"**Evidence Confidence:** {info.evidence_confidence.value}{MARKDOWN_HARD_BREAK}\n"
        f"**Inference Confidence:** {info.inference_confidence.value}"
    )
    lines.append("")
    return lines


def _md_services_split(info: TenantInfo) -> list[str]:
    """Services grouped into Microsoft 365 / Google Workspace / Tech Stack."""
    categorized = categorize_services(info)
    if not categorized:
        return []
    m365_svcs: list[str] = []
    gws_svcs: list[str] = []
    other_svcs: list[str] = []
    for service in (service for services in categorized.values() for service in services):
        if is_gws_service(service):
            gws_svcs.append(service)
        elif is_m365_service(service):
            m365_svcs.append(service)
        else:
            other_svcs.append(service)
    lines: list[str] = []
    for header, svcs in (
        ("## Microsoft 365 Services", m365_svcs),
        ("## Google Workspace Services", gws_svcs),
        ("## Tech Stack", other_svcs),
    ):
        if svcs:
            lines.append(header)
            lines.append("")
            for svc in svcs:
                lines.append(f"- {markdown_escape(svc)}")
            lines.append("")
    return lines


def _md_gws_details(info: TenantInfo) -> list[str]:
    """Google Workspace auth, identity-provider, module-indicator, and CSE details."""
    gws_modules = google_workspace_module_indicators(info)
    cse_indicators = google_workspace_cse_indicators(info)
    if not any((info.google_auth_type, info.google_idp_name, gws_modules, cse_indicators)):
        return []
    lines: list[str] = ["## Google Workspace", ""]
    if info.google_auth_type:
        lines.append(f"**Auth Type:** {markdown_escape(info.google_auth_type)}{MARKDOWN_HARD_BREAK}")
    if info.google_idp_name:
        lines.append(f"**Identity Provider:** {markdown_escape(info.google_idp_name)}{MARKDOWN_HARD_BREAK}")
    if gws_modules:
        lines.append(
            f"**Module Indicators:** {', '.join(markdown_escape(s) for s in gws_modules)}{MARKDOWN_HARD_BREAK}"
        )
    if cse_indicators:
        lines.append(
            "**CSE Configuration Indicators:** "
            f"{', '.join(markdown_escape(s) for s in cse_indicators)}{MARKDOWN_HARD_BREAK}"
        )
    if lines[-1].endswith(MARKDOWN_HARD_BREAK):
        lines[-1] = lines[-1].removesuffix(MARKDOWN_HARD_BREAK)
    lines.append("")
    return lines


def _md_insights(info: TenantInfo) -> list[str]:
    """Insights section. Insight text is markdown-escaped as defense in depth so
    the report's safety does not depend on every current and future insight
    staying within a safe alphabet."""
    if not info.insights:
        return []
    lines: list[str] = ["## Insights", ""]
    for insight in info.insights:
        lines.append(f"- {markdown_escape(insight)}")
    lines.append("")
    return lines


def _md_cert_intel(info: TenantInfo) -> list[str]:
    """Certificate-intelligence section."""
    if info.cert_summary is None:
        return []
    cs = info.cert_summary
    lines: list[str] = ["## Certificate Intelligence", ""]
    lines.append(f"- **Total Certificates:** {cs.cert_count}")
    lines.append(f"- **Issuer Diversity:** {cs.issuer_diversity} distinct issuers")
    lines.append(f"- **Issuance Velocity:** {cs.issuance_velocity} certs in last 90 days")
    lines.append(f"- **Newest Cert Age:** {cs.newest_cert_age_days} days")
    lines.append(f"- **Oldest Cert Age:** {cs.oldest_cert_age_days} days")
    if cs.top_issuers:
        lines.append(f"- **Top Issuers:** {', '.join(markdown_escape(i) for i in cs.top_issuers)}")
    lines.append("")
    return lines


def _md_tenant_domains(info: TenantInfo) -> list[str]:
    """Tenant-domains section."""
    if not info.tenant_domains:
        return []
    lines: list[str] = [f"## Tenant Domains ({info.domain_count})", ""]
    for d in info.tenant_domains:
        lines.append(f"- {markdown_escape(d)}")
    lines.append("")
    return lines


def _md_related_domains(info: TenantInfo) -> list[str]:
    """Related-domains section."""
    if not info.related_domains:
        return []
    lines: list[str] = ["## Related Domains", ""]
    for d in info.related_domains:
        lines.append(f"- {markdown_escape(d)}")
    lines.append("")
    return lines


def _md_footer(info: TenantInfo) -> list[str]:
    """Footer: separator, optional degraded-sources note, and the sources line."""
    lines: list[str] = ["---"]
    if info.degraded_sources:
        sources_list = ", ".join(markdown_escape(source) for source in info.degraded_sources)
        lines.append(
            f"*Note: Some sources were unavailable ({sources_list}) - subdomain discovery may be incomplete.*"
            f"{MARKDOWN_HARD_BREAK}"
        )
    lines.append(f"*Sources: {', '.join(markdown_escape(source) for source in info.sources)}*")
    lines.append("")
    return lines


def format_tenant_markdown(info: TenantInfo) -> str:
    """Format TenantInfo as a markdown report.

    A thin orchestrator over the per-section ``_md_*`` builders, each of which
    returns its lines (or an empty list when the section does not apply).
    Output held byte-identical by ``tests/test_golden_renders.py``
    (``markdown_dense`` / ``markdown_sparse`` / ``markdown_rich``).
    """
    from recon_tool.collection_view import collection_observable_info

    info = collection_observable_info(info)
    lines: list[str] = []
    lines.extend(_md_header(info))
    lines.extend(_md_services_split(info))
    lines.extend(_md_gws_details(info))
    lines.extend(_md_insights(info))
    lines.extend(_md_cert_intel(info))
    lines.extend(_md_tenant_domains(info))
    lines.extend(_md_related_domains(info))
    lines.extend(_md_footer(info))
    return "\n".join(lines)


def format_explanations_markdown(explanations: list[ExplanationRecord]) -> str:
    """Render explanation records as markdown subsections."""
    lines: list[str] = []
    lines.append("## Explanations")
    lines.append("")

    for rec in explanations:
        type_label = markdown_escape(rec.item_type.capitalize())
        lines.append(f"### [{type_label}] {markdown_escape(rec.item_name)}")
        lines.append("")

        if rec.curated_explanation:
            lines.append(f"*{markdown_escape(rec.curated_explanation)}*")
            lines.append("")

        if rec.fired_rules:
            lines.append(
                f"**Rules:** {', '.join(markdown_escape(rule) for rule in rec.fired_rules)}{MARKDOWN_HARD_BREAK}"
            )

        if rec.confidence_derivation:
            lines.append(f"**Confidence:** {markdown_escape(rec.confidence_derivation)}{MARKDOWN_HARD_BREAK}")

        if rec.matched_evidence:
            lines.append(f"**Evidence:** {len(rec.matched_evidence)} record(s){MARKDOWN_HARD_BREAK}")

        if lines[-1].endswith(MARKDOWN_HARD_BREAK):
            lines[-1] = lines[-1].removesuffix(MARKDOWN_HARD_BREAK)

        if rec.weakening_conditions:
            lines.append("")
            lines.append("**Weakening conditions:**")
            lines.append("")
            for cond in rec.weakening_conditions:
                lines.append(f"- {markdown_escape(cond)}")

        lines.append("")

    return "\n".join(lines)
