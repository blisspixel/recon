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

from recon_tool.formatter_classify import is_gws_service, is_m365_service
from recon_tool.models import ExplanationRecord, TenantInfo

# Backslash-escape the Markdown structural characters most useful for
# injection (links, emphasis, code spans, tables, inline HTML). Applied to
# attacker-derived free text (issuer names, display_name) in the markdown
# report so a self-logged-cert issuer or a federation brand name cannot
# inject a `[label](url)` link, a `|` table cell, a code-span breakout, or
# an HTML tag. Control bytes are already removed upstream by
# strip_control_chars; this only neutralizes printable metacharacters.
MARKDOWN_ESCAPE = str.maketrans({c: "\\" + c for c in "`*_[]()|<>"})


def markdown_escape(value: str) -> str:
    """Neutralize Markdown structural characters in attacker-derived text."""
    return value.translate(MARKDOWN_ESCAPE)


def _md_header(info: TenantInfo) -> list[str]:
    """Title and key-facts block of the markdown report."""
    lines: list[str] = []
    lines.append(f"# Tenant Report: {markdown_escape(info.display_name)}")
    lines.append("")
    lines.append(f"**Domain:** {info.queried_domain}  ")
    if info.tenant_id:
        lines.append(f"**Tenant ID:** `{info.tenant_id}`  ")
    lines.append(f"**Default Domain:** {markdown_escape(info.default_domain)}  ")
    if info.region:
        lines.append(f"**Region:** {markdown_escape(info.region)}  ")
    if info.auth_type:
        lines.append(f"**Auth Type:** {markdown_escape(info.auth_type)}  ")
    lines.append(f"**Confidence:** {info.confidence.value} ({len(info.sources)} sources)  ")
    lines.append(
        f"**Evidence Confidence:** {info.evidence_confidence.value}  \n"
        f"**Inference Confidence:** {info.inference_confidence.value}  "
    )
    lines.append("")
    return lines


def _md_services_split(info: TenantInfo) -> list[str]:
    """Services grouped into Microsoft 365 / Google Workspace / Tech Stack."""
    if not info.services:
        return []
    m365_svcs = [s for s in info.services if is_m365_service(s)]
    gws_svcs = [s for s in info.services if is_gws_service(s)]
    other_svcs = [s for s in info.services if not is_m365_service(s) and not is_gws_service(s)]
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
                lines.append(f"- {svc}")
            lines.append("")
    return lines


def _md_gws_details(info: TenantInfo) -> list[str]:
    """Google Workspace details: auth type, identity provider, active modules,
    and client-side encryption."""
    gws_slugs = set(info.slugs)
    has_gws = any(is_gws_service(s) for s in info.services) or "google-workspace" in gws_slugs
    if not has_gws:
        return []
    lines: list[str] = ["## Google Workspace", ""]
    if info.google_auth_type:
        lines.append(f"**Auth Type:** {markdown_escape(info.google_auth_type)}  ")
    if info.google_idp_name:
        lines.append(f"**Identity Provider:** {markdown_escape(info.google_idp_name)}  ")
    # Active modules from GWS CNAME detections.
    gws_modules = [s.replace("Google Workspace: ", "") for s in info.services if s.startswith("Google Workspace: ")]
    if gws_modules:
        lines.append(f"**Active Modules:** {', '.join(gws_modules)}  ")
    cse_svcs = [s for s in info.services if "CSE" in s]
    if cse_svcs:
        lines.append(f"**CSE:** {', '.join(cse_svcs)}  ")
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
        sources_list = ", ".join(info.degraded_sources)
        lines.append(
            f"*Note: Some sources were unavailable ({sources_list}) — subdomain discovery may be incomplete.*  "
        )
    lines.append(f"*Sources: {', '.join(info.sources)}*")
    lines.append("")
    return lines


def format_tenant_markdown(info: TenantInfo) -> str:
    """Format TenantInfo as a markdown report.

    A thin orchestrator over the per-section ``_md_*`` builders, each of which
    returns its lines (or an empty list when the section does not apply).
    Output held byte-identical by ``tests/test_golden_renders.py``
    (``markdown_dense`` / ``markdown_sparse`` / ``markdown_rich``).
    """
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
        type_label = rec.item_type.capitalize()
        lines.append(f"### [{type_label}] {rec.item_name}")
        lines.append("")

        if rec.curated_explanation:
            lines.append(f"*{rec.curated_explanation}*")
            lines.append("")

        if rec.fired_rules:
            lines.append(f"**Rules:** {', '.join(rec.fired_rules)}  ")

        if rec.confidence_derivation:
            lines.append(f"**Confidence:** {rec.confidence_derivation}  ")

        if rec.matched_evidence:
            lines.append(f"**Evidence:** {len(rec.matched_evidence)} record(s)  ")

        if rec.weakening_conditions:
            lines.append("")
            lines.append("**Weakening conditions:**")
            lines.append("")
            for cond in rec.weakening_conditions:
                lines.append(f"- {cond}")

        lines.append("")

    return "\n".join(lines)
