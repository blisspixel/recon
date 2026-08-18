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

from recon_tool.explanation_lineage import explanation_lineage_label
from recon_tool.formatter.briefing import BriefingView
from recon_tool.formatter.classify import (
    categorize_services,
    compact_categorized_services,
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
    """Neutralize Markdown structural characters in attacker-derived text.

    The report escapes the full punctuation set on every dynamic field, not a
    readable subset: service labels and insight text can carry substrings parsed
    from source records (a hostile ``FederationBrandName``, a crafted TXT value),
    and ``region``/``auth_type`` come from the identity endpoint. A narrower
    escape was tried and reverted when the injection tests caught it. The cost is
    that a domain reads as ``example\\.com`` when the report is pasted raw; the
    defense is worth more than the polish.
    """
    cleaned = strip_control_chars(value, max_len=len(value)).strip()
    return cleaned.translate(MARKDOWN_ESCAPE)


def _markdown_identifier(value: str) -> str:
    """Render a simple ASCII identifier as code, otherwise as literal text."""
    if value.isascii() and value and all(c.isalnum() or c == "-" for c in value):
        return f"`{value}`"
    return markdown_escape(value)


def _md_header(info: TenantInfo, view: BriefingView, detailed: bool) -> list[str]:
    """Title and key-facts block of the markdown report.

    The title is the queried domain, not the display name: ``display_name`` is
    the attacker-controllable ``FederationBrandName`` from the identity endpoint,
    and promoting it to the document title is the strongest assertion the format
    can make about an unverified string (the same reasoning the CSV path uses for
    formula injection). It is carried below, labelled unverified, on the full
    escape. The block leads with the vendor roles, mirroring the panel and
    ``--plain`` (ADR-0015), so the report answers who handles mail.
    """
    lines: list[str] = []
    source_noun = "source" if view.source_count == 1 else "sources"
    lines.append(f"# Tenant Report: {markdown_escape(info.queried_domain)}")
    lines.append("")
    if view.is_split:
        lines.append(f"**Mail:** {markdown_escape(view.mail or '')}{MARKDOWN_HARD_BREAK}")
        lines.append(f"**Identity:** {markdown_escape(view.identity or '')}{MARKDOWN_HARD_BREAK}")
        lines.append(f"**Provider:** {markdown_escape(view.provider_on_split or '')}{MARKDOWN_HARD_BREAK}")
    else:
        provider = view.provider_detailed if detailed else view.provider
        lines.append(f"**Provider:** {markdown_escape(provider)}{MARKDOWN_HARD_BREAK}")
    if info.display_name:
        lines.append(f"**Display name (unverified):** {markdown_escape(info.display_name)}{MARKDOWN_HARD_BREAK}")
    if info.tenant_id:
        lines.append(f"**Tenant ID:** {_markdown_identifier(info.tenant_id)}{MARKDOWN_HARD_BREAK}")
    if info.default_domain and info.default_domain != info.queried_domain:
        lines.append(f"**Tenant Domain:** {markdown_escape(info.default_domain)}{MARKDOWN_HARD_BREAK}")
    if info.region:
        lines.append(f"**Region:** {markdown_escape(info.region)}{MARKDOWN_HARD_BREAK}")
    if info.auth_type:
        lines.append(f"**Auth Type:** {markdown_escape(info.auth_type)}{MARKDOWN_HARD_BREAK}")
    lines.append(f"**Confidence:** {view.confidence_tier} ({view.source_count} {source_noun}){MARKDOWN_HARD_BREAK}")
    lines.append(
        f"**Evidence Confidence:** {info.evidence_confidence.value}{MARKDOWN_HARD_BREAK}\n"
        f"**Inference Confidence:** {info.inference_confidence.value}"
    )
    lines.append("")
    return lines


def _md_services_split(info: TenantInfo, detailed: bool = False) -> list[str]:
    """Services grouped into Microsoft 365 / Google Workspace / Tech Stack.

    ``detailed`` is the --explain / --verbose report, which keeps every
    evidence-role qualifier. The default report compacts them (ADR-0012) and
    closes the section with one italic pointer at the detailed surfaces.
    """
    categorized = categorize_services(info)
    compacted_count = 0
    dropped_count = 0
    if not detailed:
        categorized, compacted_count, dropped_count = compact_categorized_services(categorized)
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
    # Emitted even when every service was dropped and no section survives: a
    # report that silently omits matches reads as a report that found none.
    # Rendered as a bare italic line rather than a section so the stable H2
    # structure gains no heading.
    notes: list[str] = []
    if compacted_count:
        notes.append("Evidence roles omitted; run with `--explain` for the evidence trail.")
    if dropped_count:
        noun = "match" if dropped_count == 1 else "matches"
        notes.append(f"{dropped_count} unattributed {noun} omitted; `--full` shows every match.")
    if notes:
        lines.append(f"*{' '.join(notes)}*")
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
        # The IdP name comes from the identity endpoint, so it keeps the full escape.
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


def _md_insights(info: TenantInfo, view: BriefingView, full: bool) -> list[str]:
    """Insights section: the briefing's cut by default, every line under --full.

    Insight text is recon-authored controlled vocabulary, so it takes the
    structural escape (readable when pasted raw) rather than the full one.
    """
    insights = info.insights if full else view.insights_display
    if not insights:
        return []
    lines: list[str] = ["## Insights", ""]
    for insight in insights:
        lines.append(f"- {markdown_escape(insight)}")
    if not full:
        note = view.insights_note("--md --full")
        if note is not None:
            lines.append(f"- *{note}*")
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


def _md_related_domains(info: TenantInfo, view: BriefingView, full: bool) -> list[str]:
    """Related-domains section: the high-signal cut by default, all under --full."""
    related = info.related_domains if full else view.related_shown
    if not related:
        return []
    lines: list[str] = ["## Related Domains", ""]
    for d in related:
        lines.append(f"- {markdown_escape(d)}")
    if not full:
        note = view.related_note("--md --full")
        if note is not None:
            lines.append(f"- *{note}*")
    lines.append("")
    return lines


# The scope line the report carries out of the terminal. `--gaps` closes with a
# caveat; the report format, the one most likely to land in a deck or a ticket,
# had none, so the hedge left the terminal stripped off. Static, recon-authored,
# so it needs no escaping.
_MD_SCOPE_CAVEAT = (
    "Scope: these are public observations from DNS, certificate transparency, and "
    "unauthenticated identity endpoints, readable by anyone with `dig` and a browser. "
    "They show what a domain publishes, not what an organization licenses, deploys, or "
    "uses, and are not a security rating."
)


def _md_footer(info: TenantInfo) -> list[str]:
    """Footer: separator, optional degraded-sources note, sources, and scope line."""
    lines: list[str] = ["---"]
    if info.degraded_sources:
        sources_list = ", ".join(markdown_escape(source) for source in info.degraded_sources)
        lines.append(
            f"*Note: Some sources were unavailable ({sources_list}) - subdomain discovery may be incomplete.*"
            f"{MARKDOWN_HARD_BREAK}"
        )
    lines.append(f"*Sources: {', '.join(markdown_escape(source) for source in info.sources)}*")
    lines.append("")
    lines.append(f"*{_MD_SCOPE_CAVEAT}*")
    lines.append("")
    return lines


def format_tenant_markdown(
    info: TenantInfo,
    *,
    detailed: bool = False,
    full: bool = False,
    confidence_mode: str = "hedged",
) -> str:
    """Format TenantInfo as a markdown report.

    A thin orchestrator over the per-section ``_md_*`` builders, each of which
    returns its lines (or an empty list when the section does not apply). The
    report is the panel in Markdown: it leads with the vendor roles, makes the
    briefing's cuts on insights and related domains, and honors
    ``confidence_mode`` (ADR-0017). ``detailed`` is the --explain / --verbose
    report and keeps every evidence-role qualifier; the default compacts them
    (ADR-0012). ``full`` restores every insight and related domain, the report's
    pre-2.16 behavior, named by the ``--md --full`` notes.
    """
    from recon_tool.collection_view import collection_observable_info
    from recon_tool.formatter.briefing import build_briefing

    info = collection_observable_info(info)
    view = build_briefing(info, confidence_mode=confidence_mode, detailed=detailed)
    lines: list[str] = []
    lines.extend(_md_header(info, view, detailed))
    lines.extend(_md_services_split(info, detailed))
    lines.extend(_md_gws_details(info))
    lines.extend(_md_insights(info, view, full))
    lines.extend(_md_cert_intel(info))
    lines.extend(_md_tenant_domains(info))
    lines.extend(_md_related_domains(info, view, full))
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

        lines.append(f"**Lineage:** {explanation_lineage_label(rec.lineage_status)}{MARKDOWN_HARD_BREAK}")

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
