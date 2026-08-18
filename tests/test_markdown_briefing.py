"""--md is the panel in Markdown: roles, briefing cuts, confidence mode (ADR-0017).

Before 2.16 the Markdown report had no provider row (it could not answer who
handles mail), rendered every insight and related domain as a roll call, ignored
--confidence-mode, and promoted the attacker-controllable display name to the
document title. These pin the fixed behavior.
"""

from __future__ import annotations

from dataclasses import replace

from recon_tool.formatter import format_tenant_markdown
from tests.test_role_split_panel import single_vendor_info, split_info


def _rich():
    return replace(
        split_info(),
        related_domains=(
            "login.beta.invalid",
            "sso.beta.invalid",
            *(f"host{i}.beta.invalid" for i in range(30)),
        ),
        insights=(
            "Email security: observed controls: DMARC reject, DKIM",
            "Federated identity observed; external IdP not identified",
            "Provider indicators co-observed: Microsoft 365, Google Workspace",
            "MX gateway observed: Proofpoint",
            "Certificate issuance concentrated at one issuer",
            "Legacy protocol indicator observed",
            "Tenant region reported as NA",
        ),
    )


def test_title_is_the_queried_domain_not_the_display_name() -> None:
    """display_name is attacker-controllable; it must not be the document title."""
    info = replace(single_vendor_info(), display_name="Totally Legit Bank")
    md = format_tenant_markdown(info)

    assert md.splitlines()[0].startswith("# Tenant Report:")
    assert "# Tenant Report: Totally Legit Bank" not in md
    assert "**Display name (unverified):** Totally Legit Bank" in md


def test_report_answers_who_handles_mail() -> None:
    md = format_tenant_markdown(single_vendor_info())

    assert "**Provider:**" in md


def test_split_leads_with_mail_and_identity() -> None:
    md = format_tenant_markdown(split_info())
    lines = md.splitlines()

    assert any(line.startswith("**Mail:** Google Workspace") for line in lines)
    assert any(line.startswith("**Identity:** Microsoft 365") for line in lines)
    mail_i = next(i for i, line in enumerate(lines) if line.startswith("**Mail:**"))
    prov_i = next(i for i, line in enumerate(lines) if line.startswith("**Provider:**"))
    assert mail_i < prov_i


def test_default_cuts_insights_and_related_with_notes() -> None:
    md = format_tenant_markdown(_rich())

    assert md.count("- host") < 10
    assert "use --md --full to see all" in md
    # The note counts against the record, so a curated-away line is still counted.
    assert "more, use --md --full to see all*" in md


def test_full_restores_every_entry_and_drops_notes() -> None:
    md = format_tenant_markdown(_rich(), full=True)

    # Domains carry the full escape, so match on the host substring.
    assert "host29" in md
    assert "use --md --full to see all" not in md


def test_confidence_mode_reaches_the_insight_wording() -> None:
    info = replace(
        single_vendor_info(),
        insights=("AI-platform indicators observed: Anthropic",),
    )
    hedged = format_tenant_markdown(info, confidence_mode="hedged")
    strict = format_tenant_markdown(info, confidence_mode="strict")

    # Strict mode drops the "indicators observed" hedge, so the reports differ.
    assert hedged != strict
    assert "indicators observed" in hedged
    assert "indicators observed" not in strict


def test_report_carries_a_scope_caveat_out_of_the_terminal() -> None:
    """--md is what lands in a deck; the hedge has to travel with it."""
    md = format_tenant_markdown(single_vendor_info())

    assert "Scope: these are public observations" in md
    assert "not a security rating" in md
