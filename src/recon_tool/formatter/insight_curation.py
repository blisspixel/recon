"""Insight curation for the default panel.

Split out of ``panel.py`` so the panel module keeps shrinking under the
file-size ratchet, and because this is editorial *policy* - which insight
lines are laundry lists, restatements of the Services block, or overlapping
wordings of one underlying signal - rather than rendering. It depends on
nothing but the insight strings themselves and does no Rich rendering, so it
is testable in isolation and readable without the panel around it.

The name is public because pyright-strict forbids cross-module access to
underscore names; ``panel.py`` calls it directly.
"""

from __future__ import annotations


def curate_insights(insights: tuple[str, ...]) -> list[str]:
    """Filter and deduplicate insights for the default panel.

    Two kinds of cleanup:

    1. **Drop laundry-list dumps.** Prefixes like ``"Security stack:"``,
       ``"Security-vendor indicators observed:"``, ``"Infrastructure:"``,
       ``"PKI:"``, and ``"Google Workspace module indicators observed:"``
       all duplicate information that
       the Services block already shows in a categorized, deduped
       form. Low-signal organizational-size hints
       (``"mid-size organization"``, ``"domains in tenant"``) read as
       padding and add nothing.

    2. **Collapse overlapping signal families.** Real runs often
       trigger three or four signals about the same underlying pattern
       because `signals.yaml` has multiple rules covering it from
       different angles. On a dual-provider run (M365 tenant + Google
       Workspace via DKIM) the Insights block used to show:

           Dual provider: Google + Microsoft coexistence
           Dual Email Provider: microsoft365, google-workspace
           Dual Email Delivery Path: microsoft365, google-workspace
           Secondary Email Provider Observed: google-workspace

       Four different wordings of the same fact. The curator collapses
       these into a single canonical line, keeping the highest-
       signal wording and dropping the rest.

    The collapse rules are intentionally narrow: only overlapping
    signals that describe the same underlying pattern. Real distinct
    signals ("Edge Layering" vs "Zero Trust Pattern Observed") never collapse
    into each other.
    """
    drop_prefixes = (
        "Security stack:",
        "Security-vendor indicators observed:",
        "Network-security vendor indicator",
        "Device-management vendor indicator",
        "Infrastructure:",
        "PKI:",
        "Google Workspace modules:",  # module list also belongs in Services
        "Google Workspace module indicators observed:",
    )
    # Drop insights that restate what the Services
    # block or header already shows. These follow a "Label: slug1, slug2"
    # pattern where the slugs are visible in the categorized Services
    # section. They add zero interpretation - just a differently-worded
    # service list. Keep insights that synthesize (scores, topology,
    # tier inference, migration patterns, security observations).
    restatement_prefixes = (
        # These all follow the "Label: slug1, slug2" pattern where the
        # slugs are already visible in the categorized Services section.
        # They add zero interpretation - just a differently-worded list.
        "Multi-Cloud:",
        "Dev & Engineering Heavy:",
        "Heavy Outbound Stack:",
        "Modern Collaboration:",
        "Google Cloud Investment:",
        "Google-Native Identity:",
        "Dual provider:",
        "Provider indicators co-observed:",
        "Dual Email Provider:",
        "Dual Email Delivery Path:",
        "Google MTA-STS Enforcing:",
        "AI Platform Diversity:",
        "AI Adoption:",  # bare form; "Without Governance" variant kept (security context)
        "Enterprise Security Stack:",
        "Digital Transformation:",
        "Email gateway:",  # already in Provider line
        "MX gateway observed:",
        "Email Gateway Topology:",
        "Email delivery path:",
        "Secondary Email Provider Observed:",
    )
    curated: list[str] = []
    for line in insights:
        if any(line.startswith(pfx) for pfx in drop_prefixes):
            continue
        if any(line.startswith(pfx) for pfx in restatement_prefixes):
            continue
        lower = line.lower()
        if "mid-size organization" in lower or "domains in tenant" in lower:
            continue
        curated.append(line)

    # ── Collapse overlapping signal families ──────────────────────────

    # Dual-provider family: four overlapping signals all describing
    # "both Microsoft 365 and Google Workspace detected". We keep the
    # most informative wording ("Dual provider: Google + Microsoft
    # coexistence") and drop the rest.
    dual_family_prefixes = (
        "Dual Email Provider:",
        "Dual Email Delivery Path:",
        "Secondary Email Provider Observed:",
    )
    has_canonical_dual = any(
        line.startswith("Dual provider:") or "Google + Microsoft coexistence" in line for line in curated
    )
    if has_canonical_dual:
        curated = [line for line in curated if not any(line.startswith(pfx) for pfx in dual_family_prefixes)]
    else:
        # No canonical line - keep at most one of the family as a
        # promoted representative. "Dual Email Delivery Path" is the
        # most information-dense wording of the three, so prefer it.
        family_lines = [line for line in curated if any(line.startswith(pfx) for pfx in dual_family_prefixes)]
        if len(family_lines) >= 2:
            # Preference order for promotion
            pref_order = (
                "Dual Email Delivery Path:",
                "Dual Email Provider:",
                "Secondary Email Provider Observed:",
            )
            chosen: str | None = None
            for pfx in pref_order:
                for line in family_lines:
                    if line.startswith(pfx):
                        chosen = line
                        break
                if chosen:
                    break
            curated = [line for line in curated if line not in family_lines or line == chosen]

    # "Dual Email Provider" signal family overlap with the older
    # "Dual provider: Google + Microsoft coexistence" insight line:
    # when BOTH the canonical insight and the newer "Dual Email
    # Provider" signal fire, keep only the canonical (human-readable)
    # one. Already handled above via has_canonical_dual; this comment
    # just documents the precedence for future maintainers.

    # ── Email security aux-note dedup ──────────────────────────────
    # The score line ("Email security: <inventory>") already
    # names what's present/absent. The auxiliary "DMARC: none", "No
    # DMARC record at apex", "No DKIM at common selectors" insights
    # restate the same observation in prose. Keep the score line on
    # the default panel; the aux notes stay in the raw `insights`
    # JSON field for consumers that want them.
    has_score_line = any(line.startswith("Email security:") for line in curated)
    if has_score_line:
        curated = [
            line
            for line in curated
            if not line.startswith("No DMARC record")
            and not line.startswith("No valid DMARC policy record")
            and not line.startswith("No DKIM at common selectors")
            and not line.startswith("No DKIM selectors observed")
            and not line.startswith("DKIM not observed")
            and not line.startswith("DMARC: none")
        ]

    # ── Google Workspace identity echo dedup ───────────────────────
    # The insight "Google Workspace: Managed identity (Google-native)"
    # restates the Auth line AND the Identity row in the Services
    # block. On domains with minimal signal this is the third time
    # the same fact appears in the panel. Drop it - the Auth line
    # already says "Managed (Google Workspace)" and the Services
    # block carries the slug detection.
    return [
        line
        for line in curated
        if line != "Google Workspace: Managed identity (Google-native)"
        and not line.startswith("Google Workspace: Managed identity")
    ]

    # Note on the "Cloud-managed identity indicators" insight: the
    # dedup for dual-provider targets happens upstream in
    # insights._auth_insights, which refuses to emit the line when
    # google_auth_type is set (the Auth line's compound format
    # "Managed (Entra ID + Google Workspace)" already carries the
    # same fact). On pure M365 targets the insight DOES fire and
    # the Auth line just says "Managed", so both surfaces carry
    # distinct information - no dedup needed here.
