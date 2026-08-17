"""ADR-0016: `--plain` emits the panel, `--plain --full` emits the record.

`--plain` is the accessibility surface, and it used to linearize the entire
structured record: ~350 lines opening with schema keys and including
`posterior_observations` and `interval_low`. A screen-reader user following the
documented recommendation heard Bayesian interval bounds before they heard which
vendor handled mail, so the accessibility path was the hardest path.

Default `--plain` now renders the panel's own rows. The full record stays
available, byte-compatible, behind `--full`.

A follow-up pass found the residual these also pin: the rows were the panel's,
but the *cuts* were not, so a populated record still read the whole
related-domain list aloud. And `provider:`, the key the guide tells a stranger
to grep, went missing on exactly the record class the role split exists for.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from recon_tool.formatter import format_tenant_plain
from recon_tool.models import TenantInfo
from tests.test_role_split_panel import single_vendor_info, split_info

# Keys that only ever belonged to the full record. Their presence in the
# default output is the regression this file exists to catch. Chosen to be
# always-emitted envelope fields rather than fixture-dependent ones, so the
# test fails on a real leak instead of passing because a fixture was sparse.
_FULL_RECORD_ONLY = ("schema_version", "record_type", "fusion_enabled", "evidence_confidence")


def test_default_plain_is_the_panel_not_the_record() -> None:
    rendered = format_tenant_plain(split_info())

    assert "queried_domain: beta.invalid" in rendered
    assert "tenant_id: c7c08208-4f4d-45f1-83cd-5e2f491ab786" in rendered
    assert "auth_type: Federated" in rendered
    for key in _FULL_RECORD_ONLY:
        assert key not in rendered


def test_default_plain_is_short_enough_to_hear() -> None:
    # The exact count will drift with fixtures; the contract is "a briefing,
    # not a dump". The pre-ADR output for this same fixture was 79 lines.
    assert len(format_tenant_plain(split_info()).splitlines()) < 25


def test_full_restores_every_record_field() -> None:
    rendered = format_tenant_plain(split_info(), full=True)

    for key in _FULL_RECORD_ONLY:
        assert f"{key}:" in rendered
    assert len(rendered.splitlines()) > len(format_tenant_plain(split_info()).splitlines())


def test_plain_uses_stable_schema_key_names() -> None:
    """A grep written against the full record must still match the panel."""
    rendered = format_tenant_plain(split_info())

    # Not "Tenant"/"Provider" (the panel's display labels) but the schema names.
    assert "tenant_id:" in rendered
    assert "Tenant " not in rendered


def test_plain_carries_the_role_split(  # ADR-0015 reaches the linear surface too
) -> None:
    rendered = format_tenant_plain(split_info())

    assert "mail: Google Workspace" in rendered
    assert "identity: Microsoft 365" in rendered


def test_split_keeps_provider_but_leads_with_the_roles() -> None:
    """The documented `grep provider:` must not miss the split record.

    `provider` is the MX-delivery-path summary on every other surface, and a
    reader hearing the file top-down still meets the roles first.
    """
    lines = format_tenant_plain(split_info()).splitlines()
    keys = [line.split(":", 1)[0] for line in lines]

    assert keys.index("mail") < keys.index("provider")
    assert keys.index("identity") < keys.index("provider")
    assert "provider: Google Workspace (MX delivery path)" in lines


def test_split_provider_says_why_it_repeats_the_vendor() -> None:
    """A screen reader hears the mail vendor twice; the second time has a reason.

    ADR-0012 compacts evidence roles out of the default view. This key is the
    exception: on a split it repeats the word `mail:` just said, so without the
    role it is a stutter rather than a second fact.
    """
    lines = format_tenant_plain(split_info()).splitlines()

    assert "mail: Google Workspace" in lines
    assert "provider: Google Workspace (MX delivery path)" in lines
    # Single-vendor records repeat nothing, so nothing needs explaining.
    assert "provider: Microsoft 365" in format_tenant_plain(single_vendor_info()).splitlines()


def test_plain_keeps_provider_for_a_single_vendor_record() -> None:
    rendered = format_tenant_plain(single_vendor_info())

    assert "provider:" in rendered
    assert "mail:" not in rendered
    assert "identity:" not in rendered


@pytest.mark.parametrize("detailed", [False, True])
def test_plain_tracks_the_panel_role_visibility_split(detailed: bool) -> None:
    """ADR-0012 still governs the labels: --explain/--verbose restore the roles.

    `provider:` on a split is the one exception and is pinned separately.
    """
    lines = format_tenant_plain(split_info(), detailed=detailed).splitlines()
    labels = [line for line in lines if line.startswith(("  - ", "mail:"))]

    assert any("MX delivery path" in line for line in labels) is detailed


def _rich_record() -> TenantInfo:
    """A populated record: the case where the briefing had to stay a briefing."""
    return replace(
        split_info(),
        related_domains=(
            "login.beta.invalid",
            "sso.beta.invalid",
            *(f"host{index}.beta.invalid" for index in range(90)),
        ),
        insights=(
            "Email security: observed controls: DMARC reject, DKIM",
            "Federated identity observed; external IdP not identified",
            "Edge Layering observed",
            "Certificate issuance concentrated at one issuer",
            "Legacy protocol indicator observed",
            "Tenant region reported as NA",
            "CDN fronting observed at the apex",
        ),
    )


def test_rich_record_keeps_the_panel_related_domain_cut() -> None:
    """The reported residual: 92 hostnames read aloud before the insights."""
    rendered = format_tenant_plain(_rich_record())

    assert rendered.count("- host") < 10
    assert "related_domains_note: 92 total, 84 more, use --plain --full to see all" in rendered
    # The panel's selection, not the first N: high-signal names lead.
    assert rendered.index("login.beta.invalid") < rendered.index("host0.beta.invalid")


def test_rich_record_caps_insights_and_says_how_many_it_withheld() -> None:
    rendered = format_tenant_plain(_rich_record())

    assert "insights_note: 2 more, use --plain --full to see all" in rendered


def test_full_still_carries_every_related_domain() -> None:
    """The cut is the briefing's, not the record's."""
    rendered = format_tenant_plain(_rich_record(), full=True)

    assert "- host89.beta.invalid" in rendered
    assert "related_domains_note" not in rendered


def test_the_two_renderers_name_the_same_related_domains() -> None:
    """The invariant the shared briefing module exists to hold.

    Drift here is the original defect: the panel cut the list and the linear
    view did not, so the same record was a briefing on one surface and a roll
    call on the other.
    """
    import io

    from rich.console import Console

    from recon_tool.formatter import render_tenant_panel

    info = _rich_record()
    console = Console(file=io.StringIO(), width=78, no_color=True, legacy_windows=False)
    console.print(render_tenant_panel(info))
    panel = console.file.getvalue()

    listed = [
        line.strip().removeprefix("- ")
        for line in format_tenant_plain(info).splitlines()
        if line.strip().startswith("- ") and line.strip().endswith(".invalid")
    ]

    assert listed
    for domain in listed:
        assert domain in panel
    assert "host8.beta.invalid" not in panel
    assert "host8.beta.invalid" not in listed


def _listed(rendered: str, key: str) -> list[str]:
    """Entries rendered under ``key:`` as a list block."""
    entries: list[str] = []
    started = False
    for line in rendered.splitlines():
        if line == f"{key}:":
            started = True
            continue
        if started:
            if line.startswith("  - "):
                entries.append(line.removeprefix("  - "))
                continue
            break
    return entries


def _note_count(rendered: str, key: str) -> int:
    """The remainder a ``*_note`` states, as a number."""
    (note,) = (line for line in rendered.splitlines() if line.startswith(f"{key}:"))
    (more,) = (word for word in note.split() if word.isdigit() and f"{word} more" in note)
    return int(more)


def _curated_record() -> TenantInfo:
    """A record whose insight list the panel curates, not just caps.

    The reported defect needed exactly this: `Provider indicators co-observed:`
    and `MX gateway observed:` are restatements the panel drops and the record
    keeps, so the cap alone never described what `--plain --full` prints. The
    original fixture could not express it because every one of its insights
    survived curation.
    """
    return replace(
        split_info(),
        related_domains=(
            "login.beta.invalid",
            "sso.beta.invalid",
            *(f"host{index}.beta.invalid" for index in range(90)),
            "*.beta.invalid",
            "tenant.onmicrosoft.com",
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


@pytest.mark.parametrize("key", ["related_domains", "insights"])
def test_each_note_reconciles_with_the_flag_it_names(key: str) -> None:
    """Shown plus withheld equals what `--full` prints on this same renderer.

    The note names one flag, so its arithmetic has to land on that flag's
    output. Counting the panel's curated set instead understated the insight
    remainder by every restatement the record keeps.
    """
    info = _curated_record()
    brief = format_tenant_plain(info)
    full = format_tenant_plain(info, full=True)

    assert len(_listed(brief, key)) + _note_count(brief, f"{key}_note") == len(_listed(full, key))


def test_a_curated_line_is_still_a_withheld_line() -> None:
    """A record under the cap can still be missing lines, and has to say so.

    Silence here reads as "you have everything", which is the failure the notes
    exist to prevent, and it is the common case: any record carrying a
    dual-provider or gateway restatement.
    """
    info = replace(
        split_info(),
        insights=(
            "Email security: observed controls: DMARC reject, DKIM",
            "Federated identity observed; external IdP not identified",
            "Certificate issuance concentrated at one issuer",
            "Provider indicators co-observed: Microsoft 365, Google Workspace",
            "MX gateway observed: Proofpoint",
        ),
    )
    brief = format_tenant_plain(info)

    assert len(_listed(brief, "insights")) == 3
    assert _note_count(brief, "insights_note") == 2


def test_related_note_counts_the_names_full_prints() -> None:
    """Wildcards and tenant artefacts are skipped by the selection, not by `--full`.

    They were left out of the total as well, so the footer stated a count the
    reader could not reach from the flag it pointed at.
    """
    info = _curated_record()

    assert "related_domains_note: 94 total, 86 more, use --plain --full to see all" in format_tenant_plain(info)
    assert len(_listed(format_tenant_plain(info, full=True), "related_domains")) == 94


def test_notes_sit_beside_the_list_they_describe() -> None:
    """A screen reader hears the remainder where the remainder belongs."""
    lines = format_tenant_plain(_rich_record()).splitlines()
    keys = [line.split(":", 1)[0].strip() for line in lines]

    assert keys.index("related_domains_note") < keys.index("insights")
    assert keys.index("insights_note") > keys.index("insights")
