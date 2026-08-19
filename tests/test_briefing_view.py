"""The shared briefing view: one definition every renderer consumes.

`build_briefing` bundles the selection helpers (role split, related-domain and
insight cuts, confidence scalars) into one object so `--md` and the MCP text
surface make the same cut the panel and `--plain` already make. These pins are
the contract the surface-parity gate builds on: the numbers here are what every
renderer must show for the same record.
"""

from __future__ import annotations

from dataclasses import replace

from recon_tool.formatter.briefing import build_briefing
from tests.test_role_split_panel import single_vendor_info, split_info


def _rich(**over: object):
    """A record whose lists the briefing must cut and whose insights it curates."""
    fields: dict[str, object] = {
        "related_domains": (
            "login.beta.invalid",
            "sso.beta.invalid",
            *(f"host{i}.beta.invalid" for i in range(90)),
            "*.beta.invalid",
            "tenant.onmicrosoft.com",
        ),
        "insights": (
            "Email security: observed controls: DMARC reject, DKIM",
            "Federated identity observed; external IdP not identified",
            "Provider indicators co-observed: Microsoft 365, Google Workspace",
            "MX gateway observed: Proofpoint",
            "Certificate issuance concentrated at one issuer",
            "Legacy protocol indicator observed",
            "Tenant region reported as NA",
        ),
    }
    fields.update(over)
    return replace(split_info(), **fields)


def test_split_carries_the_roles_and_the_tagged_provider() -> None:
    view = build_briefing(split_info(), confidence_mode="hedged", detailed=False)

    assert view.is_split
    assert view.mail == "Google Workspace"
    assert view.identity == "Microsoft 365"
    # The provider the linear surfaces keep after the roles carries its role.
    assert view.provider_on_split == "Google Workspace (MX delivery path)"


def test_detailed_keeps_the_role_qualifier_on_mail() -> None:
    default = build_briefing(split_info(), confidence_mode="hedged", detailed=False)
    detailed = build_briefing(split_info(), confidence_mode="hedged", detailed=True)

    assert "MX delivery path" not in (default.mail or "")
    assert "MX delivery path" in (detailed.mail or "")


def test_single_vendor_has_no_roles() -> None:
    view = build_briefing(single_vendor_info(), confidence_mode="hedged", detailed=False)

    assert not view.is_split
    assert view.mail is None
    assert view.identity is None
    assert view.provider_on_split is None
    assert view.provider


def test_class_named_hosts_outrank_cdn_and_e2e_test_hosts() -> None:
    """Company B shape: a cdn/e2e/test run must not hide sso./shop./workday."""
    from recon_tool.formatter.briefing import high_signal_related

    related = (
        "api.beta.invalid",
        "cdn.e2eprod1.beta.invalid",
        "cdn.e2eprod2.beta.invalid",
        "cdn.shrm.test.beta.invalid",
        "cdn.ssocm.corp.beta.invalid",
        "sso.beta.invalid",
        "shop.beta.invalid",
        "workday.beta.invalid",
        "auth.beta.invalid",
        "idp.beta.invalid",
        "accounts.beta.invalid",
        "random.beta.invalid",
    )
    picked, total = high_signal_related(related)

    assert total == 12
    assert picked[0] == "auth.beta.invalid"
    assert "sso.beta.invalid" in picked
    assert "shop.beta.invalid" in picked
    assert "workday.beta.invalid" in picked
    assert "idp.beta.invalid" in picked
    assert "accounts.beta.invalid" in picked
    assert "api.beta.invalid" in picked
    assert all("e2eprod" not in name and ".test." not in name for name in picked)
    assert "cdn.ssocm.corp.beta.invalid" not in picked
    assert "random.beta.invalid" in picked


def test_cdn_hosts_still_fill_when_no_class_named_hosts() -> None:
    from recon_tool.formatter.briefing import high_signal_related

    related = tuple(f"cdn{i}.beta.invalid" for i in range(12))
    picked, total = high_signal_related(related)

    assert total == 12
    assert picked == list(related[:8])


def test_related_note_reconciles_against_the_record() -> None:
    view = build_briefing(_rich(), confidence_mode="hedged", detailed=False)

    assert len(view.related_shown) == 8
    assert view.related_total == 94  # every entry --full prints, wildcards included
    assert view.related_note() == "94 total, 86 more, use --plain --full to see all"


def test_insight_note_counts_the_record_not_the_curated_set() -> None:
    view = build_briefing(_rich(), confidence_mode="hedged", detailed=False)

    # Two of the seven are curated away, so the panel's overflow and the record
    # remainder differ: the note the linear surfaces show counts the record.
    assert view.insights_record_total == 7
    assert len(view.insights_display) + _note_more(view.insights_note()) == 7


def test_a_curated_line_is_still_a_withheld_line() -> None:
    """Under the cap, still missing lines, so the note must still fire."""
    view = build_briefing(
        _rich(
            insights=(
                "Email security: observed controls: DMARC reject, DKIM",
                "Federated identity observed; external IdP not identified",
                "Certificate issuance concentrated at one issuer",
                "Provider indicators co-observed: Microsoft 365, Google Workspace",
                "MX gateway observed: Proofpoint",
            )
        ),
        confidence_mode="hedged",
        detailed=False,
    )

    assert len(view.insights_display) == 3
    assert view.insights_note() == "2 more, use --plain --full to see all"


def test_no_note_when_nothing_withheld() -> None:
    view = build_briefing(single_vendor_info(), confidence_mode="hedged", detailed=False)

    assert view.related_note() is None
    assert view.insights_note() is None


def test_view_is_frozen() -> None:
    view = build_briefing(split_info(), confidence_mode="hedged", detailed=False)

    try:
        view.provider = "mutated"  # type: ignore[misc]
    except AttributeError:
        return
    raise AssertionError("BriefingView must be immutable")


def _note_more(note: str | None) -> int:
    assert note is not None
    (more,) = (int(w) for w in note.split() if w.isdigit() and f"{w} more" in note)
    return more
