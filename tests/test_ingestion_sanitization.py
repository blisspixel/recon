"""Round 6 (Track D): control-char scrubbing of source-derived free text.

A domain owner controls the DMARC ``p=`` value on ``_dmarc.<domain>``, the
Google CSE ``discovery_uri`` host on ``cse.<domain>``, and the federation IdP
name. Those strings flow into ``TenantInfo.dmarc_policy``, ``services``, and
``google_idp_name`` and are rendered to the terminal panel via rich
``Text.append``, which does not strip ESC. ``merge_results`` now scrubs them at
the finalization boundary (alongside display_name / auth_type / region). These
tests pin that, and confirm clean values are untouched.
"""

from __future__ import annotations

from recon_tool.merger import merge_results
from recon_tool.models import SourceResult

# An ESC-introduced ANSI sequence plus payload — the injection a hostile record
# would carry. After scrubbing, the ESC (0x1b) must be gone; printable residue
# may remain but can no longer drive the terminal.
_INJECT = "\x1b[2J\x1b[31mPWNED"


def test_service_string_control_bytes_are_stripped() -> None:
    result = SourceResult(
        source_name="google_workspace",
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        detected_services=(f"CSE Key Manager: host{_INJECT}",),
    )
    merged = merge_results([result], queried_domain="example.com")
    assert merged.services
    assert all("\x1b" not in svc for svc in merged.services)
    # The printable label survives; only the control bytes are removed.
    assert any(svc.startswith("CSE Key Manager") for svc in merged.services)


def test_dmarc_policy_control_bytes_are_stripped() -> None:
    result = SourceResult(
        source_name="dns_records",
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        dmarc_policy=f"none{_INJECT}",
    )
    merged = merge_results([result], queried_domain="example.com")
    assert merged.dmarc_policy is not None
    assert "\x1b" not in merged.dmarc_policy


def test_google_idp_name_control_bytes_are_stripped() -> None:
    result = SourceResult(
        source_name="google_identity",
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        google_idp_name=f"evil-idp{_INJECT}",
    )
    merged = merge_results([result], queried_domain="example.com")
    assert merged.google_idp_name is not None
    assert "\x1b" not in merged.google_idp_name


def test_newline_in_service_is_stripped() -> None:
    # An interior newline would inject an extra line into the line-oriented
    # output an agent or SIEM consumes.
    result = SourceResult(
        source_name="dns_records",
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        detected_services=("Legit Service\nInjected: line",),
    )
    merged = merge_results([result], queried_domain="example.com")
    assert all("\n" not in svc for svc in merged.services)


def test_clean_values_pass_through_unchanged() -> None:
    result = SourceResult(
        source_name="dns_records",
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        dmarc_policy="reject",
        detected_services=("Microsoft 365", "DMARC", "SPF: strict (-all)"),
        google_idp_name="Okta",
    )
    merged = merge_results([result], queried_domain="example.com")
    assert merged.dmarc_policy == "reject"
    assert "Microsoft 365" in merged.services
    assert "SPF: strict (-all)" in merged.services
    assert merged.google_idp_name == "Okta"
