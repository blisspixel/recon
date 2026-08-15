"""ADR-0016: `--plain` emits the panel, `--plain --full` emits the record.

`--plain` is the accessibility surface, and it used to linearize the entire
structured record: ~350 lines opening with schema keys and including
`posterior_observations` and `interval_low`. A screen-reader user following the
documented recommendation heard Bayesian interval bounds before they heard which
vendor handled mail, so the accessibility path was the hardest path.

Default `--plain` now renders the panel's own rows. The full record stays
available, byte-compatible, behind `--full`.
"""

from __future__ import annotations

import pytest

from recon_tool.formatter import format_tenant_plain
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
    assert "provider:" not in rendered


def test_plain_keeps_provider_for_a_single_vendor_record() -> None:
    rendered = format_tenant_plain(single_vendor_info())

    assert "provider:" in rendered
    assert "mail:" not in rendered
    assert "identity:" not in rendered


@pytest.mark.parametrize("detailed", [False, True])
def test_plain_tracks_the_panel_role_visibility_split(detailed: bool) -> None:
    """ADR-0012 still governs: --explain/--verbose restore role qualifiers."""
    rendered = format_tenant_plain(split_info(), detailed=detailed)

    assert ("MX delivery path" in rendered) is detailed
