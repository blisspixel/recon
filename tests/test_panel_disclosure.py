"""v2.0.1 panel disclosure: posterior-backed confidence dots and the clause.

With fusion (default from v2.0), the Confidence dots reflect the weakest claimed
node's posterior support and a dimmed line speaks up when a claimed node is thin
or the evidence leans against it. Without posteriors (--no-fusion) the panel is
byte-identical to v1.x. These tests pin the wiring, not the exact styling.
"""

from __future__ import annotations

import io

from rich.console import Console

from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, PosteriorObservation, TenantInfo


def _obs(name: str, posterior: float, low: float, high: float) -> PosteriorObservation:
    return PosteriorObservation(
        name=name,
        description="d",
        posterior=posterior,
        interval_low=low,
        interval_high=high,
        evidence_used=("slug:microsoft365",),
        n_eff=6.0,
        sparse=False,
    )


def _panel_text(posteriors: tuple[PosteriorObservation, ...]) -> str:
    info = TenantInfo(
        tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        display_name="Contoso",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        sources=("oidc", "userrealm", "dns", "ct"),
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        posterior_observations=posteriors,
    )
    console = Console(file=io.StringIO(), width=80, force_terminal=False)
    console.print(render_tenant_panel(info))
    return console.file.getvalue()


def test_confident_claim_shows_three_dots_no_clause() -> None:
    out = _panel_text((_obs("m365_tenant", 0.95, 0.88, 0.99),))
    assert "●●●" in out
    assert "thin on" not in out
    assert "does not back" not in out


def test_thin_claim_demotes_dots_and_speaks_up() -> None:
    out = _panel_text((_obs("m365_tenant", 0.62, 0.41, 0.78),))
    assert "●●○" in out
    assert "thin on the M365 tenant" in out


def test_contested_claim_demotes_further_and_says_evidence_does_not_back() -> None:
    out = _panel_text((_obs("m365_tenant", 0.38, 0.19, 0.61),))
    assert "●○○" in out
    assert "the evidence does not back the M365 tenant" in out


def test_no_posteriors_falls_back_to_deterministic_dots() -> None:
    # --no-fusion: no posteriors, deterministic tier dots, no clause.
    out = _panel_text(())
    assert "●●●" in out  # HIGH tier
    assert "thin on" not in out
    assert "does not back" not in out


def test_weakest_claimed_node_drives_the_dots() -> None:
    # One confident node and one thin node: the thin one wins (weakest link).
    out = _panel_text(
        (
            _obs("m365_tenant", 0.96, 0.90, 0.99),
            _obs("email_gateway_present", 0.58, 0.42, 0.74),
        )
    )
    assert "●●○" in out
    assert "thin on the email gateway" in out


def test_negative_node_does_not_demote_confidence() -> None:
    # A declarative node correctly reporting "not enforcing" (no fired evidence)
    # is not a claim and must not demote the confidence of a strong M365 verdict.
    not_enforcing = PosteriorObservation(
        name="email_security_policy_enforcing",
        description="d",
        posterior=0.06,
        interval_low=0.01,
        interval_high=0.20,
        evidence_used=(),  # nothing fired; absence-driven, not a positive claim
        n_eff=6.0,
        sparse=False,
    )
    out = _panel_text((_obs("m365_tenant", 0.95, 0.88, 0.99), not_enforcing))
    assert "●●●" in out
    assert "thin on" not in out
    assert "does not back" not in out
