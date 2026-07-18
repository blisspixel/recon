"""Panel disclosure: deterministic confidence and model display support.

The Confidence row always reports deterministic source corroboration. With
fusion, a separate Model support row reports the weakest claimed node's
threshold-relative display without turning the hand-set band into confidence.
"""

from __future__ import annotations

import io

from rich.console import Console

from recon_tool.bayesian import load_network
from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, PosteriorObservation, TenantInfo

_NETWORK_NODES = {node.name: node for node in load_network().nodes}
_NODE_BINDING = {
    "m365_tenant": "signal:m365_tenant_observed",
    "email_gateway_present": "signal:email_gateway_mx_observed",
}


def _obs(name: str, posterior: float, low: float, high: float) -> PosteriorObservation:
    return PosteriorObservation(
        name=name,
        description=_NETWORK_NODES[name].description,
        posterior=posterior,
        interval_low=low,
        interval_high=high,
        evidence_used=(_NODE_BINDING[name],),
        n_eff=6.0,
        sparse=False,
    )


def _panel_text(posteriors: tuple[PosteriorObservation, ...]) -> str:
    info = TenantInfo(
        tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        display_name="Synthetic Alpha",
        default_domain="alpha.invalid",
        queried_domain="alpha.invalid",
        confidence=ConfidenceLevel.HIGH,
        sources=("oidc", "userrealm", "dns", "ct"),
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        posterior_observations=posteriors,
    )
    console = Console(file=io.StringIO(), width=80, force_terminal=False)
    console.print(render_tenant_panel(info))
    return console.file.getvalue()


def test_high_model_support_is_separate_from_deterministic_confidence() -> None:
    out = _panel_text((_obs("m365_tenant", 0.95, 0.88, 0.99),))
    assert "Confidence   ●●● High (4 sources)" in out
    assert "Model support ●●● display above threshold for the M365 tenant" in out
    assert "believable" not in out
    assert "confident" not in out.lower()


def test_threshold_straddling_display_does_not_demote_confidence() -> None:
    out = _panel_text((_obs("m365_tenant", 0.62, 0.41, 0.78),))
    assert "Confidence   ●●● High (4 sources)" in out
    assert "Model support ●●○ threshold-straddling display for the M365 tenant" in out
    assert "thin on" not in out


def test_below_threshold_mean_avoids_an_evidence_verdict() -> None:
    out = _panel_text((_obs("m365_tenant", 0.38, 0.19, 0.61),))
    assert "Confidence   ●●● High (4 sources)" in out
    assert "Model support ●○○ model mean below threshold for the M365 tenant" in out
    assert "evidence does not back" not in out


def test_no_posteriors_falls_back_to_deterministic_dots() -> None:
    # --no-fusion: no posteriors, deterministic tier only.
    out = _panel_text(())
    assert "Confidence   ●●● High (4 sources)" in out
    assert "Model support" not in out


def test_weakest_claimed_node_drives_model_support_only() -> None:
    # Deterministic confidence stays high; the lower model display is surfaced
    # independently.
    out = _panel_text(
        (
            _obs("m365_tenant", 0.96, 0.90, 0.99),
            _obs("email_gateway_present", 0.58, 0.42, 0.74),
        )
    )
    assert "Confidence   ●●● High (4 sources)" in out
    assert "Model support ●●○ threshold-straddling display for the email gateway" in out


def test_negative_node_does_not_demote_confidence() -> None:
    # A declarative node correctly reporting "not enforcing" (no fired evidence)
    # is not a claim and must not demote the confidence of a strong M365 verdict.
    not_enforcing = PosteriorObservation(
        name="email_security_policy_enforcing",
        description=_NETWORK_NODES["email_security_policy_enforcing"].description,
        posterior=0.06,
        interval_low=0.01,
        interval_high=0.20,
        evidence_used=(),  # nothing fired; absence-driven, not a positive claim
        n_eff=6.0,
        sparse=False,
    )
    out = _panel_text((_obs("m365_tenant", 0.95, 0.88, 0.99), not_enforcing))
    assert "Confidence   ●●● High (4 sources)" in out
    assert "Model support ●●● display above threshold for the M365 tenant" in out
