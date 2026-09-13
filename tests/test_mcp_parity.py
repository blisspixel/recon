"""The agent gets the same briefing a human does (ADR-0017).

MCP text was a roll call (every insight and related host joined raw, no role
split) and MCP JSON returned empty fusion where CLI JSON populated it. These pin
the parity: the MCP text surface makes the briefing's cuts, and the MCP JSON
payload carries the same fusion the CLI does.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from recon_tool.server.lookup import _format_lookup_tenant, _lookup_tenant_text
from tests.test_role_split_panel import split_info


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


def test_mcp_text_leads_with_the_role_split() -> None:
    text = _lookup_tenant_text(split_info())
    lines = text.splitlines()

    assert any(line.startswith("Mail: Google Workspace") for line in lines)
    assert any(line.startswith("Identity: Microsoft 365") for line in lines)
    mail_i = next(i for i, line in enumerate(lines) if line.startswith("Mail:"))
    prov_i = next(i for i, line in enumerate(lines) if line.startswith("Provider:"))
    assert mail_i < prov_i


def test_mcp_text_cuts_the_roll_call_and_points_at_json() -> None:
    text = _lookup_tenant_text(_rich())

    assert text.count("host") < 12  # not all 30 hosts
    assert 'use format="json" to see all' in text


def test_mcp_json_carries_fusion() -> None:
    payload = json.loads(_format_lookup_tenant(split_info(), [], "json", explain=False))

    assert payload["fusion_enabled"] is True
    assert len(payload["posterior_observations"]) > 0
    assert payload["slug_confidences"]


@pytest.mark.parametrize("copies", [1, 20])
@pytest.mark.parametrize("degraded_sources", [(), ("dns:mx",)])
def test_mcp_json_fusion_matches_cli_json(copies: int, degraded_sources: tuple[str, ...]) -> None:
    """The Bayesian layer must not vanish between the CLI and MCP for one record."""
    from recon_tool.formatter import format_tenant_json
    from recon_tool.fusion_apply import apply_fusion

    baseline = replace(split_info(), degraded_sources=degraded_sources)
    info = replace(baseline, evidence=baseline.evidence * copies)
    fused = apply_fusion(info)
    cli = json.loads(format_tenant_json(fused))
    mcp = json.loads(_format_lookup_tenant(info, [], "json", explain=False))

    assert cli["fusion_enabled"] == mcp["fusion_enabled"]
    assert cli["slug_confidences"] == mcp["slug_confidences"]
    assert cli["posterior_observations"] == mcp["posterior_observations"]
    baseline_fused = apply_fusion(baseline)
    assert fused.slug_confidences == baseline_fused.slug_confidences
    assert fused.posterior_observations == baseline_fused.posterior_observations
    assert fused.evidence == info.evidence
    assert len(fused.evidence) == len(baseline.evidence) * copies
    if degraded_sources:
        assert "google-workspace" not in cli["slug_confidences"]
