"""The agent gets the same briefing a human does (ADR-0017).

MCP text was a roll call (every insight and related host joined raw, no role
split) and MCP JSON returned empty fusion where CLI JSON populated it. These pin
the parity: the MCP text surface makes the briefing's cuts, and the MCP JSON
payload carries the same fusion the CLI does.
"""

from __future__ import annotations

import json
from dataclasses import replace

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


def test_mcp_json_fusion_matches_cli_json() -> None:
    """The Bayesian layer must not vanish between the CLI and MCP for one record."""
    from recon_tool.formatter import format_tenant_json
    from recon_tool.fusion_apply import apply_fusion

    info = split_info()
    cli = json.loads(format_tenant_json(apply_fusion(info)))
    mcp = json.loads(_format_lookup_tenant(info, [], "json", explain=False))

    assert cli["fusion_enabled"] == mcp["fusion_enabled"]
    cli_names = [p["name"] for p in cli["posterior_observations"]]
    mcp_names = [p["name"] for p in mcp["posterior_observations"]]
    assert cli_names == mcp_names
