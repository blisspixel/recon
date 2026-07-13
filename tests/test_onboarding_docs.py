"""Drift guards for the first-run trust sequence in user documentation."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_readme_separates_offline_install_check_from_online_diagnostics() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    quick_start = readme.split("## Quick Start", 1)[1].split("## What recon Is Good For", 1)[0]

    assert quick_start.index("recon --version") < quick_start.index("recon doctor")
    assert "offline" in quick_start
    assert "online" in quick_start


def test_network_visibility_is_disclosed_before_readme_first_lookup() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    quick_start = readme.split("## Quick Start", 1)[1].split("## What recon Is Good For", 1)[0]
    before_lookup = quick_start.split("recon contoso.com", 1)[0]

    assert "DNS queries" in before_lookup
    assert "authoritative" in before_lookup
    assert "MTA-STS" in before_lookup
    assert "Google CSE" in before_lookup
    assert "BIMI" in before_lookup
    assert "--direct-probes" in before_lookup


def test_getting_started_uses_the_same_first_run_trust_sequence() -> None:
    guide = (ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8")
    install = guide.split("## Install or Update", 1)[1].split("## Update", 1)[0]
    first_lookup = guide.split("## First Lookup", 1)[1].split("## Input Normalization", 1)[0]

    assert install.index("recon --version") < install.index("recon doctor")
    assert "offline" in install
    assert "online" in install
    assert "DNS queries" in first_lookup
    assert "authoritative" in first_lookup
    assert "MTA-STS" in first_lookup
    assert "Google CSE" in first_lookup
    assert "BIMI" in first_lookup
    assert "--direct-probes" in first_lookup


def test_agent_guides_use_explained_json_and_bounded_catalog_pages() -> None:
    paths = (
        ROOT / "AGENTS.md",
        ROOT / "agents" / "claude-code" / "skills" / "recon" / "SKILL.md",
    )

    for path in paths:
        guidance = path.read_text(encoding="utf-8")
        assert 'lookup_tenant(domain, format="json", explain=true)' in guidance
        assert "lookup_tenant(domain, explain=true)" not in guidance
        assert "`lookup_tenant` with `explain=true`" not in guidance
        assert "get_fingerprints(limit=20, offset=0)" in guidance
        assert "a first page cannot establish absence" in guidance
        assert "returns parsed objects directly" not in guidance
        assert "the other data tools expose structured results" not in guidance
        assert "many analysis and catalog tools expose structured results" in guidance


def test_mcp_onboarding_requests_json_for_explanation_dag() -> None:
    guide = (ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")

    assert "with format=json and explain=true" in guide
    assert 'When `format="json"` and `explain=true`' in guide
    assert 'requires `format="json"` with\n`explain=true`' in guide
    assert '"Look up contoso.com with explain=true.' not in guide
