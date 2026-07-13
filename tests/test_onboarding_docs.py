"""Drift guards for the first-run trust sequence in user documentation."""

from __future__ import annotations

import json
import re
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


def test_agent_guides_share_collection_delta_and_provenance_contracts() -> None:
    paths = (
        ROOT / "AGENTS.md",
        ROOT / "agents" / "claude-code" / "skills" / "recon" / "SKILL.md",
    )

    for path in paths:
        guidance = path.read_text(encoding="utf-8")
        compact = " ".join(guidance.split())
        assert "authoritative" in compact
        assert "MTA-STS" in compact
        assert "Google CSE" in compact
        assert "BIMI" in compact
        assert "explicit opt-in direct probes" in compact
        assert 'reports "No cached snapshot,"' in compact
        assert "exits with code 3 without emitting a delta" in compact
        assert "returns an empty diff" not in compact
        assert "reachability does not prove exact generation-time lineage" in compact


def test_agent_client_mcp_links_resolve_to_real_headings() -> None:
    mcp_doc = (ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")
    anchors = {
        re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
        for heading in re.findall(r"^#{1,6}\s+(.+)$", mcp_doc, flags=re.MULTILINE)
    }

    for readme in (ROOT / "agents").glob("*/README.md"):
        text = readme.read_text(encoding="utf-8")
        for anchor in re.findall(r"\.\./\.\./docs/mcp\.md#([a-z0-9-]+)", text):
            assert anchor in anchors, f"{readme}: docs/mcp.md#{anchor} does not exist"


def test_agent_installer_guidance_describes_the_canonical_launcher() -> None:
    readmes = (
        ROOT / "agents" / "README.md",
        ROOT / "agents" / "claude-code" / "README.md",
        ROOT / "agents" / "cursor" / "README.md",
        ROOT / "agents" / "kiro" / "README.md",
        ROOT / "agents" / "vscode" / "README.md",
        ROOT / "agents" / "windsurf" / "README.md",
    )

    for readme in readmes:
        text = readme.read_text(encoding="utf-8")
        assert "writes a sys.path-stripping Python fallback when" not in text
        assert "auto-detects whether `recon` is on PATH" not in text


def test_vscode_and_claude_code_use_current_permission_schemas() -> None:
    vscode = json.loads((ROOT / "agents" / "vscode" / "mcp.json").read_text(encoding="utf-8"))
    vscode_block = vscode["servers"]["recon"]
    assert vscode_block["type"] == "stdio"
    assert "autoApprove" not in vscode_block

    vscode_readme = (ROOT / "agents" / "vscode" / "README.md").read_text(encoding="utf-8")
    assert "MCP: Open User Configuration" in vscode_readme
    assert "workspace-scoped only" not in vscode_readme

    claude_readme = (ROOT / "agents" / "claude-code" / "README.md").read_text(encoding="utf-8")
    assert "does not\nauto-approve every tool call" in claude_readme
    assert "The plugin path auto-approves" not in claude_readme


def test_mcp_onboarding_requests_json_for_explanation_dag() -> None:
    guide = (ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")

    assert "with format=json and explain=true" in guide
    assert 'When `format="json"` and `explain=true`' in guide
    assert 'requires `format="json"` with\n`explain=true`' in guide
    assert '"Look up contoso.com with explain=true.' not in guide


def test_agent_guidance_distinguishes_flat_explain_from_both_dags() -> None:
    for path in (
        ROOT / "AGENTS.md",
        ROOT / "agents" / "claude-code" / "skills" / "recon" / "SKILL.md",
    ):
        guidance = path.read_text(encoding="utf-8")
        normalized = " ".join(guidance.split())
        assert "Plain `recon <domain> --explain` emits the panel, per-source status, and flat" in normalized
        assert "`recon <domain> --json --explain` adds the reconstructed provenance graph" in normalized
        assert "`--explain-dag` flag renders the Bayesian inference DAG" in normalized


def test_mcp_docs_describe_narrative_error_results_separately() -> None:
    guide = (ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")
    output_section = guide.split("### Tool output: structured content and errors", 1)[1]
    error_section = output_section.split("### Read-only vs stateful", 1)[0]

    for tool in ("lookup_tenant", "chain_lookup", "explain_dag", "reload_data"):
        assert f"`{tool}`" in error_section
    assert "negative\n`result_limit` raises `ToolError`" in error_section
    assert "unexpected `reload_data` exceptions propagate\nas protocol tool errors" in error_section
    assert "ordinary narrative failure\ntext" in error_section
    assert "Oversized injections return a\nMCP tool error (`isError: true`)" in guide


def test_mcp_readonly_docs_allow_internal_bookkeeping() -> None:
    guide = (ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")
    section = guide.split("### Read-only vs stateful annotations", 1)[1].split(
        "### Reading the model-relative posteriors", 1
    )[0]

    assert "no externally\nvisible side effect" in section
    assert "internal cache, rate-limit, and diagnostic bookkeeping" in section
    assert "it does not mutate\nserver state" not in section
