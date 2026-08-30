"""Keep MCP documentation in sync with all live tool annotations.

`docs/mcp.md` tells a consumer which tools advertise read-only operation and
which are stateful. That guidance is only trustworthy if it matches every
annotation the server actually advertises, so this test parses the doc and
compares it to the registered tools. A new tool, or a tool whose behavioral
hints change, fails CI until the contract is reviewed.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from recon_tool.mcp_client.sdk_compat import model_wire_dict
from recon_tool.server import mcp

_MCP_DOC = Path(__file__).resolve().parents[1] / "docs" / "mcp.md"
_CLAUDE_PLUGIN_README = Path(__file__).resolve().parents[1] / "agents" / "claude-code" / "README.md"


def _tool_hints() -> dict[str, bool]:
    """Map every registered tool name to its explicit readOnlyHint."""

    async def _list() -> dict[str, bool]:
        hints: dict[str, bool] = {}
        for tool in await mcp.list_tools():
            ann = tool.annotations
            # Read through the wire dictionary: the SDK generations expose this
            # field under disjoint attribute names and only the protocol
            # spelling is present on both.
            hint = None if ann is None else model_wire_dict(ann).get("readOnlyHint")
            if hint is None:
                msg = f"{tool.name} must declare readOnlyHint explicitly"
                raise AssertionError(msg)
            hints[tool.name] = hint
        return hints

    return asyncio.run(_list())


def _all_tool_annotations() -> dict[str, dict[str, bool]]:
    """Map every registered tool to its four explicit protocol hints."""

    async def _list() -> dict[str, dict[str, bool]]:
        annotations: dict[str, dict[str, bool]] = {}
        for tool in await mcp.list_tools():
            wire = {} if tool.annotations is None else model_wire_dict(tool.annotations)
            values: dict[str, bool] = {}
            for field in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                value = wire.get(field)
                if not isinstance(value, bool):
                    raise AssertionError(f"{tool.name} must declare {field} explicitly")
                values[field] = value
            annotations[tool.name] = values
        return annotations

    return asyncio.run(_list())


def _tool_descriptions() -> dict[str, str]:
    """Map every registered tool name to its live discovery description."""

    async def _list() -> dict[str, str]:
        return {tool.name: tool.description or "" for tool in await mcp.list_tools()}

    return asyncio.run(_list())


def _available_tools_section() -> str:
    text = _MCP_DOC.read_text(encoding="utf-8")
    start = text.index("## Available Tools")
    end = text.index("## Catalog Resources", start)
    return text[start:end]


def _catalog_resources_section() -> str:
    text = _MCP_DOC.read_text(encoding="utf-8")
    start = text.index("## Catalog Resources")
    end = text.index("## Staleness Timestamps", start)
    return text[start:end]


def _documented_table_names(section: str) -> set[str]:
    """Tool names from the Available Tools table (first backticked cell)."""
    names: set[str] = set()
    for line in section.splitlines():
        if line.startswith("| `"):
            match = re.match(r"\|\s*`([a-z_][a-z0-9_]*)`", line)
            if match:
                names.add(match.group(1))
    return names


def _documented_stateful_names(section: str) -> set[str]:
    """Tool names from the stateful annotation guidance."""
    names: set[str] = set()
    for line in section.splitlines():
        if line.startswith("- `"):
            match = re.match(r"-\s*`([a-z_][a-z0-9_]*)`", line)
            if match:
                names.add(match.group(1))
    return names


def test_available_tools_table_lists_every_tool() -> None:
    section = _available_tools_section()
    assert _documented_table_names(section) == set(_tool_hints())


def test_documented_stateful_set_matches_annotations() -> None:
    section = _available_tools_section()
    live_stateful = {name for name, read_only in _tool_hints().items() if not read_only}
    assert _documented_stateful_names(section) == live_stateful


def test_all_tool_annotations_match_reviewed_behavior() -> None:
    """Every discovery hint is an exact reviewed contract, not a default."""
    annotations = _all_tool_annotations()
    expected_names = {
        "analyze_posture",
        "assess_exposure",
        "build_review_bundle",
        "chain_lookup",
        "clear_ephemeral_fingerprints",
        "cluster_verification_tokens",
        "compare_postures",
        "discover_fingerprint_candidates",
        "explain_dag",
        "explain_signal",
        "export_graph",
        "find_hardening_gaps",
        "get_fingerprints",
        "get_infrastructure_clusters",
        "get_posteriors",
        "get_signals",
        "inject_ephemeral_fingerprint",
        "list_ephemeral_fingerprints",
        "lookup_tenant",
        "reevaluate_domain",
        "reload_data",
        "simulate_hardening",
        "test_hypothesis",
    }
    assert set(annotations) == expected_names

    explicit_mutations = {
        "clear_ephemeral_fingerprints",
        "inject_ephemeral_fingerprint",
        "reevaluate_domain",
        "reload_data",
    }
    destructive_mutations = {
        "clear_ephemeral_fingerprints",
        "reevaluate_domain",
        "reload_data",
    }
    open_world = {
        "analyze_posture",
        "assess_exposure",
        "build_review_bundle",
        "chain_lookup",
        "cluster_verification_tokens",
        "compare_postures",
        "discover_fingerprint_candidates",
        "explain_dag",
        "explain_signal",
        "export_graph",
        "find_hardening_gaps",
        "get_infrastructure_clusters",
        "get_posteriors",
        "lookup_tenant",
        "simulate_hardening",
        "test_hypothesis",
    }
    for name, hints in annotations.items():
        assert hints["readOnlyHint"] is (name not in explicit_mutations)
        assert hints["destructiveHint"] is (name in destructive_mutations)
        assert hints["idempotentHint"] is (name != "inject_ephemeral_fingerprint")
        assert hints["openWorldHint"] is (name in open_world)


def test_claude_plugin_approval_guidance_names_every_stateful_tool() -> None:
    readme = _CLAUDE_PLUGIN_README.read_text(encoding="utf-8")
    approval = readme.split("## Approval policy", 1)[1].split("## What this plugin does", 1)[0]
    live_stateful = {name for name, read_only in _tool_hints().items() if not read_only}

    for name in live_stateful:
        assert f"`{name}`" in approval


def test_catalog_resource_examples_cover_resource_consumption_rules() -> None:
    section = _catalog_resources_section()
    compact = re.sub(r"\s+", " ", section)

    for resource in (
        "recon://fingerprints",
        "recon://signals",
        "recon://profiles",
        "recon://review-bundle-schema",
        "recon://schema",
        "recon://surface-inventory",
    ):
        assert section.count(resource) >= 2
    assert "Do not infer that the service is absent from a target domain." in compact
    assert "For quick browsing, start with `get_fingerprints(limit=20, offset=0)`" in compact
    assert "A first page cannot establish that the catalog has no match." in compact
    assert "until a page has fewer than 20 entries" in compact
    assert "Only after the exhaustive check may you say that no published fingerprint was found." in compact
    assert "Pass `profile` to `analyze_posture` only when the target type clearly" in compact
    assert "Use `$defs` for batch, summary, and delta shapes." in compact
    assert "Read `recon://surface-inventory` when a client needs a local map" in compact


def test_live_tool_descriptions_preserve_evidentiary_limits() -> None:
    descriptions = _tool_descriptions()
    chain_description = " ".join(descriptions["chain_lookup"].split())

    assert "does not establish ownership or a corporate relationship" in chain_description
    assert "every ``related_domains`` observation" in chain_description
    assert "each queued name can" in chain_description.lower()
    for breadcrumb in ("CT", "CNAME", "Exchange/identity endpoint", "autodiscover", "DKIM tenant-domain"):
        assert breadcrumb in chain_description
    assert "requires independent triage" in descriptions["discover_fingerprint_candidates"]
    assert "does not establish a third-party service" in descriptions["discover_fingerprint_candidates"]
    assert "real third-party SaaS" not in descriptions["discover_fingerprint_candidates"]
    assert "definitions are not evidence about any queried domain" in descriptions["get_fingerprints"]
    assert "definitions are not evidence about any queried domain" in descriptions["get_signals"]
    assert "likelihood remains explicitly unresolved" in descriptions["test_hypothesis"]
    assert "model-relative diagnostic" in descriptions["explain_dag"]
    assert "calibrated probability" in descriptions["explain_dag"]


def test_live_tool_descriptions_preserve_output_and_state_contracts() -> None:
    descriptions = {name: " ".join(description.lower().split()) for name, description in _tool_descriptions().items()}

    assert "compact text by default" in descriptions["lookup_tenant"]
    assert "json returns a detailed serialized record" in descriptions["lookup_tenant"]
    assert "public dns" in descriptions["lookup_tenant"]
    assert "mta-sts" in descriptions["lookup_tenant"]
    assert "explicit opt-in" in descriptions["lookup_tenant"]
    assert "structured object" in descriptions["get_posteriors"]
    assert "json string" not in descriptions["get_posteriors"]
    assert "list of observation objects by default" in descriptions["analyze_posture"]
    assert "envelope" in descriptions["analyze_posture"]
    assert "gap-report object" in descriptions["find_hardening_gaps"]
    assert "fresh" in descriptions["build_review_bundle"]
    assert "direct probes are always disabled" in descriptions["build_review_bundle"]
    assert "not a security score" in descriptions["build_review_bundle"]

    assert "server process" in descriptions["inject_ephemeral_fingerprint"]
    assert "server process" in descriptions["list_ephemeral_fingerprints"]
    assert "server process" in descriptions["clear_ephemeral_fingerprints"]
    assert "process lookup cache" in descriptions["reevaluate_domain"]
    assert "session cache" not in descriptions["reevaluate_domain"]

    reload_description = descriptions["reload_data"]
    for required in (
        "fingerprint, signal, and posture",
        "process lookup cache",
        "rate limiter",
        "ephemeral catalog",
        "no network",
    ):
        assert required in reload_description


def test_mcp_docs_name_exact_process_wide_state_and_catalog_limits() -> None:
    section = _available_tools_section()
    compact = re.sub(r"\s+", " ", section).lower()

    assert "exactly four explicit configuration or cache-rewrite tools" in compact
    assert "current server process" in compact
    assert "session lookup-result cache" not in compact
    assert "current session" not in compact
    assert "definitions describe matching and derivation capabilities, not target evidence." in compact
    assert "likelihood remains explicitly unresolved" in compact
