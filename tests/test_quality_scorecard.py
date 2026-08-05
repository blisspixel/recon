"""Contract tests for the aggregate-safe product-quality baseline scorecard."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from scripts.quality_scorecard import (
    _approx_tokens,
    _byte_length,
    _catalog_surface,
    _duplicate_definition_bytes,
    _render_markdown,
    build_scorecard,
)


@pytest.fixture(scope="module")
def scorecard() -> dict[str, Any]:
    """Build the scorecard once; it registers the MCP surface and reads the catalog.

    Module-scoped on purpose. Measuring the MCP surface spins up an asyncio event
    loop, and on Windows every new loop allocates a socket pair for its self-pipe.
    Rebuilding per test multiplies that churn across parallel workers for no gain,
    since the measurement is deterministic for a given revision.
    """
    return build_scorecard()


@pytest.fixture(scope="module")
def mcp_cost(scorecard: dict[str, Any]) -> dict[str, Any]:
    """Reuse the scorecard's MCP measurement rather than recomputing it."""
    return scorecard["measurements"]["mcp_context_cost"]


def test_byte_length_measures_the_compact_wire_form() -> None:
    # Padded JSON must not inflate the reported cost: a client receives the
    # compact form, so the measurement has to ignore incidental whitespace.
    assert _byte_length({"b": 1, "a": 2}) == len('{"a":2,"b":1}')


def test_byte_length_counts_utf8_not_characters() -> None:
    assert _byte_length("é") > len('"é"')


def test_approx_tokens_divides_by_the_declared_divisor() -> None:
    assert _approx_tokens(400) == 100


def test_duplicate_definition_accounting_charges_only_the_repeats() -> None:
    shared = {"type": "string"}
    tools = [
        {"outputSchema": {"$defs": {"Shared": shared, "OnlyHere": {"type": "integer"}}}},
        {"outputSchema": {"$defs": {"Shared": shared}}},
        {"outputSchema": {"$defs": {"Shared": shared}}},
    ]
    result = _duplicate_definition_bytes(tools)

    assert result["tools_carrying_definitions"] == 3
    assert result["distinct_definition_bodies"] == 2
    assert result["bodies_shared_by_multiple_tools"] == 1
    # Three copies of one body means two are redundant, not three.
    assert result["redundant_bytes"] == _byte_length(shared) * 2


def test_duplicate_definition_accounting_separates_same_name_different_body() -> None:
    # Two tools can legitimately define different shapes under one name. Those
    # are not redundant copies and must not be counted as recoverable bytes.
    tools = [
        {"outputSchema": {"$defs": {"Summary": {"type": "string"}}}},
        {"outputSchema": {"$defs": {"Summary": {"type": "integer"}}}},
    ]
    result = _duplicate_definition_bytes(tools)

    assert result["distinct_definition_bodies"] == 2
    assert result["bodies_shared_by_multiple_tools"] == 0
    assert result["redundant_bytes"] == 0


def test_duplicate_definition_accounting_tolerates_a_bare_surface() -> None:
    result = _duplicate_definition_bytes([{"name": "no_schema"}])

    assert result["tools_carrying_definitions"] == 0
    assert result["redundant_bytes"] == 0
    assert result["most_redundant"] == []


def test_mcp_context_cost_reports_the_registered_surface(mcp_cost: dict[str, Any]) -> None:
    assert mcp_cost["tool_count"] == len(mcp_cost["per_tool"])
    assert mcp_cost["tool_count"] > 0
    assert mcp_cost["session_context_bytes"] == mcp_cost["discovery_bytes"] + mcp_cost["instruction_preamble_bytes"]
    assert all(entry["total_bytes"] > 0 for entry in mcp_cost["per_tool"])


def test_mcp_per_tool_costs_are_ranked_largest_first(mcp_cost: dict[str, Any]) -> None:
    sizes = [entry["total_bytes"] for entry in mcp_cost["per_tool"]]

    assert sizes == sorted(sizes, reverse=True)


def test_mcp_headroom_bound_is_not_larger_than_the_payload(mcp_cost: dict[str, Any]) -> None:
    headroom = mcp_cost["headroom"]

    # Dropping a field can only shrink the payload. A trim that appears to grow
    # it would mean the measurement is not reading the same serialization.
    assert headroom["discovery_without_output_schema_bytes"] <= mcp_cost["discovery_bytes"]
    assert 0.0 <= headroom["output_schema_share_of_discovery"] <= 1.0


def test_catalog_surface_rule_counts_reconcile() -> None:
    catalog = _catalog_surface()
    dates = catalog["verification_dates"]

    assert catalog["entries"] > 0
    assert catalog["detection_rules"] == sum(catalog["rules_by_type"].values())
    assert dates["dated_rules"] + dates["undated_rules"] == catalog["detection_rules"]
    assert sum(catalog["entries_by_category"].values()) == catalog["entries"]
    assert sum(catalog["entries_by_confidence"].values()) == catalog["entries"]


def test_scorecard_binds_results_to_a_code_and_catalog_revision(scorecard: dict[str, Any]) -> None:
    # A scorecard that cannot say what it measured is not a baseline.
    revisions = scorecard["revisions"]

    assert revisions["catalog_digest_sha256"]
    assert "commit" in revisions
    assert scorecard["reproduction"]["command"].endswith("scripts/quality_scorecard.py")


def test_scorecard_declares_it_used_neither_network_nor_corpus(scorecard: dict[str, Any]) -> None:
    reproduction = scorecard["reproduction"]

    assert reproduction["network"] == "not used"
    assert reproduction["private_corpus"] == "not used"


def test_scorecard_names_unmeasured_channels_with_a_blocker(scorecard: dict[str, Any]) -> None:
    # Phase 1 requires unmeasured channels to be named. An empty ledger would
    # read as full coverage, which is the failure this section exists to stop.
    unmeasured = scorecard["unmeasured"]

    assert unmeasured
    assert all(entry["metric"] and entry["blocker"] and entry["reason"] for entry in unmeasured)


def test_scorecard_names_an_owner_for_everything_it_delegates(scorecard: dict[str, Any]) -> None:
    delegated = scorecard["measured_elsewhere"]

    assert delegated
    assert all(entry["owner"] and entry["reason"] for entry in delegated)


def test_scorecard_is_json_serializable(scorecard: dict[str, Any]) -> None:
    assert json.loads(json.dumps(scorecard, sort_keys=True)) == scorecard


def test_markdown_memo_reports_the_measured_numbers(scorecard: dict[str, Any]) -> None:
    memo = _render_markdown(scorecard)
    cost = scorecard["measurements"]["mcp_context_cost"]

    assert "# Product-quality baseline scorecard" in memo
    assert f"{cost['session_context_bytes']:,} bytes" in memo
    assert "## Unmeasured" in memo
    for entry in scorecard["unmeasured"]:
        assert entry["metric"] in memo


def test_markdown_memo_never_prints_a_non_commit_hash_as_a_commit_receipt(scorecard: dict[str, Any]) -> None:
    # test_documentation_integrity resolves every backticked hex string in
    # validation/*.md as a git commit. The catalog digest is a content hash, so
    # it must not be emitted bare or a committed memo breaks that gate.
    memo = _render_markdown(scorecard)
    receipts = set(re.findall(r"`([0-9a-f]{7,40})`", memo))
    digest = scorecard["revisions"]["catalog_digest_sha256"] or ""

    assert digest[:12] not in receipts
    assert f"`sha256:{digest[:12]}`" in memo


def test_markdown_memo_tolerates_an_absent_git_revision(scorecard: dict[str, Any]) -> None:
    # The harness must still render inside a source archive with no git metadata.
    detached = {**scorecard, "revisions": {**scorecard["revisions"], "commit": None}}

    assert "unknown" in _render_markdown(detached)
