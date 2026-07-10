"""Tests for FastMCP Server Instructions (v0.10.3)."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")


class TestServerInstructions:
    def test_instructions_present(self) -> None:
        """FastMCP server must be initialized with instructions."""
        from recon_tool.server import mcp

        assert mcp.instructions is not None
        assert len(mcp.instructions) > 500  # substantive, not a placeholder

    def test_instructions_mention_key_tools(self) -> None:
        """Instructions should point the agent at the core tools."""
        from recon_tool.server import mcp

        instructions = mcp.instructions or ""
        assert "lookup_tenant" in instructions
        assert "analyze_posture" in instructions
        assert "find_hardening_gaps" in instructions
        assert "simulate_hardening" in instructions

    def test_instructions_state_invariants(self) -> None:
        """Agents must know the tool is passive and hedged."""
        from recon_tool.server import mcp

        instructions = (mcp.instructions or "").lower()
        assert "passive" in instructions
        assert "hedged" in instructions or "hedge" in instructions

    def test_instructions_name_target_visible_http_boundaries(self) -> None:
        """Instructions must not hide the default and opt-in HTTP requests."""
        from recon_tool.server import mcp

        instructions = mcp.instructions or ""
        assert "MTA-STS" in instructions
        assert "target-visible" in instructions
        assert "Google CSE and BIMI" in instructions
        assert "never touches a target's own HTTP infrastructure" not in instructions

    def test_instructions_describe_score_as_model_bound(self) -> None:
        """Agents must not interpret the compatibility score as a verdict."""
        from recon_tool.server import mcp

        instructions = mcp.instructions or ""
        assert "model-bound public-evidence index" in instructions
        assert "not an overall security score" in instructions

    def test_instructions_explain_confidence(self) -> None:
        """Agents need to interpret High/Medium/Low correctly."""
        from recon_tool.server import mcp

        instructions = mcp.instructions or ""
        assert "High" in instructions
        assert "Medium" in instructions
        assert "Low" in instructions
