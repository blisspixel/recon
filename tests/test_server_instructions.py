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

    def test_defensive_review_requests_json_before_explanations(self) -> None:
        """The composition example must select the format that carries provenance."""
        from recon_tool.server import mcp

        instructions = mcp.instructions or ""
        assert instructions.count('lookup_tenant(domain, format="json", explain=True)') >= 2
        assert "lookup_tenant(domain, explain=True)" not in instructions
        assert "Prefer `explain=True` on `lookup_tenant`" not in instructions
        assert "returns flat explanations for its observations, not an `explanation_dag`" in instructions

    def test_introspection_starts_with_a_bounded_fingerprint_page(self) -> None:
        """The injected routing guidance must not recommend the full catalog first."""
        from recon_tool.server import mcp

        instructions = mcp.instructions or ""
        assert "get_fingerprints(limit=20, offset=0)" in instructions
        assert "get_fingerprints()" not in instructions
        assert "Before reporting no catalog match" in instructions
        assert "until one returns fewer than 20 entries" in instructions

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
        assert "configured recursive resolver" in instructions
        assert "authoritative DNS" in instructions
        assert "may observe the resulting traffic" in instructions
        assert "only default target-owned HTTP/application" in instructions
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

        instructions = " ".join((mcp.instructions or "").split())
        assert "deterministic merged-output summary tier" in instructions
        assert "same-claim corroboration" in instructions
        assert "not confidence in every claim or a calibrated probability" in instructions
        assert "High (3+ corroborating sources)" not in instructions
        assert "Medium (2 sources, partial)" not in instructions

    def test_instructions_distinguish_default_and_structured_lookup_output(self) -> None:
        """Default text is compact; only the JSON form carries full structured data."""
        from recon_tool.server import mcp

        instructions = " ".join((mcp.instructions or "").split())
        assert "compact agent-readable summary" in instructions
        assert 'format="json"' in instructions
        assert "detailed serialized JSON TenantInfo" in instructions
        assert "Returns the full TenantInfo" not in instructions

    def test_instructions_preserve_related_namespace_limits(self) -> None:
        """CNAME and CT discovery cannot establish a corporate relationship."""
        from recon_tool.server import mcp

        instructions = " ".join((mcp.instructions or "").split())
        assert "does not establish ownership or a corporate relationship" in instructions
        assert "portfolio / subsidiary" not in instructions

    def test_instructions_describe_untrusted_text_sanitization_precisely(self) -> None:
        """Printable directive-like data can survive control-character sanitization."""
        from recon_tool.server import mcp

        instructions = " ".join((mcp.instructions or "").split())
        assert "C0/C1 and bidirectional control characters" in instructions
        assert "printable directive-like text can remain" in instructions
        assert "strips terminal and markdown control sequences" not in instructions

    def test_instructions_bound_cache_only_ephemeral_replay(self) -> None:
        """The zero-network workflow must name what can and cannot be replayed."""
        from recon_tool.server import mcp

        instructions = " ".join((mcp.instructions or "").split())
        for replayable in ("TXT", "SPF", "MX", "NS", "CNAME"):
            assert replayable in instructions
        for fresh_only in ("cname_target", "subdomain_txt", "caa", "srv", "dmarc_rua"):
            assert fresh_only in instructions
        assert "fresh lookup through the normal documented network boundary" in instructions

    def test_instructions_name_exact_process_wide_mutations(self) -> None:
        """Server instructions must expose all stateful effects without session fiction."""
        from recon_tool.server import mcp

        instructions = " ".join((mcp.instructions or "").split())
        assert "Exactly four explicit configuration or cache-rewrite tools" in instructions
        for name in (
            "inject_ephemeral_fingerprint",
            "clear_ephemeral_fingerprints",
            "reload_data",
            "reevaluate_domain",
        ):
            assert f"`{name}`" in instructions
        assert "clears the lookup cache" in instructions
        assert "preserving the rate limiter and ephemeral catalog" in instructions
        assert "replaces one cached result without a network request" in instructions
        assert "current session" not in instructions
