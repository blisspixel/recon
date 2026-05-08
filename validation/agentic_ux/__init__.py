"""Agentic UX validation harness for the v1.9.2 bridge milestone.

The harness drives three persona prompts (security analyst, due-diligence
researcher, ops engineer) across two recon-output fixtures (a dense lookup
of Microsoft's fictional ``contoso.com``, and a hand-stripped
``hardened-sparse`` variant). For each persona / fixture pair the harness
runs twice — once with the v1.9 ``--fusion`` posterior block included,
once with the fusion fields stripped — so a binary scoring rubric can
diff the agent's reasoning between the two runs.

Why agentic, not interview-based: recon's MCP server is a primary user-
facing surface, which means an AI agent reading recon JSON is a real
production persona, not a placeholder for a human one. See
``docs/roadmap.md`` -> v1.9.2 for the full rationale.

The module is deliberately decoupled from ``recon_tool``: nothing here
imports from the package being validated, so the harness can run against
recon outputs captured from any version. Consumers import submodules
directly (``from validation.agentic_ux.providers import ...``).
"""
