"""The model-relative posterior guidance must stay present."""

from __future__ import annotations

from recon_tool.server import _SERVER_INSTRUCTIONS, mcp  # pyright: ignore[reportPrivateUsage]


def test_instructions_carry_the_reading_guidance() -> None:
    collapsed = " ".join(_SERVER_INSTRUCTIONS.lower().split())
    assert "reading the model-relative posteriors" in collapsed
    assert "evidence-responsive uncertainty band" in collapsed
    assert "not a bayesian credible interval" in collapsed
    assert "inspect the provenance" in collapsed

    # The unresolved signals and declarative-absence exception are named.
    assert "sparse" in collapsed
    assert "empty" in collapsed
    assert "evidence_used" in collapsed
    assert "unit_counterfactuals" in collapsed
    assert "observed" in collapsed

    # Non-fire is an explicit policy, not a derivation from MNAR or proof of
    # real-world absence.
    assert "absence is not disproof" in collapsed
    assert "explicit policy" in collapsed
    assert "never infer private-state absence" in collapsed


def test_reading_guidance_is_in_the_live_instructions() -> None:
    assert mcp.instructions is not None
    assert "reading the model-relative posteriors" in mcp.instructions.lower()
