"""The posterior-reading guidance must stay present.

recon's Bayesian surface returns a point posterior beside an 80% credible
interval and a sparse flag. A consuming LLM agent will latch onto the scalar
and flatten the uncertainty unless the surface tells it not to — the
robot-librarian failure mode (confidently answering rather than saying "I
cannot tell"). The injected server instructions carry a "Reading the
posteriors" section that names the three unresolved signals (sparse, a
0.5-straddling interval, empty evidence) and states that absence is not
disproof (the adversarial missing-data rule). This guards that guidance, and
the tool-level `sparse_count` summary, against silent removal — the same
discipline as the data-not-instructions demarcation.
"""

from __future__ import annotations

from recon_tool.server import _SERVER_INSTRUCTIONS, mcp  # pyright: ignore[reportPrivateUsage]


def test_instructions_carry_the_reading_guidance() -> None:
    collapsed = " ".join(_SERVER_INSTRUCTIONS.lower().split())
    assert "reading the posteriors" in collapsed
    # The interval, not the point estimate, is the answer.
    assert "credible interval" in collapsed
    assert "not just the number" in collapsed
    # The three unresolved signals are named.
    assert "sparse" in collapsed
    assert "empty" in collapsed
    assert "evidence_used" in collapsed
    # Absence-is-not-disproof (the MNAR rule) is spelled out.
    assert "absence is not disproof" in collapsed
    assert "we cannot tell" in collapsed


def test_reading_guidance_is_in_the_live_instructions() -> None:
    assert mcp.instructions is not None
    assert "reading the posteriors" in mcp.instructions.lower()
