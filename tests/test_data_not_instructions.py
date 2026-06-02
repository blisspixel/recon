"""The data-not-instructions demarcation must stay present.

recon is a conduit of attacker-influenceable strings (DNS TXT, CT SAN names,
BIMI metadata, identity-endpoint responses) into an LLM's context. The injected
server instructions mark that content as data, not instructions, so a consuming
agent does not act on a value that reads like a directive. This guards the
demarcation against silent removal in both the instructions and SECURITY.md.
"""

from __future__ import annotations

from pathlib import Path

from recon_tool.server import _SERVER_INSTRUCTIONS, mcp  # pyright: ignore[reportPrivateUsage]

_SECURITY_MD = Path(__file__).resolve().parents[1] / "SECURITY.md"


def test_instructions_carry_the_demarcation() -> None:
    # Collapse whitespace so the checks do not depend on line wrapping.
    collapsed = " ".join(_SERVER_INSTRUCTIONS.lower().split())
    assert "untrusted observed content" in collapsed
    assert "data, not instructions" in collapsed
    # Never-follow framing is spelled out.
    assert "never as instructions to follow" in collapsed
    # The observed sources are named so the model knows what is untrusted.
    for source in ("dns txt", "certificate- transparency", "bimi", "identity-endpoint"):
        assert source in collapsed


def test_demarcation_is_in_the_live_instructions() -> None:
    assert mcp.instructions is not None
    assert "untrusted observed content" in mcp.instructions.lower()


def test_security_md_documents_the_demarcation() -> None:
    text = _SECURITY_MD.read_text(encoding="utf-8").lower()
    assert "data-not-instructions demarcation" in text
    assert "untrusted observed content" in text
