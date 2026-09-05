"""Regression coverage for equivalent repeated-alternation representations."""

from __future__ import annotations

import pytest

from recon_tool.regex_safety import validate_regex


@pytest.mark.parametrize("source", ["catalog:test", "ephemeral:test", "specificity gate"])
@pytest.mark.parametrize(
    "pattern",
    [
        r"^((.|..))+!$",
        r"^((a|aa))+z$",
        r"^(?:(?:a|aa))+z$",
        r"^((?i:a|aa))+z$",
        r"^(\x61|aa)+z$",
        r"^(a|A)+z$",
        r"(?x)^(a b|ab)+z$",
        r"^(?x:a b|ab)+z$",
        r"^(ab|a[b])+z$",
        r"^(a|)+z$",
        r"^((a|aa)){20}z$",
    ],
)
def test_ambiguous_repetition_is_refused_before_matching(pattern: str, source: str) -> None:
    assert not validate_regex(pattern, source)


@pytest.mark.parametrize(
    "pattern",
    [r"(foo|bar)+", r"(?:foo|bar)+", r"(foo\.|bar\.)+", r"^[a-z0-9-]+\.example\.invalid$", r"(a+)"],
)
def test_disjoint_literals_and_ordinary_repetition_remain_accepted(pattern: str) -> None:
    assert validate_regex(pattern, "catalog:test")
    assert validate_regex(pattern, "ephemeral:test")


@pytest.mark.asyncio
async def test_ephemeral_injection_rejects_before_specificity_matching(monkeypatch: pytest.MonkeyPatch) -> None:
    from recon_tool.mcp_client.sdk_compat import ToolError
    from recon_tool.server.ephemeral import inject_ephemeral_fingerprint

    def unexpected_matching(*_args: object, **_kwargs: object) -> None:
        pytest.fail("unsafe expression reached specificity matching")

    monkeypatch.setattr("recon_tool.specificity.evaluate_pattern", unexpected_matching)
    with pytest.raises(ToolError, match="Validation failed"):
        await inject_ephemeral_fingerprint(
            "Synthetic Boundary", "synthetic-boundary", "SaaS", "high", [{"type": "txt", "pattern": r"^((.|..))+!$"}]
        )
