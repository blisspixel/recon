"""Real TXT RDATA bytes reach policy parsers without presentation escaping."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import dns.rdata
import dns.rrset
import pytest

from recon_tool.sources import dns_base, dns_email
from recon_tool.sources.dns_tables import is_dkim_key_record
from recon_tool.validator import strip_control_chars


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("wire_text", "expected"),
    [
        (r'"v=DKIM1;\009" "p=YWJj"', "v=DKIM1;\tp=YWJj"),
        (r'"proof=quote\"and\\slash"', 'proof=quote"and\\slash'),
        (r'"v=spf1 include:sendgrid.net" " -all"', "v=spf1 include:sendgrid.net -all"),
        (r'"bad=\027[2J\010forged"', "bad=\x1b[2J\nforged"),
    ],
)
async def test_txt_character_strings_preserve_exact_values(
    monkeypatch: pytest.MonkeyPatch, wire_text: str, expected: str
) -> None:
    rdata = dns.rdata.from_text("IN", "TXT", wire_text)
    answers = MagicMock()
    answers.canonical_name = "example.com."
    answers.__iter__.return_value = iter([rdata])
    resolver = MagicMock()
    resolver.resolve = AsyncMock(return_value=answers)
    monkeypatch.setattr(dns_base, "get_resolver", lambda: resolver)
    values = await dns_base.safe_resolve("example.com", "TXT")
    assert values == [expected]
    if expected.startswith("v=DKIM1"):
        assert is_dkim_key_record(values[0])
    rendered = strip_control_chars(values[0])
    assert "\x1b" not in rendered
    assert "\n" not in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize("split_record", [False, True])
async def test_spf_cardinality_counts_wire_records_before_text_deduplication(
    monkeypatch: pytest.MonkeyPatch, split_record: bool
) -> None:
    records = dns.rrset.from_text(
        "example.com",
        60,
        "IN",
        "TXT",
        '"v=spf1 -all"',
        '"v=spf1 " "-all"' if split_record else '"v=spf1 -all"',
    )
    answers = MagicMock()
    answers.canonical_name = "example.com."
    answers.__iter__.side_effect = records.__iter__
    resolver = MagicMock()
    resolver.resolve = AsyncMock(return_value=answers)
    monkeypatch.setattr(dns_base, "get_resolver", lambda: resolver)
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")
    assert ("SPF: strict (-all)" in ctx.services) is (not split_record)
