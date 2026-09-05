"""Every accepted MCP lookup format honors its explanation flag offline."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from unittest.mock import AsyncMock, Mock

import pytest

pytest.importorskip("mcp")

from recon_tool.explanation_lineage import explanation_lineage_label
from recon_tool.formatter.explanations import format_explanations_text
from recon_tool.formatter.markdown import markdown_escape
from recon_tool.models import EvidenceRecord, ExplanationLineageStatus, ExplanationRecord
from recon_tool.server import _cache_clear, _rate_limit, lookup_tenant
from tests.test_cli_explain import SAMPLE_INFO, SAMPLE_RESULTS


@pytest.fixture(autouse=True)
def _isolated_server_state() -> Iterator[None]:
    _cache_clear()
    _rate_limit.clear()
    yield
    _cache_clear()
    _rate_limit.clear()


@pytest.mark.asyncio
@pytest.mark.parametrize("output_format", ["text", "markdown", "json"])
@pytest.mark.parametrize("explain", [False, True])
@pytest.mark.parametrize("degraded", [False, True])
async def test_lookup_explain_is_observable_in_every_accepted_format(
    monkeypatch: pytest.MonkeyPatch, output_format: str, explain: bool, degraded: bool
) -> None:
    info = replace(SAMPLE_INFO, degraded_sources=("dns:dmarc",) if degraded else ())
    resolve = AsyncMock(return_value=(info, SAMPLE_RESULTS))
    monkeypatch.setattr("recon_tool.server.app.resolve_tenant", resolve)

    first = await lookup_tenant("alpha.invalid", format=output_format, explain=explain)
    cached = await lookup_tenant("alpha.invalid", format=output_format, explain=explain)
    assert first == cached
    resolve.assert_awaited_once_with("alpha.invalid")
    if output_format == "json":
        data = json.loads(first)
        assert ("explanations" in data) is explain
        assert ("explanation_dag" in data) is explain
        assert data["degraded_sources"] == (["dns:dmarc"] if degraded else [])
        if explain:
            assert data["explanations"]
            assert all("lineage_status" in record for record in data["explanations"])
    else:
        assert ("Explanations\n" in first) is explain
        assert ("Lineage:" in first) is explain
        marker = markdown_escape("dns:dmarc") if output_format == "markdown" else "dns:dmarc"
        assert (marker in first) is degraded
        assert "explanation_dag" not in first


def _record(status: ExplanationLineageStatus) -> ExplanationRecord:
    exact = status in {ExplanationLineageStatus.EXACT, ExplanationLineageStatus.EXACT_RULE_ONLY}
    evidence = EvidenceRecord(source_type="MX", raw_value="synthetic.invalid", rule_name="Synthetic", slug="synthetic")
    return ExplanationRecord(
        item_name="Synthetic observation",
        item_type="insight",
        matched_evidence=(evidence,) if status is ExplanationLineageStatus.EXACT else (),
        fired_rules=("Synthetic rule",),
        confidence_derivation="Synthetic fixture only",
        weakening_conditions=("Collection may be incomplete",),
        lineage_status=status,
        lineage_rule_ids=("synthetic:rule",) if exact else (),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("output_format", ["text", "markdown", "json"])
@pytest.mark.parametrize("lineage", list(ExplanationLineageStatus))
async def test_lookup_formats_preserve_each_lineage_qualification(
    monkeypatch: pytest.MonkeyPatch, output_format: str, lineage: ExplanationLineageStatus
) -> None:
    monkeypatch.setattr("recon_tool.server.app.resolve_tenant", AsyncMock(return_value=(SAMPLE_INFO, SAMPLE_RESULTS)))
    record = _record(lineage)
    monkeypatch.setattr("recon_tool.server.lookup._lookup_tenant_explanations", Mock(return_value=[record]))
    result = await lookup_tenant("alpha.invalid", format=output_format, explain=True)

    if output_format == "json":
        explanation = json.loads(result)["explanations"][0]
        assert explanation["lineage_status"] == lineage.value
    else:
        label = explanation_lineage_label(lineage)
        assert label in result
        assert "synthetic.invalid" not in result


def test_plain_explanations_do_not_introduce_control_bytes_or_raw_evidence() -> None:
    record = replace(
        _record(ExplanationLineageStatus.EXACT),
        item_name="Synthetic\x1b[31m\nheading",
        curated_explanation="Description\r\ncontinued",
        fired_rules=("Rule\x1b[0m",),
        confidence_derivation="Fixture\nonly",
        weakening_conditions=("Condition\x00value",),
    )
    rendered = format_explanations_text([record])
    assert "\x1b" not in rendered
    assert "\x00" not in rendered
    assert "\r" not in rendered
    assert "\nheading" not in rendered
    assert "synthetic.invalid" not in rendered
    assert "Evidence: 1 record(s)" in rendered
