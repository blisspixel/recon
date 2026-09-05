"""Network-free delivery checks for empty, partial, and failed workflows."""

from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import AsyncMock, Mock

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.models import ConfidenceLevel, ReconLookupError, SourceResult, TenantInfo

_RUNNER = CliRunner()


def _empty_info() -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="",
        default_domain="empty.invalid",
        queried_domain="empty.invalid",
        confidence=ConfidenceLevel.LOW,
        sources=("dns_records",),
        ct_attempt_outcome="skipped",
    )


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize(("error_type", "exit_code"), [("no_data", 3), ("timeout", 4), ("all_sources_failed", 4)])
def test_failed_delta_never_replaces_baseline_or_reports_no_changes(
    monkeypatch: pytest.MonkeyPatch, error_type: str, exit_code: int, json_output: bool
) -> None:
    baseline = _empty_info()
    resolver = AsyncMock(
        side_effect=ReconLookupError(
            domain=baseline.queried_domain,
            message="Synthetic collection failure",
            error_type=error_type,
        )
    )
    cache_put = Mock()
    monkeypatch.setattr("recon_tool.cache.cache_get", Mock(return_value=baseline))
    monkeypatch.setattr("recon_tool.cache.cache_put", cache_put)
    monkeypatch.setattr("recon_tool.resolver.resolve_tenant", resolver)

    result = _RUNNER.invoke(app, ["delta", baseline.queried_domain, *(["--json"] if json_output else [])])

    assert result.exit_code == exit_code, result.output
    assert result.stdout == ""
    assert result.stderr
    assert "No changes" not in result.output
    cache_put.assert_not_called()
    resolver.assert_awaited_once()


@pytest.mark.parametrize("json_output", [False, True])
def test_partial_empty_delta_reports_limits_instead_of_complete_no_change(
    monkeypatch: pytest.MonkeyPatch, json_output: bool
) -> None:
    baseline = _empty_info()
    current = replace(baseline, degraded_sources=("dns:dmarc",))
    resolver = AsyncMock(return_value=(current, []))
    cache_put = Mock()
    monkeypatch.setattr("recon_tool.cache.cache_get", Mock(return_value=baseline))
    monkeypatch.setattr("recon_tool.cache.cache_put", cache_put)
    monkeypatch.setattr("recon_tool.resolver.resolve_tenant", resolver)

    result = _RUNNER.invoke(app, ["delta", baseline.queried_domain, *(["--json"] if json_output else [])])

    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    if json_output:
        payload = json.loads(result.stdout)
        assert payload["has_changes"] is False
        limitations = payload["incomplete_comparison"]
        assert limitations["current_degraded_sources"] == ["dns:dmarc"]
        assert "changed_dmarc_policy" in limitations["suppressed_fields"]
        assert "changed_email_security_score" in limitations["suppressed_fields"]
    else:
        assert "No confirmed changes detected" in result.stdout
        assert "dns:dmarc" in result.stdout
        assert "incomplete" in result.stdout.lower()
        assert "No changes detected" not in result.stdout
    cache_put.assert_called_once_with(baseline.queried_domain, current)
    resolver.assert_awaited_once()


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize("partial", [False, True])
def test_sparse_review_preserves_collection_state_without_extra_resolution(
    monkeypatch: pytest.MonkeyPatch, json_output: bool, partial: bool
) -> None:
    degraded = ("dns:dmarc",) if partial else ()
    info = replace(_empty_info(), degraded_sources=degraded)
    source = SourceResult(source_name="dns_records", degraded_sources=degraded, ct_attempt_outcome="skipped")
    resolver = AsyncMock(return_value=(info, [source]))
    monkeypatch.setattr("recon_tool.resolver.resolve_tenant", resolver)

    result = _RUNNER.invoke(app, ["review", info.queried_domain, "--no-ct", *(["--json"] if json_output else [])])

    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    if json_output:
        payload = json.loads(result.stdout)
        assert payload["workflow"]["status"] == "completed"
        assert payload["workflow"]["collection_validity"] == (
            "partial" if partial else "complete_for_recorded_opportunities"
        )
        assert payload["workflow"]["freshness_assessment"] == "not_assigned"
        assert payload["result"]["explained_baseline"]["lookup"]["confidence"] == "low"
    else:
        assert "Workflow status:** completed" in result.stdout
        assert "Confidence:** low" in result.stdout
        assert r"Freshness assessment:** not\_assigned" in result.stdout
        if partial:
            assert "Collection validity:** partial" in result.stdout
            assert r"dns\:dmarc" in result.stdout
    resolver.assert_awaited_once_with(info.queried_domain, timeout=120.0, skip_ct=True, active_probes=False)
