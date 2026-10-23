"""Historical snapshots cannot establish changes for unrecorded fields."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from recon_tool.cache import tenant_info_to_dict
from recon_tool.cli import app
from recon_tool.delta import compute_delta
from recon_tool.formatter.delta import format_delta_dict, render_delta_panel
from recon_tool.models import TenantInfo


@pytest.fixture
def current() -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="Synthetic namespace",
        default_domain="example.com",
        queried_domain="example.com",
        services=("Synthetic service",),
        slugs=("aws-route53", "gcp-dns"),
        insights=("Multi-Cloud: Amazon Web Services, Google Cloud",),
    )


@pytest.mark.parametrize(("field", "label"), [("services", "services"), ("slugs", "slugs"), ("insights", "signals")])
@pytest.mark.parametrize("recorded", ["missing", "empty", "populated"])
def test_collection_presence_controls_comparability(current: TenantInfo, field: str, label: str, recorded: str) -> None:
    previous = tenant_info_to_dict(current)
    if recorded == "missing":
        del previous[field]
    elif recorded == "empty":
        previous[field] = []
    report = compute_delta(previous, current)
    additions = getattr(report, f"added_{label}")
    assert bool(additions) is (recorded == "empty")
    assert not getattr(report, f"removed_{label}")
    if recorded == "missing":
        assert report.incomplete_comparison is not None
        assert {f"added_{label}", f"removed_{label}"} <= set(report.incomplete_comparison.suppressed_fields)
        assert report.incomplete_comparison.degraded_sources == ()
    else:
        assert report.incomplete_comparison is None


@pytest.mark.parametrize("field", ["confidence", "domain_count"])
@pytest.mark.parametrize("recorded", [False, True])
def test_unknown_scalar_baseline_is_named(current: TenantInfo, field: str, recorded: bool) -> None:
    previous = tenant_info_to_dict(current)
    if recorded:
        previous[field] = None
    else:
        del previous[field]
    report = compute_delta(previous, current)
    assert getattr(report, f"changed_{field}") is None
    assert report.incomplete_comparison is not None
    assert f"changed_{field}" in report.incomplete_comparison.suppressed_fields


@pytest.mark.parametrize("degraded", [False, True])
def test_projection_cannot_turn_missing_fields_into_recorded_empty_sets(current: TenantInfo, degraded: bool) -> None:
    previous = tenant_info_to_dict(current)
    for field in ("services", "slugs", "insights"):
        del previous[field]
    if degraded:
        previous["degraded_sources"] = ["dns:mx"]
    report = compute_delta(previous, current)
    assert not report.has_changes
    assert report.incomplete_comparison is not None
    assert {
        "added_services",
        "removed_services",
        "added_slugs",
        "removed_slugs",
        "added_signals",
        "removed_signals",
    } <= set(report.incomplete_comparison.suppressed_fields)


@pytest.mark.parametrize("field", ["services", "slugs", "insights", "confidence", "domain_count"])
@pytest.mark.parametrize("json_output", [False, True])
def test_compare_cli_preserves_missing_baseline_diagnostics(
    current: TenantInfo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, json_output: bool
) -> None:
    previous = tenant_info_to_dict(current)
    del previous[field]
    snapshot = tmp_path / "baseline.json"
    snapshot.write_text(json.dumps(previous), encoding="utf-8")
    resolver = AsyncMock(return_value=(current, []))
    monkeypatch.setattr("recon_tool.resolver.resolve_tenant", resolver)
    result = CliRunner().invoke(app, ["example.com", "--compare", str(snapshot), *(["--json"] if json_output else [])])
    assert result.exit_code == 0, result.output
    assert "No changes detected" not in result.stdout
    if json_output:
        payload = json.loads(result.stdout)
        assert payload["has_changes"] is False
        assert payload["incomplete_comparison"]["suppressed_fields"]
    else:
        assert "previous snapshot did not record" in result.stdout
        assert "No confirmed changes detected" in result.stdout
    resolver.assert_awaited_once()


@pytest.mark.parametrize("field", ["services", "slugs", "insights"])
@pytest.mark.parametrize("value", [None, "", {}, [42]])
def test_malformed_recorded_sets_remain_validation_errors(current: TenantInfo, field: str, value: Any) -> None:
    previous = tenant_info_to_dict(current)
    previous[field] = value
    with pytest.raises(ValueError, match=field):
        compute_delta(previous, current)


def test_minimal_historical_baseline_renders_no_fabricated_additions(current: TenantInfo) -> None:
    report = compute_delta({}, current)
    payload = format_delta_dict(report)
    assert payload["added_services"] == payload["added_slugs"] == payload["added_signals"] == []
    assert not payload["has_changes"]
    assert "changed_confidence" in payload["incomplete_comparison"]["suppressed_fields"]
    assert "changed_domain_count" in payload["incomplete_comparison"]["suppressed_fields"]
    panel = render_delta_panel(report)
    assert "previous snapshot did not record" in str(panel.renderable)
