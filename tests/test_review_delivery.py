"""CLI and MCP delivery coverage for NamespaceReviewBundle v1."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.exit_codes import EXIT_INTERNAL, EXIT_NO_DATA, EXIT_VALIDATION
from recon_tool.mcp_client.sdk_compat import ToolError
from recon_tool.models import ConfidenceLevel, EvidenceRecord, ReconLookupError, SourceResult, TenantInfo
from recon_tool.server import _cache_set, _rate_limit_clear, build_review_bundle

runner = CliRunner()


def _fixture(*, display_name: str = "Example Industries") -> tuple[TenantInfo, list[SourceResult]]:
    evidence = EvidenceRecord("TXT", "v=DMARC1; p=reject", "DMARC", "dmarc")
    info = TenantInfo(
        tenant_id=None,
        display_name=display_name,
        default_domain="example.com",
        queried_domain="example.com",
        confidence=ConfidenceLevel.HIGH,
        services=("DMARC",),
        slugs=("dmarc",),
        dmarc_policy="reject",
        evidence=(evidence,),
        ct_attempt_outcome="skipped",
    )
    source = SourceResult(
        source_name="dns_records",
        dmarc_policy="reject",
        raw_dns_records=(("TXT", evidence.raw_value),),
        evidence=(evidence,),
        ct_attempt_outcome="skipped",
    )
    return info, [source]


def test_review_cli_json_collects_once_with_cache_bypass_contract() -> None:
    info, results = _fixture()
    resolve = AsyncMock(return_value=(info, results))
    with patch("recon_tool.resolver.resolve_tenant", new=resolve):
        result = runner.invoke(
            app,
            ["review", "mail.example.com", "--json", "--no-ct", "--timeout", "30"],
        )

    assert result.exit_code == 0, result.output
    bundle = json.loads(result.stdout)
    assert bundle["record_type"] == "review_bundle"
    assert bundle["scope"]["input_coordinate"] == "mail.example.com"
    assert bundle["scope"]["queried_domain"] == "example.com"
    assert bundle["collection"]["cache"]["result_cache"] == "bypassed"
    assert bundle["collection"]["options"]["direct_probes"] is False
    resolve.assert_awaited_once_with(
        "example.com",
        timeout=30.0,
        skip_ct=True,
        active_probes=False,
    )


def test_review_cli_preflights_existing_output_before_collection(tmp_path: Path) -> None:
    output = tmp_path / "review.json"
    output.write_text("caller-owned", encoding="utf-8")
    resolve = AsyncMock()
    with patch("recon_tool.resolver.resolve_tenant", new=resolve):
        result = runner.invoke(app, ["review", "example.com", "--output", str(output)])

    assert result.exit_code == EXIT_VALIDATION
    assert "already exists" in result.output
    assert output.read_text(encoding="utf-8") == "caller-owned"
    resolve.assert_not_awaited()


def test_review_cli_rejects_directory_output_before_collection_even_with_force(tmp_path: Path) -> None:
    resolve = AsyncMock()
    with patch("recon_tool.resolver.resolve_tenant", new=resolve):
        result = runner.invoke(
            app,
            ["review", "example.com", "--output", str(tmp_path), "--force"],
        )

    assert result.exit_code == EXIT_VALIDATION
    assert "must be a file path" in result.output
    resolve.assert_not_awaited()


def test_review_cli_unexpected_collection_error_is_safe_and_internal() -> None:
    internal_detail = "credential-shaped internal detail"
    with patch("recon_tool.resolver.resolve_tenant", new=AsyncMock(side_effect=RuntimeError(internal_detail))):
        result = runner.invoke(app, ["review", "example.com", "--json"])

    assert result.exit_code == EXIT_INTERNAL
    assert "internal error" in result.output
    assert internal_detail not in result.output


def test_review_cli_writes_typed_no_data_bundle(tmp_path: Path) -> None:
    output = tmp_path / "review.json"
    error = ReconLookupError(
        domain="example.com",
        message="no public records",
        error_type="no_data",
        source_errors=(("dns_records", "no records"),),
    )
    with patch("recon_tool.resolver.resolve_tenant", new=AsyncMock(side_effect=error)):
        result = runner.invoke(
            app,
            ["review", "example.com", "--output", str(output), "--json"],
        )

    assert result.exit_code == EXIT_NO_DATA
    bundle = json.loads(output.read_text(encoding="utf-8"))
    assert json.loads(result.stdout) == bundle
    assert bundle["workflow"] == {
        "status": "failed",
        "collection_validity": "unavailable",
        "freshness_assessment": "not_assigned",
    }
    assert bundle["result"] == {
        "record_type": "review_error",
        "error_kind": "lookup",
        "failed_source_roles": ["dns_records"],
    }


@pytest.mark.asyncio
async def test_review_mcp_bypasses_populated_result_cache_and_collects_once() -> None:
    _rate_limit_clear()
    stale, stale_results = _fixture(display_name="Stale cache")
    fresh, fresh_results = _fixture(display_name="Fresh collection")
    _cache_set("example.com", stale, stale_results)
    resolve = AsyncMock(return_value=(fresh, fresh_results))

    with patch("recon_tool.server.app.resolve_tenant", new=resolve):
        bundle = await build_review_bundle("example.com", no_ct=True, timeout_seconds=25)

    assert bundle["result"]["explained_baseline"]["lookup"]["display_name"] == "Fresh collection"
    assert bundle["collection"]["cache"]["result_cache"] == "bypassed"
    assert bundle["collection"]["vantage"] == "mcp-server"
    resolve.assert_awaited_once_with(
        "example.com",
        timeout=25.0,
        skip_ct=True,
        active_probes=False,
    )


@pytest.mark.asyncio
async def test_review_mcp_returns_typed_timeout_without_observations() -> None:
    _rate_limit_clear()
    error = ReconLookupError(domain="example.com", message="timed out", error_type="timeout")
    with patch("recon_tool.server.app.resolve_tenant", new=AsyncMock(side_effect=error)):
        bundle = await build_review_bundle("example.com")

    assert bundle["workflow"]["status"] == "failed"
    assert bundle["workflow"]["collection_validity"] == "not_observed"
    assert bundle["result"] == {
        "record_type": "review_error",
        "error_kind": "timeout",
        "failed_source_roles": [],
    }
    assert "explained_baseline" not in bundle["result"]
    assert "review_candidates" not in bundle["result"]


@pytest.mark.asyncio
async def test_review_mcp_rejects_invalid_domain_before_collection() -> None:
    _rate_limit_clear()
    resolve = AsyncMock()
    with (
        patch("recon_tool.server.app.resolve_tenant", new=resolve),
        pytest.raises(ToolError, match="Invalid domain format"),
    ):
        await build_review_bundle("not a domain")
    resolve.assert_not_awaited()


@pytest.mark.asyncio
async def test_review_mcp_rejects_boolean_timeout_before_validation_or_collection() -> None:
    _rate_limit_clear()
    resolve = AsyncMock()
    admission = AsyncMock()
    with (
        patch("recon_tool.server.app.resolve_tenant", new=resolve),
        patch("recon_tool.server.review.rate_limit_try_acquire", new=admission),
        pytest.raises(ToolError, match="finite positive number"),
    ):
        await build_review_bundle("example.com", timeout_seconds=True)  # type: ignore[arg-type]
    resolve.assert_not_awaited()
    admission.assert_not_called()


@pytest.mark.asyncio
async def test_review_mcp_failed_bundle_composition_is_safe_tool_error() -> None:
    _rate_limit_clear()
    lookup_error = ReconLookupError(
        domain="example.com",
        message="no public records",
        error_type="no_data",
        source_errors=(("dns_records", "no records"),),
    )
    internal_detail = "raw internal artifact failure"
    with (
        patch("recon_tool.server.app.resolve_tenant", new=AsyncMock(side_effect=lookup_error)),
        patch("recon_tool.server.review.build_review_error_bundle", side_effect=RuntimeError(internal_detail)),
        pytest.raises(ToolError) as exc_info,
    ):
        await build_review_bundle("example.com")

    message = str(exc_info.value)
    assert "composing a failed review bundle" in message
    assert "RuntimeError" in message
    assert internal_detail not in message
