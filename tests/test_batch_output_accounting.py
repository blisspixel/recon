"""Synthetic output failures cannot contribute successful batch observations."""

from __future__ import annotations

import asyncio
import importlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.cli.batch import _batch_process_one
from recon_tool.models import ConfidenceLevel, TenantInfo

_RUNNER = CliRunner()
_ERROR_PREFIX = "\x00ERR:"


def _info(domain: str) -> TenantInfo:
    return TenantInfo(
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        display_name="Synthetic Shared Name",
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.MEDIUM,
        sources=("dns_records", "openid_configuration"),
        site_verification_tokens=("google-site-verification=synthetic-shared-token",),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("output_mode", ["panel", "json", "markdown", "csv", "ndjson"])
async def test_output_failure_does_not_register_successful_batch_info(
    monkeypatch: pytest.MonkeyPatch, output_mode: str
) -> None:
    info = _info("failed.invalid")
    infos: dict[str, Any] = {}
    resolver = AsyncMock(return_value=(info, []))
    monkeypatch.setattr("recon_tool.resolver.resolve_tenant", resolver)

    def fail_format(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("synthetic formatter failure")

    monkeypatch.setattr(importlib.import_module("recon_tool.cli.batch"), "_batch_success_result", fail_format)
    result = await _batch_process_one(
        info.queried_domain,
        semaphore=asyncio.Semaphore(1),
        batch_infos=infos,
        timeout=1.0,
        skip_ct=True,
        fusion=False,
        json_output=output_mode == "json",
        ndjson=output_mode == "ndjson",
        csv_output=output_mode == "csv",
        markdown=output_mode == "markdown",
        include_unclassified=False,
        error_prefix=_ERROR_PREFIX,
    )

    assert infos == {}
    assert "Internal batch error" in str(result)
    assert "synthetic formatter failure" not in str(result)
    resolver.assert_awaited_once_with("failed.invalid", timeout=1.0, skip_ct=True)


@pytest.mark.parametrize("ecosystem_summary", [False, True])
def test_json_failure_cannot_create_peers_hyperedges_or_summary_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ecosystem_summary: bool
) -> None:
    from recon_tool.formatter import format_tenant_dict

    domains = tmp_path / "domains.txt"
    domains.write_text("good.invalid\nfailed.invalid\n", encoding="utf-8")

    async def resolve(domain: str, **_kwargs: object) -> tuple[TenantInfo, list[Any]]:
        return _info(domain), []

    def format_one(info: TenantInfo, **kwargs: Any) -> dict[str, Any]:
        if info.queried_domain == "failed.invalid":
            raise RuntimeError("synthetic formatter failure")
        return format_tenant_dict(info, **kwargs)

    monkeypatch.setattr("recon_tool.resolver.resolve_tenant", resolve)
    monkeypatch.setattr("recon_tool.formatter.format_tenant_dict", format_one)
    options = ["--include-ecosystem", "--summary"] if ecosystem_summary else []

    result = _RUNNER.invoke(app, ["batch", str(domains), "--json", *options])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    records = payload["domains"] if ecosystem_summary else payload
    assert records[0]["queried_domain"] == "good.invalid"
    assert records[1]["record_type"] == "error"
    assert records[1]["domain"] == "failed.invalid"
    assert records[1]["error_kind"] == "lookup"
    for field in ("shared_tenant", "shared_display_name", "shared_verification_tokens"):
        assert not records[0].get(field)
    if ecosystem_summary:
        assert payload["ecosystem_hyperedges"] == []
        assert payload["cohort_summary"]["n"] == 1
        assert payload["cohort_summary"]["observability"]["attempted"] == 2
        assert payload["cohort_summary"]["observability"]["resolved"] == 1
