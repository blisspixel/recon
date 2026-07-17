from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.merger import merge_results
from recon_tool.models import (
    ConfidenceLevel,
    DnsCatalogSummary,
    SourceResult,
    TenantInfo,
    UnclassifiedDnsObservation,
)
from recon_tool.sources import dns_base, dns_email, dns_infra
from validation import catalog_baseline


def _tenant(**overrides: Any) -> TenantInfo:
    values: dict[str, Any] = {
        "tenant_id": None,
        "display_name": "Example Fixture",
        "default_domain": "example.com",
        "queried_domain": "example.com",
        "confidence": ConfidenceLevel.MEDIUM,
    }
    values.update(overrides)
    return TenantInfo(**values)


def _summary(record_type: str, *, observed: int = 1, classified: int = 0) -> dict[str, Any]:
    return {
        "record_type": record_type,
        "availability": "available",
        "opportunity_count": 1,
        "observed_count": observed,
        "classified_count": classified,
        "unclassified_count": observed - classified,
        "truncated": False,
    }


def test_detection_context_deduplicates_and_upgrades_classification() -> None:
    ctx = dns_base.DetectionCtx()
    ctx.record_catalog_query("txt")
    ctx.record_catalog_observation("txt", "@", "fixture-token=one", classified=False)
    ctx.record_catalog_observation("txt", "@", "fixture-token=one", classified=True)
    ctx.record_catalog_observation("txt", "@", "unknown-token=two", classified=False)

    assert ctx.catalog_summaries() == (
        DnsCatalogSummary(
            record_type="txt",
            opportunity_count=1,
            observed_count=2,
            classified_count=1,
        ),
    )
    assert ctx.unclassified_dns_observations() == (
        UnclassifiedDnsObservation(record_type="txt", owner="@", value="unknown-token=two"),
    )


def test_catalog_diagnostics_are_opt_in_and_complete() -> None:
    info = _tenant(
        dns_catalog_summaries=(
            DnsCatalogSummary("txt", opportunity_count=1, observed_count=2, classified_count=1),
        ),
        unclassified_dns_observations=(
            UnclassifiedDnsObservation("txt", "@", "fixture-token=unknown"),
        ),
        degraded_sources=("dns:mx",),
    )

    default = format_tenant_dict(info)
    assert "dns_catalog_summary" not in default
    assert "unclassified_dns_observations" not in default

    diagnostic = format_tenant_dict(info, include_unclassified=True)
    rows = {row["record_type"]: row for row in diagnostic["dns_catalog_summary"]}
    assert set(rows) == set(catalog_baseline.RECORD_TYPES)
    assert rows["txt"]["availability"] == "available"
    assert rows["txt"]["unclassified_count"] == 1
    assert rows["mx"]["availability"] == "unavailable"
    assert rows["srv"]["availability"] == "unmeasured"
    assert diagnostic["unclassified_dns_observations"] == [
        {"record_type": "txt", "owner": "@", "value": "fixture-token=unknown"}
    ]


def test_merger_preserves_catalog_diagnostics() -> None:
    info = merge_results(
        [
            SourceResult(
                source_name="dns_records",
                dns_catalog_summaries=(DnsCatalogSummary("mx", 1, 2, 1),),
                unclassified_dns_observations=(UnclassifiedDnsObservation("mx", "@", "mail.example.net"),),
            )
        ],
        "example.com",
    )

    assert info.dns_catalog_summaries == (DnsCatalogSummary("mx", 1, 2, 1),)
    assert info.unclassified_dns_observations == (
        UnclassifiedDnsObservation("mx", "@", "mail.example.net"),
    )


@pytest.mark.asyncio
async def test_txt_detector_accounts_for_spf_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(*_args: Any, **_kwargs: Any) -> list[str]:
        return [
            "v=spf1 include:spf.protection.outlook.com include:mail.example.net -all",
            "fixture-token=unknown",
        ]

    monkeypatch.setattr(dns_base, "safe_resolve", fake_resolve)
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")

    summaries = {summary.record_type: summary for summary in ctx.catalog_summaries()}
    assert summaries["spf"].observed_count == 2
    assert summaries["spf"].classified_count == 1
    assert UnclassifiedDnsObservation("spf", "@", "mail.example.net") in ctx.unclassified_dns_observations()


@pytest.mark.asyncio
async def test_srv_unavailable_target_is_not_a_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(*_args: Any, **_kwargs: Any) -> list[str]:
        return ["0 0 0 ."]

    monkeypatch.setattr(dns_base, "safe_resolve", fake_resolve)
    ctx = dns_base.DetectionCtx()
    await dns_infra.detect_srv(ctx, "example.com")

    summary = next(item for item in ctx.catalog_summaries() if item.record_type == "srv")
    assert summary.opportunity_count == 5
    assert summary.observed_count == 0
    assert ctx.unclassified_dns_observations() == ()


def test_aggregate_is_target_free_and_private_queue_retains_evidence() -> None:
    records = [
        {
            "queried_domain": "example.com",
            "partial": False,
            "degraded_sources": [],
            "dns_catalog_summary": [_summary("mx")],
            "unclassified_dns_observations": [
                {"record_type": "mx", "owner": "@", "value": "mail.provider.example.net"}
            ],
        },
        {
            "queried_domain": "example.org",
            "partial": False,
            "degraded_sources": [],
            "dns_catalog_summary": [_summary("mx")],
            "unclassified_dns_observations": [
                {"record_type": "mx", "owner": "@", "value": "mx.provider.example.net"}
            ],
        },
    ]

    aggregate, candidates = catalog_baseline.aggregate_records(
        records,
        min_count=2,
        min_distinct_namespaces=2,
        max_samples=2,
    )

    rendered = json.dumps(aggregate, sort_keys=True)
    assert "example.com" not in rendered
    assert "example.org" not in rendered
    assert "provider.example.net" not in rendered
    assert aggregate["record_types"]["mx"]["recurrent_candidate_buckets"] == 1
    assert candidates["mx"][0]["key"] == "provider.example.net"
    assert candidates["mx"][0]["distinct_namespace_count"] == 2


def test_main_writes_separate_private_and_aggregate_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "results.ndjson"
    results.write_text(
        json.dumps(
            {
                "queried_domain": "example.com",
                "partial": False,
                "degraded_sources": [],
                "dns_catalog_summary": [_summary("txt")],
                "unclassified_dns_observations": [
                    {"record_type": "txt", "owner": "@", "value": "fixture-token=secret"}
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def catalog_metadata_fixture(_path: Path) -> dict[str, Any]:
        return {
            "digest_sha256": "a" * 64,
            "entries": 1,
            "detections": 1,
            "dated_detections": 1,
            "undated_detections": 0,
        }

    monkeypatch.setattr(
        catalog_baseline,
        "_catalog_metadata",
        catalog_metadata_fixture,
    )
    monkeypatch.setattr(catalog_baseline, "_git_revision", lambda: ("b" * 40, False))

    assert (
        catalog_baseline.main(
            [
                "--input",
                str(results),
                "--output-dir",
                str(tmp_path),
                "--min-count",
                "1",
                "--min-distinct-namespaces",
                "1",
            ]
        )
        == 0
    )

    aggregate_text = (tmp_path / "catalog-aggregate.json").read_text(encoding="utf-8")
    gaps_text = (tmp_path / "catalog-gaps.json").read_text(encoding="utf-8")
    assert "example.com" not in aggregate_text
    assert "fixture-token=secret" not in aggregate_text
    assert "fixture-token=secret" in gaps_text
    assert (tmp_path / "catalog-manifest.json").exists()
