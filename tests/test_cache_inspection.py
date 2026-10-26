"""Read-only result-cache metadata inspection tests."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from recon_tool.cache import DEFAULT_TTL, cache_dir, cache_get, cache_put
from recon_tool.cache_inspection import inspect_result_cache, list_result_cache
from recon_tool.cache_values import CacheInspection
from recon_tool.cli import app
from recon_tool.formatter.collection_status import project_collection_status
from recon_tool.models import ConfidenceLevel, TenantInfo
from recon_tool.source_status import collection_incomplete


@pytest.fixture
def isolated_cache(tmp_path: Path) -> Iterator[Path]:
    with patch.dict(os.environ, {"RECON_CONFIG_DIR": str(tmp_path)}):
        yield tmp_path


def _info(domain: str) -> TenantInfo:
    return TenantInfo(
        tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        display_name="Private display value",
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.HIGH,
        sources=("dns_records",),
        services=("private-service",),
    )


def test_inspect_result_cache_returns_only_validated_metadata(isolated_cache: Path) -> None:
    cache_put("example.com", _info("example.com"))

    inspection = inspect_result_cache("example.com")

    assert not inspection.failed
    assert inspection.entry is not None
    assert inspection.entry.domain == "example.com"
    assert inspection.entry.cached_at != "unknown"
    assert inspection.entry.resolved_at != "unknown"
    assert inspection.entry.age_seconds >= 0.0
    assert inspection.entry.file_size_bytes > 0
    assert inspection.entry.reusable
    assert not hasattr(inspection.entry, "display_name")
    assert not hasattr(inspection.entry, "tenant_id")
    assert not hasattr(inspection.entry, "services")


def test_inspect_result_cache_reports_expired_entry_without_hiding_it(isolated_cache: Path) -> None:
    cache_put("expired.invalid", _info("expired.invalid"))
    old = time.time() - DEFAULT_TTL - 1
    os.utime(cache_dir() / "expired.invalid.json", (old, old))

    inspection = inspect_result_cache("expired.invalid")

    assert not inspection.failed
    assert inspection.entry is not None
    assert not inspection.entry.reusable
    assert inspection.entry.age_seconds > DEFAULT_TTL


def test_inspect_result_cache_distinguishes_missing_from_invalid(isolated_cache: Path) -> None:
    missing = inspect_result_cache("missing.invalid")
    cache_dir().mkdir(parents=True)
    (cache_dir() / "broken.invalid.json").write_text("NOT JSON", encoding="utf-8")
    broken = inspect_result_cache("broken.invalid")

    assert missing.entry is None
    assert not missing.failed
    assert broken.entry is None
    assert broken.failed


def test_list_result_cache_counts_invalid_entries(isolated_cache: Path) -> None:
    cache_put("valid.invalid", _info("valid.invalid"))
    (cache_dir() / "broken.invalid.json").write_text("NOT JSON", encoding="utf-8")

    listing = list_result_cache()

    assert [entry.domain for entry in listing.entries] == ["valid.invalid"]
    assert listing.failed == 1
    assert listing.inspected == 2
    assert listing.total == 2


def test_list_result_cache_bounds_payload_inspection_and_counts_residue(isolated_cache: Path) -> None:
    cache_dir().mkdir(parents=True)
    for index in range(105):
        (cache_dir() / f"d{index:03d}.invalid.json").write_text("{}", encoding="utf-8")
    (cache_dir() / "d000.invalid.abcd1234.tmp").write_text("private payload", encoding="utf-8")
    (cache_dir() / "operator-notes.tmp").write_text("keep", encoding="utf-8")

    with patch(
        "recon_tool.cache_inspection.inspect_result_cache",
        return_value=CacheInspection(failed=True),
    ) as inspect:
        listing = list_result_cache(limit=3)

    assert [call.args[0] for call in inspect.call_args_list] == [
        "d000.invalid",
        "d001.invalid",
        "d002.invalid",
    ]
    assert listing.inspected == 3
    assert listing.total == 105
    assert listing.failed == 3
    assert listing.temporary_files == 1


# -- Read admission and inspection agreement (issue #223) -------------------


_SCENARIO_FIELDS: dict[str, dict[str, object]] = {
    "clean": {},
    "core_failure": {"degraded_sources": ("identity:user_realm",), "confidence": ConfidenceLevel.LOW},
    "dns_channel_failure": {"degraded_sources": ("dns:mx",)},
    "all_ct_failed": {"degraded_sources": ("certspotter", "crt.sh")},
    "ct_fallback_recovered": {
        "degraded_sources": ("crt.sh",),
        "ct_provider_used": "certspotter",
        "ct_subdomain_count": 5,
    },
    "ct_cache_recovered": {
        "degraded_sources": ("certspotter", "crt.sh"),
        "ct_provider_used": "crt.sh (cached)",
        "ct_cache_age_days": 2,
        "ct_subdomain_count": 3,
    },
    "sparse_empty": {
        "tenant_id": None,
        "confidence": ConfidenceLevel.LOW,
        "services": (),
        "sources": ("dns_records",),
    },
}


def _scenario(domain: str, scenario: str) -> TenantInfo:
    return replace(_info(domain), **_SCENARIO_FIELDS[scenario])


_SCENARIO_ADMISSION = {
    "clean": "reusable",
    "sparse_empty": "reusable",
    "ct_fallback_recovered": "reusable",
    "ct_cache_recovered": "reusable",
    "core_failure": "collection_incomplete",
    "dns_channel_failure": "collection_incomplete",
    "all_ct_failed": "collection_incomplete",
}


@pytest.mark.parametrize("scenario", sorted(_SCENARIO_ADMISSION))
def test_inspection_status_agrees_with_lookup_read_admission(isolated_cache: Path, scenario: str) -> None:
    domain = f"{scenario.replace('_', '-')}.invalid"
    cache_put(domain, _scenario(domain, scenario))

    inspection = inspect_result_cache(domain)

    assert inspection.entry is not None
    assert inspection.entry.admission == _SCENARIO_ADMISSION[scenario]
    assert inspection.entry.reusable == (cache_get(domain) is not None)
    # Every structurally valid entry stays available as a delta baseline.
    assert cache_get(domain, ttl=30 * 86400, admit_incomplete=True) is not None


def test_incomplete_collection_matches_the_human_warning_projection() -> None:
    for scenario, admission in _SCENARIO_ADMISSION.items():
        info = _scenario("projection.invalid", scenario)
        incomplete = collection_incomplete(info.degraded_sources, ct_provider_used=info.ct_provider_used)
        assert incomplete == (admission == "collection_incomplete"), scenario
        # The human warning note and read admission share one meaning.
        assert project_collection_status(info).is_warning == incomplete, scenario


def test_inspection_reports_why_an_entry_is_not_reused(isolated_cache: Path) -> None:
    cache_put("partial.invalid", _scenario("partial.invalid", "core_failure"))

    entry = inspect_result_cache("partial.invalid").entry

    assert entry is not None
    assert entry.status == "not reusable; previous collection had unavailable sources"
    assert entry.short_status == "partial"
    assert not hasattr(entry, "degraded_sources")


def test_expired_takes_precedence_over_incomplete_in_both_readers(isolated_cache: Path) -> None:
    cache_put("old-partial.invalid", _scenario("old-partial.invalid", "core_failure"))
    old = time.time() - DEFAULT_TTL - 1
    os.utime(cache_dir() / "old-partial.invalid.json", (old, old))

    entry = inspect_result_cache("old-partial.invalid").entry

    assert entry is not None
    assert entry.admission == "expired"
    assert entry.status == "expired; next lookup refreshes"
    assert cache_get("old-partial.invalid") is None


def test_lineage_invalid_entry_is_not_reusable_in_either_reader(isolated_cache: Path) -> None:
    cache_put("lineage.invalid", _info("lineage.invalid"))
    path = cache_dir() / "lineage.invalid.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    del payload["insight_claims"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    entry = inspect_result_cache("lineage.invalid").entry

    assert entry is not None
    assert entry.admission == "lineage_invalid"
    assert entry.status == "not reusable; generated-insight lineage does not validate"
    assert cache_get("lineage.invalid") is None


def test_cache_show_renders_the_shared_admission_status(isolated_cache: Path) -> None:
    cache_put("shown.invalid", _scenario("shown.invalid", "core_failure"))
    cache_put("sparse.invalid", _scenario("sparse.invalid", "sparse_empty"))
    runner = CliRunner()

    single = runner.invoke(app, ["cache", "show", "shown.invalid"])
    listing = runner.invoke(app, ["cache", "show"])

    assert single.exit_code == 0, single.output
    assert "not reusable; previous collection had unavailable sources" in " ".join(single.output.split())
    # Metadata only: the stored payload's degraded markers are not echoed.
    assert "identity:user_realm" not in single.output
    assert listing.exit_code == 0, listing.output
    rows = {line.split()[0]: line.split()[1] for line in listing.output.splitlines() if ".invalid" in line}
    assert rows == {"shown.invalid": "partial", "sparse.invalid": "reusable"}
