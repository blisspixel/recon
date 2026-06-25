from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_checker() -> Any:
    spec = importlib.util.spec_from_file_location(
        "schema_source_checker",
        ROOT / "scripts" / "check_schema_sources.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    cast(Any, spec.loader).exec_module(module)
    return module


CHECKER = _load_checker()


def test_current_schema_properties_have_sources() -> None:
    audit = CHECKER.audit_schema_sources(CHECKER.load_schema_properties(), CHECKER.tenant_info_fields())

    assert audit.ok
    assert audit.schema_property_count == 56


def test_formatter_derived_fields_are_explicit() -> None:
    sources = CHECKER.SPECIAL_SCHEMA_SOURCES

    assert sources["provider"] == "formatter-derived provider summary"
    assert sources["email_security_score"] == "formatter-derived email control count"
    assert sources["schema_version"] == "static formatter envelope version"
    assert sources["shared_tenant"] == "batch-mode extension"


def test_unknown_schema_property_is_reported() -> None:
    audit = CHECKER.audit_schema_sources({"tenant_id", "new_field"}, {"tenant_id"})

    assert not audit.ok
    assert audit.untraced_schema_properties == ("new_field",)


def test_unrepresented_tenant_field_is_reported() -> None:
    audit = CHECKER.audit_schema_sources({"tenant_id"}, {"tenant_id", "new_model_field"})

    assert not audit.ok
    assert audit.unrepresented_tenant_fields == ("new_model_field",)


def test_stale_special_source_is_reported() -> None:
    audit = CHECKER.audit_schema_sources({"tenant_id"}, {"tenant_id"})

    assert not audit.ok
    assert "provider" in audit.stale_special_sources


def test_schema_source_map_labels_tenant_fields_and_special_sources() -> None:
    mapping = CHECKER.schema_source_map({"tenant_id", "provider", "new_field"}, {"tenant_id"})

    assert mapping["tenant_id"] == "TenantInfo.tenant_id"
    assert mapping["provider"] == "formatter-derived provider summary"
    assert mapping["new_field"] == "<untraced>"


def test_audit_report_includes_issues_and_intentional_omissions() -> None:
    audit = CHECKER.audit_schema_sources({"tenant_id", "new_field"}, {"tenant_id", "cached_at"})
    report = CHECKER.audit_report(audit, CHECKER.schema_source_map({"tenant_id", "new_field"}, {"tenant_id"}))

    assert report["ok"] is False
    assert report["issues"]["untraced_schema_properties"] == ["new_field"]
    assert report["intentional_tenantinfo_omissions"]["cached_at"] == (
        "cache metadata, not emitted by the lookup JSON formatter"
    )


def test_json_cli_outputs_report_for_success(capsys: pytest.CaptureFixture[str]) -> None:
    result = CHECKER.main(["--json"])

    assert result == 0
    report = CHECKER.json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["schema_property_count"] == 56
    assert report["schema_sources"]["tenant_id"] == "TenantInfo.tenant_id"
    assert report["issues"]["untraced_schema_properties"] == []
