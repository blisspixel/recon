from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

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
