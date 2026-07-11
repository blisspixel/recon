from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from recon_tool.schema_contract import REQUIRED_TOP_LEVEL_FIELDS

ROOT = Path(__file__).resolve().parents[1]


def _load_generator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "schema_generator",
        ROOT / "scripts" / "generate_schema.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    cast(Any, spec.loader).exec_module(module)
    return module


GENERATOR = _load_generator()


def test_generated_schema_matches_committed_schema_copies() -> None:
    docs_schema = GENERATOR.load_schema(GENERATOR._DOCS_SCHEMA)
    generated = GENERATOR.build_schema(docs_schema)

    assert generated == docs_schema
    assert GENERATOR.load_schema(GENERATOR._PACKAGED_SCHEMA) == generated


def test_generated_top_level_fields_are_code_owned() -> None:
    fields = GENERATOR.generated_top_level_fields()

    assert fields[: len(REQUIRED_TOP_LEVEL_FIELDS)] == REQUIRED_TOP_LEVEL_FIELDS
    assert GENERATOR.CONDITIONAL_TOP_LEVEL_FIELDS == (
        "ct_provider_used",
        "ct_cache_age_days",
        "ct_attempt_outcome",
        "evidence",
        "explanation_dag",
        "shared_display_name",
        "shared_tenant",
        "shared_verification_tokens",
        "unclassified_cname_chains",
    )
    assert len(fields) == 56
    assert len(fields) == len(set(fields))


def test_explanation_dag_fragment_describes_emitted_shape() -> None:
    schema = GENERATOR.load_schema(GENERATOR._DOCS_SCHEMA)
    fragment = schema["properties"]["explanation_dag"]

    assert fragment["required"] == [
        "nodes",
        "edges",
        "schema_version",
    ]
    assert fragment["properties"]["schema_version"] == {"const": 1}
    assert fragment["properties"]["provenance_complete"]["type"] == "boolean"
    assert fragment["properties"]["disconnected_terminals"]["items"] == {"type": "string"}


def test_build_schema_rejects_missing_property_fragment() -> None:
    template = GENERATOR.load_schema(GENERATOR._DOCS_SCHEMA)
    broken = dict(template)
    properties = dict(template["properties"])
    properties.pop("tenant_id")
    broken["properties"] = properties

    with pytest.raises(ValueError, match="missing property fragments: tenant_id"):
        GENERATOR.build_schema(broken)


def test_build_schema_rejects_stale_required_field() -> None:
    template = GENERATOR.load_schema(GENERATOR._DOCS_SCHEMA)
    broken = dict(template)
    broken["required"] = [*template["required"], "not_a_real_field"]

    with pytest.raises(ValueError, match="stale required fields: not_a_real_field"):
        GENERATOR.build_schema(broken)


def test_check_target_compares_schema_objects_not_formatting(capsys: pytest.CaptureFixture[str]) -> None:
    generated = GENERATOR.build_schema(GENERATOR.load_schema(GENERATOR._DOCS_SCHEMA))
    generated_text = GENERATOR.dumps_schema(generated)

    assert GENERATOR._check_target(GENERATOR._DOCS_SCHEMA, generated_text)
    assert "is current" in capsys.readouterr().out


def test_main_check_accepts_current_schema_copies(tmp_path: Path) -> None:
    docs_copy = tmp_path / "recon-schema.json"
    packaged_copy = tmp_path / "packaged-recon-schema.json"
    docs_copy.write_text(GENERATOR._DOCS_SCHEMA.read_text(encoding="utf-8"), encoding="utf-8")
    packaged_copy.write_text(GENERATOR._PACKAGED_SCHEMA.read_text(encoding="utf-8"), encoding="utf-8")

    assert GENERATOR.main(["--schema", str(docs_copy), "--packaged-schema", str(packaged_copy), "--check"]) == 0
