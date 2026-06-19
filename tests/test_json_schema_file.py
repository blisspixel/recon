"""Drift guard for ``docs/recon-schema.json``.

The committed JSON Schema file is the machine-readable form of the
``docs/schema.md`` contract. These tests fail if the schema and the actual
``format_tenant_json`` output drift apart in either direction:

- A field added to the JSON output without being added to the schema.
- A field removed from the JSON output that the schema still requires.
- A schema field declared with a property name that the output never
  produces.

Per-field type assertions live in ``test_json_schema_contract.py``; this
file is concerned only with shape symmetry between the artifact and the
emitter.
"""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

import pytest

from recon_tool.formatter import format_tenant_json
from recon_tool.models import (
    BIMIIdentity,
    CertBurst,
    CertSummary,
    ChainMotifObservation,
    DeltaReport,
    EvidenceRecord,
    InfrastructureCluster,
    InfrastructureClusterReport,
    NodeConflict,
    NodeEvidence,
    NodeUnitCounterfactual,
    PosteriorObservation,
    SurfaceAttribution,
    TenantInfo,
    UnclassifiedCnameChain,
)

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "recon-schema.json"


@pytest.fixture
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def fixture_payload(fully_populated_tenant_info: TenantInfo) -> dict:
    return json.loads(format_tenant_json(fully_populated_tenant_info))


def test_schema_is_valid_json_schema_2020_12(schema: dict) -> None:
    """Basic well-formedness: top-level keys we depend on are present."""
    assert schema.get("$schema", "").endswith("2020-12/schema")
    assert schema.get("type") == "object"
    assert isinstance(schema.get("properties"), dict)
    assert isinstance(schema.get("required"), list)


def test_every_output_key_appears_in_schema_properties(schema: dict, fixture_payload: dict) -> None:
    """Drift guard: a new field in JSON output without a schema entry is a bug."""
    schema_props = set(schema["properties"].keys())
    output_keys = set(fixture_payload.keys())
    undocumented = output_keys - schema_props
    assert not undocumented, (
        f"JSON output has fields the schema does not document: {sorted(undocumented)}. "
        "Add them to docs/recon-schema.json (and docs/schema.md) before merging."
    )


def test_every_schema_required_field_appears_in_output(schema: dict, fixture_payload: dict) -> None:
    """Drift guard: a required schema field that the formatter never emits is a bug."""
    required = set(schema["required"])
    output_keys = set(fixture_payload.keys())
    missing = required - output_keys
    assert not missing, (
        f"Schema marks fields as required that the formatter does not emit: "
        f"{sorted(missing)}. Either remove them from required, or fix the formatter."
    )


def test_required_fields_are_a_subset_of_properties(schema: dict) -> None:
    """Required must reference declared properties only."""
    props = set(schema["properties"].keys())
    required = set(schema["required"])
    orphans = required - props
    assert not orphans, f"Required fields not declared in properties: {sorted(orphans)}"


def test_internal_refs_resolve(schema: dict) -> None:
    """Every $ref inside the document points at a real $defs entry."""
    defs = set(schema.get("$defs", {}).keys())
    serialized = json.dumps(schema)
    # naive but sufficient: scan for "#/$defs/<name>"
    import re

    refs = set(re.findall(r'"#/\$defs/([A-Za-z0-9_]+)"', serialized))
    unresolved = refs - defs
    assert not unresolved, f"Unresolved $defs references: {sorted(unresolved)}"


def test_delta_report_def_present(schema: dict) -> None:
    """DeltaReport is documented in $defs so consumers can validate `recon delta` output."""
    assert "DeltaReport" in schema.get("$defs", {})


def test_batch_mode_defs_present(schema: dict) -> None:
    """Each batch output mode has a $defs entry (v1.9.26 schema-contract polish).

    The root schema is single-domain success output; batch and NDJSON modes
    interleave success objects with ``{domain, error}`` records. Those shapes
    live in dedicated $defs so a consumer can validate every output mode. Full
    shape assertions live in ``test_batch_ndjson_schema.py``.
    """
    defs = schema.get("$defs", {})
    for name in ("BatchArray", "BatchNdjsonRecord", "BatchResult", "BatchErrorRecord"):
        assert name in defs, f"missing $defs/{name}"


@pytest.mark.parametrize(
    ("def_name", "model", "omitted_fields", "schema_only_fields"),
    [
        ("BIMIIdentity", BIMIIdentity, set(), set()),
        ("CertBurst", CertBurst, set(), set()),
        ("CertSummary", CertSummary, set(), set()),
        ("ChainMotif", ChainMotifObservation, set(), set()),
        ("DeltaReport", DeltaReport, set(), {"record_type"}),
        ("EvidenceRecord", EvidenceRecord, set(), set()),
        ("InfrastructureCluster", InfrastructureCluster, set(), set()),
        ("InfrastructureClusterReport", InfrastructureClusterReport, {"edges"}, set()),
        ("NodeConflict", NodeConflict, set(), set()),
        ("NodeEvidence", NodeEvidence, set(), set()),
        ("NodeUnitCounterfactual", NodeUnitCounterfactual, set(), set()),
        ("PosteriorObservation", PosteriorObservation, set(), set()),
        ("SurfaceAttribution", SurfaceAttribution, set(), set()),
        ("UnclassifiedCnameChain", UnclassifiedCnameChain, set(), set()),
    ],
)
def test_model_backed_defs_match_dataclass_fields(
    schema: dict,
    def_name: str,
    model: type,
    omitted_fields: set[str],
    schema_only_fields: set[str],
) -> None:
    """Model-backed $defs must move with their dataclasses.

    The schema remains hand-maintained, but nested model docs should not silently
    lose or invent fields. Intentional exceptions are explicit here: for example
    raw infrastructure graph edges are MCP-only and not part of the default JSON
    envelope.
    """
    definition = schema["$defs"][def_name]
    schema_fields = set(definition["properties"])
    model_fields = {field.name for field in fields(model)} - omitted_fields

    missing = model_fields - schema_fields
    unexpected = schema_fields - model_fields - schema_only_fields

    assert not missing, f"{def_name} schema is missing model fields: {sorted(missing)}"
    assert not unexpected, f"{def_name} schema has fields not on {model.__name__}: {sorted(unexpected)}"


def test_schema_contract_constant_matches_required(schema: dict) -> None:
    """Drift guard for the runtime mirror used by ``recon doctor``.

    ``recon_tool.schema_contract.REQUIRED_TOP_LEVEL_FIELDS`` is a tuple
    of the same fields the schema marks required. Doctor reads it at
    runtime to verify the emitter still produces the locked contract.
    If the schema file gains/loses a required field but the constant
    is not updated, this test fails so the doctor stops lying about
    coverage.
    """
    from recon_tool.schema_contract import REQUIRED_TOP_LEVEL_FIELDS

    constant_set = set(REQUIRED_TOP_LEVEL_FIELDS)
    schema_required = set(schema["required"])
    only_in_constant = constant_set - schema_required
    only_in_schema = schema_required - constant_set
    drift_message = (
        f"REQUIRED_TOP_LEVEL_FIELDS drift from docs/recon-schema.json. "
        f"In constant only: {sorted(only_in_constant)}. "
        f"In schema only: {sorted(only_in_schema)}. "
        "Update recon_tool/schema_contract.py to match."
    )
    assert not only_in_constant, drift_message
    assert not only_in_schema, drift_message
