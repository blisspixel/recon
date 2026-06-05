"""Batch / NDJSON record contract (v1.9.26).

The single-domain ``--json`` contract is pinned by
``test_json_schema_contract.py`` and ``test_json_schema_file.py``. Batch
runs (``recon batch --json`` and ``recon batch --ndjson``) interleave two
record shapes per line / element: a single-domain success object and a
``{domain, error}`` error record emitted when a domain fails validation or
lookup. Those two shapes, and the deterministic rule a consumer applies to
tell them apart, are the v1.9.26 schema-contract polish.

These tests validate a synthetic batch NDJSON sample with the single
deterministic rule set (``classify_batch_record``): success records carry
the full single-domain shape, error records are handled by the explicit
``{domain, error}`` allowance, and nothing else is accepted. The sample
uses Microsoft fictional brands only (Contoso, Northwind); no real or
private-corpus data is committed. The maintainer can point the same rule
set at a private-corpus ``--ndjson`` run locally.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from recon_tool.formatter import format_tenant_dict
from recon_tool.models import TenantInfo
from recon_tool.schema_contract import (
    BATCH_ERROR_RECORD_KEYS,
    REQUIRED_TOP_LEVEL_FIELDS,
    classify_batch_record,
)

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "recon-schema.json"


@pytest.fixture
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def synthetic_ndjson(fully_populated_tenant_info: TenantInfo) -> str:
    """A batch NDJSON sample: two success records and one error record.

    Mirrors exactly what the ``recon batch --ndjson`` path emits: one JSON
    object per line, a success object from ``format_tenant_dict`` for
    domains that resolved, and a ``{domain, error}`` record for one that
    failed validation. Fictional brands only.
    """
    contoso = fully_populated_tenant_info
    northwind = replace(
        fully_populated_tenant_info,
        display_name="Northwind Traders",
        default_domain="northwind.com",
        queried_domain="northwind.com",
    )
    lines = [
        json.dumps(format_tenant_dict(contoso)),
        json.dumps(format_tenant_dict(northwind)),
        # The exact shape cli.py emits on a validation failure (SH7/SH8 v2.0:
        # adds error_kind and the record_type discriminator).
        json.dumps(
            {
                "domain": "not a valid domain",
                "error": "invalid domain syntax",
                "error_kind": "validation",
                "record_type": "error",
            }
        ),
    ]
    return "\n".join(lines) + "\n"


def test_every_ndjson_record_classifies_as_success_or_error(synthetic_ndjson: str) -> None:
    """The acceptance contract: every line is a success object or an error record.

    Applying the single deterministic rule set to the whole sample, no line
    falls through to ``"unknown"``. A run that produced an unclassifiable
    record would be a contract break.
    """
    classes = [classify_batch_record(json.loads(line)) for line in synthetic_ndjson.splitlines() if line]
    assert classes == ["success", "success", "error"]
    assert "unknown" not in classes


def test_success_records_carry_the_full_single_domain_shape(synthetic_ndjson: str) -> None:
    """Success records pass the full shape: every required single-domain field present."""
    required = set(REQUIRED_TOP_LEVEL_FIELDS)
    for line in synthetic_ndjson.splitlines():
        record = json.loads(line)
        if classify_batch_record(record) != "success":
            continue
        missing = required - set(record.keys())
        assert not missing, f"success record missing required fields: {sorted(missing)}"


def test_error_records_match_the_explicit_allowance(synthetic_ndjson: str) -> None:
    """v2.0 error records are exactly {domain, error, error_kind, record_type}."""
    v2_error_keys = {"domain", "error", "error_kind", "record_type"}
    error_records = [
        json.loads(line)
        for line in synthetic_ndjson.splitlines()
        if line and classify_batch_record(json.loads(line)) == "error"
    ]
    assert error_records, "sample should contain at least one error record"
    for record in error_records:
        assert set(record.keys()) == v2_error_keys
        assert isinstance(record["domain"], str)
        assert isinstance(record["error"], str)
        assert record["error_kind"] in ("validation", "lookup", "timeout")
        assert record["record_type"] == "error"


def test_classifier_rejects_malformed_records() -> None:
    """A record that is neither shape classifies as ``unknown`` (rejectable)."""
    # Half an error record.
    assert classify_batch_record({"domain": "x"}) == "unknown"
    # A success object with a required field dropped.
    truncated = dict.fromkeys(REQUIRED_TOP_LEVEL_FIELDS)
    truncated.pop("tenant_id")
    assert classify_batch_record(truncated) == "unknown"
    # Empty object.
    assert classify_batch_record({}) == "unknown"


def test_include_ecosystem_always_emits_wrapper_on_all_failed_batch(capsys) -> None:
    """SH9: --include-ecosystem emits the BatchResult wrapper even when no domain
    resolved, so the top-level type does not flip to a bare array."""
    from recon_tool.cli import _batch_emit_json

    error_record = {
        "domain": "bad",
        "error": "invalid domain syntax",
        "error_kind": "validation",
        "record_type": "error",
    }
    _batch_emit_json([error_record], {}, include_ecosystem=True)
    out = json.loads(capsys.readouterr().out)
    assert isinstance(out, dict), "all-failed --include-ecosystem must stay a wrapper, not a bare array"
    assert out["record_type"] == "batch_result"
    assert out["ecosystem_hyperedges"] == []
    assert out["domains"] == [error_record]


def test_batch_only_fields_keep_a_record_classified_as_success(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    """The batch-wide enrichment keys are additive and do not break classification."""
    record = format_tenant_dict(fully_populated_tenant_info)
    record["shared_verification_tokens"] = [{"token": "MS=ms12345", "peer": "northwind.com"}]
    record["shared_tenant"] = [{"tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "peers": ["northwind.com"]}]
    record["shared_display_name"] = [
        {"display_name": "Contoso Ltd", "normalized_name": "contoso", "peers": ["contoso.co.uk"]}
    ]
    assert classify_batch_record(record) == "success"


# --- schema-file alignment: the rule set mirrors docs/recon-schema.json ---


def test_schema_declares_batch_error_record(schema: dict) -> None:
    """``BatchErrorRecord`` is the closed v2.0 four-key shape."""
    v2_error_keys = {"domain", "error", "error_kind", "record_type"}
    defs = schema.get("$defs", {})
    assert "BatchErrorRecord" in defs
    ber = defs["BatchErrorRecord"]
    assert set(ber["required"]) == v2_error_keys
    assert ber.get("additionalProperties") is False
    assert set(ber["properties"].keys()) == v2_error_keys
    # The legacy two-key set stays the pre-v2.0 fallback in the classifier.
    assert set(BATCH_ERROR_RECORD_KEYS) == {"domain", "error"}


def test_schema_declares_batch_array_and_ndjson_defs(schema: dict) -> None:
    """Each batch output mode has a $defs entry whose elements allow both shapes."""
    defs = schema.get("$defs", {})
    for name in ("BatchArray", "BatchNdjsonRecord", "BatchResult"):
        assert name in defs, f"missing $defs/{name}"

    # BatchArray items and BatchNdjsonRecord both oneOf {root, BatchErrorRecord}.
    def _oneof_refs(node: dict) -> set[str]:
        return {branch.get("$ref", "") for branch in node.get("oneOf", [])}

    array_item_refs = _oneof_refs(defs["BatchArray"]["items"])
    assert array_item_refs == {"#", "#/$defs/BatchErrorRecord"}

    ndjson_refs = _oneof_refs(defs["BatchNdjsonRecord"])
    assert ndjson_refs == {"#", "#/$defs/BatchErrorRecord"}

    # BatchResult wraps domains (same oneOf) and a required ecosystem_hyperedges,
    # and carries the SH7 record_type discriminator.
    assert set(defs["BatchResult"]["required"]) == {"record_type", "domains", "ecosystem_hyperedges"}
    domain_item_refs = _oneof_refs(defs["BatchResult"]["properties"]["domains"]["items"])
    assert domain_item_refs == {"#", "#/$defs/BatchErrorRecord"}


def test_root_schema_describes_single_domain_scope(schema: dict) -> None:
    """The top-level description scopes the root to single-domain success output."""
    description = schema["description"]
    assert "single-domain" in description
    # Points consumers at the other-mode defs so the prose is unambiguous.
    for ref in ("BatchArray", "BatchErrorRecord", "BatchResult", "BatchNdjsonRecord", "DeltaReport"):
        assert ref in description, f"root description should mention {ref}"
