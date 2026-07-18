"""Batch / NDJSON record contract.

The single-domain ``--json`` contract is pinned by
``test_json_schema_contract.py`` and ``test_json_schema_file.py``. Batch
runs (``recon batch --json`` and ``recon batch --ndjson``) interleave two
record shapes per line / element: a single-domain success object and a
``{domain, error}`` error record emitted when a domain fails validation or
lookup. Those two shapes, and the deterministic rule a consumer applies to
tell them apart, are the schema-contract polish.

These tests validate a synthetic batch NDJSON sample with the single
deterministic rule set (``classify_batch_record``): success records carry
the full single-domain shape, error records are handled by the explicit
``{domain, error}`` allowance, and nothing else is accepted. The sample
uses explicit synthetic labels and reserved domains; no real or private-corpus
data is committed. The maintainer can point the same rule set at a
private-corpus ``--ndjson`` run locally.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from recon_tool.formatter import format_tenant_dict
from recon_tool.models import BIMIIdentity, CandidateValue, MergeConflicts, TenantInfo
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
    failed validation. Explicit synthetic labels only.
    """
    alpha = fully_populated_tenant_info
    gamma = replace(
        fully_populated_tenant_info,
        display_name="Synthetic Gamma",
        default_domain="gamma.invalid",
        queried_domain="gamma.invalid",
    )
    lines = [
        json.dumps(format_tenant_dict(alpha)),
        json.dumps(format_tenant_dict(gamma)),
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
    """Success envelopes carry every required single-domain field."""
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


def test_record_type_does_not_bypass_shape_validation() -> None:
    """record_type selects the key envelope; it cannot bypass key checks.

    A malformed payload that only sets record_type must not be accepted: the
    required-field set (success) and the closed four-key set (error) are still
    enforced. Property value validation belongs to the JSON Schema.
    """
    # record_type=lookup but missing every required success field.
    assert classify_batch_record({"record_type": "lookup"}) == "unknown"
    # record_type=lookup with only a couple of fields present.
    assert classify_batch_record({"record_type": "lookup", "queried_domain": "x"}) == "unknown"
    # record_type=error with arbitrary extra field (schema is closed).
    assert classify_batch_record({"record_type": "error", "evil": True}) == "unknown"
    # record_type=error missing error_kind/domain.
    assert classify_batch_record({"record_type": "error", "error": "boom"}) == "unknown"
    # A well-formed v2.0 error record still classifies as error.
    good_error = {"domain": "bad", "error": "invalid", "error_kind": "validation", "record_type": "error"}
    assert classify_batch_record(good_error) == "error"
    # A well-formed v2.0 error record with one extra key is rejected (closed shape).
    assert classify_batch_record({**good_error, "extra": 1}) == "unknown"
    # A full success record with record_type=lookup classifies as success.
    full_success = dict.fromkeys(REQUIRED_TOP_LEVEL_FIELDS, "x")
    full_success["record_type"] = "lookup"
    assert classify_batch_record(full_success) == "success"
    assert classify_batch_record({**full_success, "record_type": "bogus"}) == "unknown"
    assert classify_batch_record({**full_success, "record_type": 7}) == "unknown"


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


def _cross_domain_info(
    domain: str,
    *,
    tenant_id: str | None = None,
    tokens: tuple[str, ...] = (),
    slugs: tuple[str, ...] = (),
    bimi_org: str | None = None,
    degraded_sources: tuple[str, ...] = (),
    merge_conflicts: MergeConflicts | None = None,
) -> TenantInfo:
    """Build a minimal batch-correlation fixture with controlled channels."""
    return TenantInfo(
        tenant_id=tenant_id,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        slugs=slugs,
        site_verification_tokens=tokens,
        bimi_identity=BIMIIdentity(organization=bimi_org) if bimi_org else None,
        degraded_sources=degraded_sources,
        merge_conflicts=merge_conflicts,
    )


def test_batch_token_overlap_ignores_unavailable_apex_txt(capsys) -> None:
    """Raw partial TXT state must not leak into cross-domain token output."""
    infos = {
        "a.invalid": _cross_domain_info("a.invalid", tokens=("MS=shared",)),
        "b.invalid": _cross_domain_info(
            "b.invalid",
            tokens=("MS=shared",),
            degraded_sources=("dns:apex_txt",),
        ),
    }
    records = [{"queried_domain": domain} for domain in infos]

    from recon_tool.cli import _batch_emit_json

    _batch_emit_json(records, infos, include_ecosystem=False)
    out = json.loads(capsys.readouterr().out)

    assert all("shared_verification_tokens" not in record for record in out)


def test_batch_ecosystem_ignores_unavailable_bimi(capsys) -> None:
    """Raw partial BIMI identity must not produce a BIMI organization edge."""
    infos = {
        "a.invalid": _cross_domain_info("a.invalid", bimi_org="Example Corp"),
        "b.invalid": _cross_domain_info(
            "b.invalid",
            bimi_org="Example Corp",
            degraded_sources=("dns:bimi",),
        ),
    }
    records = [{"queried_domain": domain} for domain in infos]

    from recon_tool.cli import _batch_emit_json

    _batch_emit_json(records, infos, include_ecosystem=True)
    out = json.loads(capsys.readouterr().out)

    assert all(edge["edge_type"] != "bimi_org" for edge in out["ecosystem_hyperedges"])


def test_batch_ecosystem_uses_collection_observable_slugs(capsys) -> None:
    """An unavailable apex TXT channel cannot contribute shared slug overlap."""
    txt_slugs = ("microsoft365", "google-site", "spf-strict")
    infos = {
        "a.invalid": _cross_domain_info("a.invalid", slugs=txt_slugs),
        "b.invalid": _cross_domain_info(
            "b.invalid",
            slugs=txt_slugs,
            degraded_sources=("dns:apex_txt",),
        ),
    }
    records = [{"queried_domain": domain} for domain in infos]

    from recon_tool.cli import _batch_emit_json

    _batch_emit_json(records, infos, include_ecosystem=True)
    out = json.loads(capsys.readouterr().out)

    assert all(edge["edge_type"] != "shared_slugs" for edge in out["ecosystem_hyperedges"])


def test_shared_tenant_uses_positive_identity_across_dns_degradation(capsys) -> None:
    """DNS availability does not mask a positive provider identity response."""
    tenant_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    infos = {
        "a.invalid": _cross_domain_info("a.invalid", tenant_id=tenant_id),
        "b.invalid": _cross_domain_info("b.invalid", tenant_id=tenant_id, degraded_sources=("dns",)),
    }
    records = [{"queried_domain": domain} for domain in infos]

    from recon_tool.cli import _batch_emit_json

    _batch_emit_json(records, infos, include_ecosystem=False)
    out = json.loads(capsys.readouterr().out)

    assert all(record["shared_tenant"][0]["tenant_id"] == tenant_id for record in out)


def test_shared_tenant_excludes_conflicted_identity(capsys) -> None:
    """A selected first-wins tenant value is not clustered when sources disagree."""
    tenant_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    conflicts = MergeConflicts(
        tenant_id=(
            CandidateValue(value=tenant_id, source="oidc_discovery", confidence="medium"),
            CandidateValue(
                value="00000000-0000-0000-0000-000000000001",
                source="identity_peer",
                confidence="medium",
            ),
        )
    )
    infos = {
        "a.invalid": _cross_domain_info("a.invalid", tenant_id=tenant_id),
        "b.invalid": _cross_domain_info("b.invalid", tenant_id=tenant_id, merge_conflicts=conflicts),
    }
    records = [{"queried_domain": domain} for domain in infos]

    from recon_tool.cli import _batch_emit_json

    _batch_emit_json(records, infos, include_ecosystem=False)
    out = json.loads(capsys.readouterr().out)

    assert all("shared_tenant" not in record for record in out)


def test_batch_only_fields_keep_a_record_classified_as_success(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    """The batch-wide enrichment keys are additive and do not break classification."""
    record = format_tenant_dict(fully_populated_tenant_info)
    record["shared_verification_tokens"] = [{"token": "MS=ms12345", "peer": "gamma.invalid"}]
    record["shared_tenant"] = [{"tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "peers": ["gamma.invalid"]}]
    record["shared_display_name"] = [
        {"display_name": "Synthetic Alpha Ltd", "normalized_name": "alpha", "peers": ["alpha.invalid"]}
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
