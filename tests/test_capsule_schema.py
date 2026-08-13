"""Independent Draft 2020-12 checks for observation-capsule records."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from recon_tool.capsule import CollectionContext, build_capsule, compare_capsules, replay_capsule
from recon_tool.models import EvidenceRecord, SourceResult, TenantInfo

_ROOT = Path(__file__).resolve().parents[1]
_DOCS_SCHEMA = _ROOT / "docs" / "observation-capsule-schema.json"
_PACKAGED_SCHEMA = _ROOT / "src" / "recon_tool" / "data" / "observation-capsule-schema.json"


def _records() -> tuple[dict, dict, dict]:
    ended_at = datetime(2026, 8, 13, 12, 0, 3, tzinfo=UTC)
    evidence = EvidenceRecord("TXT", "v=DMARC1; p=reject", "DMARC", "dmarc")
    info = TenantInfo(
        tenant_id=None,
        display_name="Example Industries Ltd",
        default_domain="example.com",
        queried_domain="example.com",
        dmarc_policy="reject",
        evidence=(evidence,),
        resolved_at=ended_at.isoformat(),
    )
    source = SourceResult(
        source_name="dns_records",
        dmarc_policy="reject",
        raw_dns_records=(("TXT", evidence.raw_value),),
        evidence=(evidence,),
    )
    capsule = build_capsule(
        info,
        [source],
        CollectionContext(
            started_at=ended_at - timedelta(seconds=2),
            ended_at=ended_at,
            ct_enabled=False,
            direct_probes=False,
            timeout_seconds=30.0,
        ),
    )
    return capsule, replay_capsule(capsule), compare_capsules(capsule, capsule)


def _validator() -> Draft202012Validator:
    schema = json.loads(_DOCS_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_packaged_capsule_schema_exactly_matches_documented_schema() -> None:
    assert _PACKAGED_SCHEMA.read_bytes() == _DOCS_SCHEMA.read_bytes()


def test_capsule_replay_and_delta_validate_independently() -> None:
    validator = _validator()
    for record in _records():
        validator.validate(record)


def test_schema_rejects_unknown_capsule_property() -> None:
    validator = _validator()
    capsule, _replay, _delta = _records()
    malformed = copy.deepcopy(capsule)
    malformed["unknown"] = True
    errors = list(validator.iter_errors(malformed))
    assert errors


def test_schema_record_discriminators_are_exclusive() -> None:
    validator = _validator()
    _capsule, replay, _delta = _records()
    malformed = copy.deepcopy(replay)
    malformed["record_type"] = "observation_capsule"
    errors = list(validator.iter_errors(malformed))
    assert errors
