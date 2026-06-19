from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from recon_tool.schema_contract import REQUIRED_TOP_LEVEL_FIELDS, classify_batch_record

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "automation-examples.md"
SCHEMA = ROOT / "docs" / "recon-schema.json"
SAMPLE = ROOT / "examples" / "sample-output.json"


def _doc_text() -> str:
    return DOC.read_text(encoding="utf-8")


def _json_blocks() -> list[dict[str, Any]]:
    blocks = re.findall(r"```json\n(.*?)\n```", _doc_text(), flags=re.DOTALL)
    return [json.loads(block) for block in blocks]


def test_automation_examples_are_discoverable_from_indexes() -> None:
    docs_index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    examples_index = (ROOT / "examples" / "README.md").read_text(encoding="utf-8")

    assert "[automation-examples.md](automation-examples.md)" in docs_index
    assert "[`docs/automation-examples.md`](../docs/automation-examples.md)" in examples_index


def test_automation_examples_cover_every_json_output_mode() -> None:
    text = _doc_text()
    compact = re.sub(r"\s+", " ", text)

    for phrase in (
        "Single Lookup",
        "Batch Array",
        "Batch Wrapper",
        "NDJSON",
        "Delta",
        "Cohort Summary",
    ):
        assert f"## {phrase}" in text
    for schema_name in ("BatchResult", "BatchErrorRecord", "DeltaReport"):
        assert schema_name in text
    assert "Reject `unknown`." in text
    assert "Do not narrate causes unless another source provided that explanation." in compact


def test_single_lookup_sample_matches_schema_required_fields() -> None:
    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))

    assert sample["record_type"] == "lookup"
    assert sample["schema_version"] == "2.0"
    assert set(REQUIRED_TOP_LEVEL_FIELDS) <= set(sample)


def test_json_snippets_parse_and_match_declared_shapes() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    blocks = _json_blocks()

    assert len(blocks) == 2
    batch_wrapper, delta = blocks

    assert batch_wrapper["record_type"] == "batch_result"
    assert set(schema["$defs"]["BatchResult"]["required"]) <= set(batch_wrapper)
    assert [classify_batch_record(record) for record in batch_wrapper["domains"]] == ["error"]

    assert delta["record_type"] == "delta"
    assert set(schema["$defs"]["DeltaReport"]["required"]) <= set(delta)
    assert delta["changed_dmarc_policy"] == {"from": "none", "to": "reject"}
