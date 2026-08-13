"""Contract tests for the independent JSON Schema interoperability gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.check_schema_interoperability import (
    _resolve_local_pointer,
    _walk_json,
    characterize_schema,
    main,
)


def test_current_schema_passes_independent_interoperability_gate() -> None:
    report = characterize_schema()

    assert report.ok
    assert report.draft == "2020-12"
    assert report.schema_bytes > 0
    assert report.schema_nodes > 0
    assert report.local_ref_count > 0
    assert report.external_ref_count == 0
    assert report.unresolved_local_refs == ()
    assert report.representative_payload_bytes > 0


def test_schema_copies_must_be_content_identical(tmp_path: Path) -> None:
    docs = tmp_path / "docs.json"
    packaged = tmp_path / "packaged.json"
    docs.write_text("{}\n", encoding="utf-8")
    packaged.write_text('{"different": true}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="content-identical"):
        characterize_schema(docs, packaged)


def test_walker_counts_refs_depth_and_format_keywords() -> None:
    value = {"$ref": "#/$defs/item", "$defs": {"item": {"type": "string", "format": "uri"}}}

    nodes, depth, refs, format_count = _walk_json(value)

    assert nodes == 6
    assert depth == 3
    assert refs == ["#/$defs/item"]
    assert format_count == 1


def test_local_pointer_decodes_rfc_6901_tokens() -> None:
    document = {"$defs": {"a/b": {"~key": 7}}}

    assert _resolve_local_pointer(document, "#/$defs/a~1b/~0key") == 7


def test_unresolved_local_ref_fails_report(tmp_path: Path) -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "$ref": "#/$defs/missing",
    }
    docs = tmp_path / "docs.json"
    packaged = tmp_path / "packaged.json"
    text = json.dumps(schema)
    docs.write_text(text, encoding="utf-8")
    packaged.write_text(text, encoding="utf-8")

    report = characterize_schema(docs, packaged)

    assert not report.ok
    assert report.unresolved_local_refs == ("#/$defs/missing",)


def test_cli_json_report_is_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["draft"] == "2020-12"
