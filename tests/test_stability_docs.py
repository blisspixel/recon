from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "docs" / "recon-schema.json"
STABILITY = ROOT / "docs" / "stability.md"


def test_stability_json_field_counts_match_schema() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    text = STABILITY.read_text(encoding="utf-8")
    expected = (
        f"{len(schema['properties'])} top-level properties, "
        f"{len(schema['required'])} required on single-domain success output"
    )

    assert expected in text
    assert not re.search(r"\b47 stable fields\b", text)
