"""The `recon://schema` MCP resource and its bundled-copy drift guard.

`docs/recon-schema.json` is the published source of truth, but the wheel ships
only the `recon_tool` package, so a byte-identical copy lives at
`recon_tool/data/recon-schema.json` for the schema-discovery resource to serve
offline. These tests keep the copy in sync and confirm the resource is wired.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from recon_tool.schema_contract import packaged_schema_text
from recon_tool.server import mcp

_REPO = Path(__file__).resolve().parents[1]
_DOCS_SCHEMA = _REPO / "docs" / "recon-schema.json"
_PACKAGED_SCHEMA = _REPO / "src" / "recon_tool" / "data" / "recon-schema.json"


def _normalize(text: str) -> str:
    return text.replace("\r\n", "\n")


def test_bundled_schema_matches_docs() -> None:
    """The packaged copy is identical to the published docs schema."""
    assert _normalize(_PACKAGED_SCHEMA.read_text(encoding="utf-8")) == _normalize(
        _DOCS_SCHEMA.read_text(encoding="utf-8")
    )


def test_loader_returns_the_schema() -> None:
    loaded = json.loads(packaged_schema_text())
    docs = json.loads(_DOCS_SCHEMA.read_text(encoding="utf-8"))
    assert loaded == docs
    assert loaded["title"] == "recon JSON output"
    # The contract version is carried in the schema's own description.
    assert "contract" in loaded["description"]


def test_schema_resource_is_registered() -> None:
    resources = asyncio.run(mcp.list_resources())
    by_uri = {str(r.uri): r for r in resources}
    assert "recon://schema" in by_uri
    assert by_uri["recon://schema"].mimeType == "application/json"
