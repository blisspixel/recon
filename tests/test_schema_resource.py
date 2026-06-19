"""Bundled MCP JSON resources and their copied-data drift guards.

`docs/recon-schema.json` is the published source of truth, but the wheel ships
only the `recon_tool` package, so a byte-identical copy lives at
`recon_tool/data/recon-schema.json` for the schema-discovery resource to serve
offline. The generated surface inventory follows the same packaged-copy
discipline. These tests keep the copies in sync and confirm the resources are
wired.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from recon_tool.schema_contract import packaged_schema_text
from recon_tool.server import mcp
from recon_tool.surface_inventory import packaged_surface_inventory_text

_REPO = Path(__file__).resolve().parents[1]
_DOCS_SCHEMA = _REPO / "docs" / "recon-schema.json"
_DOCS_SURFACE_INVENTORY = _REPO / "docs" / "surface-inventory.json"
_PACKAGED_SCHEMA = _REPO / "src" / "recon_tool" / "data" / "recon-schema.json"
_PACKAGED_SURFACE_INVENTORY = _REPO / "src" / "recon_tool" / "data" / "surface-inventory.json"


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


def test_bundled_surface_inventory_matches_docs() -> None:
    """The packaged copy is identical to the generated docs inventory."""
    assert _normalize(_PACKAGED_SURFACE_INVENTORY.read_text(encoding="utf-8")) == _normalize(
        _DOCS_SURFACE_INVENTORY.read_text(encoding="utf-8")
    )


def test_surface_inventory_loader_returns_the_docs_inventory() -> None:
    loaded = json.loads(packaged_surface_inventory_text())
    docs = json.loads(_DOCS_SURFACE_INVENTORY.read_text(encoding="utf-8"))
    assert loaded == docs
    assert loaded["stability"] == "non_contractual_generated_inventory"


def test_surface_inventory_resource_is_registered() -> None:
    resources = asyncio.run(mcp.list_resources())
    by_uri = {str(r.uri): r for r in resources}
    assert "recon://surface-inventory" in by_uri
    assert by_uri["recon://surface-inventory"].mimeType == "application/json"
