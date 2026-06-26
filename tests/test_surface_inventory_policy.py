from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _compact(text: str) -> str:
    return " ".join(text.split())


def test_surface_inventory_promotion_decision_is_documented() -> None:
    adr = (ROOT / "docs" / "adr" / "0007-surface-inventory-discovery-context.md").read_text(encoding="utf-8")
    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    mcp_docs = (ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")
    adr_index = (ROOT / "docs" / "adr" / "README.md").read_text(encoding="utf-8")

    assert "- **Status:** Accepted" in adr
    assert "Do not promote `docs/surface-inventory.json` or `recon://surface-inventory`" in adr
    assert "v2.3 stable surface" in adr
    assert "concrete external consumer" in adr
    assert "not stable runtime API contracts" in _compact(readme)
    assert "ADR-0007" in roadmap
    assert "ADR-0007" in mcp_docs
    assert "0007-surface-inventory-discovery-context.md" in adr_index


def test_surface_inventory_promotion_gate_stays_specific() -> None:
    adr = (ROOT / "docs" / "adr" / "0007-surface-inventory-discovery-context.md").read_text(encoding="utf-8")

    required_gate_terms = [
        "concrete external consumer",
        "smallest useful subset",
        "compatibility policy",
        "Contract tests",
        "Migration notes",
    ]
    for term in required_gate_terms:
        assert term in adr
