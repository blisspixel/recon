"""Bundled surface-inventory resource loader."""

from __future__ import annotations

from importlib.resources import files


def packaged_surface_inventory_text() -> str:
    """Return the packaged generated surface inventory."""
    return (files("recon_tool") / "data" / "surface-inventory.json").read_text(encoding="utf-8")
