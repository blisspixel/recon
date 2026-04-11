"""Signal intelligence engine — derives insights from fingerprint matches.

Signals are organized in three layers (defined in signals.yaml):
  Layer 1: Single-category detection (e.g., "2+ security tools")
  Layer 2: Cross-category composites (e.g., "AI + collab + cloud = Digital Transformation")
  Layer 3: Consistency checks (contradictions between signal layers)

This layered approach is inspired by multi-vector fusion architectures —
combining independent signal layers produces insights no single layer can.

Also supports custom signals from ~/.recon/signals.yaml
(additive only — custom entries cannot override or disable built-in ones).
Set RECON_CONFIG_DIR to override the custom directory.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("recon")

__all__ = [
    "Signal",
    "SignalMatch",
    "evaluate_signals",
    "load_signals",
    "reload_signals",
]


@dataclass(frozen=True)
class Signal:
    """A validated, immutable signal definition loaded from signals.yaml.

    Frozen dataclass ensures cached signals cannot be mutated
    (mirrors Fingerprint pattern).
    """

    name: str
    category: str
    confidence: str
    description: str
    candidates: tuple[str, ...]
    min_matches: int


def _validate_and_build_signal(signal: dict[str, Any], index: int) -> Signal | None:
    """Validate a single signal definition and return a frozen Signal, or None.

    Required: name (str), requires.any (non-empty list).
    Optional: category, confidence, min_matches, description.
    Logs warnings and returns None for invalid entries.
    Does NOT mutate the input dict.
    """
    if not isinstance(signal, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
        logger.warning("Signal at index %d is not a dict — skipped", index)
        return None
    name = signal.get("name")
    if not name or not isinstance(name, str):
        logger.warning("Signal at index %d missing 'name' — skipped", index)
        return None
    requires = signal.get("requires")
    if not isinstance(requires, dict):
        logger.warning("Signal %r missing 'requires' dict — skipped", name)
        return None
    candidates = requires.get("any")
    if not isinstance(candidates, list) or not candidates:
        logger.warning("Signal %r has empty or missing 'requires.any' — skipped", name)
        return None
    min_matches = signal.get("min_matches", 1)
    if not isinstance(min_matches, int) or min_matches < 1:
        logger.warning("Signal %r has invalid min_matches %r — defaulting to 1", name, min_matches)
        min_matches = 1
    return Signal(
        name=name,
        category=signal.get("category", ""),
        confidence=signal.get("confidence", "medium"),
        description=signal.get("description", ""),
        candidates=tuple(candidates),
        min_matches=min_matches,
    )


def _load_from_path(path: Path) -> list[Signal]:
    """Load and validate signals from a single YAML file."""
    if not path.exists():
        return []
    source = str(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to load signals from %s: %s", source, exc)
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("signals", [])
    if not isinstance(raw, list):
        return []
    results: list[Signal] = []
    for i, s in enumerate(raw):
        sig = _validate_and_build_signal(s, i)
        if sig is not None:
            results.append(sig)
    return results


@lru_cache(maxsize=1)
def load_signals() -> tuple[Signal, ...]:
    """Load and validate signal definitions from YAML (built-in + custom).

    Returns a tuple of frozen Signal dataclasses. The tuple (immutable)
    and frozen dataclasses ensure the cached result cannot be corrupted.

    Custom signals from ~/.recon/signals.yaml (or RECON_CONFIG_DIR) are
    loaded after built-in signals and are additive only — they cannot
    override or disable built-in signals.

    Results are cached for the process lifetime. In the CLI this is fine
    (short-lived process). In the MCP server (long-lived), call
    reload_signals() to pick up changes.
    """
    data_path = Path(__file__).parent / "data" / "signals.yaml"
    custom_dir = os.environ.get("RECON_CONFIG_DIR")
    custom_path = Path(custom_dir) / "signals.yaml" if custom_dir else Path.home() / ".recon" / "signals.yaml"

    entries: list[Signal] = []
    entries.extend(_load_from_path(data_path))
    entries.extend(_load_from_path(custom_path))
    return tuple(entries)


def reload_signals() -> None:
    """Clear signal cache so the next call reloads from disk."""
    load_signals.cache_clear()


@dataclass(frozen=True)
class SignalMatch:
    """Result of a signal evaluation — immutable."""

    name: str
    category: str
    confidence: str
    matched: tuple[str, ...]
    description: str = ""


def evaluate_signals(
    detected_slugs: set[str],
    dmarc_policy: str | None = None,
) -> list[SignalMatch]:
    """Evaluate which signals fire based on detected fingerprint slugs.

    Returns list of frozen SignalMatch dataclasses with metadata, matched slugs,
    and optional description.

    The dmarc_policy parameter enables cross-signal consistency checks
    that combine slug-based detection with non-slug context (e.g.,
    "gateway deployed but DMARC not enforcing").
    """
    results: list[SignalMatch] = []
    for signal in load_signals():
        matched = [slug for slug in signal.candidates if slug in detected_slugs]

        if len(matched) >= signal.min_matches:
            # Cross-signal consistency check: "Gateway Without DMARC Enforcement"
            # fires only if a gateway is present AND dmarc is not enforcing.
            # This can't be expressed in pure YAML slug matching, so we filter here.
            if (
                signal.category == "Consistency"
                and "DMARC" in signal.name
                and dmarc_policy in ("reject", "quarantine")
            ):
                continue  # DMARC is enforcing — no inconsistency

            results.append(SignalMatch(
                name=signal.name,
                category=signal.category,
                confidence=signal.confidence,
                matched=tuple(matched),
                description=signal.description,
            ))

    return results
