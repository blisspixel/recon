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

from recon_tool.models import MetadataCondition, SignalContext

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
    metadata: tuple[MetadataCondition, ...] = ()


_VALID_METADATA_FIELDS = frozenset({
    "dmarc_policy", "auth_type", "email_security_score",
    "spf_include_count", "issuance_velocity",
})
_VALID_OPERATORS = frozenset({"eq", "neq", "gte", "lte"})


def _parse_metadata_block(name: str, raw_metadata: list[dict[str, Any]]) -> tuple[MetadataCondition, ...] | None:
    """Parse and validate a metadata block. Returns None if any entry is invalid."""
    conditions: list[MetadataCondition] = []
    for entry in raw_metadata:
        if not isinstance(entry, dict):
            logger.warning("Signal %r has non-dict metadata entry — skipped entire signal", name)
            return None
        field = entry.get("field")
        operator = entry.get("operator")
        value = entry.get("value")
        if field not in _VALID_METADATA_FIELDS:
            logger.warning("Signal %r has invalid metadata field %r — skipped entire signal", name, field)
            return None
        if operator not in _VALID_OPERATORS:
            logger.warning("Signal %r has invalid metadata operator %r — skipped entire signal", name, operator)
            return None
        if value is None:
            logger.warning("Signal %r has missing metadata value — skipped entire signal", name)
            return None
        conditions.append(MetadataCondition(field=field, operator=operator, value=value))
    return tuple(conditions)


def _validate_and_build_signal(signal: dict[str, Any], index: int) -> Signal | None:
    """Validate a single signal definition and return a frozen Signal, or None.

    Required: name (str), and at least one of requires.any or metadata.
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

    # Parse optional metadata block
    metadata_conditions: tuple[MetadataCondition, ...] = ()
    raw_metadata = signal.get("metadata")
    if raw_metadata is not None:
        if not isinstance(raw_metadata, list) or not raw_metadata:
            logger.warning("Signal %r has invalid 'metadata' block — skipped", name)
            return None
        parsed = _parse_metadata_block(name, raw_metadata)
        if parsed is None:
            return None
        metadata_conditions = parsed

    # Parse optional requires block
    requires = signal.get("requires")
    candidates: tuple[str, ...] = ()
    min_matches = 0

    if requires is not None:
        if not isinstance(requires, dict):
            logger.warning("Signal %r has invalid 'requires' — skipped", name)
            return None
        any_list = requires.get("any")
        if isinstance(any_list, list) and any_list:
            candidates = tuple(any_list)
            min_matches = signal.get("min_matches", 1)
            if not isinstance(min_matches, int) or min_matches < 1:
                logger.warning("Signal %r has invalid min_matches %r — defaulting to 1", name, min_matches)
                min_matches = 1
        elif metadata_conditions:
            # requires block present but no valid any list — OK if metadata present
            pass
        else:
            logger.warning("Signal %r has empty or missing 'requires.any' and no metadata — skipped", name)
            return None
    elif not metadata_conditions:
        # No requires and no metadata — skip
        logger.warning("Signal %r has neither 'requires' nor 'metadata' — skipped", name)
        return None

    return Signal(
        name=name,
        category=signal.get("category", ""),
        confidence=signal.get("confidence", "medium"),
        description=signal.get("description", ""),
        candidates=candidates,
        min_matches=min_matches,
        metadata=metadata_conditions,
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


def _evaluate_metadata_condition(condition: MetadataCondition, context: SignalContext) -> bool:
    """Evaluate a single metadata condition against the context."""
    field_value = getattr(context, condition.field, None)

    op = condition.operator
    target = condition.value

    # neq with None field → True (field doesn't exist, so it's not equal to target)
    if field_value is None:
        return op == "neq"

    # For numeric operators, try numeric comparison
    if op in ("gte", "lte"):
        try:
            numeric_field = int(field_value) if not isinstance(field_value, int) else field_value
            numeric_target = int(target) if not isinstance(target, int) else target
            if op == "gte":
                return numeric_field >= numeric_target
            return numeric_field <= numeric_target
        except (ValueError, TypeError):
            return False

    # String comparison for eq/neq
    str_field = str(field_value).lower()
    str_target = str(target).lower()
    if op == "eq":
        return str_field == str_target
    if op == "neq":
        return str_field != str_target
    return False


def evaluate_signals(
    context: SignalContext,
) -> list[SignalMatch]:
    """Evaluate which signals fire based on detected fingerprint slugs and metadata.

    Returns list of frozen SignalMatch dataclasses with metadata, matched slugs,
    and optional description.

    Signals can match on slug presence (requires.any), metadata conditions, or both.
    When both are present, the signal fires only if both slug threshold AND all
    metadata conditions are satisfied.
    """
    results: list[SignalMatch] = []
    for signal in load_signals():
        # Check slug matches (if signal has candidates)
        matched = [slug for slug in signal.candidates if slug in context.detected_slugs]
        slug_satisfied = len(matched) >= signal.min_matches

        # Check metadata conditions (if signal has any)
        metadata_satisfied = all(
            _evaluate_metadata_condition(cond, context)
            for cond in signal.metadata
        ) if signal.metadata else True

        # Signal fires only if BOTH slug and metadata conditions are met
        # For metadata-only signals (no candidates), slug_satisfied is True (min_matches=0)
        if slug_satisfied and metadata_satisfied:
            results.append(SignalMatch(
                name=signal.name,
                category=signal.category,
                confidence=signal.confidence,
                matched=tuple(matched),
                description=signal.description,
            ))

    return results
