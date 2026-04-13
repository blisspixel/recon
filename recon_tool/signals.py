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
    contradicts: tuple[str, ...] = ()
    requires_signals: tuple[str, ...] = ()
    explain: str = ""


_VALID_METADATA_FIELDS = frozenset(
    {
        "dmarc_policy",
        "auth_type",
        "email_security_score",
        "spf_include_count",
        "issuance_velocity",
    }
)
_VALID_OPERATORS = frozenset({"eq", "neq", "gte", "lte"})


def _parse_metadata_block(name: str, raw_metadata: list[Any]) -> tuple[MetadataCondition, ...] | None:
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
        # No requires and no metadata — check if requires_signals is present
        raw_requires_signals_check = signal.get("requires_signals")
        if not (isinstance(raw_requires_signals_check, list) and raw_requires_signals_check):
            logger.warning("Signal %r has neither 'requires' nor 'metadata' nor 'requires_signals' — skipped", name)
            return None

    # Parse optional contradicts field
    contradicts: tuple[str, ...] = ()
    raw_contradicts = signal.get("contradicts")
    if raw_contradicts is not None:
        if not isinstance(raw_contradicts, list):
            logger.warning("Signal %r has invalid 'contradicts' (not a list) — skipped", name)
            return None
        for entry in raw_contradicts:
            if not isinstance(entry, str) or not entry:
                logger.warning("Signal %r has invalid entry in 'contradicts' — skipped", name)
                return None
        contradicts = tuple(raw_contradicts)

    # Parse optional requires_signals field
    requires_signals: tuple[str, ...] = ()
    raw_requires_signals = signal.get("requires_signals")
    if raw_requires_signals is not None:
        if not isinstance(raw_requires_signals, list):
            logger.warning("Signal %r has invalid 'requires_signals' (not a list) — skipped", name)
            return None
        for entry in raw_requires_signals:
            if not isinstance(entry, str) or not entry:
                logger.warning("Signal %r has invalid entry in 'requires_signals' — skipped", name)
                return None
        requires_signals = tuple(raw_requires_signals)

    # Parse optional explain field
    raw_explain = signal.get("explain")
    if raw_explain is not None and not isinstance(raw_explain, str):
        logger.warning("Signal %r has non-string 'explain' — defaulting to empty", name)
        raw_explain = ""
    explain: str = raw_explain if isinstance(raw_explain, str) else ""

    return Signal(
        name=name,
        category=signal.get("category", ""),
        confidence=signal.get("confidence", "medium"),
        description=signal.get("description", ""),
        candidates=candidates,
        min_matches=min_matches,
        metadata=metadata_conditions,
        contradicts=contradicts,
        requires_signals=requires_signals,
        explain=explain,
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


def _validate_meta_signals(entries: list[Signal]) -> list[Signal]:
    """Validate meta-signals at load time and remove invalid ones.

    A meta-signal (has requires_signals) is invalid if it references:
    - A signal name that does not exist in the loaded definitions
    - Another meta-signal (cycle prevention)

    Invalid meta-signals are logged as warnings and excluded from the result.
    Non-meta signals pass through unchanged.
    """
    non_meta_names: set[str] = set()
    meta_names: set[str] = set()
    for sig in entries:
        if sig.requires_signals:
            meta_names.add(sig.name)
        else:
            non_meta_names.add(sig.name)

    all_names = non_meta_names | meta_names
    valid: list[Signal] = []
    for sig in entries:
        if not sig.requires_signals:
            valid.append(sig)
            continue
        # Check for references to non-existent signals
        missing = [name for name in sig.requires_signals if name not in all_names]
        if missing:
            logger.warning(
                "Meta-signal %r references non-existent signal(s) %r — skipped",
                sig.name,
                missing,
            )
            continue
        # Check for references to other meta-signals (cycle prevention)
        meta_refs = [name for name in sig.requires_signals if name in meta_names]
        if meta_refs:
            logger.warning(
                "Meta-signal %r references other meta-signal(s) %r — skipped (cycle prevention)",
                sig.name,
                meta_refs,
            )
            continue
        valid.append(sig)
    return valid


@lru_cache(maxsize=1)
def load_signals() -> tuple[Signal, ...]:
    """Load and validate signal definitions from YAML (built-in + custom).

    Returns a tuple of frozen Signal dataclasses. The tuple (immutable)
    and frozen dataclasses ensure the cached result cannot be corrupted.

    Custom signals from ~/.recon/signals.yaml (or RECON_CONFIG_DIR) are
    loaded after built-in signals and are additive only — they cannot
    override or disable built-in signals.

    Meta-signals (those with requires_signals) are validated at load time:
    references to non-existent signals or other meta-signals are logged
    as warnings and the invalid meta-signal is excluded.

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
    entries = _validate_meta_signals(entries)
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


def _evaluate_single_signal(signal: Signal, context: SignalContext) -> SignalMatch | None:
    """Evaluate a single signal against the context, returning a match or None.

    Checks contradicts suppression, slug matches, and metadata conditions.
    """
    # Check contradicts: if any contradiction slug is present, suppress
    if signal.contradicts and any(slug in context.detected_slugs for slug in signal.contradicts):
        return None

    # Check slug matches (if signal has candidates)
    matched = [slug for slug in signal.candidates if slug in context.detected_slugs]
    slug_satisfied = len(matched) >= signal.min_matches

    # Check metadata conditions (if signal has any)
    metadata_satisfied = (
        all(_evaluate_metadata_condition(cond, context) for cond in signal.metadata) if signal.metadata else True
    )

    # Signal fires only if BOTH slug and metadata conditions are met
    # For metadata-only signals (no candidates), slug_satisfied is True (min_matches=0)
    if slug_satisfied and metadata_satisfied:
        return SignalMatch(
            name=signal.name,
            category=signal.category,
            confidence=signal.confidence,
            matched=tuple(matched),
            description=signal.description,
        )
    return None


def evaluate_signals(
    context: SignalContext,
) -> list[SignalMatch]:
    """Two-pass signal evaluation with contradicts suppression.

    Returns list of frozen SignalMatch dataclasses with metadata, matched slugs,
    and optional description.

    Pass 1: Evaluate all non-meta signals (those without requires_signals).
      - Contradicts suppression: if any slug in signal.contradicts is present
        in context.detected_slugs, the signal is skipped.
      - Then standard slug + metadata evaluation.

    Pass 2: Evaluate meta-signals (those with requires_signals).
      - A meta-signal fires only if ALL named signals from requires_signals
        fired in pass 1, AND all other conditions (contradicts, slug, metadata)
        are also satisfied.

    Evaluation order within each pass is file order (deterministic).
    """
    all_signals = load_signals()

    # Split into non-meta and meta signals, preserving file order
    non_meta = [s for s in all_signals if not s.requires_signals]
    meta = [s for s in all_signals if s.requires_signals]

    # Pass 1: evaluate non-meta signals
    first_pass: list[SignalMatch] = []
    for signal in non_meta:
        match = _evaluate_single_signal(signal, context)
        if match is not None:
            first_pass.append(match)

    # Pass 2: evaluate meta-signals against first-pass results
    fired_names = {m.name for m in first_pass}
    second_pass: list[SignalMatch] = []
    for signal in meta:
        # All referenced signals must have fired in pass 1
        if not all(name in fired_names for name in signal.requires_signals):
            continue
        # Then check contradicts + slug + metadata conditions
        match = _evaluate_single_signal(signal, context)
        if match is not None:
            second_pass.append(match)

    return first_pass + second_pass
