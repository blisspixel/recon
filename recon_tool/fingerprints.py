"""Load SaaS fingerprint patterns from YAML data file.

Supports the multi-detection schema:
  fingerprints:
    - name: OpenAI
      slug: openai
      category: AI & Generative
      confidence: high
      detections:
        - type: txt
          pattern: "^openai-domain-verification="

Also supports custom fingerprints from ~/.recon/fingerprints.yaml
(additive only — custom entries cannot override or disable built-in ones).
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, NamedTuple

import yaml

logger = logging.getLogger("recon")

__all__ = [
    "Detection",
    "DetectionRule",
    "EphemeralCapacityError",
    "Fingerprint",
    "clear_ephemeral",
    "get_caa_patterns",
    "get_cname_patterns",
    "get_dmarc_rua_patterns",
    "get_ephemeral",
    "get_m365_names",
    "get_m365_slugs",
    "get_mx_patterns",
    "get_ns_patterns",
    "get_spf_patterns",
    "get_srv_patterns",
    "get_subdomain_txt_patterns",
    "get_txt_patterns",
    "inject_ephemeral",
    "load_fingerprints",
    "match_txt",
    "reload_fingerprints",
]

# Hard cap on pattern length. Not a ReDoS fix by itself — see _validate_regex.
_MAX_PATTERN_LENGTH = 500

_VALID_DETECTION_TYPES = frozenset({"txt", "spf", "mx", "ns", "cname", "subdomain_txt", "caa", "srv", "dmarc_rua"})
_VALID_CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})
_VALID_MATCH_MODES = frozenset({"any", "all"})

# Structural patterns known to cause catastrophic backtracking.
# Matches nested quantifiers like (a+)+, (a*)+, (a+)*, (\w+)+, etc.
# Also catches overlapping alternation patterns like (a|a)+ and
# polynomial backtracking like \w+\w+\w+ (3+ adjacent quantifiers).
# This is a heuristic — not exhaustive — but catches the most common
# ReDoS vectors from user-supplied custom fingerprints.
_REDOS_RE = re.compile(
    r"\([^)]*[+*][^)]*\)[+*]"  # (group-with-quantifier) followed by quantifier
    r"|"
    r"(?:[+*]\??\.\*[+*])"  # quantifier + .* + quantifier
    r"|"
    r"(?:\.[+*]\??\.[+*]\??\.[+*])"  # three adjacent .X quantifiers (polynomial)
)


class Detection(NamedTuple):
    """A single fingerprint detection rule — replaces anonymous tuples."""

    pattern: str
    name: str
    slug: str
    category: str
    confidence: str


@dataclass(frozen=True)
class DetectionRule:
    """A validated detection rule within a fingerprint."""

    type: str
    pattern: str
    description: str = ""
    reference: str = ""
    weight: float = 1.0


@dataclass(frozen=True)
class Fingerprint:
    """A validated, immutable fingerprint entry loaded from YAML.

    Frozen dataclass ensures cached fingerprints cannot be mutated.
    """

    name: str
    slug: str
    category: str
    confidence: str
    m365: bool
    detections: tuple[DetectionRule, ...]
    provider_group: str | None = None  # e.g., "microsoft365", "google-workspace"
    display_group: str | None = None  # e.g., "Email & Communication", "Security"
    match_mode: str = "any"  # "any" (OR) or "all" (AND)


def _validate_regex(pattern: str, source: str) -> bool:
    """Validate a regex pattern is safe to compile and not degenerate.

    Three-layer defense:
    1. Reject empty / excessively long patterns.
    2. Reject patterns with known catastrophic-backtracking structures
       (nested quantifiers like (a+)+). This is a heuristic, not a proof —
       for full safety, swap in google-re2 or another linear-time engine.
    3. Reject patterns that don't compile.
    """
    if not pattern:
        logger.warning("Empty regex pattern in %s — skipped", source)
        return False
    if len(pattern) > _MAX_PATTERN_LENGTH:
        logger.warning(
            "Regex pattern too long (%d chars) in %s — skipped",
            len(pattern),
            source,
        )
        return False
    # Heuristic ReDoS check: reject nested quantifiers
    if _REDOS_RE.search(pattern):
        logger.warning(
            "Potentially unsafe regex (nested quantifiers) %r in %s — skipped",
            pattern,
            source,
        )
        return False
    try:
        re.compile(pattern)
    except re.error as exc:
        logger.warning("Invalid regex %r in %s: %s — skipped", pattern, source, exc)
        return False
    return True


def _validate_fingerprint(fp: dict[str, Any], source: str) -> Fingerprint | None:
    """Validate a single fingerprint entry and return a frozen Fingerprint, or None.

    Does NOT mutate the input dict. Returns a frozen dataclass.
    """
    if not isinstance(fp, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
        logger.warning("Non-dict fingerprint entry in %s — skipped", source)
        return None

    name = fp.get("name")
    if not name or not isinstance(name, str):
        logger.warning("Fingerprint missing 'name' in %s — skipped", source)
        return None

    detections_raw = fp.get("detections")
    if not isinstance(detections_raw, list) or not detections_raw:
        logger.warning("Fingerprint %r has no detections in %s — skipped", name, source)
        return None

    confidence = fp.get("confidence", "medium")
    if confidence not in _VALID_CONFIDENCE_LEVELS:
        logger.warning(
            "Fingerprint %r has invalid confidence %r in %s — defaulting to medium",
            name,
            confidence,
            source,
        )
        confidence = "medium"

    valid_detections: list[DetectionRule] = []
    for det in detections_raw:
        if not isinstance(det, dict):
            continue
        det_type = det.get("type")
        if det_type not in _VALID_DETECTION_TYPES:
            logger.warning(
                "Fingerprint %r has unknown detection type %r in %s — skipped",
                name,
                det_type,
                source,
            )
            continue
        pattern = det.get("pattern", "")
        if not _validate_regex(pattern, f"{source}:{name}"):
            continue
        # Parse and validate detection weight
        weight = 1.0
        raw_weight = det.get("weight")
        if raw_weight is not None:
            try:
                weight = float(raw_weight)
            except (TypeError, ValueError):
                logger.warning(
                    "Fingerprint %r detection has non-numeric weight %r in %s — defaulting to 1.0",
                    name,
                    raw_weight,
                    source,
                )
                weight = 1.0
            else:
                if weight < 0.0 or weight > 1.0:
                    logger.warning(
                        "Fingerprint %r detection has out-of-range weight %r in %s — defaulting to 1.0",
                        name,
                        raw_weight,
                        source,
                    )
                    weight = 1.0

        valid_detections.append(
            DetectionRule(
                type=det_type,
                pattern=pattern,
                description=det.get("description", ""),
                reference=det.get("reference", ""),
                weight=weight,
            )
        )

    if not valid_detections:
        logger.warning("Fingerprint %r has no valid detections in %s — skipped", name, source)
        return None

    slug = fp.get("slug", name.lower().replace(" ", "-"))
    category = fp.get("category", "Misc")
    m365 = bool(fp.get("m365", False))

    match_mode = fp.get("match_mode", "any")
    if match_mode not in _VALID_MATCH_MODES:
        logger.warning(
            "Fingerprint %r has invalid match_mode %r in %s — skipped",
            name,
            match_mode,
            source,
        )
        return None

    return Fingerprint(
        name=name,
        slug=slug,
        category=category,
        confidence=confidence,
        m365=m365,
        detections=tuple(valid_detections),
        provider_group=fp.get("provider_group") if isinstance(fp.get("provider_group"), str) else None,
        display_group=fp.get("display_group") if isinstance(fp.get("display_group"), str) else None,
        match_mode=match_mode,
    )


def _load_from_path(path: Path) -> list[Fingerprint]:
    """Load and validate fingerprints from a single YAML file."""
    if not path.exists():
        return []

    source = str(path)
    try:
        text = path.read_text(encoding="utf-8")
        loaded = yaml.safe_load(text)
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to load fingerprints from %s: %s", source, exc)
        return []

    raw: list[Any] = []
    if isinstance(loaded, dict) and "fingerprints" in loaded:
        raw = loaded["fingerprints"]
    elif isinstance(loaded, list):
        raw = loaded
    else:
        logger.warning(
            "Unexpected YAML structure in %s — expected dict with 'fingerprints' key or list",
            source,
        )
        return []

    if not isinstance(raw, list):
        return []

    results: list[Fingerprint] = []
    for fp_raw in raw:
        fp = _validate_fingerprint(fp_raw, source)
        if fp is not None:
            results.append(fp)
    return results


# ── Ephemeral fingerprint storage ───────────────────────────────────────
# Session-scoped, in-memory only. Protected by a lock for thread safety
# in async contexts (asyncio.to_thread, etc.).

_ephemeral_lock = threading.Lock()
_ephemeral_fingerprints: list[Fingerprint] = []

# Hard cap on session-scoped ephemeral fingerprints. Without this,
# a long-running MCP server exposing ``inject_ephemeral_fingerprint``
# could be driven into unbounded memory growth by a malicious or
# prompt-injected client calling the tool in a loop. 100 is generous
# for legitimate session extension (users typically inject a handful
# of custom rules) and well below any memory-growth concern. Callers
# who need more can restart the server or rely on built-in fingerprints.
_MAX_EPHEMERAL_FINGERPRINTS: int = 100


class EphemeralCapacityError(RuntimeError):
    """Raised when the ephemeral-fingerprint cap is reached."""


def inject_ephemeral(fp: Fingerprint) -> None:
    """Add a validated Fingerprint to the ephemeral collection.

    Clears pattern caches so subsequent calls to load_fingerprints()
    and get_*_patterns() include the new fingerprint.

    Raises:
        EphemeralCapacityError: when the per-process cap of
            ``_MAX_EPHEMERAL_FINGERPRINTS`` is reached. Callers (the
            MCP tool in particular) surface this as a user-facing
            rejection rather than letting the list grow unbounded.
    """
    with _ephemeral_lock:
        if len(_ephemeral_fingerprints) >= _MAX_EPHEMERAL_FINGERPRINTS:
            raise EphemeralCapacityError(
                f"Ephemeral fingerprint cap reached ({_MAX_EPHEMERAL_FINGERPRINTS}). "
                "Clear the collection with clear_ephemeral() or restart the server."
            )
        _ephemeral_fingerprints.append(fp)
    # Invalidate caches
    load_fingerprints.cache_clear()
    _get_detections.cache_clear()


def clear_ephemeral() -> int:
    """Remove all ephemeral fingerprints. Returns count removed.

    Clears pattern caches so subsequent calls exclude ephemeral patterns.
    """
    with _ephemeral_lock:
        count = len(_ephemeral_fingerprints)
        _ephemeral_fingerprints.clear()
    # Invalidate caches
    load_fingerprints.cache_clear()
    _get_detections.cache_clear()
    return count


def get_ephemeral() -> tuple[Fingerprint, ...]:
    """Return all currently loaded ephemeral fingerprints."""
    with _ephemeral_lock:
        return tuple(_ephemeral_fingerprints)


def _load_from_dir(directory: Path) -> list[Fingerprint]:
    """Load every ``*.yaml`` file in ``directory`` in sorted order.

    Deterministic ordering makes detection semantics reproducible: when
    two entries produce the same pattern, the winner is the one from the
    alphabetically-first file. File sort order is stable across platforms
    because ``Path.glob`` returns lexicographic ordering after
    ``sorted()``.
    """
    if not directory.is_dir():
        return []
    entries: list[Fingerprint] = []
    for path in sorted(directory.glob("*.yaml")):
        entries.extend(_load_from_path(path))
    return entries


@lru_cache(maxsize=1)
def load_fingerprints() -> tuple[Fingerprint, ...]:
    """Load fingerprints from YAML data files (built-in + custom).

    Returns a tuple of frozen Fingerprint dataclasses. The tuple (immutable)
    and frozen dataclasses ensure the cached result cannot be corrupted by
    callers mutating the return value.

    Results are cached for the process lifetime. In the CLI this is fine
    (short-lived process). In the MCP server (long-lived), call
    reload_fingerprints() to pick up changes to custom fingerprints.

    Built-in catalog layout (v1.1+): ``data/fingerprints/<category>.yaml``.
    The pre-split monolith at ``data/fingerprints.yaml`` is still accepted
    as a fallback so a bisect against an old tree doesn't break. Custom
    fingerprints (``~/.recon/fingerprints.yaml``) are still a single file
    — contributors adding in bulk can point ``RECON_CONFIG_DIR`` at a
    directory containing ``fingerprints.yaml`` OR a ``fingerprints/``
    subdirectory of split files.
    """
    base = Path(__file__).parent / "data"
    data_dir = base / "fingerprints"
    data_file = base / "fingerprints.yaml"

    custom_dir_env = os.environ.get("RECON_CONFIG_DIR")
    custom_base = Path(custom_dir_env) if custom_dir_env else Path.home() / ".recon"
    custom_file = custom_base / "fingerprints.yaml"
    custom_dir = custom_base / "fingerprints"

    entries: list[Fingerprint] = []
    # Built-in: prefer the split directory when present; fall back to the
    # monolith only if the directory doesn't exist. Avoiding both-load
    # keeps slug uniqueness tractable during the migration window.
    if data_dir.is_dir():
        entries.extend(_load_from_dir(data_dir))
    else:
        entries.extend(_load_from_path(data_file))
    # Custom: file and directory are both valid (additive). A user might
    # keep their legacy single-file override even after the built-in split.
    entries.extend(_load_from_path(custom_file))
    entries.extend(_load_from_dir(custom_dir))
    # Append ephemeral fingerprints (not cached separately — cache is
    # invalidated on inject/clear so this always reflects current state)
    with _ephemeral_lock:
        entries.extend(_ephemeral_fingerprints)
    return tuple(entries)


def reload_fingerprints() -> None:
    """Clear all fingerprint/pattern caches so the next call reloads from disk.

    Useful for long-lived processes (MCP server) when custom fingerprints change.
    """
    load_fingerprints.cache_clear()
    _get_detections.cache_clear()
    get_m365_names.cache_clear()
    get_m365_slugs.cache_clear()


@lru_cache(maxsize=8)
def _get_detections(det_type: str) -> tuple[Detection, ...]:
    """Flatten fingerprints into Detection tuples for a given detection type.

    Returns a tuple (immutable) to prevent cache corruption.
    """
    results: list[Detection] = []
    for fp in load_fingerprints():
        for det in fp.detections:
            if det.type == det_type and det.pattern:
                results.append(Detection(det.pattern, fp.name, fp.slug, fp.category, fp.confidence))
    return tuple(results)


# Public accessors — thin wrappers over _get_detections for readability.
# All return tuple[Detection, ...] (immutable).


def get_txt_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for TXT record matching."""
    return _get_detections("txt")


def get_spf_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for SPF include matching."""
    return _get_detections("spf")


def get_mx_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for MX record matching."""
    return _get_detections("mx")


def get_ns_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for NS record matching."""
    return _get_detections("ns")


def get_cname_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for CNAME record matching."""
    return _get_detections("cname")


def get_subdomain_txt_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for subdomain-specific TXT record matching.

    These patterns have a 'pattern' field formatted as 'subdomain:regex' where
    subdomain is the prefix to query (e.g. '_slack-challenge') and regex is
    matched against the TXT value at that subdomain.
    """
    return _get_detections("subdomain_txt")


def get_caa_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for CAA record matching."""
    return _get_detections("caa")


def get_dmarc_rua_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for DMARC RUA vendor domain matching."""
    return _get_detections("dmarc_rua")


def get_srv_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for SRV record matching.

    NOTE: No built-in fingerprints currently use SRV detection. This accessor
    exists as an extension point for custom fingerprints that need SRV matching.
    """
    return _get_detections("srv")


@lru_cache(maxsize=1)
def get_m365_names() -> frozenset[str]:
    """Return names of fingerprints that indicate M365."""
    return frozenset(fp.name for fp in load_fingerprints() if fp.m365)


@lru_cache(maxsize=1)
def get_m365_slugs() -> frozenset[str]:
    """Return slugs of fingerprints that indicate M365.

    Slug-based detection is more stable than name-based — renaming a
    fingerprint's display name won't break M365 detection.
    """
    return frozenset(fp.slug for fp in load_fingerprints() if fp.m365)


# Maximum TXT record length to match against. DNS TXT records are limited to
# ~64KB in practice (multiple 255-byte strings). Anything longer is likely
# malformed or adversarial input designed to trigger regex backtracking.
_MAX_TXT_MATCH_LENGTH = 4096


def match_txt(txt_value: str, patterns: tuple[Detection, ...] | list[Detection]) -> Detection | None:
    """Match a TXT record value against patterns. Returns the matching Detection or None.

    Rejects excessively long input to bound regex execution time.
    """
    if len(txt_value) > _MAX_TXT_MATCH_LENGTH:
        return None
    for det in patterns:
        try:
            if re.search(det.pattern, txt_value, re.IGNORECASE):
                return det
        except re.error:
            # Defensive: pattern was validated on load, but guard against edge cases
            continue
    return None
