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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

import deal
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
    "get_cname_target_patterns",
    "get_cname_target_rules",
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
    "validate_ephemeral_input_size",
]

# Hard cap on pattern length. Not a ReDoS fix by itself — see _validate_regex.
_MAX_PATTERN_LENGTH = 500

# Generous per-file ceiling on third-party / ~/.recon catalog files. The
# bundled catalog ships well under this; the cap protects the long-lived
# MCP server from an oversized user file driving per-lookup matching cost
# or holding unbounded memory.
_MAX_CATALOG_ENTRIES_PER_FILE = 2000

_VALID_DETECTION_TYPES = frozenset(
    {"txt", "spf", "mx", "ns", "cname", "cname_target", "subdomain_txt", "caa", "srv", "dmarc_rua"}
)
# cname_target tier classifies the matched service. Application-tier wins over
# infrastructure-tier when both match in the same CNAME chain (e.g., Auth0
# fronted by Cloudflare attributes the subdomain to Auth0). Default tier when
# the YAML field is absent is "application".
_VALID_CNAME_TARGET_TIERS = frozenset({"application", "infrastructure"})
_VALID_CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})
_VALID_MATCH_MODES = frozenset({"any", "all"})

# Structural patterns known to cause catastrophic backtracking.
# Catches: nested quantifiers like (a+)+, (a*)+, (\w+)+ and the bounded
# form (a+){20}; and polynomial backtracking like \w+\w+\w+ (3+ adjacent
# quantifiers). This is a heuristic, not exhaustive: it deliberately does
# NOT flag quantified alternation like (foo|bar)+, because non-overlapping
# alternation is safe and common in real fingerprints, and distinguishing
# the dangerous overlapping form (a|a)+ from the safe form needs real
# analysis a regex cannot do. Overlapping-alternation and nested-group
# ReDoS are instead bounded by the independent input length caps
# (_MAX_TXT_MATCH_LENGTH here and the subdomain_txt cap in dns.py), which
# cap worst-case backtracking regardless of pattern. A linear-time engine
# (google-re2) would remove the heuristic but crosses the pure-Python
# dependency floor.
_REDOS_RE = re.compile(
    r"\([^)]*[+*][^)]*\)[+*{]"  # (group-with-quantifier) then + * or {n}, e.g. (a+)+
    r"|"
    r"(?:[+*]\??\.\*[+*])"  # quantifier + .* + quantifier
    r"|"
    r"(?:\.[+*]\??\.[+*]\??\.[+*])"  # three adjacent .X quantifiers (polynomial)
)

# Quantified alternation group, e.g. (a|aa)+ or (a|ab)*. Only the prefix-
# overlapping case backtracks catastrophically (one branch is a prefix of
# another, so a match can be partitioned ambiguously); disjoint alternation
# such as (foo|bar)+ is linear and stays allowed. See _alternation_redos.
_ALT_GROUP_QUANT_RE = re.compile(r"\(([^()]*\|[^()]*)\)[+*{]")


def _alternation_redos(pattern: str) -> bool:
    """Flag quantified alternation groups whose branches prefix-overlap.

    ``(a|aa)+`` and ``(a|ab)+`` cause exponential backtracking because one
    branch is a prefix of another, making a partial match ambiguous. Disjoint
    branches such as ``(foo|bar)+`` do not, so we flag only the prefix-overlap
    case. This is a heuristic over simple (non-nested) groups, not a proof; the
    docstring on _validate_regex notes the linear-time-engine swap for full
    safety.
    """
    for match in _ALT_GROUP_QUANT_RE.finditer(pattern):
        branches = [b.strip() for b in match.group(1).split("|")]
        for i, first in enumerate(branches):
            for second in branches[i + 1 :]:
                if first and second and (first.startswith(second) or second.startswith(first)):
                    return True
    return False


def _strip_escapes_and_classes(pattern: str) -> str:
    """Remove escaped characters and character-class contents so a structural
    metacharacter scan does not trip on literals like ``\\+`` or ``[+*]``."""
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2  # drop the escape and its target
            continue
        if c == "[":
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1  # a literal ] as the first class member
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1  # skip the closing ]
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _has_nested_quantifier(pattern: str) -> bool:
    """Flag a quantified group whose body itself contains a quantifier, e.g.
    ``(a+)+``, ``((a+))+``, ``(a+b+)+``, ``(a{2,4})+``. This is the
    catastrophic-backtracking shape that the flat ``_REDOS_RE`` misses once a
    paren is nested (its ``[^)]*`` limbs cannot span an inner group). A regex
    cannot match balanced parentheses, so this uses a paren-matching scan over
    the pattern with escapes and character classes removed first.
    """
    cleaned = _strip_escapes_and_classes(pattern)
    stack: list[int] = []
    for i, ch in enumerate(cleaned):
        if ch == "(":
            stack.append(i)
        elif ch == ")" and stack:
            open_i = stack.pop()
            nxt = cleaned[i + 1] if i + 1 < len(cleaned) else ""
            if nxt in "+*{" and any(q in cleaned[open_i + 1 : i] for q in "+*{"):
                return True
    return False


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
    # Only meaningful for type == "cname_target". One of "application" or
    # "infrastructure". When a CNAME chain matches both tiers, the application
    # match is the primary attribution and the infrastructure match is kept
    # as supplementary evidence. For other detection types this field is
    # ignored.
    tier: str = "application"


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
    # v1.8 relationship metadata — purely descriptive hints used by the
    # ecosystem hypergraph and downstream display logic. NEVER an
    # ownership assertion. Each field is optional and free-form.
    #   product_family — vendor-internal product line (e.g. "Microsoft 365",
    #                    "Google Workspace", "Atlassian Cloud").
    #   parent_vendor  — corporate parent the product rolls up to (e.g.
    #                    "Microsoft", "Salesforce" for Slack, "Google").
    #   bimi_org       — exact organization name expected on a BIMI VMC for
    #                    domains under this product. Used for cross-domain
    #                    BIMI clustering in the v1.8 hypergraph.
    product_family: str | None = None
    parent_vendor: str | None = None
    bimi_org: str | None = None


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
    # Heuristic ReDoS check: reject nested quantifiers and prefix-overlapping
    # quantified alternation (e.g. (a|aa)+), both catastrophic-backtracking shapes.
    if _REDOS_RE.search(pattern) or _alternation_redos(pattern) or _has_nested_quantifier(pattern):
        logger.warning(
            "Potentially unsafe regex (catastrophic backtracking) %r in %s — skipped",
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


def _validate_subdomain_txt_pattern(pattern: str, source: str, name: str) -> bool:
    """Validate ``subdomain_txt`` uses ``subdomain:regex`` format."""
    if ":" not in pattern:
        logger.warning(
            "Fingerprint %r subdomain_txt pattern %r in %s is missing 'subdomain:regex' delimiter - skipped",
            name,
            pattern,
            source,
        )
        return False
    subdomain, regex = pattern.split(":", 1)
    if not subdomain or not regex:
        logger.warning(
            "Fingerprint %r subdomain_txt pattern %r in %s must include non-empty subdomain and regex - skipped",
            name,
            pattern,
            source,
        )
        return False
    return _validate_regex(regex, f"{source}:{name}")


def _parse_detection_weight(raw_weight: Any, name: str, source: str) -> float:
    """Parse and clamp a detection weight to [0.0, 1.0]; default 1.0."""
    if raw_weight is None:
        return 1.0
    try:
        weight = float(raw_weight)
    except (TypeError, ValueError):
        logger.warning(
            "Fingerprint %r detection has non-numeric weight %r in %s — defaulting to 1.0",
            name,
            raw_weight,
            source,
        )
        return 1.0
    if weight < 0.0 or weight > 1.0:
        logger.warning(
            "Fingerprint %r detection has out-of-range weight %r in %s — defaulting to 1.0",
            name,
            raw_weight,
            source,
        )
        return 1.0
    return weight


def _parse_cname_target_tier(det: dict[str, Any], name: str, source: str) -> str:
    """Return the cname_target tier if valid, else default 'application'."""
    raw_tier = det.get("tier", "application")
    if raw_tier in _VALID_CNAME_TARGET_TIERS:
        return raw_tier
    logger.warning(
        "Fingerprint %r cname_target detection has invalid tier %r in %s — defaulting to application",
        name,
        raw_tier,
        source,
    )
    return "application"


def _parse_detection_rule(det: Any, name: str, source: str) -> DetectionRule | None:
    """Validate one detection entry and return a DetectionRule, or None to skip."""
    if not isinstance(det, dict):
        return None
    det_type = det.get("type")
    if det_type not in _VALID_DETECTION_TYPES:
        logger.warning(
            "Fingerprint %r has unknown detection type %r in %s — skipped",
            name,
            det_type,
            source,
        )
        return None
    pattern = det.get("pattern", "")
    if not isinstance(pattern, str):
        logger.warning(
            "Fingerprint %r has non-string pattern %r in %s — skipped",
            name,
            pattern,
            source,
        )
        return None
    if det_type == "subdomain_txt":
        if not _validate_subdomain_txt_pattern(pattern, source, name):
            return None
    elif not _validate_regex(pattern, f"{source}:{name}"):
        return None

    weight = _parse_detection_weight(det.get("weight"), name, source)
    tier = _parse_cname_target_tier(det, name, source) if det_type == "cname_target" else "application"
    return DetectionRule(
        type=det_type,
        pattern=pattern,
        description=det.get("description", ""),
        reference=det.get("reference", ""),
        weight=weight,
        tier=tier,
    )


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
        rule = _parse_detection_rule(det, name, source)
        if rule is not None:
            valid_detections.append(rule)

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

    def _opt_str(field_name: str) -> str | None:
        raw = fp.get(field_name)
        if isinstance(raw, str):
            cleaned = raw.strip()
            if cleaned:
                return cleaned
        return None

    return Fingerprint(
        name=name,
        slug=slug,
        category=category,
        confidence=confidence,
        m365=m365,
        detections=tuple(valid_detections),
        provider_group=_opt_str("provider_group"),
        display_group=_opt_str("display_group"),
        match_mode=match_mode,
        product_family=_opt_str("product_family"),
        parent_vendor=_opt_str("parent_vendor"),
        bimi_org=_opt_str("bimi_org"),
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

    # Cap third-party / ~/.recon catalog files at a generous ceiling so an
    # oversized user file does not inflate per-lookup matching cost or hold
    # unbounded memory in the long-lived MCP server.
    if len(raw) > _MAX_CATALOG_ENTRIES_PER_FILE:
        logger.warning(
            "fingerprint file %s has %d entries; truncating to %d.",
            source,
            len(raw),
            _MAX_CATALOG_ENTRIES_PER_FILE,
        )
        raw = raw[:_MAX_CATALOG_ENTRIES_PER_FILE]

    results: list[Fingerprint] = []
    for fp_raw in raw:
        fp = _validate_fingerprint(fp_raw, source)
        if fp is not None:
            results.append(fp)
    return results


# ── Ephemeral fingerprint storage ───────────────────────────────────────
# Session-scoped, in-memory only. Protected by a re-entrant lock so the
# cached catalog views and ephemeral collection stay coherent across
# inject/clear/load operations, including when callers use asyncio.to_thread().

_ephemeral_lock = threading.RLock()
_ephemeral_fingerprints: list[Fingerprint] = []


@dataclass(slots=True)
class _FingerprintCacheState:
    fingerprints: tuple[Fingerprint, ...] | None = None
    detections: dict[str, tuple[Detection, ...]] = field(default_factory=dict)
    m365_names: frozenset[str] | None = None
    m365_slugs: frozenset[str] | None = None


_cache_state = _FingerprintCacheState()

# Hard caps on session-scoped ephemeral fingerprints. Without these,
# a long-running MCP server exposing ``inject_ephemeral_fingerprint``
# could be driven into unbounded memory growth or lookup slowdown by a
# malicious or prompt-injected client calling the tool in a loop. The
# caps are intentionally generous for legitimate session extension
# (users typically inject a handful of custom rules) while keeping
# memory and per-lookup pattern work bounded.
_MAX_EPHEMERAL_FINGERPRINTS: int = 100
_MAX_EPHEMERAL_DETECTIONS_PER_FINGERPRINT: int = 20
_MAX_EPHEMERAL_DETECTIONS_TOTAL: int = 500
_MAX_EPHEMERAL_TEXT_FIELD_LENGTH: int = 200


class EphemeralCapacityError(RuntimeError):
    """Raised when the ephemeral-fingerprint cap is reached."""


def validate_ephemeral_input_size(
    *,
    name: str,
    slug: str,
    category: str,
    confidence: str,
    detection_count: int,
) -> None:
    """Reject oversized ephemeral inputs before expensive validation work."""
    text_fields = {
        "name": name,
        "slug": slug,
        "category": category,
        "confidence": confidence,
    }
    for field_name, value in text_fields.items():
        if len(value) > _MAX_EPHEMERAL_TEXT_FIELD_LENGTH:
            raise EphemeralCapacityError(
                f"Ephemeral fingerprint {field_name} is too long ({len(value)} > {_MAX_EPHEMERAL_TEXT_FIELD_LENGTH})."
            )
    if detection_count > _MAX_EPHEMERAL_DETECTIONS_PER_FINGERPRINT:
        raise EphemeralCapacityError(
            "Ephemeral fingerprint detection cap exceeded "
            f"({detection_count} > {_MAX_EPHEMERAL_DETECTIONS_PER_FINGERPRINT})."
        )


def _invalidate_caches_locked() -> None:
    """Clear derived fingerprint caches while holding ``_ephemeral_lock``."""
    _cache_state.fingerprints = None
    _cache_state.detections.clear()
    _cache_state.m365_names = None
    _cache_state.m365_slugs = None


def inject_ephemeral(fp: Fingerprint) -> None:
    """Add a validated Fingerprint to the ephemeral collection.

    Clears pattern caches so subsequent calls to load_fingerprints()
    and get_*_patterns() include the new fingerprint.

    Raises:
        EphemeralCapacityError: when the per-process cap of
            ``_MAX_EPHEMERAL_FINGERPRINTS`` or
            ``_MAX_EPHEMERAL_DETECTIONS_TOTAL`` is reached, or when
            the candidate fingerprint is oversized. Callers (the MCP
            tool in particular) surface this as a user-facing rejection
            rather than letting in-memory state grow unbounded.
    """
    validate_ephemeral_input_size(
        name=fp.name,
        slug=fp.slug,
        category=fp.category,
        confidence=fp.confidence,
        detection_count=len(fp.detections),
    )
    with _ephemeral_lock:
        if len(_ephemeral_fingerprints) >= _MAX_EPHEMERAL_FINGERPRINTS:
            raise EphemeralCapacityError(
                f"Ephemeral fingerprint cap reached ({_MAX_EPHEMERAL_FINGERPRINTS}). "
                "Clear the collection with clear_ephemeral() or restart the server."
            )
        current_detections = sum(len(existing.detections) for existing in _ephemeral_fingerprints)
        requested_detections = current_detections + len(fp.detections)
        if requested_detections > _MAX_EPHEMERAL_DETECTIONS_TOTAL:
            raise EphemeralCapacityError(
                "Ephemeral detection cap reached "
                f"({_MAX_EPHEMERAL_DETECTIONS_TOTAL}). "
                "Clear the collection with clear_ephemeral() or restart the server."
            )
        _ephemeral_fingerprints.append(fp)
        _invalidate_caches_locked()


def clear_ephemeral() -> int:
    """Remove all ephemeral fingerprints. Returns count removed.

    Clears pattern caches so subsequent calls exclude ephemeral patterns.
    """
    with _ephemeral_lock:
        count = len(_ephemeral_fingerprints)
        _ephemeral_fingerprints.clear()
        _invalidate_caches_locked()
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
    with _ephemeral_lock:
        if _cache_state.fingerprints is not None:
            return _cache_state.fingerprints

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
        entries.extend(_ephemeral_fingerprints)

        result = tuple(entries)
        _cache_state.fingerprints = result
        return result


def reload_fingerprints() -> None:
    """Clear all fingerprint/pattern caches so the next call reloads from disk.

    Useful for long-lived processes (MCP server) when custom fingerprints change.
    """
    with _ephemeral_lock:
        _invalidate_caches_locked()


def _get_detections(det_type: str) -> tuple[Detection, ...]:
    """Flatten fingerprints into Detection tuples for a given detection type.

    Returns a tuple (immutable) to prevent cache corruption.
    """
    with _ephemeral_lock:
        cached = _cache_state.detections.get(det_type)
        if cached is not None:
            return cached

        results: list[Detection] = []
        for fp in load_fingerprints():
            for det in fp.detections:
                if det.type == det_type and det.pattern:
                    results.append(Detection(det.pattern, fp.name, fp.slug, fp.category, fp.confidence))

        result = tuple(results)
        _cache_state.detections[det_type] = result
        return result


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


@dataclass(frozen=True)
class CnameTargetDetection:
    """A cname_target detection enriched with tier information.

    Distinct from Detection because cname_target carries a tier field that
    Detection does not — application vs infrastructure governs which slug
    becomes the primary attribution for a subdomain whose CNAME chain
    matches both tiers.
    """

    pattern: str
    name: str
    slug: str
    category: str
    confidence: str
    tier: str


def get_cname_target_rules() -> tuple[CnameTargetDetection, ...]:
    """Return tier-aware detections for CNAME-target classification.

    Used by the surface-attribution pipeline to walk CNAME chains for
    every related domain and attribute each subdomain to a specific
    SaaS or infrastructure provider.
    """
    with _ephemeral_lock:
        cached = _cache_state.detections.get("cname_target")
        if cached is not None:
            # We stored CnameTargetDetection under the same dict — see below.
            return cached  # type: ignore[return-value]

        results: list[CnameTargetDetection] = []
        for fp in load_fingerprints():
            for det in fp.detections:
                if det.type == "cname_target" and det.pattern:
                    results.append(
                        CnameTargetDetection(
                            pattern=det.pattern,
                            name=fp.name,
                            slug=fp.slug,
                            category=fp.category,
                            confidence=fp.confidence,
                            tier=det.tier,
                        )
                    )

        result = tuple(results)
        # Stored in the same cache as Detection; the public accessor for
        # cname_target uses CnameTargetDetection, so type-confused callers
        # would self-correct on first access.
        _cache_state.detections["cname_target"] = result  # type: ignore[assignment]
        return result


def get_cname_target_patterns() -> tuple[Detection, ...]:
    """Return Detection tuples for cname_target rules.

    Backwards-compatibility shim returning the lighter Detection shape
    (without tier). Callers needing tier should use
    get_cname_target_rules().
    """
    rules = get_cname_target_rules()
    return tuple(Detection(r.pattern, r.name, r.slug, r.category, r.confidence) for r in rules)


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


def get_m365_names() -> frozenset[str]:
    """Return names of fingerprints that indicate M365."""
    with _ephemeral_lock:
        if _cache_state.m365_names is None:
            _cache_state.m365_names = frozenset(fp.name for fp in load_fingerprints() if fp.m365)
        return _cache_state.m365_names


def get_m365_slugs() -> frozenset[str]:
    """Return slugs of fingerprints that indicate M365.

    Slug-based detection is more stable than name-based — renaming a
    fingerprint's display name won't break M365 detection.
    """
    with _ephemeral_lock:
        if _cache_state.m365_slugs is None:
            _cache_state.m365_slugs = frozenset(fp.slug for fp in load_fingerprints() if fp.m365)
        return _cache_state.m365_slugs


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


def _no_shadowed_pairs_survive(result: list[Detection]) -> bool:
    """Contract: no kept detection's pattern strictly shadows another's.

    After filtering, there must be no pair of kept detections with
    different slugs where one pattern is a strict substring of the other.
    That pair is exactly the double-count the filter exists to remove, so
    its survival is a bug.
    """
    pats = [(d.slug, d.pattern.lower()) for d in result]
    for slug_a, pa in pats:
        for slug_b, pb in pats:
            if pa == pb or slug_a == slug_b:
                continue
            if pa in pb:
                return False
    return True


@deal.post(_no_shadowed_pairs_survive)  # pyright: ignore[reportUntypedFunctionDecorator]
def filter_shadowed_matches(
    matches: list[Detection] | tuple[Detection, ...],
) -> list[Detection]:
    """Specificity-suppression for substring matchers that accumulate.

    SPF accumulates matches because multiple distinct vendor includes
    can legitimately appear on one record (M365 + Salesforce, etc.).
    The other substring matchers (MX, NS, CAA, dmarc_rua, cname,
    cname_target) take a different approach , they sort patterns
    longest-first and ``break`` on the first match, so a narrower
    pattern always wins. SPF cannot ``break`` without losing the
    multi-vendor case, so it instead collects every match and asks
    this function to drop the shadowed ones.

    Two cases the function distinguishes:

    1. Same slug, different patterns: both fire, slug accumulates once
       in ctx.slugs. No double-count, both kept.
    2. Different slugs, one pattern is a strict substring of another:
       the broader slug would fire alongside the narrower one and
       double-count in ctx.slugs. The broader is dropped.

    Pre-condition: every Detection in *matches* has already been
    verified to match the same record (its pattern was found via
    substring containment). The function does not re-match; it only
    enforces specificity between the matches the caller already
    collected.

    Returns the matches to keep , those whose pattern is NOT a strict
    substring of another match's pattern under a different slug.
    Non-overlapping matches (e.g. spf.protection.outlook.com plus
    _spf.salesforce.com on the same SPF record) both survive, which is
    the correct semantics: multiple distinct vendor signals can fire
    on one record.
    """
    if not matches:
        return list(matches)
    info = [(m, m.pattern.lower()) for m in matches]
    keep: list[Detection] = []
    for m, pl in info:
        shadowed = False
        for m2, pl2 in info:
            if pl == pl2:
                continue
            if m2.slug == m.slug:
                # Same-slug, different patterns , not a shadow.
                continue
            if pl in pl2:
                # m's pattern is a strict substring of m2's; m is
                # shadowed by m2 (the more specific match).
                shadowed = True
                break
        if not shadowed:
            keep.append(m)
    return keep
