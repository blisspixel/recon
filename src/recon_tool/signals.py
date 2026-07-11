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
    "canonicalize_signal_observation",
    "evaluate_signals",
    "load_signals",
    "public_signal_names",
    "reload_signals",
    "reportable_signals",
    "resolve_reportable_signal",
    "signal_observation_label",
    "signal_rule_names_from_observation",
]


# Signal names are stable rule identifiers used by profiles and saved output.
# Several historic identifiers encode conclusions that generic public catalog
# matches cannot support. All public projections must use these claim-safe
# observation labels while retaining the rule identifier only as provenance.
_SIGNAL_OBSERVATION_LABELS: dict[str, str] = {
    "AI Adoption": "AI-platform indicators observed",
    "High GTM Maturity": "Sales and marketing platform indicators observed",
    "Enterprise Security Stack": "Multiple security-vendor indicators observed",
    "Modern Collaboration": "Collaboration-platform indicators observed",
    "Dev & Engineering Heavy": "Developer-tool indicators observed",
    "Data & Analytics Investment": "Data and analytics platform indicators observed",
    "Multi-Cloud": (
        "Multiple cloud-vendor catalog indicators co-observed; provider roles and diversity are unresolved"
    ),
    "Edge Layering": "Multiple edge-vendor catalog indicators co-observed; source roles may differ",
    "Observability & SRE": "Observability-vendor indicators observed",
    "Digital Transformation": "AI, collaboration, and cloud-platform indicators co-observed",
    "Sales-Led Growth": "CRM, sales-engagement, and marketing-platform indicators co-observed",
    "Product-Led Growth": "Analytics, engagement, and support-platform indicators co-observed",
    "Multi-Layer Security Tooling": "Multiple security-category vendor indicators observed",
    "Security Gap \N{EM DASH} Gateway Without DMARC Enforcement": (
        "Email-security vendor indicator with no effective DMARC enforcement observed"
    ),
    "Heavy Outbound Stack": "Multiple email-sender vendor indicators observed",
    "File Collaboration Sprawl": "File-sharing platform indicators co-observed",
    "Zero Trust Pattern Observed": "Identity, network-security, and endpoint-vendor indicators co-observed",
    "Startup Tool Mix": "Developer, collaboration, and analytics-platform indicators co-observed",
    "Dual Email Provider": "Microsoft 365 and Google Workspace indicators co-observed",
    "Google-Native Identity": "Google service and identity indicators co-observed",
    "High-Security Posture (CSE)": "Google Workspace CSE indicator observed",
    "Google Cloud Investment": "Google cloud-service indicators observed",
    "Google Workspace Full Suite": "Google Workspace provider and module indicators co-observed",
    "Google Federated Identity": "Google federated-identity observation",
    "Google MTA-STS Enforcing": "Google MTA-STS enforce policy observed",
    "Federated Identity with Complex Email Delegation": (
        "Identity-vendor indicator with complex SPF delegation observed"
    ),
    "Active Email Sending with Minimal Security": (
        "Email-sender vendor indicator with a low public email-control score"
    ),
    "High Certificate Issuance Activity": "High certificate issuance activity observed",
    "Agentic AI Infrastructure": "Multiple AI or automation-platform indicators observed",
    "AI Platform Diversity": "Multiple AI-platform indicators observed",
    "Software Supply Chain Maturity": "Software-supply-chain vendor indicators observed",
    "Edge-Native Architecture": "Edge-platform indicators observed",
    "Enterprise Email Deliverability": "Email-deliverability vendor indicator observed",
    "DMARC Governance Investment": "DMARC-reporting vendor indicator observed",
    "Email Gateway Topology": "Email-security vendor and primary-provider indicators co-observed",
    "Secondary Email Provider Observed": ("Secondary email-service indicator co-observed with an MX-based primary"),
}

# These rules depend on negative premises whose observation opportunity is not
# represented in SignalContext. They remain stable identifiers for backward
# compatibility but cannot support a public observation.
_NONREPORTABLE_SIGNAL_NAMES = frozenset(
    {
        "Dual Email Delivery Path",
        "Incomplete Identity Migration",
    }
)


def signal_observation_label(rule_name: str) -> str | None:
    """Return claim-safe public copy for a stable signal rule identifier.

    Custom signal names pass through unchanged because they are operator-owned.
    ``None`` means the rule lacks a supportable public projection and must be
    omitted from insights, explanations, posture hypotheses, and deltas.
    """
    if rule_name in _NONREPORTABLE_SIGNAL_NAMES:
        return None
    return _SIGNAL_OBSERVATION_LABELS.get(rule_name, rule_name)


def signal_rule_names_from_observation(observation: str) -> tuple[str, ...]:
    """Resolve a rendered observation prefix to stable signal rule IDs.

    Both current claim-safe labels and reportable historical raw identifiers
    are recognized. Unknown prose and nonreportable rules return an empty
    tuple. The tuple shape makes any future many-to-one label explicit.
    """
    prefix = observation.partition(": ")[0] if ": " in observation else observation
    matching_labels = tuple(rule_name for rule_name, label in _SIGNAL_OBSERVATION_LABELS.items() if label == prefix)
    if matching_labels:
        return matching_labels
    if prefix in _NONREPORTABLE_SIGNAL_NAMES:
        return ()
    if any(signal.name == prefix for signal in load_signals()):
        return (prefix,)
    return ()


def canonicalize_signal_observation(observation: str) -> str | None:
    """Project current or cached signal text through the public claim policy.

    Recognized historical raw rule prefixes are rewritten to their claim-safe
    label. Nonreportable rules are dropped. Non-signal prose passes through
    unchanged so callers can apply this function to a complete insight list.
    """
    normalized = observation.casefold()
    if normalized.startswith("high-maturity hardening pattern") or "hardening pattern observed" in normalized:
        return None
    prefix, separator, details = observation.partition(": ")
    if prefix in _NONREPORTABLE_SIGNAL_NAMES:
        return None
    rule_names = signal_rule_names_from_observation(observation)
    if not rule_names:
        return observation
    label = signal_observation_label(rule_names[0])
    if label is None:
        return None
    return f"{label}: {details}" if separator else label


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
    expected_counterparts: tuple[str, ...] = ()  # slugs expected to co-occur
    exclude_matches_in_primary: bool = False  # filter matches already in primary_email_provider
    # Hedged positive observations when an adversary-friendly slug set
    # is absent. The absence engine reads this and emits a two-sided positive
    # observation when this signal fires AND none of these slugs are detected.
    # Example: "Edge Layering" fires, consumer SaaS slugs are absent → emit
    # "High-maturity hardening pattern (observed) — fits deliberate hardening
    #  or a dormant/parked target".
    positive_when_absent: tuple[str, ...] = ()


# Display names for provider slugs that can appear in primary_email_provider.
# Used by exclude_matches_in_primary filter. Kept in sync with merger.py
# _EMAIL_PROVIDER_SLUG_NAMES.
_PROVIDER_SLUG_DISPLAY_NAMES: dict[str, str] = {
    "microsoft365": "Microsoft 365",
    "google-workspace": "Google Workspace",
    "zoho": "Zoho Mail",
    "protonmail": "ProtonMail",
    "aws-ses": "AWS SES",
}


_VALID_METADATA_FIELDS = frozenset(
    {
        "dmarc_policy",
        "dmarc_effective_policy",
        "auth_type",
        "email_security_score",
        "spf_include_count",
        "issuance_velocity",
        "dmarc_pct",
        "primary_email_provider",
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


def _parse_strict_str_list(name: str, field: str, raw: Any) -> tuple[str, ...] | None:
    """Parse a list-of-non-empty-strings field. None input is absent (empty).

    Returns the tuple on success (possibly empty), or None to reject the whole
    signal when the value is present but malformed.
    """
    if raw is None:
        return ()
    if not isinstance(raw, list):
        logger.warning("Signal %r has invalid %r (not a list) — skipped", name, field)
        return None
    for entry in raw:
        if not isinstance(entry, str) or not entry:
            logger.warning("Signal %r has invalid entry in %r — skipped", name, field)
            return None
    return tuple(raw)


def _parse_lenient_str_list(name: str, field: str, raw: Any) -> tuple[str, ...]:
    """Parse a list-of-non-empty-strings field, defaulting to empty on any error.

    Unlike :func:`_parse_strict_str_list`, a malformed value never rejects the
    signal; it falls back to an empty tuple with a warning.
    """
    if raw is None:
        return ()
    if not isinstance(raw, list):
        logger.warning("Signal %r has invalid %r (not a list) — defaulting to empty", name, field)
        return ()
    for entry in raw:
        if not isinstance(entry, str) or not entry.strip():
            logger.warning("Signal %r has invalid entry in %r — defaulting to empty tuple", name, field)
            return ()
    return tuple(raw)


def _parse_requires_block(name: str, signal: dict[str, Any], has_metadata: bool) -> tuple[tuple[str, ...], int] | None:
    """Parse the optional ``requires`` block into (candidates, min_matches).

    Returns None to reject the signal when neither a valid ``requires.any``,
    metadata, nor ``requires_signals`` is present.
    """
    requires = signal.get("requires")
    if requires is not None:
        if not isinstance(requires, dict):
            logger.warning("Signal %r has invalid 'requires' — skipped", name)
            return None
        any_list = requires.get("any")
        if isinstance(any_list, list) and any_list:
            min_matches = signal.get("min_matches", 1)
            if not isinstance(min_matches, int) or min_matches < 1:
                logger.warning("Signal %r has invalid min_matches %r — defaulting to 1", name, min_matches)
                min_matches = 1
            return tuple(any_list), min_matches
        if has_metadata:
            # requires block present but no valid any list — OK if metadata present
            return (), 0
        logger.warning("Signal %r has empty or missing 'requires.any' and no metadata — skipped", name)
        return None
    if not has_metadata:
        # No requires and no metadata — OK only if requires_signals is present
        raw_requires_signals_check = signal.get("requires_signals")
        if not (isinstance(raw_requires_signals_check, list) and raw_requires_signals_check):
            logger.warning("Signal %r has neither 'requires' nor 'metadata' nor 'requires_signals' — skipped", name)
            return None
    return (), 0


def _validate_and_build_signal(signal: dict[str, Any], index: int) -> Signal | None:
    """Validate a single signal definition and return a frozen Signal, or None.

    Required: name (str), and at least one of requires.any or metadata.
    Optional: category, confidence, min_matches, description.
    Logs warnings and returns None for invalid entries.
    Does NOT mutate the input dict.
    """
    if not isinstance(signal, dict):  # pyright: ignore[reportUnnecessaryIsInstance, reportUnreachable]
        logger.warning("Signal at index %d is not a dict — skipped", index)  # pyright: ignore[reportUnreachable]
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
    parsed_requires = _parse_requires_block(name, signal, bool(metadata_conditions))
    if parsed_requires is None:
        return None
    candidates, min_matches = parsed_requires

    # Parse optional contradicts / requires_signals fields (strict: a malformed
    # value rejects the whole signal).
    contradicts = _parse_strict_str_list(name, "contradicts", signal.get("contradicts"))
    if contradicts is None:
        return None
    requires_signals = _parse_strict_str_list(name, "requires_signals", signal.get("requires_signals"))
    if requires_signals is None:
        return None

    # Parse optional explain field
    raw_explain = signal.get("explain")
    if raw_explain is not None and not isinstance(raw_explain, str):
        logger.warning("Signal %r has non-string 'explain' — defaulting to empty", name)
        raw_explain = ""
    explain: str = raw_explain if isinstance(raw_explain, str) else ""

    # Parse optional expected_counterparts field (lenient: a malformed value
    # falls back to an empty tuple rather than rejecting the signal).
    expected_counterparts = _parse_lenient_str_list(name, "expected_counterparts", signal.get("expected_counterparts"))

    # Parse optional exclude_matches_in_primary field
    raw_exclude_primary = signal.get("exclude_matches_in_primary", False)
    if not isinstance(raw_exclude_primary, bool):
        logger.warning(
            "Signal %r has non-bool 'exclude_matches_in_primary' — defaulting to False",
            name,
        )
        raw_exclude_primary = False

    # Parse optional positive_when_absent field. Same shape as
    # expected_counterparts: a list of slug strings, lenient on error.
    positive_when_absent = _parse_lenient_str_list(name, "positive_when_absent", signal.get("positive_when_absent"))

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
        expected_counterparts=expected_counterparts,
        exclude_matches_in_primary=raw_exclude_primary,
        positive_when_absent=positive_when_absent,
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
    from recon_tool.paths import config_dir

    data_path = Path(__file__).parent / "data" / "signals.yaml"
    custom_path = config_dir() / "signals.yaml"

    entries: list[Signal] = []
    entries.extend(_load_from_path(data_path))
    entries.extend(_load_from_path(custom_path))
    entries = _validate_meta_signals(entries)
    return tuple(entries)


def reload_signals() -> None:
    """Clear signal cache so the next call reloads from disk."""
    load_signals.cache_clear()


def reportable_signals() -> tuple[tuple[Signal, str], ...]:
    """Return signal definitions paired with their public observation labels.

    Stable rule identifiers remain an internal provenance contract. Public
    catalog surfaces consume this projection so a historical identifier cannot
    bypass the claim policy merely because no domain is being evaluated.
    """
    return tuple(
        (signal, label) for signal in load_signals() if (label := signal_observation_label(signal.name)) is not None
    )


def public_signal_names(names: tuple[str, ...] | list[str]) -> list[str]:
    """Project a sequence of rule identifiers to reportable public labels."""
    return [label for name in names if (label := signal_observation_label(name)) is not None]


def resolve_reportable_signal(name: str) -> tuple[Signal, str] | None:
    """Resolve a public label or reportable legacy rule identifier.

    Accepting a reportable legacy identifier preserves invocation
    compatibility, but callers must render only the returned public label.
    Nonreportable identifiers deliberately resolve to ``None``.
    """
    for signal, label in reportable_signals():
        if name in {label, signal.name}:
            return signal, label
    return None


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
    if condition.field in context.unavailable_metadata_fields:
        return False
    field_value = getattr(context, condition.field, None)

    op = condition.operator
    target = condition.value

    # Unknown is not evidence for equality or inequality.
    if field_value is None:
        return False

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

    # Optionally filter out matches whose display name is already present
    # in the known primary email provider. Used by signals like "Legacy
    # Provider Residue" to avoid flagging the current primary as residue
    # of itself. The check considers both the strict primary (from MX) and
    # the inferred likely_primary (from DKIM/identity evidence on
    # gateway-fronted domains). When exclude_matches_in_primary is set and
    # neither is known, the signal refuses to fire — a residue claim
    # requires a known primary to be residue against.
    if signal.exclude_matches_in_primary:
        combined_primary = " | ".join(
            p
            for p in (
                context.primary_email_provider,
                context.likely_primary_email_provider,
            )
            if p
        )
        if not combined_primary:
            return None
        combined_primary_lower = combined_primary.lower()
        matched = [
            slug for slug in matched if _PROVIDER_SLUG_DISPLAY_NAMES.get(slug, "").lower() not in combined_primary_lower
        ]

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
