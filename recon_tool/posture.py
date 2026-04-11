"""Posture analyzer — derives neutral observations from resolved domain data.

Observations are factual statements about a domain's configuration state.
They do NOT prescribe action, assign blame, or frame findings as attacks,
defenses, vulnerabilities, or recommendations.

Observation rules are loaded from data/posture.yaml with additive override
from ~/.recon/posture.yaml (same pattern as signals.py and fingerprints.py).
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

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_STRICT,
)
from recon_tool.models import Observation, TenantInfo

logger = logging.getLogger("recon")

__all__ = [
    "analyze_posture",
    "load_posture_rules",
    "reload_posture",
]

BANNED_TERMS = frozenset({
    "vulnerability", "attack", "exploit", "weakness",
    "recommendation", "should", "must fix", "risk",
    "threat", "remediate", "harden",
})

_VALID_CATEGORIES = frozenset({
    "identity", "email", "infrastructure",
    "saas_footprint", "certificate", "consistency",
})
_VALID_SALIENCE = frozenset({"high", "medium", "low"})
_VALID_METADATA_FIELDS = frozenset({
    "dmarc_policy", "auth_type", "email_security_score",
    "spf_include_count", "issuance_velocity",
})
_VALID_OPERATORS = frozenset({"eq", "neq", "gte", "lte"})


@dataclass(frozen=True)
class _MetadataCondition:
    """A single metadata condition within a posture rule."""

    field: str
    operator: str
    value: str | int


@dataclass(frozen=True)
class _PostureRule:
    """A validated, immutable posture observation rule loaded from YAML."""

    name: str
    category: str
    salience: str
    template: str
    slugs_any: tuple[str, ...] = ()
    slugs_min: int = 0
    slugs_max: int | None = None
    metadata: tuple[_MetadataCondition, ...] = ()


def _parse_metadata_block(name: str, raw_metadata: list[Any]) -> tuple[_MetadataCondition, ...] | None:
    """Parse and validate a metadata block. Returns None if any entry is invalid."""
    conditions: list[_MetadataCondition] = []
    for entry in raw_metadata:
        if not isinstance(entry, dict):
            logger.warning("Posture rule %r has non-dict metadata entry — skipped entire rule", name)
            return None
        field = entry.get("field")
        operator = entry.get("operator")
        value = entry.get("value")
        if field not in _VALID_METADATA_FIELDS:
            logger.warning("Posture rule %r has invalid metadata field %r — skipped entire rule", name, field)
            return None
        if operator not in _VALID_OPERATORS:
            logger.warning("Posture rule %r has invalid metadata operator %r — skipped entire rule", name, operator)
            return None
        if value is None:
            logger.warning("Posture rule %r has missing metadata value — skipped entire rule", name)
            return None
        conditions.append(_MetadataCondition(field=field, operator=operator, value=value))
    return tuple(conditions)


def _validate_and_build_rule(rule: dict[str, Any], index: int) -> _PostureRule | None:
    """Validate a single posture rule and return a frozen _PostureRule, or None."""
    if not isinstance(rule, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
        logger.warning("Posture rule at index %d is not a dict — skipped", index)
        return None

    name = rule.get("name")
    if not name or not isinstance(name, str):
        logger.warning("Posture rule at index %d missing 'name' — skipped", index)
        return None

    category = rule.get("category", "")
    if category not in _VALID_CATEGORIES:
        logger.warning("Posture rule %r has invalid category %r — skipped", name, category)
        return None

    salience = rule.get("salience", "medium")
    if salience not in _VALID_SALIENCE:
        logger.warning("Posture rule %r has invalid salience %r — skipped", name, salience)
        return None

    template = rule.get("template")
    if not template or not isinstance(template, str):
        logger.warning("Posture rule %r missing 'template' — skipped", name)
        return None

    condition = rule.get("condition")
    if not isinstance(condition, dict):
        logger.warning("Posture rule %r missing 'condition' — skipped", name)
        return None

    # Parse slug conditions
    slugs_any: tuple[str, ...] = ()
    slugs_min = 0
    slugs_max: int | None = None
    raw_slugs = condition.get("slugs_any")
    if isinstance(raw_slugs, list) and raw_slugs:
        slugs_any = tuple(raw_slugs)
        slugs_min = condition.get("slugs_min", 1)
        if not isinstance(slugs_min, int) or slugs_min < 0:
            logger.warning("Posture rule %r has invalid slugs_min — defaulting to 1", name)
            slugs_min = 1
        raw_max = condition.get("slugs_max")
        if raw_max is not None:
            if isinstance(raw_max, int) and raw_max >= 0:
                slugs_max = raw_max
            else:
                logger.warning("Posture rule %r has invalid slugs_max — ignored", name)

    # Parse metadata conditions
    metadata_conditions: tuple[_MetadataCondition, ...] = ()
    raw_metadata = condition.get("metadata")
    if raw_metadata is not None:
        if not isinstance(raw_metadata, list) or not raw_metadata:
            logger.warning("Posture rule %r has invalid 'metadata' block — skipped", name)
            return None
        parsed = _parse_metadata_block(name, raw_metadata)
        if parsed is None:
            return None
        metadata_conditions = parsed

    # Must have at least one condition type
    if not slugs_any and not metadata_conditions:
        logger.warning("Posture rule %r has no slug or metadata conditions — skipped", name)
        return None

    return _PostureRule(
        name=name,
        category=category,
        salience=salience,
        template=template,
        slugs_any=slugs_any,
        slugs_min=slugs_min,
        slugs_max=slugs_max,
        metadata=metadata_conditions,
    )


def _load_from_path(path: Path) -> list[_PostureRule]:
    """Load and validate posture rules from a single YAML file."""
    if not path.exists():
        return []
    source = str(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to load posture rules from %s: %s", source, exc)
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("observations", [])
    if not isinstance(raw, list):
        return []
    results: list[_PostureRule] = []
    for i, r in enumerate(raw):
        rule = _validate_and_build_rule(r, i)
        if rule is not None:
            results.append(rule)
    return results


@lru_cache(maxsize=1)
def load_posture_rules() -> tuple[_PostureRule, ...]:
    """Load and validate posture rules from YAML (built-in + custom).

    Returns a tuple of frozen _PostureRule dataclasses. Custom rules from
    ~/.recon/posture.yaml (or RECON_CONFIG_DIR) are additive only.

    Results are cached for the process lifetime. Call reload_posture()
    to pick up changes in long-lived processes (MCP server).
    """
    data_path = Path(__file__).parent / "data" / "posture.yaml"
    custom_dir = os.environ.get("RECON_CONFIG_DIR")
    custom_path = Path(custom_dir) / "posture.yaml" if custom_dir else Path.home() / ".recon" / "posture.yaml"

    entries: list[_PostureRule] = []
    entries.extend(_load_from_path(data_path))
    entries.extend(_load_from_path(custom_path))
    return tuple(entries)


def reload_posture() -> None:
    """Clear posture rule cache so the next call reloads from disk."""
    load_posture_rules.cache_clear()


def _compute_metadata_value(field: str, info: TenantInfo) -> str | int | None:
    """Compute a metadata field value from TenantInfo."""
    if field == "dmarc_policy":
        return info.dmarc_policy
    if field == "auth_type":
        return info.auth_type
    if field == "email_security_score":
        # Count presence of DMARC, DKIM, SPF strict, MTA-STS, BIMI (0-5)
        score = sum(
            1 for svc in info.services
            if svc in {SVC_DMARC, SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_SPF_STRICT, SVC_MTA_STS, SVC_BIMI}
        )
        return min(score, 5)
    if field == "spf_include_count":
        for svc in info.services:
            if svc.startswith("SPF complexity:"):
                try:
                    return int(svc.split(":")[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
        return None
    if field == "issuance_velocity":
        if info.cert_summary is not None:
            return info.cert_summary.issuance_velocity
        return None
    return None


def _evaluate_metadata_condition(condition: _MetadataCondition, info: TenantInfo) -> bool:
    """Evaluate a single metadata condition against TenantInfo."""
    field_value = _compute_metadata_value(condition.field, info)

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


def _contains_banned_term(text: str) -> bool:
    """Check if text contains any banned term (case-insensitive)."""
    lower = text.lower()
    return any(term in lower for term in BANNED_TERMS)


def analyze_posture(info: TenantInfo) -> tuple[Observation, ...]:
    """Produce neutral observations from resolved domain data.

    Evaluates posture rules against the TenantInfo, renders templates,
    and enforces the BANNED_TERMS list. Returns a tuple of frozen
    Observation instances.
    """
    slugs_set = set(info.slugs)
    results: list[Observation] = []

    for rule in load_posture_rules():
        # Evaluate slug conditions
        matched_slugs: list[str] = []
        if rule.slugs_any:
            matched_slugs = [s for s in rule.slugs_any if s in slugs_set]
            if len(matched_slugs) < rule.slugs_min:
                continue
            if rule.slugs_max is not None and len(matched_slugs) > rule.slugs_max:
                continue

        # Evaluate metadata conditions
        if rule.metadata:
            all_met = all(
                _evaluate_metadata_condition(cond, info)
                for cond in rule.metadata
            )
            if not all_met:
                continue

        # Render template
        statement = rule.template
        if "{matched_slugs}" in statement:
            statement = statement.replace("{matched_slugs}", ", ".join(matched_slugs))
        if "{matched_count}" in statement:
            statement = statement.replace("{matched_count}", str(len(matched_slugs)))
        if "{email_security_score}" in statement:
            score = _compute_metadata_value("email_security_score", info)
            statement = statement.replace("{email_security_score}", str(score if score is not None else 0))
        if "{issuance_velocity}" in statement:
            velocity = _compute_metadata_value("issuance_velocity", info)
            statement = statement.replace("{issuance_velocity}", str(velocity if velocity is not None else 0))

        # Enforce banned terms
        if _contains_banned_term(statement):
            logger.warning(
                "Posture observation %r contains banned term — dropped", rule.name,
            )
            continue

        results.append(Observation(
            category=rule.category,
            salience=rule.salience,
            statement=statement,
            related_slugs=tuple(matched_slugs),
        ))

    return tuple(results)
