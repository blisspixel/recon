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
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from recon_tool.constants import effective_dmarc_policy, email_security_score
from recon_tool.models import Observation, TenantInfo

logger = logging.getLogger("recon")

__all__ = [
    "analyze_posture",
    "load_posture_rules",
    "reload_posture",
]

DISCOURAGED_COPY_TERMS = frozenset(
    {
        "vulnerability",
        "attack",
        "exploit",
        "weakness",
        "recommendation",
        "should",
        "must fix",
        "risk",
        "threat",
        "remediate",
        "harden",
    }
)

# Backward-compatible alias for callers that imported the old internal name.
# These terms guide recon-authored prose; they are not an input blocklist.
BANNED_TERMS = DISCOURAGED_COPY_TERMS

_VALID_CATEGORIES = frozenset(
    {
        "identity",
        "email",
        "infrastructure",
        "saas_footprint",
        "certificate",
        "consistency",
    }
)
_VALID_SALIENCE = frozenset({"high", "medium", "low"})
_VALID_METADATA_FIELDS = frozenset(
    {
        "dmarc_policy",
        "dmarc_effective_policy",
        "auth_type",
        "email_security_score",
        "email_posture_observed",
        "spf_include_count",
        "issuance_velocity",
        "dmarc_pct",
        "primary_email_provider",
    }
)
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
    explain: str = ""


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


def _parse_slug_condition(condition: dict[str, Any], name: str) -> tuple[tuple[str, ...], int, int | None]:
    """Parse the slugs_any / slugs_min / slugs_max sub-block of a posture rule
    condition, with the same defaulting and warnings as the inline version.
    Returns ``((), 0, None)`` when no slug condition is present.
    """
    raw_slugs = condition.get("slugs_any")
    if not (isinstance(raw_slugs, list) and raw_slugs):
        return (), 0, None
    slugs_any = tuple(raw_slugs)
    slugs_min = condition.get("slugs_min", 1)
    if not isinstance(slugs_min, int) or slugs_min < 0:
        logger.warning("Posture rule %r has invalid slugs_min — defaulting to 1", name)
        slugs_min = 1
    slugs_max: int | None = None
    raw_max = condition.get("slugs_max")
    if raw_max is not None:
        if isinstance(raw_max, int) and raw_max >= 0:
            slugs_max = raw_max
        else:
            logger.warning("Posture rule %r has invalid slugs_max — ignored", name)
    return slugs_any, slugs_min, slugs_max


def _parse_rule_explain(name: str, raw_explain: object) -> str:
    """Return optional curated copy while rejecting non-string values."""
    if raw_explain is None:
        return ""
    if isinstance(raw_explain, str):
        return raw_explain
    logger.warning("Posture rule %r has non-string 'explain' - defaulting to empty", name)
    return ""


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
    slugs_any, slugs_min, slugs_max = _parse_slug_condition(condition, name)

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

    # Parse explain field
    explain = _parse_rule_explain(name, rule.get("explain"))

    return _PostureRule(
        name=name,
        category=category,
        salience=salience,
        template=template,
        slugs_any=slugs_any,
        slugs_min=slugs_min,
        slugs_max=slugs_max,
        metadata=metadata_conditions,
        explain=explain,
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
    from recon_tool.paths import config_dir

    data_path = Path(__file__).parent / "data" / "posture.yaml"
    custom_path = config_dir() / "posture.yaml"

    entries: list[_PostureRule] = []
    entries.extend(_load_from_path(data_path))
    entries.extend(_load_from_path(custom_path))
    return tuple(entries)


def reload_posture() -> None:
    """Clear posture rule cache so the next call reloads from disk."""
    load_posture_rules.cache_clear()


def _compute_metadata_value(field: str, info: TenantInfo) -> str | int | None:
    """Compute a metadata field value from TenantInfo."""
    direct_values: dict[str, str | int | None] = {
        "dmarc_policy": info.dmarc_policy,
        "auth_type": info.auth_type,
        "dmarc_pct": info.dmarc_pct,
        "primary_email_provider": info.primary_email_provider,
    }
    if field in direct_values:
        return direct_values[field]
    if field == "dmarc_effective_policy":
        return effective_dmarc_policy(info.dmarc_policy, info.dmarc_pct, info.dmarc_testing)
    if field == "email_security_score":
        from recon_tool.email_security import observed_email_control_services

        return email_security_score(
            observed_email_control_services(info.evidence),
            info.dmarc_policy,
            info.dmarc_pct,
            info.dmarc_testing,
        )
    if field == "email_posture_observed":
        email_source_types = {
            "MX",
            "SPF",
            "DMARC",
            "DKIM",
            "BIMI",
            "MTA_STS",
            "MTA_STS_POLICY",
            "TLS_RPT",
        }
        return int(
            any(
                (evidence.source_type.upper() in email_source_types or evidence.slug == "tls-rpt")
                and not (evidence.source_type.upper() == "MX" and evidence.slug == "null-mx")
                for evidence in info.evidence
            )
        )
    if field == "spf_include_count":
        return info.spf_include_count or None
    if field == "issuance_velocity":
        if info.cert_summary is not None:
            return info.cert_summary.issuance_velocity
        return None
    return None


def _evaluate_metadata_condition(condition: _MetadataCondition, info: TenantInfo) -> bool:
    """Evaluate a single metadata condition against TenantInfo."""
    from recon_tool.source_status import ObservationChannel, SourceStatus

    status = SourceStatus.from_degraded_sources(info.degraded_sources)
    channel_by_field: dict[str, ObservationChannel] = {
        "dmarc_policy": "dmarc",
        "dmarc_effective_policy": "dmarc",
        "dmarc_pct": "dmarc",
        "spf_include_count": "apex_txt",
        "primary_email_provider": "mx",
    }
    channel = channel_by_field.get(condition.field)
    if channel is not None and status.channel_unavailable(channel):
        return False
    if condition.field == "email_security_score" and any(
        status.channel_unavailable(name) for name in ("dmarc", "dkim", "apex_txt", "mta_sts", "bimi")
    ):
        return False
    field_value = _compute_metadata_value(condition.field, info)

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


def _find_discouraged_copy_terms(text: str) -> tuple[str, ...]:
    """Return discouraged generated-copy terms present in text."""
    lower = text.lower()
    return tuple(term for term in DISCOURAGED_COPY_TERMS if term in lower)


def analyze_posture(info: TenantInfo) -> tuple[Observation, ...]:
    """Produce neutral observations from resolved domain data.

    Evaluates posture rules against the TenantInfo and renders templates.
    The neutral-language term list is advisory: it logs copy drift but never
    blocks user-supplied data or drops observations at runtime.
    """
    from recon_tool.collection_view import collection_observable_info

    info = collection_observable_info(info)
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
            all_met = all(_evaluate_metadata_condition(cond, info) for cond in rule.metadata)
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
        if "{dmarc_pct}" in statement:
            dmarc_pct = _compute_metadata_value("dmarc_pct", info)
            statement = statement.replace("{dmarc_pct}", str(dmarc_pct if dmarc_pct is not None else 0))

        discouraged_terms = _find_discouraged_copy_terms(statement)
        if discouraged_terms:
            logger.warning(
                "Posture observation %r contains discouraged copy term(s): %s",
                rule.name,
                ", ".join(discouraged_terms),
            )

        results.append(
            Observation(
                category=rule.category,
                salience=rule.salience,
                statement=statement,
                related_slugs=tuple(matched_slugs),
                source_name=rule.name,
            )
        )

    return tuple(results)
