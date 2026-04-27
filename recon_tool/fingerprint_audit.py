"""Audit helpers for multi-detection fingerprint hardening.

The audit is intentionally advisory. It does not change match behavior; it
identifies where a human should keep ``match_mode: any``, consider
``match_mode: all``, or tighten broad patterns after validation evidence.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Literal, cast

from recon_tool.fingerprints import DetectionRule, Fingerprint, load_fingerprints

AuditClassification = Literal["alternative", "corroborating", "too_broad"]
AuditRecommendation = Literal["keep_any", "review_for_all", "tighten_patterns", "already_all"]

__all__ = [
    "AuditClassification",
    "AuditRecommendation",
    "FingerprintAuditEntry",
    "audit_multi_detection_fingerprints",
    "format_fingerprint_audit_dict",
    "render_fingerprint_audit_markdown",
    "summarize_fingerprint_catalog",
]

_VERIFICATION_WORDS = (
    "verification",
    "verify",
    "validation",
    "challenge",
    "site-verification",
    "domain-verification",
    "verification-code",
)

_ROUTING_TYPES = frozenset({"cname", "spf", "ns"})


@dataclass(frozen=True)
class FingerprintAuditEntry:
    """Advisory audit result for one multi-detection fingerprint."""

    slug: str
    name: str
    category: str
    match_mode: str
    detection_count: int
    detection_types: tuple[str, ...]
    classification: AuditClassification
    recommendation: AuditRecommendation
    reasons: tuple[str, ...]
    patterns: tuple[str, ...]


def summarize_fingerprint_catalog(
    fingerprints: tuple[Fingerprint, ...] | None = None,
) -> dict[str, object]:
    """Return no-network catalog health metrics for validation reports."""
    fps = fingerprints if fingerprints is not None else load_fingerprints()
    detections = [rule for fp in fps for rule in fp.detections]
    category_counts = Counter(fp.category for fp in fps)
    match_modes = Counter(fp.match_mode for fp in fps)

    return {
        "total_fingerprints": len(fps),
        "total_detections": len(detections),
        "multi_detection_fingerprints": sum(1 for fp in fps if len(fp.detections) > 1),
        "match_modes": dict(sorted(match_modes.items())),
        "category_counts": dict(sorted(category_counts.items())),
        "fingerprints_with_detection_descriptions": sum(
            1 for fp in fps if any(rule.description for rule in fp.detections)
        ),
        "fingerprints_with_detection_references": sum(
            1 for fp in fps if any(rule.reference for rule in fp.detections)
        ),
        "detections_with_description": sum(1 for rule in detections if rule.description),
        "detections_with_reference": sum(1 for rule in detections if rule.reference),
        "weighted_detections": sum(1 for rule in detections if rule.weight != 1.0),
    }


def _is_verification_rule(rule: DetectionRule) -> bool:
    pattern = rule.pattern.lower()
    if rule.type not in {"txt", "subdomain_txt"}:
        return False
    if any(word in pattern for word in _VERIFICATION_WORDS):
        return True
    return pattern.startswith("^") and "=" in pattern


def _is_broad_routing_rule(rule: DetectionRule) -> bool:
    pattern = rule.pattern.strip()
    if rule.type not in _ROUTING_TYPES:
        return False
    return not (pattern.startswith("^") or pattern.endswith("$"))


def _is_generic_unanchored_rule(rule: DetectionRule) -> bool:
    pattern = rule.pattern.strip()
    if pattern.startswith("^") or pattern.endswith("$"):
        return False
    cleaned = pattern.replace("\\.", ".").replace("|", "").replace("-", "")
    if "." in cleaned:
        return False
    return len(cleaned) <= 24


def _classify_fingerprint(fp: Fingerprint) -> tuple[AuditClassification, AuditRecommendation, tuple[str, ...]]:
    rules = fp.detections
    detection_types = {rule.type for rule in rules}
    verification_count = sum(1 for rule in rules if _is_verification_rule(rule))
    broad_routing_count = sum(1 for rule in rules if _is_broad_routing_rule(rule))
    generic_unanchored_count = sum(1 for rule in rules if _is_generic_unanchored_rule(rule))

    reasons: list[str] = []
    if verification_count:
        reasons.append(f"{verification_count} specific TXT/subdomain verification detection(s)")
    if broad_routing_count:
        reasons.append(f"{broad_routing_count} broad routing/delegation detection(s)")
    if generic_unanchored_count:
        reasons.append(f"{generic_unanchored_count} generic unanchored pattern(s)")
    if len(detection_types) == 1:
        reasons.append(f"all detections use {next(iter(detection_types))}")
    else:
        reasons.append("mixed detection types")

    if fp.match_mode == "all":
        return "corroborating", "already_all", tuple(reasons)

    if generic_unanchored_count and not verification_count:
        reasons.append("generic unanchored routing evidence should be tightened before any match-mode change")
        return "too_broad", "tighten_patterns", tuple(reasons)

    if broad_routing_count and verification_count:
        reasons.append("broad routing evidence is paired with explicit ownership evidence")
        return "corroborating", "review_for_all", tuple(reasons)

    if verification_count == len(rules):
        reasons.append("detections look like alternate verification token formats")
        return "alternative", "keep_any", tuple(reasons)

    if len(detection_types) == 1:
        reasons.append("same-record-type detections look like alternate routes")
        return "alternative", "keep_any", tuple(reasons)

    if broad_routing_count:
        reasons.append("mixed routing evidence looks like alternate passive routes")
        return "alternative", "keep_any", tuple(reasons)

    reasons.append("mixed evidence should be reviewed before changing match_mode")
    return "corroborating", "review_for_all", tuple(reasons)


def audit_multi_detection_fingerprints(
    fingerprints: tuple[Fingerprint, ...] | None = None,
) -> tuple[FingerprintAuditEntry, ...]:
    """Audit fingerprints with two or more detection rules."""
    fps = fingerprints if fingerprints is not None else load_fingerprints()
    entries: list[FingerprintAuditEntry] = []
    for fp in fps:
        if len(fp.detections) < 2:
            continue
        classification, recommendation, reasons = _classify_fingerprint(fp)
        entries.append(
            FingerprintAuditEntry(
                slug=fp.slug,
                name=fp.name,
                category=fp.category,
                match_mode=fp.match_mode,
                detection_count=len(fp.detections),
                detection_types=tuple(sorted({rule.type for rule in fp.detections})),
                classification=classification,
                recommendation=recommendation,
                reasons=reasons,
                patterns=tuple(rule.pattern for rule in fp.detections),
            )
        )
    return tuple(sorted(entries, key=lambda entry: (entry.recommendation, entry.category, entry.slug)))


def format_fingerprint_audit_dict(
    entries: tuple[FingerprintAuditEntry, ...],
    fingerprints: tuple[Fingerprint, ...] | None = None,
) -> dict[str, object]:
    """Return a JSON-safe audit summary."""
    classifications = Counter(entry.classification for entry in entries)
    recommendations = Counter(entry.recommendation for entry in entries)
    return {
        "catalog_summary": summarize_fingerprint_catalog(fingerprints),
        "total_multi_detection_fingerprints": len(entries),
        "classifications": dict(sorted(classifications.items())),
        "recommendations": dict(sorted(recommendations.items())),
        "entries": [asdict(entry) for entry in entries],
    }


def render_fingerprint_audit_markdown(
    entries: tuple[FingerprintAuditEntry, ...],
    fingerprints: tuple[Fingerprint, ...] | None = None,
) -> str:
    """Render a compact Markdown audit report."""
    data = format_fingerprint_audit_dict(entries, fingerprints)
    summary = cast(dict[str, object], data["catalog_summary"])
    lines = [
        "# Fingerprint Match-Mode Audit",
        "",
        "## Catalog Summary",
        "",
        f"- fingerprints: {summary['total_fingerprints']}",
        f"- detection rules: {summary['total_detections']}",
        f"- multi-detection fingerprints: {summary['multi_detection_fingerprints']}",
        f"- match modes: {_format_counter(summary['match_modes'])}",
        (
            "- detection descriptions: "
            f"{summary['detections_with_description']}/{summary['total_detections']}"
        ),
        (
            "- detection references: "
            f"{summary['detections_with_reference']}/{summary['total_detections']}"
        ),
        f"- weighted detections: {summary['weighted_detections']}/{summary['total_detections']}",
        "",
        "## Summary",
        "",
        f"- multi-detection fingerprints: {data['total_multi_detection_fingerprints']}",
    ]

    for name, count in data["classifications"].items():  # type: ignore[union-attr]
        lines.append(f"- classification `{name}`: {count}")
    for name, count in data["recommendations"].items():  # type: ignore[union-attr]
        lines.append(f"- recommendation `{name}`: {count}")

    lines.extend(["", "## Review Queue", ""])
    if not entries:
        lines.append("- none")
    else:
        for entry in entries:
            types = ", ".join(entry.detection_types)
            lines.append(
                f"- `{entry.slug}` ({entry.name}): {entry.classification}, "
                f"{entry.recommendation}; {entry.detection_count} detections [{types}]"
            )
            lines.append(f"  reason: {'; '.join(entry.reasons)}")

    return "\n".join(lines) + "\n"


def _format_counter(value: object) -> str:
    if not isinstance(value, dict) or not value:
        return "none"
    return ", ".join(f"{name}={count}" for name, count in value.items())
