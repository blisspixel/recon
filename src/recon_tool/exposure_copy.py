"""Shared neutral-copy and evidence helpers for the exposure surface.

``exposure.py`` and ``exposure_gaps.py`` both generate operator-facing prose and
both attach evidence references to it. These helpers live here so the gap
detectors can be split out without importing back into ``exposure`` and forming
a cycle.

The copy check is a lint on recon-authored text, not an input blocklist: it logs
a discouraged term and returns the string unchanged, so a wording slip is
visible in logs without suppressing an observation.
"""

from __future__ import annotations

import logging

from recon_tool.exposure_models import EvidenceReference
from recon_tool.models import TenantInfo
from recon_tool.posture import DISCOURAGED_COPY_TERMS

logger = logging.getLogger(__name__)

EXPOSURE_DISCOURAGED_COPY_TERMS: frozenset[str] = DISCOURAGED_COPY_TERMS | frozenset(
    {
        "target",
        "attack surface",
        "vulnerabilities to exploit",
        "finding",
        "remediation",
    }
)


def check_neutral_copy(text: str) -> str:
    """Log discouraged generated-copy terms without blocking the output."""
    lower = text.lower()
    for term in EXPOSURE_DISCOURAGED_COPY_TERMS:
        if term in lower:
            logger.warning("Discouraged copy term '%s' found in generated prose: %s", term, text)
    return text


def build_evidence_refs(info: TenantInfo, slugs: frozenset[str] | set[str]) -> tuple[EvidenceReference, ...]:
    """Build EvidenceReference entries from TenantInfo.evidence matching given slugs."""
    return tuple(
        EvidenceReference(
            source_type=evidence.source_type,
            raw_value=evidence.raw_value,
            rule_name=evidence.rule_name,
            slug=evidence.slug,
        )
        for evidence in info.evidence
        if evidence.slug in slugs
    )


def evidence_slugs(info: TenantInfo, source_types: frozenset[str]) -> set[str]:
    """Return slugs backed by one of the role-bearing evidence types."""
    return {
        evidence.slug for evidence in info.evidence if evidence.slug and evidence.source_type.upper() in source_types
    }
