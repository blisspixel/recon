"""Immutable evidence records shared by runtime claim models."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["EvidenceRecord"]


@dataclass(frozen=True)
class EvidenceRecord:
    """One retained occurrence linking a detection to its public record.

    Collectors create these records when a catalog rule matches, and the merge
    pipeline propagates them into ``TenantInfo`` without loss.
    """

    source_type: str  # TXT, MX, CNAME, HTTP, SPF, NS, CAA, SRV, or another declared channel
    raw_value: str  # Observed public-record value or bounded HTTP excerpt
    rule_name: str  # Catalog detection rule that matched
    slug: str  # Canonical catalog indicator emitted by the rule
