"""Internal proof-carrying models for posture observations."""

from __future__ import annotations

from dataclasses import dataclass

from recon_tool.evidence_models import EvidenceRecord

__all__ = ["Observation", "PostureMetadataDependency", "metadata_predicate_satisfied"]


@dataclass(frozen=True)
class PostureMetadataDependency:
    """One typed metadata predicate captured when a posture rule fires."""

    field: str
    operator: str
    expected_value: str | int
    observed_value: str | int | tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.field:
            raise ValueError("posture metadata dependency field must not be empty")
        if not self.operator:
            raise ValueError("posture metadata dependency operator must not be empty")


@dataclass(frozen=True)
class Observation:
    """A neutral observation plus its transient generation-time lineage.

    The four original display fields remain the public posture contract.
    ``source_name``, ``supporting_evidence``, ``metadata_dependencies``, and
    ``observation_scope`` are internal proof state used by explanation and
    profile layers; posture formatters intentionally do not serialize them.
    """

    category: str
    salience: str
    statement: str
    related_slugs: tuple[str, ...]
    source_name: str = ""
    supporting_evidence: tuple[EvidenceRecord, ...] = ()
    metadata_dependencies: tuple[PostureMetadataDependency, ...] = ()
    observation_scope: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        lineage = self.supporting_evidence or self.metadata_dependencies or self.observation_scope
        if not self.source_name and lineage:
            raise ValueError("posture lineage requires a non-empty source name")
        if any(not scope for scope in self.observation_scope):
            raise ValueError("posture observation scopes must not be empty")


def metadata_predicate_satisfied(
    operator: str,
    expected_value: str | int,
    observed_value: str | int | tuple[str, ...],
) -> bool:
    """Evaluate one captured posture predicate without reading live state."""
    if operator in {"gte", "lte"}:
        if isinstance(observed_value, tuple):
            return False
        try:
            observed_number = int(observed_value)
            expected_number = int(expected_value)
        except (TypeError, ValueError):
            return False
        return observed_number >= expected_number if operator == "gte" else observed_number <= expected_number

    if operator == "not_contains":
        return isinstance(observed_value, tuple) and str(expected_value).casefold() not in {
            item.casefold() for item in observed_value
        }

    observed_text = str(observed_value).casefold()
    expected_text = str(expected_value).casefold()
    comparisons = {"eq": observed_text == expected_text, "neq": observed_text != expected_text}
    return comparisons.get(operator, False)
