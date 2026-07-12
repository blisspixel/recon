"""Bounded proof-carrying contracts for narrow public observations.

This module is intentionally internal. It establishes one executable claim
family without changing tenant JSON, cache, MCP, or package-facade contracts.
The cohort summary consumes a transient state projection. Positive and explicit
disconfirming evidence remain independent, so disagreement is retained as
conflict instead of being resolved by precedence.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from itertools import product
from typing import Any

from recon_tool.constants import effective_dmarc_policy
from recon_tool.models import EvidenceRecord, TenantInfo
from recon_tool.source_status import SourceStatus


class CollectionState(StrEnum):
    """Outcome of one explicitly scoped observation opportunity."""

    NOT_ATTEMPTED = "not_attempted"
    OBSERVED_VALUE = "observed_value"
    OBSERVED_EMPTY = "observed_empty"
    UNAVAILABLE = "unavailable"
    NOT_ENABLED = "not_enabled"
    NOT_APPLICABLE = "not_applicable"


class ConstructionState(StrEnum):
    """Whether observed material formed one admissible typed unit."""

    COMPLETE = "complete"
    INVALID = "invalid"
    INCOMPLETE = "incomplete"
    MIXED = "mixed"


class ClaimState(StrEnum):
    """Four-state projection of positive and negative certificate presence."""

    UNRESOLVED = "unresolved"
    SUPPORTED = "supported"
    DISCONFIRMED = "disconfirmed_within_public_model"
    CONFLICTED = "conflicted"


class TimeState(StrEnum):
    """Freshness state, kept orthogonal to the four-state claim result."""

    CURRENT = "current"
    STALE = "stale"
    UNKNOWN = "unknown"
    MIXED = "mixed"


class ClaimEvaluationLimitError(ValueError):
    """Raised when an exact evaluation would exceed a declared bound."""


Certificate = frozenset[str]
Antichain = tuple[Certificate, ...]


def _evidence_payload(evidence: EvidenceRecord) -> tuple[str, str, str, str]:
    return evidence.source_type, evidence.raw_value, evidence.rule_name, evidence.slug


def evidence_origin_ref(evidence: EvidenceRecord) -> str:
    """Return an unambiguous content reference for one stored raw observation."""
    encoded = json.dumps(
        _evidence_payload(evidence),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"evidence:sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True, slots=True)
class DependencyUnit:
    """One canonical observation unit and the atoms it directly establishes."""

    unit_id: str
    atoms: frozenset[str]
    collection_state: CollectionState
    construction_state: ConstructionState
    observed_at: datetime | None
    record_owner: str
    source_family: str
    vantage: str | None
    provenance_complete: bool
    origin_refs: tuple[str, ...] = ()
    evidence: tuple[EvidenceRecord, ...] = ()

    def __post_init__(self) -> None:
        if not self.unit_id:
            raise ValueError("unit_id must not be empty")
        if not self.record_owner:
            raise ValueError("record_owner must not be empty")
        if not self.source_family:
            raise ValueError("source_family must not be empty")
        if any(not atom for atom in self.atoms):
            raise ValueError("dependency-unit atoms must not be empty")
        canonical_refs = tuple(sorted(set(self.origin_refs)))
        object.__setattr__(self, "origin_refs", canonical_refs)
        if self.provenance_complete and self.atoms:
            if self.vantage is None or not self.vantage.strip():
                raise ValueError("signed dependency units require a non-empty vantage")
            if not self.evidence:
                raise ValueError("signed dependency units require stored raw evidence")
            expected_refs = tuple(sorted({evidence_origin_ref(item) for item in self.evidence}))
            if canonical_refs != expected_refs:
                raise ValueError("origin_refs must identify every stored raw evidence record exactly")


@dataclass(frozen=True, slots=True)
class ObservationLedger:
    """Canonical set of dependency units with collision-safe identity."""

    units: tuple[DependencyUnit, ...] = ()

    def __post_init__(self) -> None:
        canonical: dict[str, DependencyUnit] = {}
        for unit in self.units:
            existing = canonical.get(unit.unit_id)
            if existing is not None and existing != unit:
                raise ValueError(f"unit_id {unit.unit_id!r} refers to different dependency units")
            canonical[unit.unit_id] = unit
        object.__setattr__(self, "units", tuple(canonical[key] for key in sorted(canonical)))


@dataclass(frozen=True, slots=True)
class MonotoneRule:
    """One positive Horn rule over explicit atoms."""

    name: str
    premises: frozenset[str]
    conclusion: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("rule name must not be empty")
        if not self.premises or any(not premise for premise in self.premises):
            raise ValueError("rules require at least one non-empty premise")
        if not self.conclusion:
            raise ValueError("rule conclusion must not be empty")


def _topological_conclusions(rules: tuple[MonotoneRule, ...]) -> tuple[str, ...]:
    """Return a deterministic conclusion order for an acyclic Horn program."""
    conclusions = frozenset(rule.conclusion for rule in rules)
    dependencies: dict[str, set[str]] = {conclusion: set() for conclusion in conclusions}
    for rule in rules:
        dependencies[rule.conclusion].update(rule.premises & conclusions)

    ordered: list[str] = []
    remaining = {conclusion: set(required) for conclusion, required in dependencies.items()}
    while remaining:
        ready = sorted(conclusion for conclusion, required in remaining.items() if not required)
        if not ready:
            cycle = ", ".join(sorted(remaining))
            raise ValueError(f"claim rules must be acyclic; cycle involves: {cycle}")
        ordered.extend(ready)
        for conclusion in ready:
            remaining.pop(conclusion)
        for required in remaining.values():
            required.difference_update(ready)
    return tuple(ordered)


@dataclass(frozen=True, slots=True)
class ClaimContract:
    """Finite monotone rule system for one exact claim."""

    claim_id: str
    positive_atom: str
    negative_atom: str
    rules: tuple[MonotoneRule, ...]
    freshness: timedelta
    renderer_obligations: tuple[str, ...]
    resolving_evidence: tuple[str, ...]
    max_units: int = 32
    max_atoms: int = 64
    max_rules: int = 256
    max_certificates: int = 256
    max_conjunction_combinations: int = 65_536
    max_total_conjunction_combinations: int = 65_536

    def __post_init__(self) -> None:
        if not self.claim_id:
            raise ValueError("claim_id must not be empty")
        if not self.positive_atom or not self.negative_atom:
            raise ValueError("claim sign atoms must not be empty")
        if self.positive_atom == self.negative_atom:
            raise ValueError("positive and negative atoms must differ")
        if self.freshness <= timedelta(0):
            raise ValueError("freshness must be positive")
        if self.freshness.microseconds != 0:
            raise ValueError("freshness must use whole-second precision")
        if (
            min(
                self.max_units,
                self.max_atoms,
                self.max_rules,
                self.max_certificates,
                self.max_conjunction_combinations,
                self.max_total_conjunction_combinations,
            )
            <= 0
        ):
            raise ValueError("claim evaluation bounds must be positive")
        if len(self.rules) > self.max_rules:
            raise ValueError(f"rule limit {self.max_rules} exceeded; contract refused")
        rule_names = [rule.name for rule in self.rules]
        if len(rule_names) != len(set(rule_names)):
            raise ValueError("rule names must be unique within a claim contract")
        _topological_conclusions(self.rules)


@dataclass(frozen=True, slots=True)
class ClaimDossier:
    """Internal proof dossier for one claim at one frozen evaluation time."""

    claim_id: str
    subject: str
    namespace: str
    scope: str
    as_of: str
    freshness_seconds: int
    state: ClaimState
    time_state: TimeState
    construction_state: ConstructionState
    positive_certificates: Antichain
    negative_certificates: Antichain
    units: tuple[DependencyUnit, ...]
    observation_window: tuple[str, str] | None
    unavailable_units: tuple[str, ...]
    stale_units: tuple[str, ...]
    provenance_complete: bool
    provenance_limitations: tuple[str, ...]
    certificates_complete: bool
    renderer_obligations: tuple[str, ...]
    resolving_evidence: tuple[str, ...]


def merge_ledgers(*ledgers: ObservationLedger) -> ObservationLedger:
    """Return canonical ACI union; claim closure must be recomputed afterward."""
    return ObservationLedger(tuple(unit for ledger in ledgers for unit in ledger.units))


def _certificate_key(certificate: Certificate) -> tuple[int, tuple[str, ...]]:
    return len(certificate), tuple(sorted(certificate))


def _minimal_antichain(
    certificates: tuple[Certificate, ...] | list[Certificate],
) -> Antichain:
    unique = sorted(set(certificates), key=_certificate_key)
    minimal: list[Certificate] = []
    for candidate in unique:
        if any(existing <= candidate for existing in minimal):
            continue
        minimal.append(candidate)
    return tuple(minimal)


def _multiply_antichains(
    families: tuple[Antichain, ...],
    *,
    max_combinations: int,
    max_total_remaining: int,
) -> tuple[Antichain, int]:
    if not families or any(not family for family in families):
        return (), 0
    combination_count = 1
    for family in families:
        combination_count *= len(family)
        if combination_count > max_combinations:
            raise ClaimEvaluationLimitError(
                f"per-rule conjunction combination limit {max_combinations} exceeded; exact evaluation refused"
            )
    if combination_count > max_total_remaining:
        raise ClaimEvaluationLimitError("cumulative conjunction combination limit exceeded; exact evaluation refused")
    combined: Antichain = (frozenset(),)
    for family in families:
        combined = _minimal_antichain([left | right for left, right in product(combined, family)])
    return combined, combination_count


def _require_certificate_bound(
    proofs: Antichain,
    *,
    atom: str,
    limit: int,
) -> None:
    if len(proofs) > limit:
        raise ClaimEvaluationLimitError(
            f"certificate limit {limit} exceeded for atom {atom!r}; exact evaluation refused"
        )


def _aware_utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is None or value.utcoffset() is None:
        return None
    return value.astimezone(UTC)


def _require_aware_utc(value: datetime) -> datetime:
    normalized = _aware_utc(value)
    if normalized is None:
        raise ValueError("as_of must be timezone-aware")
    return normalized


def _unit_time_state(unit: DependencyUnit, *, as_of: datetime, freshness: timedelta) -> TimeState:
    observed_at = _aware_utc(unit.observed_at)
    if observed_at is None or observed_at > as_of:
        return TimeState.UNKNOWN
    if as_of - observed_at > freshness:
        return TimeState.STALE
    return TimeState.CURRENT


def _aggregate_time_state(states: tuple[TimeState, ...]) -> TimeState:
    distinct = frozenset(states)
    if not distinct or distinct == frozenset({TimeState.UNKNOWN}):
        return TimeState.UNKNOWN
    if len(distinct) == 1:
        return next(iter(distinct))
    return TimeState.MIXED


def _aggregate_construction_state(units: tuple[DependencyUnit, ...]) -> ConstructionState:
    states = frozenset(unit.construction_state for unit in units)
    if not states:
        return ConstructionState.INCOMPLETE
    if len(states) == 1:
        return next(iter(states))
    return ConstructionState.MIXED


def _claim_state(positive: Antichain, negative: Antichain) -> ClaimState:
    if positive and negative:
        return ClaimState.CONFLICTED
    if positive:
        return ClaimState.SUPPORTED
    if negative:
        return ClaimState.DISCONFIRMED
    return ClaimState.UNRESOLVED


def evaluate_claim(
    contract: ClaimContract,
    ledger: ObservationLedger,
    *,
    subject: str,
    namespace: str,
    scope: str,
    as_of: datetime,
    provenance_limitations: tuple[str, ...] = (),
) -> ClaimDossier:
    """Evaluate a bounded claim exactly, or fail rather than truncate proofs."""
    evaluation_time = _require_aware_utc(as_of)
    if len(ledger.units) > contract.max_units:
        raise ClaimEvaluationLimitError(f"unit limit {contract.max_units} exceeded; exact evaluation refused")

    all_atoms = {contract.positive_atom, contract.negative_atom}
    all_atoms.update(atom for unit in ledger.units for atom in unit.atoms)
    all_atoms.update(rule.conclusion for rule in contract.rules)
    all_atoms.update(premise for rule in contract.rules for premise in rule.premises)
    if len(all_atoms) > contract.max_atoms:
        raise ClaimEvaluationLimitError(f"atom limit {contract.max_atoms} exceeded; exact evaluation refused")

    unit_times = tuple(
        _unit_time_state(unit, as_of=evaluation_time, freshness=contract.freshness) for unit in ledger.units
    )
    stale_units = tuple(
        unit.unit_id for unit, time_state in zip(ledger.units, unit_times, strict=True) if time_state is TimeState.STALE
    )
    unavailable_units = tuple(
        unit.unit_id for unit in ledger.units if unit.collection_state is CollectionState.UNAVAILABLE
    )

    proofs: dict[str, Antichain] = {}
    observed_states = {CollectionState.OBSERVED_VALUE, CollectionState.OBSERVED_EMPTY}
    for unit, time_state in zip(ledger.units, unit_times, strict=True):
        if (
            time_state is not TimeState.CURRENT
            or unit.collection_state not in observed_states
            or unit.construction_state is not ConstructionState.COMPLETE
            or not unit.provenance_complete
        ):
            continue
        origin = (frozenset({unit.unit_id}),)
        for atom in unit.atoms:
            proofs[atom] = _minimal_antichain([*proofs.get(atom, ()), *origin])

    rules_by_conclusion: dict[str, list[MonotoneRule]] = {}
    for rule in contract.rules:
        rules_by_conclusion.setdefault(rule.conclusion, []).append(rule)
    conclusion_order = _topological_conclusions(contract.rules)
    conclusion_set = frozenset(conclusion_order)

    for atom, atom_proofs in proofs.items():
        if atom not in conclusion_set:
            _require_certificate_bound(
                atom_proofs,
                atom=atom,
                limit=contract.max_certificates,
            )

    conjunction_combinations = 0
    for conclusion in conclusion_order:
        candidates = list(proofs.get(conclusion, ()))
        for rule in sorted(
            rules_by_conclusion[conclusion],
            key=lambda item: (tuple(sorted(item.premises)), item.name),
        ):
            families = tuple(proofs.get(premise, ()) for premise in sorted(rule.premises))
            derived, combinations = _multiply_antichains(
                families,
                max_combinations=contract.max_conjunction_combinations,
                max_total_remaining=(contract.max_total_conjunction_combinations - conjunction_combinations),
            )
            conjunction_combinations += combinations
            candidates.extend(derived)
        exact = _minimal_antichain(candidates)
        _require_certificate_bound(
            exact,
            atom=conclusion,
            limit=contract.max_certificates,
        )
        if exact:
            proofs[conclusion] = exact
        else:
            proofs.pop(conclusion, None)

    positive = proofs.get(contract.positive_atom, ())
    negative = proofs.get(contract.negative_atom, ())
    timestamps = sorted(normalized for unit in ledger.units if (normalized := _aware_utc(unit.observed_at)) is not None)
    window = (timestamps[0].isoformat(), timestamps[-1].isoformat()) if timestamps else None
    incomplete_time = any(state is TimeState.UNKNOWN for state in unit_times)
    incomplete_construction = any(unit.construction_state is ConstructionState.INCOMPLETE for unit in ledger.units)
    provenance_complete = (
        bool(ledger.units)
        and not incomplete_time
        and not incomplete_construction
        and all(unit.provenance_complete for unit in ledger.units)
    )

    return ClaimDossier(
        claim_id=contract.claim_id,
        subject=subject,
        namespace=namespace,
        scope=scope,
        as_of=evaluation_time.isoformat(),
        freshness_seconds=int(contract.freshness.total_seconds()),
        state=_claim_state(positive, negative),
        time_state=_aggregate_time_state(unit_times),
        construction_state=_aggregate_construction_state(ledger.units),
        positive_certificates=positive,
        negative_certificates=negative,
        units=ledger.units,
        observation_window=window,
        unavailable_units=unavailable_units,
        stale_units=stale_units,
        provenance_complete=provenance_complete,
        provenance_limitations=provenance_limitations,
        certificates_complete=True,
        renderer_obligations=contract.renderer_obligations,
        resolving_evidence=contract.resolving_evidence,
    )


_DMARC_REJECT_ATOM = "dns:dmarc:policy:reject"
_DMARC_NON_REJECT_ATOM = "dns:dmarc:policy:explicit-non-reject"
_DMARC_CLAIM_POSITIVE = "claim:dns.dmarc.valid_policy_is_reject.v1:positive"
_DMARC_CLAIM_NEGATIVE = "claim:dns.dmarc.valid_policy_is_reject.v1:negative"
_DMARC_VALID_POLICIES = frozenset({"none", "quarantine", "reject"})
_DMARC_PROVENANCE_LIMITATIONS = (
    "per-query DMARC observation time is not retained; resolution completion time is used",
    "DNS response code, authority, and safety-suppression provenance are not retained for empty results",
    "DNSSEC validation status is not retained",
    "recursive resolver identity is not retained",
)
DMARC_REJECT_CLAIM_STATE_FIELD = "_recon_internal_dmarc_reject_claim_state"
DMARC_EFFECTIVE_POLICY_FIELD = "_recon_internal_dmarc_effective_policy"


DMARC_APEX_REJECT_CONTRACT = ClaimContract(
    claim_id="dns.dmarc.valid_policy_is_reject.v1",
    positive_atom=_DMARC_CLAIM_POSITIVE,
    negative_atom=_DMARC_CLAIM_NEGATIVE,
    rules=(
        MonotoneRule("valid-reject", frozenset({_DMARC_REJECT_ATOM}), _DMARC_CLAIM_POSITIVE),
        MonotoneRule(
            "valid-explicit-non-reject",
            frozenset({_DMARC_NON_REJECT_ATOM}),
            _DMARC_CLAIM_NEGATIVE,
        ),
    ),
    freshness=timedelta(hours=24),
    renderer_obligations=("batch cohort-summary DMARC rates",),
    resolving_evidence=(
        "one fresh valid apex DMARC record with p=reject",
        "one fresh valid apex DMARC record with p=none or p=quarantine",
    ),
    max_units=32,
    max_atoms=32,
    max_rules=16,
    max_certificates=128,
    max_conjunction_combinations=4_096,
    max_total_conjunction_combinations=4_096,
)


def _parse_observed_at(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _evidence_key(evidence: EvidenceRecord) -> tuple[str, str, str, str]:
    return _evidence_payload(evidence)


def _explicit_dmarc_policy_from_raw(record: str, domain: str) -> str | None:
    """Parse only an explicitly published ``p`` value from one DMARC record."""
    from recon_tool.sources.dns_email import parse_explicit_dmarc_policy_record

    return parse_explicit_dmarc_policy_record(record, domain)


def _dmarc_unit_id(
    *,
    publication_point: str,
    observed_at: datetime | None,
    policy: str | None,
    collection_state: CollectionState,
    construction_state: ConstructionState,
    evidence: tuple[EvidenceRecord, ...],
    conflict_candidates: tuple[tuple[str, str, str], ...],
) -> str:
    payload = {
        "collection_state": collection_state.value,
        "conflict_candidates": conflict_candidates,
        "construction_state": construction_state.value,
        "evidence": tuple(_evidence_key(record) for record in evidence),
        "observed_at": observed_at.isoformat() if observed_at is not None else None,
        "policy": policy,
        "publication_point": publication_point,
        "version": 1,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    return f"dns:dmarc:{digest}"


def _dmarc_unit(info: TenantInfo) -> DependencyUnit:
    subject = info.queried_domain.strip().rstrip(".").lower()
    publication_point = f"_dmarc.{subject}"
    evidence_by_key = {
        _evidence_key(record): record for record in info.evidence if record.source_type.upper() == "DMARC"
    }
    evidence = tuple(evidence_by_key[key] for key in sorted(evidence_by_key))
    explicit_policy_evidence = tuple(
        (record, _explicit_dmarc_policy_from_raw(record.raw_value, subject))
        for record in evidence
        if record.slug == "dmarc"
    )
    invalid_evidence = any(record.slug == "dmarc-invalid" for record in evidence)
    policy = info.dmarc_policy.lower() if isinstance(info.dmarc_policy, str) else None
    status = SourceStatus.from_degraded_sources(info.degraded_sources)
    has_merge_conflict = bool(info.merge_conflicts and info.merge_conflicts.dmarc_policy)
    conflict_candidates = tuple(
        sorted(
            (candidate.value, candidate.source, candidate.confidence)
            for candidate in (info.merge_conflicts.dmarc_policy if info.merge_conflicts else ())
        )
    )

    atoms: frozenset[str] = frozenset()
    if status.channel_unavailable("dmarc"):
        collection_state = CollectionState.UNAVAILABLE
        construction_state = ConstructionState.INCOMPLETE
    elif has_merge_conflict:
        collection_state = CollectionState.OBSERVED_VALUE if evidence else CollectionState.OBSERVED_EMPTY
        construction_state = ConstructionState.INCOMPLETE
    elif (
        policy in _DMARC_VALID_POLICIES
        and len(explicit_policy_evidence) == 1
        and explicit_policy_evidence[0][1] == policy
        and not invalid_evidence
    ):
        collection_state = CollectionState.OBSERVED_VALUE
        construction_state = ConstructionState.COMPLETE
        atoms = frozenset({_DMARC_REJECT_ATOM if policy == "reject" else _DMARC_NON_REJECT_ATOM})
    elif policy is None and invalid_evidence:
        collection_state = CollectionState.OBSERVED_VALUE
        construction_state = ConstructionState.INVALID
    elif policy is None and not evidence:
        collection_state = CollectionState.OBSERVED_EMPTY
        construction_state = ConstructionState.COMPLETE
    else:
        collection_state = CollectionState.OBSERVED_VALUE if evidence else CollectionState.OBSERVED_EMPTY
        construction_state = ConstructionState.INCOMPLETE

    observed_at = _parse_observed_at(info.resolved_at)
    provenance_complete = (
        collection_state is CollectionState.OBSERVED_VALUE
        and construction_state is ConstructionState.COMPLETE
        and observed_at is not None
        and observed_at.tzinfo is not None
        and observed_at.utcoffset() is not None
        and bool(evidence)
    )
    origin_refs = tuple(evidence_origin_ref(record) for record in evidence)
    return DependencyUnit(
        unit_id=_dmarc_unit_id(
            publication_point=publication_point,
            observed_at=_aware_utc(observed_at),
            policy=policy,
            collection_state=collection_state,
            construction_state=construction_state,
            evidence=evidence,
            conflict_candidates=conflict_candidates,
        ),
        atoms=atoms,
        collection_state=collection_state,
        construction_state=construction_state,
        observed_at=observed_at,
        record_owner=publication_point,
        source_family="dns",
        vantage="configured recursive resolver",
        provenance_complete=provenance_complete,
        origin_refs=origin_refs,
        evidence=evidence,
    )


def _mapping_has_dmarc_conflict(record: Mapping[str, Any]) -> bool:
    conflicts = record.get("evidence_conflicts")
    return isinstance(conflicts, list) and any(
        isinstance(item, Mapping) and item.get("field") == "dmarc_policy" for item in conflicts
    )


def _evidence_from_mapping(item: object) -> EvidenceRecord | None:
    if not isinstance(item, Mapping):
        return None
    values = tuple(item.get(field) for field in ("source_type", "raw_value", "rule_name", "slug"))
    if not all(isinstance(value, str) for value in values):
        return None
    source_type, raw_value, rule_name, slug = values
    return EvidenceRecord(str(source_type), str(raw_value), str(rule_name), str(slug))


def _mapping_dmarc_evidence(record: Mapping[str, Any]) -> tuple[EvidenceRecord, ...] | None:
    raw_evidence = record.get("evidence")
    if not isinstance(raw_evidence, list):
        return None
    evidence: dict[tuple[str, str, str, str], EvidenceRecord] = {}
    for item in raw_evidence:
        parsed = _evidence_from_mapping(item)
        if parsed is None or parsed.source_type.upper() != "DMARC":
            continue
        evidence[_evidence_key(parsed)] = parsed
    return tuple(evidence[key] for key in sorted(evidence))


def _raw_dmarc_effective_policy(record: EvidenceRecord, domain: str, policy: str) -> str | None:
    from recon_tool.sources.dns_email import parse_dmarc_tags

    tags = parse_dmarc_tags(record.raw_value, domain)
    if tags is None:
        return None
    pct: int | None = None
    if (raw_pct := tags.get("pct")) is not None and 1 <= len(raw_pct) <= 3 and raw_pct.isascii() and raw_pct.isdigit():
        candidate_pct = int(raw_pct)
        if 0 <= candidate_pct <= 100:
            pct = candidate_pct
    testing = tags.get("t", "n").lower() == "y"
    return effective_dmarc_policy(policy, pct, testing)


def dmarc_explicit_policy_projection_from_mapping(
    record: Mapping[str, Any],
) -> tuple[ClaimState, str | None]:
    """Project raw-bound policy state and effective level without a time claim."""
    unresolved = ClaimState.UNRESOLVED, None
    raw_policy = record.get("dmarc_policy")
    policy = raw_policy.lower() if isinstance(raw_policy, str) else None
    if policy not in _DMARC_VALID_POLICIES or _mapping_has_dmarc_conflict(record):
        return unresolved

    ordered = _mapping_dmarc_evidence(record)
    if ordered is None or any(item.slug == "dmarc-invalid" for item in ordered):
        return unresolved
    domain = str(record.get("queried_domain") or "unknown")
    explicit = tuple(
        (item, _explicit_dmarc_policy_from_raw(item.raw_value, domain)) for item in ordered if item.slug == "dmarc"
    )
    if len(explicit) != 1 or explicit[0][1] != policy:
        return unresolved
    effective_policy = _raw_dmarc_effective_policy(explicit[0][0], domain, policy)
    if effective_policy is None:
        return unresolved
    state = ClaimState.SUPPORTED if policy == "reject" else ClaimState.DISCONFIRMED
    return state, effective_policy


def dmarc_apex_reject_dossier(
    info: TenantInfo,
    *,
    as_of: datetime | None = None,
) -> ClaimDossier:
    """Evaluate whether the exact apex DMARC record declares ``p=reject``.

    Empty or invalid observations remain unresolved because the current
    resolver does not retain DNS authority or authenticated-denial material.
    Explicit valid ``p=none`` and ``p=quarantine`` values are the only negative
    alternatives in this first contract.
    """
    evaluation_time = datetime.now(UTC) if as_of is None else as_of
    subject = info.queried_domain.strip().rstrip(".").lower()
    publication_point = f"_dmarc.{subject}"
    return evaluate_claim(
        DMARC_APEX_REJECT_CONTRACT,
        ObservationLedger((_dmarc_unit(info),)),
        subject=subject,
        namespace="dns",
        scope=f"{publication_point} TXT",
        as_of=evaluation_time,
        provenance_limitations=_DMARC_PROVENANCE_LIMITATIONS,
    )
