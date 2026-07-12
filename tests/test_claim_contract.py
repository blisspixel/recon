from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import combinations
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

import recon_tool
from recon_tool.claim_contract import (
    DMARC_APEX_REJECT_CONTRACT,
    DMARC_REJECT_CLAIM_STATE_FIELD,
    ClaimContract,
    ClaimEvaluationLimitError,
    ClaimState,
    CollectionState,
    ConstructionState,
    DependencyUnit,
    MonotoneRule,
    ObservationLedger,
    TimeState,
    dmarc_apex_reject_dossier,
    evaluate_claim,
    evidence_origin_ref,
    merge_ledgers,
)
from recon_tool.models import CandidateValue, EvidenceRecord, MergeConflicts, TenantInfo

NOW = datetime(2026, 7, 11, 12, tzinfo=UTC)


def _dmarc_evidence(policy: str, *, slug: str = "dmarc") -> EvidenceRecord:
    return EvidenceRecord(
        source_type="DMARC",
        raw_value=f"v=DMARC1; p={policy}",
        rule_name="DMARC",
        slug=slug,
    )


def _info(
    *,
    policy: str | None = None,
    evidence: tuple[EvidenceRecord, ...] = (),
    degraded_sources: tuple[str, ...] = (),
    resolved_at: str | None = NOW.isoformat(),
    merge_conflicts: MergeConflicts | None = None,
    queried_domain: str = "contoso.com",
) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="Contoso",
        default_domain="contoso.com",
        queried_domain=queried_domain,
        dmarc_policy=policy,
        evidence=evidence,
        degraded_sources=degraded_sources,
        resolved_at=resolved_at,
        merge_conflicts=merge_conflicts,
    )


def _unit(
    unit_id: str,
    *atoms: str,
    observed_at: datetime | None = NOW,
    collection_state: CollectionState = CollectionState.OBSERVED_VALUE,
    provenance_complete: bool = True,
) -> DependencyUnit:
    evidence = EvidenceRecord(
        source_type="synthetic",
        raw_value=unit_id,
        rule_name="test fixture",
        slug="synthetic",
    )
    return DependencyUnit(
        unit_id=unit_id,
        atoms=frozenset(atoms),
        collection_state=collection_state,
        construction_state=ConstructionState.COMPLETE,
        observed_at=observed_at,
        record_owner="_claim.contoso.com",
        source_family="synthetic",
        vantage="test",
        provenance_complete=provenance_complete,
        origin_refs=((evidence_origin_ref(evidence),) if provenance_complete else ()),
        evidence=((evidence,) if provenance_complete else ()),
    )


def _contract(
    *rules: MonotoneRule,
    **overrides: Any,
) -> ClaimContract:
    options: dict[str, Any] = {
        "freshness": timedelta(days=1),
        "max_units": 16,
        "max_atoms": 32,
        "max_rules": 16,
        "max_certificates": 64,
        "max_conjunction_combinations": 4_096,
        "max_total_conjunction_combinations": 4_096,
    }
    options.update(overrides)
    return ClaimContract(
        claim_id="test.claim",
        positive_atom="claim:test:positive",
        negative_atom="claim:test:negative",
        rules=rules,
        renderer_obligations=("internal-test",),
        resolving_evidence=("explicit test evidence",),
        **options,
    )


class TestDmarcApexRejectAdapter:
    def test_valid_reject_is_supported_by_one_raw_rrset_unit(self) -> None:
        evidence = _dmarc_evidence("reject")

        dossier = dmarc_apex_reject_dossier(
            _info(policy="reject", evidence=(evidence,)),
            as_of=NOW + timedelta(hours=1),
        )

        assert dossier.claim_id == "dns.dmarc.valid_policy_is_reject.v1"
        assert dossier.subject == "contoso.com"
        assert dossier.namespace == "dns"
        assert dossier.scope == "_dmarc.contoso.com TXT"
        assert dossier.as_of == (NOW + timedelta(hours=1)).isoformat()
        assert dossier.freshness_seconds == 86_400
        assert dossier.state is ClaimState.SUPPORTED
        assert dossier.time_state is TimeState.CURRENT
        assert dossier.negative_certificates == ()
        assert dossier.positive_certificates == (frozenset({dossier.units[0].unit_id}),)
        assert dossier.units[0].evidence == (evidence,)
        assert dossier.units[0].record_owner == "_dmarc.contoso.com"
        assert dossier.certificates_complete
        assert dossier.provenance_complete
        assert dossier.provenance_limitations == (
            "per-query DMARC observation time is not retained; resolution completion time is used",
            "DNS response code, authority, and safety-suppression provenance are not retained for empty results",
            "DNSSEC validation status is not retained",
            "recursive resolver identity is not retained",
        )

    @pytest.mark.parametrize(
        ("scalar_policy", "raw_policy"),
        [("reject", "none"), ("none", "reject")],
    )
    def test_scalar_policy_must_match_canonical_raw_evidence(
        self,
        scalar_policy: str,
        raw_policy: str,
    ) -> None:
        dossier = dmarc_apex_reject_dossier(
            _info(policy=scalar_policy, evidence=(_dmarc_evidence(raw_policy),)),
            as_of=NOW + timedelta(hours=1),
        )

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.units[0].construction_state is ConstructionState.INCOMPLETE
        assert not dossier.units[0].atoms
        assert not dossier.provenance_complete

    @pytest.mark.parametrize(
        ("scalar_policy", "raw_record"),
        [
            (
                "reject",
                "v=DMARC1; p=reject; np=bogus; rua=mailto:dmarc@example.com",
            ),
            ("none", "v=DMARC1; p=none; sp=bogus; rua=mailto:dmarc@example.com"),
            ("none", "v=DMARC1; p=none; np=bogus; rua=mailto:dmarc@example.com"),
            ("none", "v=DMARC1; p=bogus; rua=mailto:dmarc@example.com"),
            ("none", "v=DMARC1; rua=mailto:dmarc@example.com"),
        ],
    )
    def test_defaulted_or_inapplicable_policy_is_not_an_explicit_certificate(
        self,
        scalar_policy: str,
        raw_record: str,
    ) -> None:
        evidence = EvidenceRecord("DMARC", raw_record, "DMARC", "dmarc")

        dossier = dmarc_apex_reject_dossier(
            _info(policy=scalar_policy, evidence=(evidence,)),
            as_of=NOW + timedelta(hours=1),
        )

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.units[0].construction_state is ConstructionState.INCOMPLETE

    @pytest.mark.parametrize("policy", ["none", "quarantine"])
    def test_explicit_incompatible_policy_is_disconfirmed(self, policy: str) -> None:
        dossier = dmarc_apex_reject_dossier(
            _info(policy=policy, evidence=(_dmarc_evidence(policy),)),
            as_of=NOW + timedelta(hours=1),
        )

        assert dossier.state is ClaimState.DISCONFIRMED
        assert dossier.positive_certificates == ()
        assert dossier.negative_certificates == (frozenset({dossier.units[0].unit_id}),)

    def test_successful_empty_is_observed_but_not_authoritative_negative(self) -> None:
        dossier = dmarc_apex_reject_dossier(_info(), as_of=NOW + timedelta(hours=1))

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.units[0].collection_state is CollectionState.OBSERVED_EMPTY
        assert dossier.positive_certificates == ()
        assert dossier.negative_certificates == ()

    def test_scalar_without_raw_lineage_is_incomplete_and_unresolved(self) -> None:
        dossier = dmarc_apex_reject_dossier(
            _info(policy="reject"),
            as_of=NOW + timedelta(hours=1),
        )

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.units[0].construction_state is ConstructionState.INCOMPLETE
        assert not dossier.provenance_complete

    @pytest.mark.parametrize(
        "evidence",
        [
            (_dmarc_evidence("reject", slug="dmarc-invalid"),),
            (
                _dmarc_evidence("reject", slug="dmarc-invalid"),
                _dmarc_evidence("none", slug="dmarc-invalid"),
            ),
        ],
    )
    def test_invalid_or_multiple_record_rrset_remains_unresolved(
        self,
        evidence: tuple[EvidenceRecord, ...],
    ) -> None:
        dossier = dmarc_apex_reject_dossier(_info(evidence=evidence), as_of=NOW + timedelta(hours=1))

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.units[0].construction_state is ConstructionState.INVALID
        assert dossier.positive_certificates == ()
        assert dossier.negative_certificates == ()

    @pytest.mark.parametrize("marker", ["dns:dmarc", "dns", "detector:email_security"])
    def test_unavailable_collection_never_becomes_negative(self, marker: str) -> None:
        dossier = dmarc_apex_reject_dossier(
            _info(
                policy="none",
                evidence=(_dmarc_evidence("none"),),
                degraded_sources=(marker,),
            ),
            as_of=NOW + timedelta(hours=1),
        )

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.units[0].collection_state is CollectionState.UNAVAILABLE
        assert dossier.negative_certificates == ()

    def test_stale_evidence_is_retained_but_not_projected_as_current(self) -> None:
        dossier = dmarc_apex_reject_dossier(
            _info(
                policy="reject",
                evidence=(_dmarc_evidence("reject"),),
                resolved_at=(NOW - timedelta(days=2)).isoformat(),
            ),
            as_of=NOW,
        )

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.time_state is TimeState.STALE
        assert dossier.stale_units == (dossier.units[0].unit_id,)
        assert dossier.positive_certificates == ()

    def test_freshness_boundary_is_inclusive_then_stale_one_microsecond_later(self) -> None:
        info = _info(policy="reject", evidence=(_dmarc_evidence("reject"),))

        boundary = dmarc_apex_reject_dossier(info, as_of=NOW + timedelta(hours=24))
        beyond = dmarc_apex_reject_dossier(
            info,
            as_of=NOW + timedelta(hours=24, microseconds=1),
        )

        assert boundary.state is ClaimState.SUPPORTED
        assert boundary.time_state is TimeState.CURRENT
        assert beyond.state is ClaimState.UNRESOLVED
        assert beyond.time_state is TimeState.STALE

    @pytest.mark.parametrize(
        "resolved_at",
        [
            None,
            "not-a-timestamp",
            "2026-07-11T12:00:00",
            (NOW + timedelta(minutes=1)).isoformat(),
        ],
    )
    def test_missing_invalid_or_naive_time_is_explicitly_unknown(self, resolved_at: str | None) -> None:
        dossier = dmarc_apex_reject_dossier(
            _info(
                policy="reject",
                evidence=(_dmarc_evidence("reject"),),
                resolved_at=resolved_at,
            ),
            as_of=NOW,
        )

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.time_state is TimeState.UNKNOWN
        assert not dossier.provenance_complete

    def test_domain_and_equivalent_timestamps_are_canonicalized(self) -> None:
        evidence = _dmarc_evidence("reject")
        first = dmarc_apex_reject_dossier(
            _info(
                policy="reject",
                evidence=(evidence,),
                queried_domain="CONTOSO.COM.",
                resolved_at="2026-07-11T12:00:00Z",
            ),
            as_of=NOW,
        )
        second = dmarc_apex_reject_dossier(
            _info(policy="reject", evidence=(evidence,), resolved_at=NOW.isoformat()),
            as_of=NOW,
        )

        assert first == second

    def test_merged_field_conflict_without_raw_candidate_lineage_fails_closed(self) -> None:
        conflicts = MergeConflicts(
            dmarc_policy=(
                CandidateValue("reject", "dns-a", "high"),
                CandidateValue("none", "dns-b", "high"),
            )
        )

        dossier = dmarc_apex_reject_dossier(
            _info(
                policy="reject",
                evidence=(_dmarc_evidence("reject"),),
                merge_conflicts=conflicts,
            ),
            as_of=NOW + timedelta(hours=1),
        )

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.units[0].construction_state is ConstructionState.INCOMPLETE
        assert not dossier.provenance_complete

    def test_duplicate_and_reordered_raw_views_do_not_change_the_unit(self) -> None:
        evidence = _dmarc_evidence("reject")
        first = dmarc_apex_reject_dossier(
            _info(policy="reject", evidence=(evidence, evidence)),
            as_of=NOW,
        )
        second = dmarc_apex_reject_dossier(
            _info(policy="reject", evidence=(evidence,)),
            as_of=NOW,
        )

        assert first == second

    def test_unit_identity_is_unambiguous_when_raw_fields_contain_separators(self) -> None:
        first_evidence = EvidenceRecord("DMARC", "x\x1fy", "z", "dmarc-invalid")
        second_evidence = EvidenceRecord("DMARC", "x", "y\x1fz", "dmarc-invalid")

        first = dmarc_apex_reject_dossier(
            _info(evidence=(first_evidence,)),
            as_of=NOW,
        )
        second = dmarc_apex_reject_dossier(
            _info(evidence=(second_evidence,)),
            as_of=NOW,
        )

        assert first.units[0].unit_id != second.units[0].unit_id

    def test_renderer_obligations_are_internal_and_package_facade_is_unchanged(self) -> None:
        assert DMARC_APEX_REJECT_CONTRACT.renderer_obligations == ("batch cohort-summary DMARC rates",)
        assert not hasattr(recon_tool, "DMARC_APEX_REJECT_CONTRACT")
        assert DMARC_REJECT_CLAIM_STATE_FIELD.startswith("_recon_internal_")


class TestClaimAlgebra:
    def test_dmarc_contract_retains_explicit_policy_conflict(self) -> None:
        positive_premise = next(
            iter(
                next(
                    rule
                    for rule in DMARC_APEX_REJECT_CONTRACT.rules
                    if rule.conclusion == DMARC_APEX_REJECT_CONTRACT.positive_atom
                ).premises
            )
        )
        negative_premise = next(
            iter(
                next(
                    rule
                    for rule in DMARC_APEX_REJECT_CONTRACT.rules
                    if rule.conclusion == DMARC_APEX_REJECT_CONTRACT.negative_atom
                ).premises
            )
        )
        ledger = ObservationLedger(
            (
                _unit("reject-observation", positive_premise),
                _unit("non-reject-observation", negative_premise),
            )
        )

        dossier = evaluate_claim(
            DMARC_APEX_REJECT_CONTRACT,
            ledger,
            subject="contoso.com",
            namespace="dns",
            scope="_dmarc.contoso.com TXT",
            as_of=NOW,
        )

        assert dossier.state is ClaimState.CONFLICTED
        assert dossier.positive_certificates == (frozenset({"reject-observation"}),)
        assert dossier.negative_certificates == (frozenset({"non-reject-observation"}),)

    def test_conflict_retains_both_certificate_families(self) -> None:
        contract = _contract(
            MonotoneRule("positive", frozenset({"p"}), "claim:test:positive"),
            MonotoneRule("negative", frozenset({"n"}), "claim:test:negative"),
        )
        ledger = ObservationLedger((_unit("positive", "p"), _unit("negative", "n")))

        dossier = evaluate_claim(contract, ledger, subject="contoso.com", namespace="test", scope="test", as_of=NOW)

        assert dossier.state is ClaimState.CONFLICTED
        assert dossier.positive_certificates == (frozenset({"positive"}),)
        assert dossier.negative_certificates == (frozenset({"negative"}),)

    def test_cross_view_conjunction_appears_only_after_ledger_replay(self) -> None:
        contract = _contract(MonotoneRule("joint", frozenset({"a", "b"}), "claim:test:positive"))
        left = ObservationLedger((_unit("left", "a"),))
        right = ObservationLedger((_unit("right", "b"),))

        left_result = evaluate_claim(contract, left, subject="x", namespace="test", scope="test", as_of=NOW)
        right_result = evaluate_claim(contract, right, subject="x", namespace="test", scope="test", as_of=NOW)
        merged_result = evaluate_claim(
            contract,
            merge_ledgers(left, right),
            subject="x",
            namespace="test",
            scope="test",
            as_of=NOW,
        )

        assert left_result.state is ClaimState.UNRESOLVED
        assert right_result.state is ClaimState.UNRESOLVED
        assert merged_result.state is ClaimState.SUPPORTED
        assert merged_result.positive_certificates == (frozenset({"left", "right"}),)

    @given(
        left_ids=st.sets(st.sampled_from(("a", "b", "c"))),
        middle_ids=st.sets(st.sampled_from(("a", "b", "c"))),
        right_ids=st.sets(st.sampled_from(("a", "b", "c"))),
    )
    def test_ledger_union_is_associative_commutative_and_idempotent(
        self,
        left_ids: set[str],
        middle_ids: set[str],
        right_ids: set[str],
    ) -> None:
        def ledger(ids: set[str]) -> ObservationLedger:
            return ObservationLedger(tuple(_unit(unit_id, unit_id) for unit_id in ids))

        left = ledger(left_ids)
        middle = ledger(middle_ids)
        right = ledger(right_ids)

        assert merge_ledgers(left, left) == left
        assert merge_ledgers(left, middle) == merge_ledgers(middle, left)
        assert merge_ledgers(merge_ledgers(left, middle), right) == merge_ledgers(
            left,
            merge_ledgers(middle, right),
        )

    def test_adding_evidence_cannot_erase_an_established_sign(self) -> None:
        contract = _contract(
            MonotoneRule("positive", frozenset({"p"}), "claim:test:positive"),
            MonotoneRule("negative", frozenset({"n"}), "claim:test:negative"),
        )
        positive = ObservationLedger((_unit("positive", "p"),))
        conflicted = merge_ledgers(positive, ObservationLedger((_unit("negative", "n"),)))

        before = evaluate_claim(contract, positive, subject="x", namespace="test", scope="test", as_of=NOW)
        after = evaluate_claim(contract, conflicted, subject="x", namespace="test", scope="test", as_of=NOW)

        assert before.state is ClaimState.SUPPORTED
        assert after.state is ClaimState.CONFLICTED
        assert set(before.positive_certificates).issubset(after.positive_certificates)

    def test_stale_opposite_sign_does_not_create_current_conflict(self) -> None:
        contract = _contract(
            MonotoneRule("positive", frozenset({"p"}), "claim:test:positive"),
            MonotoneRule("negative", frozenset({"n"}), "claim:test:negative"),
        )
        ledger = ObservationLedger(
            (
                _unit("stale-positive", "p", observed_at=NOW - timedelta(days=2)),
                _unit("current-negative", "n"),
            )
        )

        dossier = evaluate_claim(
            contract,
            ledger,
            subject="x",
            namespace="test",
            scope="test",
            as_of=NOW,
        )

        assert dossier.state is ClaimState.DISCONFIRMED
        assert dossier.positive_certificates == ()
        assert dossier.negative_certificates == (frozenset({"current-negative"}),)
        assert dossier.time_state is TimeState.MIXED

    def test_antichains_agree_with_independent_exhaustive_enumeration(self) -> None:
        rules = (
            MonotoneRule("derive-x", frozenset({"a", "b"}), "x"),
            MonotoneRule("support", frozenset({"x"}), "claim:test:positive"),
        )
        contract = _contract(*rules)
        units = (
            _unit("a-only", "a"),
            _unit("b-only", "b"),
            _unit("joint", "a", "b"),
        )

        dossier = evaluate_claim(
            contract,
            ObservationLedger(units),
            subject="x",
            namespace="test",
            scope="test",
            as_of=NOW,
        )

        deriving: list[frozenset[str]] = []
        for size in range(len(units) + 1):
            for selected in combinations(units, size):
                atoms = set().union(*(unit.atoms for unit in selected)) if selected else set()
                changed = True
                while changed:
                    changed = False
                    for rule in rules:
                        if rule.premises <= atoms and rule.conclusion not in atoms:
                            atoms.add(rule.conclusion)
                            changed = True
                if contract.positive_atom in atoms:
                    deriving.append(frozenset(unit.unit_id for unit in selected))
        expected = tuple(
            sorted(
                (candidate for candidate in deriving if not any(other < candidate for other in deriving)),
                key=lambda certificate: (len(certificate), tuple(sorted(certificate))),
            )
        )

        assert dossier.positive_certificates == expected

    def test_certificate_bound_fails_closed_instead_of_truncating(self) -> None:
        contract = _contract(
            MonotoneRule("support", frozenset({"a"}), "claim:test:positive"),
            max_certificates=1,
        )
        ledger = ObservationLedger((_unit("first", "a"), _unit("second", "a")))

        with pytest.raises(ClaimEvaluationLimitError, match="certificate limit"):
            evaluate_claim(contract, ledger, subject="x", namespace="test", scope="test", as_of=NOW)

    def test_final_certificate_bound_is_independent_of_rule_names_and_order(self) -> None:
        contract = _contract(
            MonotoneRule("0-long", frozenset({"a", "b"}), "claim:test:positive"),
            MonotoneRule("z-short", frozenset({"c"}), "claim:test:positive"),
            max_certificates=1,
        )
        ledger = ObservationLedger((_unit("u1", "a", "c"), _unit("u2", "b")))

        dossier = evaluate_claim(
            contract,
            ledger,
            subject="x",
            namespace="test",
            scope="test",
            as_of=NOW,
        )

        assert dossier.positive_certificates == (frozenset({"u1"}),)

        renamed = _contract(
            MonotoneRule("z-long", frozenset({"a", "b"}), "claim:test:positive"),
            MonotoneRule("0-short", frozenset({"c"}), "claim:test:positive"),
            max_certificates=1,
        )
        assert (
            evaluate_claim(
                renamed,
                ledger,
                subject="x",
                namespace="test",
                scope="test",
                as_of=NOW,
            ).positive_certificates
            == dossier.positive_certificates
        )

    def test_atom_bound_counts_signs_and_rule_premises(self) -> None:
        contract = _contract(max_atoms=2)

        with pytest.raises(ClaimEvaluationLimitError, match="atom limit"):
            evaluate_claim(
                contract,
                ObservationLedger((_unit("unit", "premise"),)),
                subject="x",
                namespace="test",
                scope="test",
                as_of=NOW,
            )

    def test_unit_bound_accepts_exact_limit_and_refuses_limit_plus_one(self) -> None:
        contract = _contract(max_units=2)
        exact = ObservationLedger((_unit("first"), _unit("second")))
        overflow = ObservationLedger((*exact.units, _unit("third")))

        assert (
            evaluate_claim(
                contract,
                exact,
                subject="x",
                namespace="test",
                scope="test",
                as_of=NOW,
            ).state
            is ClaimState.UNRESOLVED
        )
        with pytest.raises(ClaimEvaluationLimitError, match="unit limit"):
            evaluate_claim(
                contract,
                overflow,
                subject="x",
                namespace="test",
                scope="test",
                as_of=NOW,
            )

    def test_provenance_incomplete_unit_cannot_seed_a_certificate(self) -> None:
        contract = _contract(MonotoneRule("support", frozenset({"a"}), "claim:test:positive"))

        dossier = evaluate_claim(
            contract,
            ObservationLedger((_unit("unbound", "a", provenance_complete=False),)),
            subject="x",
            namespace="test",
            scope="test",
            as_of=NOW,
        )

        assert dossier.state is ClaimState.UNRESOLVED
        assert dossier.positive_certificates == ()
        assert not dossier.provenance_complete

    def test_cyclic_contract_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="acyclic"):
            _contract(
                MonotoneRule("a-from-b", frozenset({"b"}), "a"),
                MonotoneRule("b-from-a", frozenset({"a"}), "b"),
            )

    @pytest.mark.parametrize(
        "freshness",
        [timedelta(milliseconds=500), timedelta(days=1_000_000, microseconds=1)],
    )
    def test_rule_bound_and_whole_second_freshness_are_contract_invariants(
        self,
        freshness: timedelta,
    ) -> None:
        rules = (
            MonotoneRule("first", frozenset({"a"}), "x"),
            MonotoneRule("second", frozenset({"b"}), "y"),
        )
        with pytest.raises(ValueError, match="rule limit"):
            _contract(*rules, max_rules=1)
        with pytest.raises(ValueError, match="whole-second"):
            _contract(freshness=freshness)

    def test_conjunction_work_bound_fails_before_unbounded_product(self) -> None:
        contract = _contract(
            MonotoneRule("joint", frozenset({"a", "b"}), "claim:test:positive"),
            max_conjunction_combinations=3,
        )
        ledger = ObservationLedger(
            (
                _unit("a1", "a"),
                _unit("a2", "a"),
                _unit("b1", "b"),
                _unit("b2", "b"),
            )
        )

        with pytest.raises(ClaimEvaluationLimitError, match="combination limit"):
            evaluate_claim(
                contract,
                ledger,
                subject="x",
                namespace="test",
                scope="test",
                as_of=NOW,
            )

    def test_cumulative_conjunction_work_bound_spans_all_rules(self) -> None:
        contract = _contract(
            MonotoneRule("first", frozenset({"a"}), "x"),
            MonotoneRule("second", frozenset({"a"}), "y"),
            max_conjunction_combinations=2,
            max_total_conjunction_combinations=3,
        )
        ledger = ObservationLedger((_unit("a1", "a"), _unit("a2", "a")))

        with pytest.raises(ClaimEvaluationLimitError, match="cumulative conjunction"):
            evaluate_claim(
                contract,
                ledger,
                subject="x",
                namespace="test",
                scope="test",
                as_of=NOW,
            )

    def test_duplicate_unit_ids_must_be_semantically_identical(self) -> None:
        with pytest.raises(ValueError, match="unit_id"):
            ObservationLedger((_unit("same", "a"), _unit("same", "b")))
