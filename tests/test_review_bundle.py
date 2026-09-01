"""ReviewBundle v1 construction, integrity, and local I/O tests."""

from __future__ import annotations

import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from recon_tool.capsule import content_digest
from recon_tool.models import ConfidenceLevel, EvidenceRecord, SourceResult, TenantInfo
from recon_tool.review_bundle import (
    REVIEW_BUNDLE_SCHEMA_VERSION,
    REVIEW_LIMITATIONS,
    REVIEW_SCOPE_STATEMENT,
    ReviewCollectionContext,
    build_review_bundle,
    build_review_error_bundle,
    load_review_bundle,
    validate_review_bundle,
    write_review_bundle,
)

_START = datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC)
_END = _START + timedelta(seconds=4)
_GENERATED = _END + timedelta(seconds=1)


def _evidence() -> EvidenceRecord:
    return EvidenceRecord("DMARC", "v=DMARC1; p=none", "DMARC", "dmarc")


def _info(*, degraded_sources: tuple[str, ...] = ()) -> TenantInfo:
    evidence = _evidence()
    return TenantInfo(
        tenant_id=None,
        display_name="Example Industries Ltd",
        default_domain="example.com",
        queried_domain="example.com",
        confidence=ConfidenceLevel.MEDIUM,
        sources=("dns_records", "openid_configuration"),
        services=("DMARC",),
        slugs=("dmarc",),
        dmarc_policy="none",
        evidence=(evidence,),
        degraded_sources=degraded_sources,
        resolved_at=_END.isoformat(),
        ct_attempt_outcome="skipped",
    )


def _dns_result(*, degraded: bool = False) -> SourceResult:
    evidence = _evidence()
    return SourceResult(
        source_name="dns_records",
        dmarc_policy="none",
        evidence=(evidence,),
        raw_dns_records=(("DMARC", evidence.raw_value),),
        degraded_sources=("dns:dmarc",) if degraded else (),
        ct_attempt_outcome="skipped",
    )


def _oidc_result() -> SourceResult:
    return SourceResult(source_name="openid_configuration")


def _sparse_info() -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="sparse.invalid",
        default_domain="sparse.invalid",
        queried_domain="sparse.invalid",
        confidence=ConfidenceLevel.LOW,
        sources=("dns_records",),
        resolved_at=_END.isoformat(),
        ct_attempt_outcome="skipped",
    )


def _context() -> ReviewCollectionContext:
    return ReviewCollectionContext(
        started_at=_START,
        ended_at=_END,
        ct_enabled=False,
        timeout_seconds=30.0,
        vantage="caller-local",
    )


def _bundle(
    *,
    info: TenantInfo | None = None,
    results: tuple[SourceResult, ...] | None = None,
) -> dict:
    return build_review_bundle(
        info or _info(),
        results or (_dns_result(), _oidc_result()),
        "Example.COM",
        _context(),
        generated_at=_GENERATED,
    )


def _redigest(bundle: dict) -> None:
    bundle["content_digest"] = content_digest({key: value for key, value in bundle.items() if key != "content_digest"})


def test_success_bundle_is_deterministic_and_source_order_independent() -> None:
    first = _bundle()
    second = _bundle(results=(_oidc_result(), _dns_result()))

    assert first == second
    assert first["record_type"] == "review_bundle"
    assert first["schema_version"] == REVIEW_BUNDLE_SCHEMA_VERSION
    assert first["generated_at"] == _GENERATED.isoformat()
    assert first["scope"] == {
        "kind": "single_namespace",
        "selection_basis": "caller_supplied",
        "input_coordinate": "Example.COM",
        "queried_domain": "example.com",
    }
    assert first["collection"]["cache"]["result_cache"] == "bypassed"
    assert first["collection"]["options"]["direct_probes"] is False
    assert first["workflow"] == {
        "status": "completed",
        "collection_validity": "complete_for_recorded_opportunities",
        "freshness_assessment": "not_assigned",
    }
    assert [row["source_role"] for row in first["source_opportunities"]] == [
        "dns_records",
        "openid_configuration",
    ]
    assert first["scope_statement"] == REVIEW_SCOPE_STATEMENT
    assert first["limitations"] == list(REVIEW_LIMITATIONS)


def test_success_contains_explained_stable_lookup_and_evidence_linked_candidates() -> None:
    bundle = _bundle()
    result = bundle["result"]
    baseline = result["explained_baseline"]

    assert result["record_type"] == "review_success"
    assert baseline["record_type"] == "explained_lookup_baseline"
    assert baseline["lookup"]["record_type"] == "lookup"
    assert baseline["lookup"]["schema_version"] == "2.0"
    assert baseline["lookup"]["queried_domain"] == "example.com"
    assert baseline["explanations"]
    assert baseline["explanation_dag"]["schema_version"] == 1

    ledger_ids = {item["evidence_id"] for item in result["evidence_ledger"]}
    candidates = result["review_candidates"]["candidates"]
    assert len({item["candidate_id"] for item in candidates}) == len(candidates)
    assert any(item["evidence_ids"] for item in candidates)
    assert all(set(item["evidence_ids"]) <= ledger_ids for item in candidates)
    assert all(set(item["evidence_ids"]) <= ledger_ids for item in baseline["explanations"])


def test_dense_and_sparse_baselines_share_stable_fusion_on_lookup_semantics() -> None:
    dense = _bundle()
    sparse = build_review_bundle(
        _sparse_info(),
        (SourceResult(source_name="dns_records", ct_attempt_outcome="skipped"),),
        "sparse.invalid",
        _context(),
        generated_at=_GENERATED,
    )

    for bundle in (dense, sparse):
        lookup = bundle["result"]["explained_baseline"]["lookup"]
        assert lookup["record_type"] == "lookup"
        assert lookup["schema_version"] == "2.0"
        assert lookup["fusion_enabled"] is True
        assert lookup["posterior_observations"]
    assert sparse["result"]["evidence_ledger"] == []
    assert sparse["workflow"]["collection_validity"] == "complete_for_recorded_opportunities"


def test_degraded_collection_is_partial_and_suppresses_dmarc_candidate_support() -> None:
    info = replace(_info(), degraded_sources=("dns:dmarc",))
    bundle = _bundle(info=info, results=(_dns_result(degraded=True), _oidc_result()))

    assert bundle["workflow"]["collection_validity"] == "partial"
    dns = next(row for row in bundle["source_opportunities"] if row["source_role"] == "dns_records")
    assert dns["state"] == "partial"
    assert "dns:dmarc" in bundle["result"]["review_candidates"]["degraded_sources"]
    assert all(
        "dns:dmarc" not in candidate["observation_scope"]
        for candidate in bundle["result"]["review_candidates"]["candidates"]
    )


def test_degraded_cname_keeps_ct_hosts_in_explained_baseline() -> None:
    ct_names = ("auth.example.com", "test.example.com")
    all_related = (*ct_names, "portal.example.com")
    info = replace(
        _info(),
        related_domains=all_related,
        ct_related_domains=ct_names,
        degraded_sources=("dns:cname",),
        ct_provider_used="certspotter",
        ct_subdomain_count=len(ct_names),
        ct_attempt_outcome="live_success",
    )
    dns_result = replace(
        _dns_result(),
        related_domains=all_related,
        ct_related_domains=ct_names,
        degraded_sources=("dns:cname",),
        ct_provider_used="certspotter",
        ct_subdomain_count=len(ct_names),
        ct_attempt_outcome="live_success",
    )

    bundle = build_review_bundle(
        info,
        (dns_result, _oidc_result()),
        "Example.COM",
        replace(_context(), ct_enabled=True),
        generated_at=_GENERATED,
    )
    lookup = bundle["result"]["explained_baseline"]["lookup"]

    assert bundle["workflow"]["collection_validity"] == "partial"
    assert lookup["related_domains"] == list(ct_names)
    assert lookup["surface_attributions"] == []
    assert lookup["connection_map"]["related_host_classes"]
    assert "portal.example.com" not in lookup["related_domains"]


@pytest.mark.parametrize("error_kind", ["validation", "lookup", "timeout"])
def test_error_bundle_is_typed_and_contains_no_lookup_or_candidates(error_kind: str) -> None:
    bundle = build_review_error_bundle(
        "bad coordinate",
        _context(),
        error_kind,  # type: ignore[arg-type]
        failed_source_roles=("openid_configuration", "dns_records", "dns_records"),
        generated_at=_GENERATED,
    )

    assert bundle["scope"]["queried_domain"] is None
    assert bundle["workflow"] == {
        "status": "failed",
        "collection_validity": "unavailable",
        "freshness_assessment": "not_assigned",
    }
    assert bundle["result"] == {
        "record_type": "review_error",
        "error_kind": error_kind,
        "failed_source_roles": ["dns_records", "openid_configuration"],
    }
    assert all(row["state"] == "unavailable" for row in bundle["source_opportunities"])
    assert "explained_baseline" not in bundle["result"]
    assert "review_candidates" not in bundle["result"]
    assert "evidence_ledger" not in bundle["result"]
    assert bundle["collection"]["cache"] == {
        "result_cache": "bypassed",
        "ct_provider_used": None,
        "ct_cache_age_days": None,
        "ct_attempt_outcome": None,
    }


def test_validation_error_without_attempted_sources_is_not_observed() -> None:
    bundle = build_review_error_bundle(
        "bad coordinate",
        _context(),
        "validation",
        generated_at=_GENERATED,
    )
    assert bundle["source_opportunities"] == []
    assert bundle["workflow"]["collection_validity"] == "not_observed"


def test_validator_rejects_unknown_owned_fields_and_broken_evidence_links() -> None:
    unknown = _bundle()
    unknown["unexpected"] = True
    with pytest.raises(ValueError, match="unknown or missing top-level"):
        validate_review_bundle(unknown)

    broken = copy.deepcopy(_bundle())
    broken["result"]["evidence_ledger"][0]["raw_value"] = "tampered"
    _redigest(broken)
    with pytest.raises(ValueError, match="evidence ledger ID"):
        validate_review_bundle(broken)


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("lookup", "provider"),
        ("explanation_dag", "nodes"),
    ],
)
def test_validator_enforces_embedded_lookup_and_dag_schema(section: str, field: str) -> None:
    broken = copy.deepcopy(_bundle())
    broken["result"]["explained_baseline"][section].pop(field)
    _redigest(broken)

    with pytest.raises(ValueError, match="violates the published schema"):
        validate_review_bundle(broken)


def test_builder_rejects_cached_inputs_and_contradictory_collection_attestations() -> None:
    with pytest.raises(ValueError, match="fresh TenantInfo"):
        _bundle(info=replace(_info(), cached_at=_START.isoformat()))

    direct_context = replace(_context(), direct_probes=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="direct probes were disabled"):
        build_review_bundle(
            _info(),
            (_dns_result(), _oidc_result()),
            "Example.COM",
            direct_context,
            generated_at=_GENERATED,
        )

    cached_context = replace(_context(), result_cache="hit")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="lookup-result cache was bypassed"):
        build_review_bundle(
            _info(),
            (_dns_result(), _oidc_result()),
            "Example.COM",
            cached_context,
            generated_at=_GENERATED,
        )


def test_validator_rejects_active_probe_or_cache_claim_even_with_new_digest() -> None:
    bundle = _bundle()
    bundle["collection"]["options"]["direct_probes"] = True
    bundle["collection"]["cache"]["result_cache"] = "hit"
    _redigest(bundle)
    with pytest.raises(ValueError, match="direct_probes fixed false"):
        validate_review_bundle(bundle)


def test_write_and_load_are_bounded_validated_and_no_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "example-review.json"
    bundle = _bundle()

    write_review_bundle(path, bundle)
    assert load_review_bundle(path) == bundle

    with pytest.raises(FileExistsError, match="already exists"):
        write_review_bundle(path, bundle)

    replacement = _bundle(results=(_dns_result(),))
    write_review_bundle(path, replacement, overwrite=True)
    assert load_review_bundle(path) == replacement


def test_context_rejects_naive_or_reversed_times() -> None:
    naive = ReviewCollectionContext(
        started_at=_START.replace(tzinfo=None),
        ended_at=_END,
        ct_enabled=False,
        timeout_seconds=30.0,
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        build_review_error_bundle("example.com", naive, "lookup", generated_at=_GENERATED)

    reversed_context = ReviewCollectionContext(
        started_at=_END,
        ended_at=_START,
        ct_enabled=False,
        timeout_seconds=30.0,
    )
    with pytest.raises(ValueError, match="must not precede"):
        build_review_error_bundle("example.com", reversed_context, "lookup", generated_at=_GENERATED)
