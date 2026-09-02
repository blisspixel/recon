"""Role-neutral Markdown rendering for validated ReviewBundle v1 artifacts."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta

from recon_tool.formatter.markdown import markdown_escape
from recon_tool.formatter.review import (
    format_review_bundle_markdown,
    render_review_bundle_markdown,
)
from recon_tool.models import ConfidenceLevel, EvidenceRecord, SourceResult, TenantInfo
from recon_tool.review_bundle import (
    ReviewCollectionContext,
    build_review_bundle,
    build_review_error_bundle,
    validate_review_bundle,
)

_START = datetime(2026, 8, 30, 18, 0, 0, tzinfo=UTC)
_END = _START + timedelta(seconds=2)
_GENERATED = _END + timedelta(seconds=1)


def _evidence() -> EvidenceRecord:
    return EvidenceRecord("DMARC", "v=DMARC1; p=none", "DMARC", "dmarc")


def _info(*, degraded_sources: tuple[str, ...] = ()) -> TenantInfo:
    evidence = _evidence()
    return TenantInfo(
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        display_name="Dense Example Ltd",
        default_domain="dense.invalid",
        queried_domain="dense.invalid",
        confidence=ConfidenceLevel.MEDIUM,
        sources=("dns_records", "openid_configuration"),
        services=("Microsoft 365", "DMARC"),
        slugs=("microsoft-365", "dmarc"),
        auth_type="Federated",
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


def _context() -> ReviewCollectionContext:
    return ReviewCollectionContext(
        started_at=_START,
        ended_at=_END,
        ct_enabled=False,
        timeout_seconds=30.0,
        vantage="caller-local",
    )


def _bundle(*, partial: bool = False) -> dict:
    info = _info(degraded_sources=("dns:dmarc",) if partial else ())
    bundle = build_review_bundle(
        info,
        (
            _dns_result(degraded=partial),
            SourceResult(source_name="openid_configuration"),
        ),
        "Dense.INVALID",
        _context(),
        generated_at=_GENERATED,
    )
    validate_review_bundle(bundle)
    return bundle


def test_complete_bundle_renders_exact_core_fields_in_fixed_section_order() -> None:
    bundle = _bundle()
    output = format_review_bundle_markdown(bundle)
    headings = (
        "## Collection validity",
        "## Observed mail and identity configuration",
        "## Public connection indicators",
        "## Evidence and lineage",
        "## Review candidates grouped by observation_state",
        "## Unresolved and unavailable evidence",
        "## Scope statement",
    )

    positions = [output.index(heading) for heading in headings]
    assert positions == sorted(positions)
    assert "Workflow status:** completed" in output
    assert r"Collection validity:** complete\_for\_recorded\_opportunities" in output
    assert r"Freshness assessment:** not\_assigned" in output
    assert "Lookup-result cache:** bypassed" in output
    assert "Direct probes:** False" in output
    assert "Public email controls observed:** 0 of 5" in output
    assert "not a signature or collector identity" in output
    assert render_review_bundle_markdown(bundle) == output

    result = bundle["result"]
    for evidence in result["evidence_ledger"]:
        assert markdown_escape(evidence["evidence_id"]) in output
    for candidate in result["review_candidates"]["candidates"]:
        assert markdown_escape(candidate["candidate_id"]) in output
    assert "Metadata dependencies:" in output
    assert "Absence confirmable:" in output


def test_candidates_are_grouped_by_exact_observation_state_without_ranking() -> None:
    bundle = _bundle()
    output = format_review_bundle_markdown(bundle)
    candidates = bundle["result"]["review_candidates"]["candidates"]
    states = {candidate["observation_state"] for candidate in candidates}
    expected_order = (
        "observed_weak_configuration",
        "bounded_non_observation",
        "unresolved_hideable_state",
        "observed_configuration_inconsistency",
    )
    rendered_states = [markdown_escape(state) for state in expected_order if state in states]

    positions = [output.index(f"### {state}") for state in rendered_states]
    assert positions == sorted(positions)
    assert "overall risk" not in output.lower()
    assert "remediation priority" not in output.lower()


def test_partial_bundle_names_degradation_without_assigning_freshness() -> None:
    bundle = _bundle(partial=True)
    assert bundle["workflow"]["status"] == "completed"
    assert bundle["workflow"]["collection_validity"] == "partial"

    output = format_review_bundle_markdown(bundle)

    assert "Workflow status:** completed" in output
    assert "Collection validity:** partial" in output
    assert r"Degraded sources:** dns\:dmarc" in output
    assert r"Freshness assessment:** not\_assigned" in output
    assert "stale" not in output.lower()


def test_failed_core_bundle_omits_observation_and_candidate_sections() -> None:
    bundle = build_review_error_bundle(
        "bad coordinate",
        _context(),
        "lookup",
        failed_source_roles=("identity", "dns"),
        generated_at=_GENERATED,
    )
    validate_review_bundle(bundle)

    output = format_review_bundle_markdown(bundle)

    assert "Workflow status:** failed" in output
    assert "Collection validity:** unavailable" in output
    assert "Baseline failure kind" in output
    assert "Confidence:" not in output
    assert "Degraded sources:" not in output
    assert "## Scope statement" in output
    assert "## Observed mail and identity configuration" not in output
    assert "## Public connection indicators" not in output
    assert "## Evidence and lineage" not in output
    assert "## Review candidates" not in output


def test_dynamic_text_is_escaped_and_rendering_is_deterministic() -> None:
    bundle = _bundle()
    lookup = bundle["result"]["explained_baseline"]["lookup"]
    lookup["provider"] = "[click](https://evil.invalid)\n## forged"
    candidates = bundle["result"]["review_candidates"]["candidates"]
    assert candidates
    candidates[0]["recommendation"] = "<script>alert(1)</script>"

    first = format_review_bundle_markdown(bundle)
    second = format_review_bundle_markdown(deepcopy(bundle))

    assert first == second
    assert "[click](https://evil.invalid)" not in first
    assert "## forged" not in first
    assert "<script>" not in first
    assert markdown_escape(lookup["provider"]) in first
    assert markdown_escape(candidates[0]["recommendation"]) in first
