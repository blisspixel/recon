"""Fail-closed coverage for the material default-claim taxonomy."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.check_default_claim_audit import (
    _expand_mcp_coverage,
    _reference_path,
    audit_claim_inventory,
    discover_surfaces,
    load_claim_inventory,
    main,
)

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "docs" / "default-claim-audit.json"


def test_default_claim_audit_covers_every_discovered_surface() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)

    assert audit_claim_inventory(inventory, ROOT) == []


def test_default_claim_audit_is_canonical_json() -> None:
    raw = AUDIT_PATH.read_text(encoding="utf-8")
    parsed = json.loads(raw)

    assert raw == json.dumps(parsed, indent=2, sort_keys=True) + "\n"


def test_documented_checkpoint_counts_match_the_live_inventory() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    families = tuple(inventory["claim_families"].values())
    complete = sum(family["audit_status"] == "complete" for family in families)
    incomplete_runtime = sum(family["material"] and family["lineage_status"] == "incomplete" for family in families)
    score_fields = len(discover_surfaces()["score_fields"])
    root_roadmap = " ".join((ROOT / "ROADMAP.md").read_text(encoding="utf-8").split())
    audit_doc = " ".join((ROOT / "docs" / "default-claim-audit.md").read_text(encoding="utf-8").split())
    canonical_roadmap = " ".join((ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8").split())
    runtime_family_label = f"{incomplete_runtime} material runtime " + (
        "family" if incomplete_runtime == 1 else "families"
    )

    assert f"{complete} families are complete. {runtime_family_label}" in root_roadmap
    assert f"{score_fields} score or quantitative fields" in root_roadmap
    assert f"{complete} families are complete. {runtime_family_label}" in audit_doc
    assert f"{score_fields} quantitative or categorical score fields" in audit_doc
    assert f"{complete} are complete; {runtime_family_label}" in canonical_roadmap


def test_panel_assembly_family_records_exact_runtime_lineage() -> None:
    family = load_claim_inventory(AUDIT_PATH)["claim_families"]["runtime.panel-assembly.v1"]

    assert family["audit_status"] == "complete"
    assert family["lineage_status"] == "exact"
    assert "src/recon_tool/collection_view.py#collection_observable_evidence" in family["evidence_path"]
    assert "src/recon_tool/server/lookup.py#lookup_tenant" in family["producer_paths"]


def test_service_label_family_records_exact_runtime_lineage() -> None:
    family = load_claim_inventory(AUDIT_PATH)["claim_families"]["runtime.service-label.v1"]

    assert family["audit_status"] == "complete"
    assert family["lineage_status"] == "exact"
    assert "src/recon_tool/collection_view.py#collection_observable_info" in family["evidence_path"]
    assert "src/recon_tool/formatter/classify.py#evidence_role_service_label" in family["producer_paths"]
    assert "src/recon_tool/formatter/classify.py#role_aware_service_label" in family["producer_paths"]


def test_posture_family_records_exact_generation_time_lineage() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    family = inventory["claim_families"]["runtime.posture-observation.v1"]

    assert family["audit_status"] == "complete"
    assert family["lineage_status"] == "exact"
    assert "src/recon_tool/posture_models.py#PostureMetadataDependency" in family["evidence_path"]
    assert "src/recon_tool/profiles.py#compute_baseline_anomalies" in family["producer_paths"]
    assert inventory["coverage"]["mcp_tools"]["compare_postures"] == "runtime.exposure-index.v1"
    assert (
        inventory["coverage"]["panel_producers"]["src/recon_tool/formatter/comparison.py#format_comparison_dict"]
        == "runtime.exposure-index.v1"
    )


def test_hardening_family_records_exact_generation_time_lineage() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    family = inventory["claim_families"]["runtime.hardening-guidance.v1"]

    assert family["audit_status"] == "complete"
    assert family["lineage_status"] == "exact"
    assert "src/recon_tool/exposure_models.py#HardeningMetadataDependency" in family["evidence_path"]
    assert "src/recon_tool/exposure_gaps.py#_gap" in family["producer_paths"]
    assert inventory["coverage"]["recommendation_producers"] == {
        "src/recon_tool/exposure_gaps.py#_gap": "runtime.hardening-guidance.v1",
        "src/recon_tool/exposure_gaps.py#detect_inconsistencies": "runtime.hardening-guidance.v1",
        "src/recon_tool/exposure_gaps.py#detect_missing_controls": "runtime.hardening-guidance.v1",
        "src/recon_tool/exposure_gaps.py#detect_weak_configs": "runtime.hardening-guidance.v1",
    }


def test_review_bundle_family_owns_fresh_composition_and_human_projection() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    family = inventory["claim_families"]["runtime.review-bundle.v1"]

    assert family["audit_status"] == "complete"
    assert family["lineage_status"] == "exact"
    assert "src/recon_tool/review_bundle.py#build_review_bundle" in family["producer_paths"]
    assert "src/recon_tool/server/review.py#build_review_bundle" in family["producer_paths"]
    assert (
        inventory["coverage"]["panel_producers"]["src/recon_tool/formatter/review.py#format_review_bundle_markdown"]
        == "runtime.review-bundle.v1"
    )
    assert inventory["coverage"]["mcp_tools"]["build_review_bundle"] == "runtime.review-bundle.v1"


def test_digest_report_is_deterministic_and_matches_the_contract(capsys: pytest.CaptureFixture[str]) -> None:
    inventory = load_claim_inventory(AUDIT_PATH)

    assert main(["--print-digests"]) == 0
    output = capsys.readouterr().out

    assert json.loads(output) == inventory["coverage_contract"]["surface_digests"]
    assert output == json.dumps(json.loads(output), indent=2, sort_keys=True) + "\n"


def test_guidance_discovery_ignores_heading_shaped_code_examples() -> None:
    sections = discover_surfaces()["agent_guidance_sections"]

    assert "agents/README.md#supported: claude-desktop, claude-code, cursor, vscode, windsurf, kiro" not in sections
    assert "agents/windsurf/README.md#Paste the body of AGENTS.md directly." not in sections


def test_maintainer_skill_sections_have_explicit_static_guidance_ownership() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    family = inventory["claim_families"]["static.agent-guidance.v1"]
    prefix = "agents/maintainer/skills/"
    expected = {
        f"{prefix}recon-corpus-plan/SKILL.md#Corpus planning",
        f"{prefix}recon-corpus-plan/SKILL.md#Define the question before selecting rows",
        f"{prefix}recon-corpus-plan/SKILL.md#Freeze and hand off",
        f"{prefix}recon-catalog-round/SKILL.md#Catalog round",
        f"{prefix}recon-catalog-round/SKILL.md#Admit the round",
        f"{prefix}recon-catalog-round/SKILL.md#Evaluate observations, then candidates",
        f"{prefix}recon-catalog-round/SKILL.md#Completion",
    }
    discovered = discover_surfaces()["agent_guidance_sections"]

    assert {section for section in discovered if section.startswith(prefix)} == expected
    assert all(inventory["coverage"]["agent_guidance_sections"][section] == family["claim_id"] for section in expected)
    assert {section.split("#", 1)[0] for section in expected} <= set(family["producer_paths"])
    assert {"docs/catalog-maintenance.md", "docs/data-handling-policy.md"} <= set(family["evidence_path"])
    assert family["lineage_status"] == "static"
    audit_doc = " ".join((ROOT / "docs/default-claim-audit.md").read_text(encoding="utf-8").split())
    assert f"{len(discovered)} agent-guidance sections" in audit_doc


def test_maintainer_skill_section_cannot_lose_its_owner() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    section = "agents/maintainer/skills/recon-catalog-round/SKILL.md#Admit the round"
    del inventory["coverage"]["agent_guidance_sections"][section]

    problems = audit_claim_inventory(inventory, ROOT)

    assert any("agent_guidance_sections" in problem and section in problem for problem in problems)


def test_panel_discovery_covers_every_formatter_renderer_with_qualified_ids() -> None:
    producers = discover_surfaces()["panel_producers"]

    assert "src/recon_tool/formatter/panel.py#render_tenant_panel" in producers
    assert "src/recon_tool/formatter/delta.py#render_delta_panel" in producers
    assert "src/recon_tool/formatter/exposure.py#render_exposure_panel" in producers
    assert "src/recon_tool/formatter/exposure.py#render_gaps_panel" in producers
    assert all("#" in producer for producer in producers)


def test_score_discovery_preserves_each_schema_and_typed_dict_occurrence() -> None:
    score_fields = discover_surfaces()["score_fields"]

    assert "docs/recon-schema.json#/properties/confidence" in score_fields
    assert "docs/recon-schema.json#/$defs/ChainMotif/properties/confidence" in score_fields
    assert "src/recon_tool/server/posture.py#ExposureAssessmentResult.posture_score" in score_fields
    assert "src/recon_tool/server/posture.py#ExposureIndexComponentSummary.awarded_points" in score_fields
    assert "src/recon_tool/server/posture.py#ExposureIndexComponentSummary.maximum_points" in score_fields
    assert "src/recon_tool/server/posture.py#ExposureIndexComponentSummary.unconfirmable_points" in score_fields
    assert "src/recon_tool/server/posture.py#ObservabilitySummary.model_maximum_points" in score_fields
    assert "src/recon_tool/server/posture.py#ObservabilitySummary.unconfirmable_absent_points" in score_fields
    assert "src/recon_tool/server/posture.py#HypothesisAssessmentResult.confidence" in score_fields
    assert "src/recon_tool/cli/fingerprints.py#_fingerprint_summary.confidence" in score_fields
    assert "src/recon_tool/cli/signals.py#_signal_show_payload.confidence" in score_fields
    assert "docs/recon-schema.json#/$defs/PosteriorObservation/properties/interval_low" in score_fields
    assert "docs/recon-schema.json#/$defs/PosteriorObservation/properties/interval_high" in score_fields
    assert len({field for field in score_fields if field.endswith("/confidence")}) > 1


def test_server_instruction_discovery_owns_the_material_preamble() -> None:
    sections = discover_surfaces()["server_instruction_sections"]

    assert "<preamble>" in sections


def test_json_discovery_preserves_every_nested_property_occurrence() -> None:
    fields = discover_surfaces()["json_fields"]

    assert "docs/recon-schema.json#/properties/tenant_id" in fields
    assert "docs/recon-schema.json#/$defs/DeltaReport/properties/changed_confidence" in fields
    assert "docs/recon-schema.json#/$defs/PosteriorObservation/properties/interval_low" in fields
    assert all(field.startswith("docs/recon-schema.json#/") for field in fields)


def test_mcp_discovery_owns_each_tool_and_top_level_output_property() -> None:
    surfaces = discover_surfaces()["mcp_tools"]

    assert "assess_exposure" in surfaces
    assert "assess_exposure#posture_score" in surfaces
    assert "test_hypothesis#likelihood" in surfaces
    assert "reevaluate_domain#tenant_id" in surfaces


def test_mcp_prompt_discovery_owns_each_prompt_and_argument() -> None:
    surfaces = discover_surfaces()["mcp_prompts"]

    assert surfaces == {"domain_report", "domain_report#domain"}
    inventory = load_claim_inventory(AUDIT_PATH)
    assert inventory["coverage"]["mcp_prompts"] == {
        "domain_report": "static.mcp-contract.v1",
        "domain_report#domain": "static.mcp-contract.v1",
    }


def test_default_claim_families_have_direct_paths_and_regression_tests() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)

    families = inventory["claim_families"]
    assert isinstance(families, dict)
    assert families
    for claim_id, family in families.items():
        assert claim_id == family["claim_id"]
        assert family["classification"] in {
            "direct_observation",
            "documented_derivation",
            "bounded_absence",
            "unresolved_when_unobservable",
            "static_product_contract",
            "non_claim_transport",
        }
        assert family["subject_scope"]
        assert family["producer_paths"]
        assert family["evidence_path"]
        assert family["renderer_obligations"]
        assert family["regression_tests"]
        assert family["lineage_status"] in {"exact", "static", "incomplete"}


def test_material_families_cannot_be_marked_complete_with_incomplete_lineage() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)

    for family in inventory["claim_families"].values():
        if family["material"]:
            assert not (family["audit_status"] == "complete" and family["lineage_status"] == "incomplete")


def test_static_mcp_contract_references_every_description_module_and_behavior_basis() -> None:
    """A complete static MCP audit must own every live tool-description module."""
    inventory = load_claim_inventory(AUDIT_PATH)
    family = inventory["claim_families"]["static.mcp-contract.v1"]

    assert family["audit_status"] == "complete"
    assert {
        "src/recon_tool/server/app.py#SERVER_INSTRUCTIONS",
        "src/recon_tool/server/ephemeral.py",
        "src/recon_tool/server/graph.py",
        "src/recon_tool/server/introspection.py",
        "src/recon_tool/server/lookup.py#lookup_tenant",
        "src/recon_tool/server/review.py#build_review_bundle",
        "src/recon_tool/server/posture.py",
        "src/recon_tool/server/__init__.py#domain_report",
        "docs/mcp.md",
        "docs/surface-inventory.json",
    } <= set(family["producer_paths"])
    assert {
        "src/recon_tool/server/app.py#resolve_or_cache",
        "src/recon_tool/chain.py#chain_resolve",
        "src/recon_tool/mcp_client/sdk_compat.py#tool_annotations",
        "scripts/generate_surface_inventory.py#build_inventory",
        "scripts/generate_surface_inventory.py#_mcp_inventory_async",
    } <= set(family["evidence_path"])
    assert {
        "tests/test_mcp_graph_tools.py",
        "tests/test_mcp_structured_output.py",
        "tests/test_mcp_tool_annotations.py",
        "tests/test_server.py",
        "tests/test_server_instructions.py",
        "tests/test_surface_inventory.py",
    } <= set(family["regression_tests"])


def test_related_namespace_contract_owns_every_runtime_breadcrumb_family() -> None:
    """The related-name family must name every producer behind the stable field."""
    inventory = load_claim_inventory(AUDIT_PATH)
    family = inventory["claim_families"]["runtime.related-namespace.v1"]

    assert family["audit_status"] == "complete"
    assert {
        "src/recon_tool/chain.py#chain_resolve",
        "src/recon_tool/merger.py#merge_results",
        "src/recon_tool/sources/dns.py#_detect_common_subdomains",
        "src/recon_tool/sources/dns.py#_detect_exchange_endpoints",
        "src/recon_tool/sources/dns.py#_detect_idp_hub",
        "src/recon_tool/sources/dns_email.py#_apply_exchange_dkim",
        "src/recon_tool/sources/dns_infra.py#_add_autodiscover_matches",
        "src/recon_tool/sources/dns_infra.py#_apply_cached_cert_intel",
        "src/recon_tool/sources/dns_infra.py#_query_cert_providers",
    } <= set(family["producer_paths"])
    assert {
        "tests/test_chain.py",
        "tests/test_cname_chain_validation.py",
        "tests/test_ct_pipeline_resilience.py",
        "tests/test_dns_subdetectors.py",
        "tests/test_documentation_semantic_contracts.py",
        "tests/test_json_schema_file.py",
    } <= set(family["regression_tests"])
    assert "Exchange/identity endpoint" in family["subject_scope"]
    assert "DKIM tenant-domain" in family["subject_scope"]


def test_claim_family_schema_rejects_malformed_scalar_and_array_values() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    claim_id = "runtime.catalog-indicator.v1"
    cases = (
        ("material", "yes", ".material must be boolean"),
        ("subject_scope", 1, ".subject_scope must be a non-empty string"),
        ("classification", "guess", ".classification must be one of"),
        ("lineage_status", "almost", ".lineage_status must be one of"),
        ("audit_status", "complete-ish", ".audit_status must be one of"),
        ("limits", [None], ".limits entries must be non-empty strings"),
        ("renderer_obligations", [None], ".renderer_obligations entries must be non-empty strings"),
    )

    for field, value, expected in cases:
        malformed = deepcopy(inventory)
        malformed["claim_families"][claim_id][field] = value

        assert any(expected in problem for problem in audit_claim_inventory(malformed, ROOT))


def test_claim_audit_requires_nonempty_scope_purpose_and_subject_rule() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)

    for field, value in (("purpose", None), ("scope", ""), ("subject_rule", 1)):
        malformed = deepcopy(inventory)
        malformed[field] = value

        assert any(
            f"{field} must be a non-empty string" in problem for problem in audit_claim_inventory(malformed, ROOT)
        )


def test_compact_surface_ownership_is_bound_to_exact_discovery_digests() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    malformed = deepcopy(inventory)
    malformed["coverage_contract"]["surface_digests"]["json_fields"] = "0" * 64

    assert any("json_fields digest differs" in problem for problem in audit_claim_inventory(malformed, ROOT))


def test_full_mcp_lookup_replay_inherits_json_root_claim_owners() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    problems: list[str] = []
    expanded = _expand_mcp_coverage(
        {"reevaluate_domain": "runtime.catalog-operation.v1"},
        {"tenant_id": "runtime.identity-and-tenant.v1"},
        frozenset({"reevaluate_domain"}),
        frozenset({"reevaluate_domain", "reevaluate_domain#tenant_id"}),
        problems,
    )

    assert inventory["coverage_contract"]["mcp_json_root_tools"] == ["reevaluate_domain"]
    assert expanded == {
        "reevaluate_domain": "runtime.catalog-operation.v1",
        "reevaluate_domain#tenant_id": "runtime.identity-and-tenant.v1",
    }
    assert problems == []


def test_family_references_reject_internal_absolute_and_traversal_paths() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    claim_id = "runtime.catalog-indicator.v1"
    references = (".git/HEAD", "../outside.py", str(ROOT / "README.md"), "src\\recon_tool\\models.py")

    for reference in references:
        malformed = deepcopy(inventory)
        malformed["claim_families"][claim_id]["producer_paths"] = [reference]

        assert any("reference path is not allowed" in problem for problem in audit_claim_inventory(malformed, ROOT))


def test_family_references_enforce_the_declared_artifact_role() -> None:
    inventory = load_claim_inventory(AUDIT_PATH)
    claim_id = "runtime.catalog-indicator.v1"
    cases = (
        ("regression_tests", "README.md"),
        ("producer_paths", "tests/test_fingerprints.py"),
        ("evidence_path", "tests/test_fingerprints.py"),
    )

    for reference_kind, reference in cases:
        malformed = deepcopy(inventory)
        malformed["claim_families"][claim_id][reference_kind] = [reference]

        assert any(
            f"{reference_kind} reference path is not allowed" in problem
            for problem in audit_claim_inventory(malformed, ROOT)
        )


def test_family_references_reject_cross_role_and_internal_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "src" / "recon_tool" / "models.py"
    source.parent.mkdir(parents=True)
    source.write_text("class TenantInfo: pass\n", encoding="utf-8")
    internal = tmp_path / ".git" / "HEAD"
    internal.parent.mkdir()
    internal.write_text("ref: refs/heads/main\n", encoding="utf-8")
    test_link = tmp_path / "tests" / "test_claim.py"
    test_link.parent.mkdir()
    evidence_link = source.parent / "evidence.py"
    try:
        test_link.symlink_to(source)
        evidence_link.symlink_to(internal)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    assert _reference_path("tests/test_claim.py", "regression_tests", tmp_path) is None
    assert _reference_path("src/recon_tool/evidence.py", "evidence_path", tmp_path) is None
