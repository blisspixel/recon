"""Regression checks for public documentation semantics."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_exit_code_docs_cover_delta_without_a_baseline() -> None:
    for path in ("docs/operational-contract.md", "docs/schema.md"):
        text = " ".join(_read(path).split())
        assert "no cached baseline" in text
        assert "no live resolution" in text


def test_legal_docs_describe_cache_first_assessment_semantics() -> None:
    legal = " ".join(_read("docs/legal.md").split())

    for required in (
        "They are cache-first.",
        "On a cache miss they may run the ordinary base lookup",
        "model-bound public-evidence index (0-100)",
    ):
        assert required in legal

    assert "Posture Score" not in legal
    assert "operate exclusively on data already collected" not in legal


def test_publication_docs_distinguish_historical_proof_from_current_state() -> None:
    plan = " ".join(_read("docs/external-writeup-plan.md").split())
    audit = " ".join(_read("docs/strategic-gap-audit.md").split())

    assert "Publication work remains a separate maintainer track." in plan
    assert "current draft is unfrozen" in plan
    assert "current local submission-freeze proof run" not in plan
    assert "external write-up readiness as the active next work" not in plan
    assert "current package unfrozen" in audit
    assert "June proof and final audit are historical" in audit


def test_public_package_and_development_metadata_use_current_language() -> None:
    readme = _read("README.md")
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    description = project["description"]

    assert "uv run pre-commit install" in readme
    assert "`uv run python scripts/check.py` is the canonical local gate" in readme
    assert description.startswith("Public-metadata domain intelligence")
    assert "\N{EM DASH}" not in description


def test_optional_cloud_docs_preserve_the_local_default_and_operator_boundary() -> None:
    readme = " ".join(_read("README.md").split())
    short_roadmap = " ".join(_read("ROADMAP.md").split())
    roadmap = " ".join(_read("docs/roadmap.md").split())
    plan = " ".join(_read("docs/optional-cloud-deployment-plan.md").split())

    for text in (readme, short_roadmap, roadmap, plan):
        assert "optional" in text.lower()
        assert "local" in text.lower()
        assert "project does not operate" in text.lower()
        assert "draft" in text.lower()
        assert "not a validated production deployment" in text

    assert "lower priority than the three core" in roadmap
    assert "A project-operated public SaaS or multi-tenant recon service is not planned." in plan
    assert "Current provider-validation status: none." in plan
    for maturity in (
        "Research direction",
        "Draft artifact",
        "Provider-validated reference",
        "Production-proven",
    ):
        assert maturity in plan
    for platform in (
        "Google Cloud Run",
        "AWS Bedrock AgentCore Runtime",
        "Azure Container Apps",
        "Cloudflare Workers",
        "Kubernetes",
        "Anthropic and Claude",
        "OpenAI and ChatGPT",
    ):
        assert platform in plan

    for artifact in (
        "src/recon_tool/remote_server.py",
        "deploy/container/Dockerfile",
        "deploy/gcp-cloud-run/main.tf",
    ):
        assert (ROOT / artifact).is_file()

    deployment_docs = {
        "deploy/README.md": "not yet provider-validated or production-ready",
        "deploy/container/README.md": "not a production-readiness claim",
        "deploy/gcp-cloud-run/README.md": "has not yet been applied and validated",
    }
    for path, required in deployment_docs.items():
        text = " ".join(_read(path).split())
        assert "draft" in text.lower()
        assert required in text


def test_weak_area_guidance_does_not_promote_sparse_shapes_to_org_facts() -> None:
    weak_areas = " ".join(_read("docs/weak-areas.md").split())

    for forbidden in (
        "observably running their own stack",
        "ground truth: the footprint is thin because the infrastructure is on-prem",
        "There's no organization running against them",
        "where the organization actually lives",
        "bounded by what's passively observable in public DNS",
    ):
        assert forbidden not in weak_areas

    for required in (
        "does not establish who operates the mail system or where it runs",
        "does not observe enough to choose among those explanations",
        "Token reuse does not establish",
        "do not put real target apexes in a public issue",
    ):
        assert required in weak_areas


def test_ephemeral_docs_name_cache_replay_and_fresh_lookup_boundaries() -> None:
    paths = (
        "AGENTS.md",
        "agents/claude-code/skills/recon/SKILL.md",
        "docs/mcp.md",
    )

    for path in paths:
        text = " ".join(_read(path).split())
        for replayable in ("`txt`", "`spf`", "`mx`", "`ns`", "`cname`"):
            assert replayable in text
        for fresh_only in ("`cname_target`", "`subdomain_txt`", "`caa`", "`srv`", "`dmarc_rua`"):
            assert fresh_only in text
        assert "call `reload_data`" in text
        assert "lookup-result cache" in text or "process lookup cache" in text
        assert "then run `lookup_tenant` again" in text
        assert "normal documented network boundary" in text


def test_agent_guidance_preserves_process_scope_and_output_bounds() -> None:
    """Shipped guidance must not invent an MCP session or a bounded payload size."""
    guidance_paths = (
        "AGENTS.md",
        "agents/claude-code/skills/recon/SKILL.md",
    )

    for path in guidance_paths:
        text = " ".join(_read(path).split())
        assert "server process" in text
        assert "process-wide" in text
        assert "current MCP session" not in text
        assert "session's ephemeral catalog" not in text
        assert "3-10 KB" not in text
        assert f"3{chr(0x2013)}10 KB" not in text
        assert "may grow materially with certificate-transparency and evidence data" in text


def test_agent_guidance_preserves_score_and_relationship_semantics() -> None:
    """Agent-facing summaries must retain current model and namespace limits."""
    guidance_paths = (
        "AGENTS.md",
        "agents/claude-code/skills/recon/SKILL.md",
    )

    for path in guidance_paths:
        text = " ".join(_read(path).split())
        assert "CAA: 3 issuers authorized" in text
        assert "CAA: 3 issuers restricted" not in text
        assert "count of publicly observed controls" in text
        assert "exact-evidence floor" in text
        assert "bounded ceiling" in text
        assert "current component model assigns at most 90 points" in text
        assert "not a prediction of overall security change" in text
        assert "do not establish ownership or a corporate relationship" in text
        assert "every `related_domains` observation" in text
        assert "Each queued name can trigger another full public-metadata lookup" in text
        for breadcrumb in (
            "CT",
            "CNAME",
            "Exchange/identity endpoint",
            "autodiscover",
            "DKIM tenant-domain",
        ):
            assert breadcrumb in text

    skill = " ".join(_read("agents/claude-code/skills/recon/SKILL.md").split())
    assert "an Synthetic Delta Platform" not in skill


def test_related_namespace_schema_matches_the_runtime_breadcrumb_contract() -> None:
    expected = (
        "Domain names linked by bounded CT, CNAME, Exchange/identity endpoint, "
        "autodiscover, or DKIM tenant-domain breadcrumbs. The stable field name "
        "does not imply ownership or an organizational relationship."
    )
    for path in ("docs/recon-schema.json", "src/recon_tool/data/recon-schema.json"):
        schema = json.loads(_read(path))
        assert schema["properties"]["related_domains"]["description"] == expected

    schema_docs = " ".join(_read("docs/schema.md").split())
    weak_areas = " ".join(_read("docs/weak-areas.md").split())
    for text in (schema_docs, weak_areas):
        for breadcrumb in (
            "CT",
            "CNAME",
            "Exchange/identity endpoint",
            "autodiscover",
            "DKIM tenant-domain",
        ):
            assert breadcrumb in text


def test_claude_plugin_docs_describe_process_wide_mutation() -> None:
    plugin = " ".join(_read("agents/claude-code/README.md").split())

    assert "process-wide server state" in plugin
    assert "current process catalog" in plugin
    assert "local session and catalog mutations" not in plugin
    assert "current session catalog" not in plugin


def test_current_mcp_docs_match_the_adopted_production_dependency() -> None:
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    mcp_dependencies = [dependency for dependency in project["dependencies"] if dependency.startswith("mcp")]
    assert mcp_dependencies == ["mcp>=2.0.0,<3"]

    current_docs = (
        "README.md",
        "ROADMAP.md",
        "docs/engineering-refinement-plan.md",
        "docs/mcp-2026-07-28-readiness.md",
        "docs/mcp.md",
        "docs/optional-cloud-deployment-plan.md",
        "docs/roadmap.md",
        "docs/strategic-gap-audit.md",
    )
    for path in current_docs:
        text = " ".join(_read(path).split())
        assert "mcp>=1.28.1,<2" not in text
        assert "production adoption remains pending" not in text.lower()
        assert "production remains on stable v1" not in text.lower()

    readiness = " ".join(_read("docs/mcp-2026-07-28-readiness.md").split())
    assert "mcp>=2.0.0,<3" in readiness
    assert "1.28.1 remains the rollback pin" in readiness


def test_agent_portfolio_guidance_treats_score_divergence_as_observation() -> None:
    for path in ("AGENTS.md", "agents/claude-code/skills/recon/SKILL.md"):
        text = " ".join(_read(path).split())
        assert "The outlier is the actionable finding" not in text
        assert "after checking `degraded_sources`" in text
        assert "review candidate, not an overall security ranking" in text


def test_related_enrichment_docs_preserve_subdomain_scope() -> None:
    how = " ".join(_read("docs/how-it-works.md").split())
    fingerprints = " ".join(_read("docs/fingerprints.md").split())

    for text in (how, fingerprints):
        assert "`cname_target`" in text
        assert "`surface_attributions`" in text
        assert "top-level `services` and `slugs`" in text.lower()
        assert "apex `evidence`, `detection_scores`" in text

    assert "do not become apex service or slug claims" in how
    assert "Neither path establishes active use, ownership" in fingerprints


def test_fingerprint_docs_describe_current_email_score_semantics() -> None:
    fingerprints = " ".join(_read("docs/fingerprints.md").split())

    assert "compatibility score counts five publicly observable controls" in fingerprints
    assert "Effective DMARC policy remains `reject` or `quarantine`" in fingerprints
    assert "after `pct=` and testing-mode compatibility downgrades" in fingerprints
    assert "five apex-observable controls" not in fingerprints


def test_fingerprint_docs_define_confidence_as_evidence_strength() -> None:
    fingerprints = " ".join(_read("docs/fingerprints.md").split())

    assert "reviewed rule-level evidence-strength tier" in fingerprints
    assert "It is not a calibrated probability" in fingerprints
    assert "claim that the service is active" in fingerprints


def test_contributor_fingerprint_guidance_uses_current_schema_and_claims() -> None:
    contributing = " ".join(_read("CONTRIBUTING.md").split())

    assert "recon says Exchange on-prem" not in contributing
    assert "know uses the service" not in contributing
    assert "real customer domain you can point to" not in contributing
    assert "cname, cname_target, subdomain_txt" in contributing
    assert "rule-level evidence strength, not a probability" in contributing
    assert "does not turn the rule's confidence tier into a calibrated probability" in contributing
    assert "without treating the match as proof of active service use" in contributing
    assert "Real apexes stay local" in contributing


def test_claude_integration_docs_preserve_replay_and_catalog_boundaries() -> None:
    plugin = " ".join(_read("agents/claude-code/README.md").split())
    triage = " ".join(_read("agents/claude-code/skills/recon-fingerprint-triage/SKILL.md").split())
    triage_lower = triage.lower()

    for required in (
        "retained apex/root TXT, SPF, MX, NS, and CNAME observations",
        "Owner-qualified ephemeral rules require a fresh lookup",
        "normal documented network boundary",
    ):
        assert required in plugin

    for required in (
        "every new candidate begins as `pending`",
        "exact rule shape",
        "current provider-owned public reference or a disclosure-safe aggregate basis",
        "lookalike-negative fixture",
        "sparse-result fixture",
        "provenance assertions",
        "frozen regression budget",
        "do not pool unlike record types into one coverage rate",
        "never include evaluated apexes",
        "does not claim portable agent skills or agent plugins conformance",
    ):
        assert required in triage_lower

    assert "recon rule review date" in triage_lower
    assert "not an open knowledge format `verified` event" in triage_lower


def test_okf_deferral_does_not_conflate_catalog_metadata_with_okf_trust() -> None:
    adr = " ".join(_read("docs/adr/0014-caller-owned-capsules-and-okf-deferral.md").split()).lower()
    capsules = " ".join(_read("docs/observation-capsules.md").split()).lower()

    for text in (adr, capsules):
        assert "omitted" in text or "omitting" in text
        assert "`status`" in text
        assert "`stable`" in text
        assert "fingerprint `verified`" in text
        assert "confidence" in text
        assert "aggregate" in text
        assert "`usage_count`" in text

    assert "omission cannot be used to avoid that assertion" in adr
    assert "translate field names or counts mechanically" in capsules


def test_explanation_docs_distinguish_panel_from_structured_provenance() -> None:
    schema = " ".join(_read("docs/schema.md").split())
    limitations = " ".join(_read("docs/limitations.md").split())

    for text in (schema, limitations):
        assert "`--json --explain`" in text
        assert "`explanation_dag`" in text

    assert "Plain panel `--explain` output" in schema
    assert "does not emit the structured `explanation_dag` object" in schema
    assert "`--explain` shows flat retained-evidence explanations" in limitations
