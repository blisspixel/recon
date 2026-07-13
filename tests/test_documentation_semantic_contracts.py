"""Regression checks for public documentation semantics."""

from __future__ import annotations

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
        assert "lookup-result cache" in text
        assert "then run `lookup_tenant` again" in text
        assert "normal documented network boundary" in text


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


def test_claude_integration_docs_preserve_replay_and_ownership_boundaries() -> None:
    plugin = " ".join(_read("agents/claude-code/README.md").split())
    triage = " ".join(
        _read("agents/claude-code/skills/recon-fingerprint-triage/SKILL.md").split()
    )

    for required in (
        "retained apex/root TXT, SPF, MX, NS, and CNAME observations",
        "Owner-qualified ephemeral rules require a fresh lookup",
        "normal documented network boundary",
    ):
        assert required in plugin

    for forbidden in (
        "what an apex *has*",
        "the whole domain is owned by the SaaS",
        "the organization's own brand zone",
        "inside the org's own brand zone",
        'survives triage as "real SaaS"',
    ):
        assert forbidden not in triage

    for required in (
        "it does not establish common ownership",
        "ownership and operation remain unresolved",
        "normal lookup performs its documented public-source requests",
    ):
        assert required in triage


def test_explanation_docs_distinguish_panel_from_structured_provenance() -> None:
    schema = " ".join(_read("docs/schema.md").split())
    limitations = " ".join(_read("docs/limitations.md").split())

    for text in (schema, limitations):
        assert "`--json --explain`" in text
        assert "`explanation_dag`" in text

    assert "Plain panel `--explain` output" in schema
    assert "does not emit the structured `explanation_dag` object" in schema
    assert "`--explain` shows flat retained-evidence explanations" in limitations
