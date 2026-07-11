"""Coverage tests for explanation.py insight classification + confidence.

explain_insights classifies insight strings into rule categories. Most
colon-separated formats (like "Email gateway: Proofpoint") route to the
signal-pattern branch first; only a few patterns reach the specialized
elif branches. These tests cover what's actually reachable plus
explain_confidence and explain_observations.
"""

from __future__ import annotations

from typing import Any

from recon_tool.explanation import (
    ExplanationRecord,
    explain_confidence,
    explain_insights,
    explain_observations,
    serialize_explanation,
)
from recon_tool.models import (
    ConfidenceLevel,
    EvidenceRecord,
    Observation,
    SourceResult,
)
from recon_tool.posture import load_posture_rules


def _ev(source_type: str, slug: str) -> EvidenceRecord:
    return EvidenceRecord(
        source_type=source_type,
        raw_value=f"{source_type}={slug}",
        rule_name=slug,
        slug=slug,
    )


def _call(insight: str, slugs: tuple[str, ...] = ()) -> list[ExplanationRecord]:
    evidence = tuple(_ev("TXT", s) for s in slugs)
    return explain_insights(
        insights=[insight],
        slugs=frozenset(slugs),
        services=frozenset(),
        evidence=evidence,
        detection_scores=(),
    )


class TestExplainInsightsReachableBranches:
    """Branches that don't use ': ' as a prefix separator are reachable."""

    def test_email_security_score(self) -> None:
        records = _call("Email security 3/5 good (DMARC reject, DKIM)", slugs=("dmarc",))
        assert records[0].fired_rules
        assert "email_security" in records[0].fired_rules[0]

    def test_auth_federated(self) -> None:
        records = _call("Federated identity indicators (likely ADFS/Okta/Ping — enterprise SSO)", slugs=("okta",))
        assert records[0].fired_rules
        assert "auth_insights" in records[0].fired_rules[0]

    def test_auth_cloud_managed(self) -> None:
        records = _call("Cloud-managed identity indicators (Entra ID native)")
        assert records[0].fired_rules

    def test_license_m365_e3(self) -> None:
        """The license-branch insight matches the auth elif first because
        'federated' appears in the phrase. Both classifications are valid
        for coverage purposes — we just need the record to be produced."""
        records = _call("M365 E3/E5 indicators (Intune + federated auth)")
        assert records[0].fired_rules
        # Either auth or license classification is acceptable
        assert any(keyword in records[0].fired_rules[0] for keyword in ("auth_insights", "license_insights"))

    def test_pki_insight_reaches_pki_rule(self) -> None:
        # "PKI: ..." contains ": " but is a dedicated insight rule, not a
        # signal-generated insight; it must classify as _pki_insights, not be
        # misrouted to the generic "Signal: PKI" branch.
        records = _call("PKI: Let's Encrypt, DigiCert", slugs=("letsencrypt",))
        assert records[0].fired_rules
        assert "_pki_insights" in records[0].fired_rules[0]

    def test_infrastructure_insight_reaches_infra_rule(self) -> None:
        records = _call("Infrastructure: Cloudflare, AWS")
        assert records[0].fired_rules
        assert "_infrastructure_insights" in records[0].fired_rules[0]

    def test_license_m365_standalone(self) -> None:
        """An insight without 'federated' and without a colon reaches the
        license branch directly."""
        records = _call("M365 Apps for Enterprise indicators (Office ProPlus)")
        assert records[0].fired_rules
        assert "license_insights" in records[0].fired_rules[0]

    def test_signal_pattern_insight(self) -> None:
        """'SignalName: matched' colon-separated insights route to the
        signal-derived branch first."""
        records = _call("AI Adoption: openai", slugs=("openai",))
        assert len(records) == 1
        assert any("Signal:" in r for r in records[0].fired_rules)

    def test_unmatched_insight_still_records(self) -> None:
        """Insights that match no branch still produce a record with
        empty fired_rules."""
        records = _call("A completely unknown insight format without a colon")
        assert len(records) == 1

    def test_multiple_insights_multiple_records(self) -> None:
        """Each insight produces its own ExplanationRecord."""
        records = explain_insights(
            insights=[
                "Email security 3/5 good",
                "M365 E3/E5 indicators",
                "AI Adoption: openai",
            ],
            slugs=frozenset({"openai"}),
            services=frozenset(),
            evidence=(_ev("TXT", "openai"),),
            detection_scores=(),
        )
        assert len(records) == 3


class TestExplainInsightsSpecializedBranches:
    """Insights without ': ' bypass the signal-pattern branch and reach
    the specialized keyword elifs further down. Real insight generators
    use ': ' extensively, so these branches are reached in practice only
    for a few specific formats — but the code exists to handle them and
    should be covered."""

    def test_email_gateway_without_colon(self) -> None:
        records = _call("Email gateway identified as Proofpoint", slugs=("proofpoint",))
        assert records[0].fired_rules
        assert "gateway_insights" in records[0].fired_rules[0]

    def test_security_stack_without_colon(self) -> None:
        records = _call("Security stack includes CrowdStrike", slugs=("crowdstrike",))
        assert records[0].fired_rules
        assert "security_stack" in records[0].fired_rules[0]

    def test_sase_without_colon(self) -> None:
        records = _call("SASE provider identified", slugs=("zscaler",))
        assert records[0].fired_rules
        assert "sase_insights" in records[0].fired_rules[0]

    def test_dual_provider_without_colon(self) -> None:
        records = _call(
            "Dual provider environment observed (Google + Microsoft coexistence)",
            slugs=("google-workspace", "microsoft365"),
        )
        assert records[0].fired_rules
        assert "migration_insights" in records[0].fired_rules[0]

    def test_mdm_without_colon(self) -> None:
        records = _call("Mac management via Jamf observed", slugs=("jamf",))
        assert records[0].fired_rules
        assert "mdm_insights" in records[0].fired_rules[0]

    def test_pki_without_colon(self) -> None:
        records = _call("PKI authority identified as DigiCert", slugs=("digicert",))
        # PKI branch requires `lower.startswith("pki:")` — this won't match
        # the pki branch but shouldn't error
        assert len(records) == 1

    def test_infrastructure_without_colon(self) -> None:
        records = _call("Infrastructure provider breakdown available")
        # Similarly infrastructure branch uses startswith("infrastructure:")
        assert len(records) == 1

    def test_google_workspace_managed_without_colon(self) -> None:
        records = _call("Google Workspace managed identity confirmed", slugs=("google-managed",))
        assert records[0].fired_rules
        assert "google_auth_insights" in records[0].fired_rules[0]

    def test_dmarc_standalone(self) -> None:
        records = _call("DMARC policy configured as reject")
        assert records[0].fired_rules

    def test_org_size_without_colon(self) -> None:
        records = _call("Large org signal detected (5 domains in tenant, mid-size)")
        assert records[0].fired_rules
        assert "org_size_insights" in records[0].fired_rules[0]


class TestExplainConfidence:
    def test_high_confidence_with_corroboration(self) -> None:
        results = [
            SourceResult(
                source_name="oidc_discovery",
                tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            ),
            SourceResult(source_name="user_realm", display_name="Contoso", m365_detected=True),
            SourceResult(
                source_name="dns_records",
                m365_detected=True,
                detected_services=("Microsoft 365",),
            ),
        ]
        rec = explain_confidence(
            results,
            evidence_confidence=ConfidenceLevel.HIGH,
            inference_confidence=ConfidenceLevel.HIGH,
            final_confidence=ConfidenceLevel.HIGH,
        )
        assert rec.item_type == "confidence"
        # Should reference "high" somewhere in the derivation
        assert "high" in rec.confidence_derivation.lower()
        assert "high corroboration rule" in rec.confidence_derivation
        assert "Winning claim: microsoft365" in rec.confidence_derivation

    def test_low_confidence_no_successful_sources(self) -> None:
        results = [
            SourceResult(source_name="oidc_discovery", error="HTTP 429"),
            SourceResult(source_name="dns_records", error="DNS timeout"),
        ]
        rec = explain_confidence(
            results,
            evidence_confidence=ConfidenceLevel.LOW,
            inference_confidence=ConfidenceLevel.LOW,
            final_confidence=ConfidenceLevel.LOW,
        )
        assert rec.item_type == "confidence"
        assert "low" in rec.confidence_derivation.lower()
        assert "No canonical claim met" in rec.confidence_derivation

    def test_unrelated_evidence_is_not_described_as_corroboration(self) -> None:
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Microsoft 365", "Google Workspace", "Cloudflare"),
                evidence=(
                    EvidenceRecord(source_type="TXT", raw_value="ms=123", rule_name="M365", slug="microsoft365"),
                    EvidenceRecord(
                        source_type="MX",
                        raw_value="aspmx.l.google.com",
                        rule_name="Google MX",
                        slug="google-workspace",
                    ),
                    EvidenceRecord(
                        source_type="CNAME",
                        raw_value="edge.cloudflare.net",
                        rule_name="Cloudflare",
                        slug="cloudflare",
                    ),
                ),
            ),
        ]

        rec = explain_confidence(
            results,
            evidence_confidence=ConfidenceLevel.LOW,
            inference_confidence=ConfidenceLevel.LOW,
            final_confidence=ConfidenceLevel.LOW,
        )

        assert "unrelated claims do not combine" in rec.confidence_derivation
        assert "distinct evidence source types" not in rec.confidence_derivation

    def test_errored_data_is_not_described_as_a_confidence_contributor(self) -> None:
        result = SourceResult(
            source_name="dns_records",
            detected_services=("Google Workspace",),
            evidence=(
                EvidenceRecord(
                    source_type="MX",
                    raw_value="aspmx.l.google.com",
                    rule_name="Google MX",
                    slug="google-workspace",
                ),
            ),
            error="DNS collection failed",
        )

        rec = explain_confidence(
            [result],
            evidence_confidence=ConfidenceLevel.LOW,
            inference_confidence=ConfidenceLevel.LOW,
            final_confidence=ConfidenceLevel.LOW,
        )

        assert "0 successful source(s)" in rec.confidence_derivation
        assert rec.matched_evidence == ()
        assert rec.fired_rules == ("Source: dns_records (failed)",)

    def test_winning_claim_names_qualifying_evidence_only(self) -> None:
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Google Workspace", "Cloudflare"),
                evidence=(
                    EvidenceRecord(
                        source_type="MX",
                        raw_value="aspmx.l.google.com",
                        rule_name="Google MX",
                        slug="google-workspace",
                    ),
                    EvidenceRecord(
                        source_type="DKIM",
                        raw_value="google._domainkey",
                        rule_name="Google DKIM",
                        slug="google-workspace",
                    ),
                    EvidenceRecord(
                        source_type="CNAME",
                        raw_value="edge.cloudflare.net",
                        rule_name="Cloudflare",
                        slug="cloudflare",
                    ),
                ),
            ),
        ]

        rec = explain_confidence(
            results,
            evidence_confidence=ConfidenceLevel.LOW,
            inference_confidence=ConfidenceLevel.MEDIUM,
            final_confidence=ConfidenceLevel.LOW,
        )

        assert "Winning claim: google-workspace" in rec.confidence_derivation
        assert "Qualifying record types: DKIM, MX" in rec.confidence_derivation
        assert "Qualifying sources: dns_records" in rec.confidence_derivation
        assert {evidence.slug for evidence in rec.matched_evidence} == {"google-workspace"}

    def test_duplicate_source_results_are_reported_once(self) -> None:
        result = SourceResult(source_name="dns_records", detected_services=("Cloudflare",))

        rec = explain_confidence(
            [result, result],
            evidence_confidence=ConfidenceLevel.LOW,
            inference_confidence=ConfidenceLevel.LOW,
            final_confidence=ConfidenceLevel.LOW,
        )

        assert "1 successful source(s)" in rec.confidence_derivation
        assert "Contributing sources: dns_records" in rec.confidence_derivation

    def test_repeated_tenant_claim_excludes_unrelated_evidence(self) -> None:
        unrelated = EvidenceRecord(
            source_type="TXT",
            raw_value="slack-domain-verification=123",
            rule_name="Slack verification",
            slug="slack",
        )
        results = [
            SourceResult(source_name="source_a", tenant_id="tid", evidence=(unrelated,)),
            SourceResult(source_name="source_b", tenant_id="tid"),
        ]

        rec = explain_confidence(
            results,
            evidence_confidence=ConfidenceLevel.MEDIUM,
            inference_confidence=ConfidenceLevel.MEDIUM,
            final_confidence=ConfidenceLevel.MEDIUM,
        )

        assert "Winning claim: tenant-id" in rec.confidence_derivation
        assert rec.matched_evidence == ()

    def test_repeated_tenant_claim_keeps_direct_tenant_evidence(self) -> None:
        direct = EvidenceRecord(
            source_type="HTTP",
            raw_value="tenant_id=tid",
            rule_name="OIDC Discovery",
            slug="microsoft365",
        )
        results = [
            SourceResult(source_name="source_a", tenant_id="tid", evidence=(direct,)),
            SourceResult(source_name="source_b", tenant_id="tid"),
        ]

        rec = explain_confidence(
            results,
            evidence_confidence=ConfidenceLevel.MEDIUM,
            inference_confidence=ConfidenceLevel.MEDIUM,
            final_confidence=ConfidenceLevel.MEDIUM,
        )

        assert rec.matched_evidence == (direct,)

    def test_medium_confidence_with_partial_corroboration(self) -> None:
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Cloudflare",),
                detected_slugs=("cloudflare",),
            ),
            SourceResult(
                source_name="certificate_transparency",
                detected_services=("Cloudflare",),
                detected_slugs=("cloudflare",),
            ),
        ]
        rec = explain_confidence(
            results,
            evidence_confidence=ConfidenceLevel.MEDIUM,
            inference_confidence=ConfidenceLevel.MEDIUM,
            final_confidence=ConfidenceLevel.MEDIUM,
        )
        assert rec.item_type == "confidence"
        assert "Winning claim: cloudflare" in rec.confidence_derivation


class TestExplainObservations:
    def test_observations_produce_records(self) -> None:
        observations = (
            Observation(
                category="email",
                salience="high",
                statement="DMARC policy: reject",
                related_slugs=("dmarc",),
            ),
            Observation(
                category="identity",
                salience="medium",
                statement="Federated identity detected",
                related_slugs=("okta",),
            ),
        )
        rules = load_posture_rules()
        records = explain_observations(
            observations,
            rules,
            evidence=(_ev("TXT", "dmarc"), _ev("TXT", "okta")),
            detection_scores=(),
        )
        assert len(records) == 2
        assert all(r.item_type == "observation" for r in records)

    def test_empty_observations_returns_empty_list(self) -> None:
        rules = load_posture_rules()
        records = explain_observations(
            (),
            rules,
            evidence=(),
            detection_scores=(),
        )
        assert records == []


class TestSerializeExplanation:
    def test_serializes_insight_record(self) -> None:
        records = _call("Email security 3/5 good")
        assert records
        d = serialize_explanation(records[0])
        import json

        json.dumps(d)
        assert "item_name" in d
        assert "item_type" in d

    def test_serializes_confidence_record(self) -> None:
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
        ]
        rec = explain_confidence(
            results,
            evidence_confidence=ConfidenceLevel.LOW,
            inference_confidence=ConfidenceLevel.LOW,
            final_confidence=ConfidenceLevel.LOW,
        )
        d = serialize_explanation(rec)
        import json

        json.dumps(d)
        assert d["item_type"] == "confidence"


_ = Any  # silence unused import
