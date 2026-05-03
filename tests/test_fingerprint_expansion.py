"""Fingerprint coverage expansion QA.

Validates:
- 12 new fingerprints load without warnings (9.1)
- 5 enriched fingerprints have correct detection counts and weights (9.2)
- GitHub Advanced Security pattern correction (9.3)
- 7 new signals evaluate correctly (9.4)
- 4 updated signals include new slugs (9.5)
- 4 new posture rules + 1 updated rule produce observations (9.6)
- Backward compatibility (9.7)
"""

from __future__ import annotations

import re

from recon_tool.fingerprints import load_fingerprints, reload_fingerprints
from recon_tool.models import SignalContext
from recon_tool.posture import analyze_posture, reload_posture
from recon_tool.signals import evaluate_signals, load_signals, reload_signals


def _ctx(
    slugs: set[str],
    *,
    dmarc_policy: str | None = None,
    auth_type: str | None = None,
    email_security_score: int | None = None,
    spf_include_count: int | None = None,
    issuance_velocity: int | None = None,
) -> SignalContext:
    return SignalContext(
        detected_slugs=frozenset(slugs),
        dmarc_policy=dmarc_policy,
        auth_type=auth_type,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
    )


def _signal_names(ctx: SignalContext) -> set[str]:
    return {m.name for m in evaluate_signals(ctx)}


# ── 9.1: All new fingerprints load without warnings ───────────────────


class TestNewFingerprintsLoad:
    """Verify all 12 new fingerprints load without warnings."""

    def setup_method(self) -> None:
        reload_fingerprints()

    def test_no_warnings_during_loading(self) -> None:
        reload_fingerprints()
        fps = load_fingerprints()
        # All new slugs should be present — no warnings means they loaded cleanly
        new_slugs = {
            "crewai-aid",
            "langsmith",
            "mcp-discovery",
            "cosign-attestation",
            "fastly",
            "flyio",
            "railway",
            "autospf",
            "ondmarc",
            "dmarcian",
            "easydmarc",
            "valimail",
        }
        loaded_slugs = {fp.slug for fp in fps}
        for slug in new_slugs:
            assert slug in loaded_slugs, f"New fingerprint slug '{slug}' not found in loaded fingerprints"

    def test_new_fingerprint_patterns_compile(self) -> None:
        fps = load_fingerprints()
        new_slugs = {
            "crewai-aid",
            "langsmith",
            "mcp-discovery",
            "cosign-attestation",
            "fastly",
            "flyio",
            "railway",
        }
        for fp in fps:
            if fp.slug in new_slugs:
                for det in fp.detections:
                    # txt, cname, subdomain_txt use regex; spf uses substring
                    if det.type != "spf":
                        re.compile(det.pattern)  # should not raise

    def test_spf_fingerprints_have_valid_patterns(self) -> None:
        fps = load_fingerprints()
        spf_slugs = {"autospf", "ondmarc", "dmarcian", "easydmarc", "valimail"}
        for fp in fps:
            if fp.slug in spf_slugs:
                has_spf = False
                for det in fp.detections:
                    assert det.type in ("spf", "dmarc_rua"), f"{fp.slug} has unexpected detection type {det.type}"
                    assert len(det.pattern) > 0, f"{fp.slug} has empty pattern"
                    if det.type == "spf":
                        has_spf = True
                assert has_spf, f"{fp.slug} should have at least one spf detection"

    def test_fingerprint_count_increased(self) -> None:
        fps = load_fingerprints()
        # Was ~190 in v0.7.0, adding 12 new → should be at least 202
        assert len(fps) >= 202, f"Expected at least 202 fingerprints, got {len(fps)}"


# ── 9.2: Enriched fingerprints have correct detection counts ──────────


class TestEnrichedFingerprints:
    """Verify enriched fingerprints have additional detections and correct weights.

    Aggregates detections across every Fingerprint entry that shares a slug
    so the v1.5+ "split detection rules across files" pattern works (e.g.
    surface.yaml extending the apex ping-identity entry with a cname_target
    rule). The dict still maps slug -> Fingerprint, but the chosen Fingerprint
    has all detections from across the catalog merged into it.
    """

    def setup_method(self) -> None:
        reload_fingerprints()
        from collections import defaultdict
        from dataclasses import replace

        by_slug: dict[str, list] = defaultdict(list)
        for fp in load_fingerprints():
            by_slug[fp.slug].append(fp)
        merged: dict[str, object] = {}
        for slug, group in by_slug.items():
            base = group[0]
            all_detections = tuple(d for fp in group for d in fp.detections)
            merged[slug] = replace(base, detections=all_detections)
        self.fps = merged  # pyright: ignore[reportAttributeAccessIssue]

    def test_sonatype_has_two_detections(self) -> None:
        fp = self.fps["sonatype"]
        assert len(fp.detections) == 2

    def test_sonatype_ossrh_weight(self) -> None:
        fp = self.fps["sonatype"]
        ossrh_det = [d for d in fp.detections if "OSSRH" in d.pattern]
        assert len(ossrh_det) == 1
        assert ossrh_det[0].weight == 0.8

    def test_snyk_has_two_detections(self) -> None:
        fp = self.fps["snyk"]
        assert len(fp.detections) == 2

    def test_ping_identity_has_three_detections(self) -> None:
        # v1.5.2: surface.yaml extended ping-identity with a cname_target
        # rule, so the merged catalog has 4 detections. The test now asserts
        # the floor (>=3) and confirms the original three are still there.
        fp = self.fps["ping-identity"]
        assert len(fp.detections) >= 3
        patterns = {d.pattern for d in fp.detections}
        assert "^pingone-domain-verification=" in patterns or any("pingone" in p for p in patterns)

    def test_ping_identity_email_weight(self) -> None:
        fp = self.fps["ping-identity"]
        email_det = [d for d in fp.detections if "pingoneemail" in d.pattern]
        assert len(email_det) == 1
        assert email_det[0].weight == 0.6

    def test_cyberark_has_two_detections(self) -> None:
        fp = self.fps["cyberark"]
        assert len(fp.detections) == 2

    def test_cyberark_idaptive_weight(self) -> None:
        fp = self.fps["cyberark"]
        idaptive_det = [d for d in fp.detections if "idaptive" in d.pattern]
        assert len(idaptive_det) == 1
        assert idaptive_det[0].weight == 0.7

    def test_beyond_identity_has_two_detections(self) -> None:
        fp = self.fps["beyond-identity"]
        assert len(fp.detections) == 2

    def test_beyond_identity_cname_weight(self) -> None:
        fp = self.fps["beyond-identity"]
        cname_det = [d for d in fp.detections if "authenticator" in d.pattern]
        assert len(cname_det) == 1
        assert cname_det[0].weight == 0.5


# ── 9.3: GitHub Advanced Security pattern correction ──────────────────


class TestGHASPatternCorrection:
    """Verify the corrected GitHub Advanced Security pattern."""

    def setup_method(self) -> None:
        reload_fingerprints()
        self.fps = {fp.slug: fp for fp in load_fingerprints()}

    def test_corrected_pattern_matches_expected_format(self) -> None:
        fp = self.fps["github-advanced-security"]
        pattern = fp.detections[0].pattern
        subdomain, regex = pattern.split(":", 1)
        assert subdomain == "_github-challenge"
        assert re.match(regex, "github-domain-verification=abc123")

    def test_subdomain_txt_delimiter_present(self) -> None:
        fp = self.fps["github-advanced-security"]
        for det in fp.detections:
            assert ":" in det.pattern, f"subdomain_txt pattern missing delimiter: '{det.pattern}'"


# ── 9.4: New signals evaluate correctly ───────────────────────────────


class TestNewSignals:
    """Verify all 7 new signals evaluate correctly."""

    def setup_method(self) -> None:
        reload_signals()

    # Agentic AI Infrastructure — needs 2+ slugs
    def test_agentic_ai_infrastructure_fires_with_two_slugs(self) -> None:
        names = _signal_names(_ctx({"crewai-aid", "openai"}))
        assert "Agentic AI Infrastructure" in names

    def test_agentic_ai_infrastructure_does_not_fire_with_one_slug(self) -> None:
        names = _signal_names(_ctx({"crewai-aid"}))
        assert "Agentic AI Infrastructure" not in names

    # AI Adoption Without Governance was removed in v1.0.2. Same class as
    # Shadow IT Risk / Complex Migration Window — narrative-judgment
    # synthesis inferring "shadow AI deployment" from absence of specific
    # identity providers. Speculative, not observational.
    def test_ai_without_governance_removed(self) -> None:
        names = _signal_names(_ctx({"openai"}))
        assert "AI Adoption Without Governance" not in names

    # AI Platform Diversity — needs 2+ AI provider slugs
    def test_ai_platform_diversity_fires_with_two_providers(self) -> None:
        names = _signal_names(_ctx({"openai", "anthropic"}))
        assert "AI Platform Diversity" in names

    def test_ai_platform_diversity_does_not_fire_with_one(self) -> None:
        names = _signal_names(_ctx({"openai"}))
        assert "AI Platform Diversity" not in names

    # Software Supply Chain Maturity — needs 2+ supply chain slugs
    def test_supply_chain_maturity_fires_with_two_slugs(self) -> None:
        names = _signal_names(_ctx({"github-advanced-security", "snyk"}))
        assert "Software Supply Chain Maturity" in names

    def test_supply_chain_maturity_does_not_fire_with_one(self) -> None:
        names = _signal_names(_ctx({"snyk"}))
        assert "Software Supply Chain Maturity" not in names

    # DevSecOps Investment Without Email Governance was removed in v1.0.2.
    # Pure narrative synthesis — inferring that engineering security
    # investment doesn't extend to email-layer controls is opinion, not
    # observation. Both underlying facts are already visible in the
    # services list.
    def test_devsecops_without_email_removed(self) -> None:
        names = _signal_names(_ctx({"snyk"}, email_security_score=1))
        assert "DevSecOps Investment Without Email Governance" not in names

    # Edge-Native Architecture — needs 2+ edge slugs
    def test_edge_native_fires_with_two_slugs(self) -> None:
        names = _signal_names(_ctx({"vercel", "fastly"}))
        assert "Edge-Native Architecture" in names

    def test_edge_native_does_not_fire_with_one(self) -> None:
        names = _signal_names(_ctx({"vercel"}))
        assert "Edge-Native Architecture" not in names

    def test_edge_native_fires_with_new_slugs(self) -> None:
        names = _signal_names(_ctx({"flyio", "railway"}))
        assert "Edge-Native Architecture" in names

    # Enterprise Email Deliverability — needs 1 SPF flattening slug
    def test_email_deliverability_fires_with_autospf(self) -> None:
        names = _signal_names(_ctx({"autospf"}))
        assert "Enterprise Email Deliverability" in names

    def test_email_deliverability_fires_with_ondmarc(self) -> None:
        names = _signal_names(_ctx({"ondmarc"}))
        assert "Enterprise Email Deliverability" in names

    def test_email_deliverability_fires_with_valimail(self) -> None:
        names = _signal_names(_ctx({"valimail"}))
        assert "Enterprise Email Deliverability" in names

    def test_email_deliverability_does_not_fire_without_slug(self) -> None:
        names = _signal_names(_ctx({"sendgrid"}))
        assert "Enterprise Email Deliverability" not in names


# ── 9.5: Updated signals include new slugs ────────────────────────────


class TestUpdatedSignals:
    """Verify existing signals were updated with new slugs."""

    def setup_method(self) -> None:
        reload_signals()

    def test_ai_adoption_fires_with_crewai_aid(self) -> None:
        names = _signal_names(_ctx({"crewai-aid"}))
        assert "AI Adoption" in names

    def test_ai_adoption_fires_with_langsmith(self) -> None:
        names = _signal_names(_ctx({"langsmith"}))
        assert "AI Adoption" in names

    def test_ai_adoption_fires_with_mcp_discovery(self) -> None:
        names = _signal_names(_ctx({"mcp-discovery"}))
        assert "AI Adoption" in names

    def test_enterprise_security_stack_includes_beyond_identity(self) -> None:
        # beyond-identity + one other security slug = 2 matches (min_matches: 2)
        names = _signal_names(_ctx({"beyond-identity", "okta"}))
        assert "Enterprise Security Stack" in names

    def test_dev_engineering_includes_flyio(self) -> None:
        names = _signal_names(_ctx({"flyio", "github"}))
        assert "Dev & Engineering Heavy" in names

    def test_dev_engineering_includes_railway(self) -> None:
        names = _signal_names(_ctx({"railway", "vercel"}))
        assert "Dev & Engineering Heavy" in names

    def test_dev_engineering_includes_fastly(self) -> None:
        names = _signal_names(_ctx({"fastly", "netlify"}))
        assert "Dev & Engineering Heavy" in names

    def test_multi_cloud_includes_flyio(self) -> None:
        names = _signal_names(_ctx({"flyio", "aws-route53"}))
        assert "Multi-Cloud" in names


# ── 9.6: New posture rules produce observations ──────────────────────


class TestNewPostureRules:
    """Verify new and updated posture rules produce observations."""

    def setup_method(self) -> None:
        reload_posture()

    def _observation_statements(self, slugs: tuple[str, ...], **kwargs: object) -> set[str]:
        from dataclasses import replace

        from recon_tool.models import ConfidenceLevel, TenantInfo

        info = TenantInfo(
            tenant_id=None,
            display_name="Contoso Ltd",
            default_domain="contoso.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.MEDIUM,
            slugs=slugs,
        )
        if kwargs:
            info = replace(info, **kwargs)
        observations = analyze_posture(info)
        return {obs.statement for obs in observations}

    def test_agentic_ai_detected_fires(self) -> None:
        stmts = self._observation_statements(("crewai-aid",))
        assert any("Agentic AI" in s for s in stmts)

    def test_agentic_ai_detected_fires_with_langsmith(self) -> None:
        stmts = self._observation_statements(("langsmith",))
        assert any("Agentic AI" in s for s in stmts)

    def test_supply_chain_security_detected_fires(self) -> None:
        stmts = self._observation_statements(("sonatype",))
        assert any("supply chain" in s.lower() for s in stmts)

    def test_supply_chain_security_detected_fires_with_snyk(self) -> None:
        stmts = self._observation_statements(("snyk",))
        assert any("supply chain" in s.lower() for s in stmts)

    def test_edge_compute_detected_fires_with_two(self) -> None:
        stmts = self._observation_statements(("vercel", "fastly"))
        assert any("edge" in s.lower() for s in stmts)

    def test_edge_compute_detected_does_not_fire_with_one(self) -> None:
        stmts = self._observation_statements(("vercel",))
        assert not any("edge-native" in s.lower() for s in stmts)

    def test_email_deliverability_management_fires(self) -> None:
        stmts = self._observation_statements(("ondmarc",))
        assert any("SPF flattening" in s or "DMARC management" in s for s in stmts)

    def test_email_deliverability_management_fires_with_valimail(self) -> None:
        stmts = self._observation_statements(("valimail",))
        assert any("SPF flattening" in s or "DMARC management" in s for s in stmts)

    def test_updated_ai_tooling_fires_with_langsmith(self) -> None:
        stmts = self._observation_statements(("langsmith",))
        assert any("AI/LLM tooling" in s for s in stmts)

    def test_updated_ai_tooling_fires_with_mcp_discovery(self) -> None:
        stmts = self._observation_statements(("mcp-discovery",))
        assert any("AI/LLM tooling" in s for s in stmts)


# ── 9.7: Backward compatibility ──────────────────────────────────────


class TestBackwardCompatibilityV080:
    """Verify all existing fingerprints and signals still load and evaluate."""

    def setup_method(self) -> None:
        reload_fingerprints()
        reload_signals()
        reload_posture()

    def test_all_existing_fingerprints_load(self) -> None:
        fps = load_fingerprints()
        # v0.7.0 had ~194 fingerprints; we added 12 → at least 202
        assert len(fps) >= 202

    def test_all_existing_signals_load(self) -> None:
        signals = load_signals()
        # Signal count floats with curation. Signals that violated the
        # "observable facts in neutral language" or "no narrative
        # synthesis" invariants have been retired (Shadow IT Risk,
        # Complex Migration Window, Governance Sprawl, Security Stack
        # Without Governance, AI Adoption Without Governance, DevSecOps
        # Investment Without Email Governance). We keep a floor high
        # enough to catch accidental mass-deletion, not a moving target
        # that breaks on intentional curation.
        assert len(signals) >= 35

    def test_existing_signal_still_fires(self) -> None:
        """Enterprise Security Stack should still fire with original slugs."""
        names = _signal_names(_ctx({"crowdstrike", "okta"}))
        assert "Enterprise Security Stack" in names

    def test_existing_contradiction_still_works(self) -> None:
        """Incomplete Identity Migration should still be suppressed by microsoft365."""
        names = _signal_names(_ctx({"okta", "microsoft365"}))
        assert "Incomplete Identity Migration" not in names

    def test_removed_meta_signals_do_not_fire(self) -> None:
        # Complex Migration Window removed — narrative synthesis, not
        # observable from DNS.
        names = _signal_names(
            _ctx(
                {
                    "crowdstrike",
                    "okta",
                    "microsoft365",
                    "google-workspace",
                }
            )
        )
        assert "Complex Migration Window" not in names

    def test_all_signal_names_unique(self) -> None:
        signals = load_signals()
        names = [s.name for s in signals]
        assert len(names) == len(set(names)), "Duplicate signal names found"

    def test_all_fingerprint_slugs_unique(self) -> None:
        """Each (name, slug) pair must appear at most once.

        Multiple YAML entries may legitimately share both name and slug — for
        example, surface.yaml extends apex fingerprints with a separate file
        of cname_target rules so the catalog's seed evidence and its
        CNAME-chain classification stay independently reviewable. The
        invariant we actually care about is that there is never a name
        collision on *different* services (two fingerprints both named
        "Shopify" but with different slugs would be a bug).
        """
        fps = load_fingerprints()
        # Build name -> set of slugs. Each name should map to exactly one slug.
        by_name: dict[str, set[str]] = {}
        for fp in fps:
            by_name.setdefault(fp.name, set()).add(fp.slug)
        collisions = {name: slugs for name, slugs in by_name.items() if len(slugs) > 1}
        assert not collisions, (
            "Names mapping to multiple slugs (different services share a "
            f"display name): {collisions}"
        )
