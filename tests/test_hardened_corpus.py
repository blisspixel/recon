"""Regression guards for A1-A7 fixes across synthetic hardened-target archetypes.

This module pins the behavior of the A-bug fixes discovered when the tool was
run against heavily-proxied enterprise targets. Every fixture is fabricated
(no real company names or domains) but mirrors the shape of real hardened
profiles:

- ``hardened_edge_01`` — layered CDN proxy + enterprise email gateway + dual
  M365/GWS primary + strong DMARC. Proxy-heavy minimal public SaaS footprint.
- ``dual_provider_baseline_01`` — both M365 and GWS as primary email providers
  via MX topology, no legacy residue expected.
- ``legacy_residue_01`` — single primary provider with a second provider
  present only via TXT/DKIM (true migration residue).
- ``dormant_parked_01`` — minimal signals, Cloudflare-fronted, strong DMARC.
  The reference negative for hardened-target recognition: edge proxy alone
  is not a maturity signal.
- ``small_shop_cdn_01`` — one CDN, one provider, nothing else. Reference
  negative for the residue guard.

These tests use committed, synthetic fingerprint slugs only. Real test
domains used during development live outside the repo.
"""

from __future__ import annotations

from recon_tool.absence import evaluate_absence_signals
from recon_tool.models import SignalContext
from recon_tool.signals import evaluate_signals, load_signals, reload_signals


def _ctx(
    slugs: set[str],
    dmarc_policy: str | None = None,
    primary_email_provider: str | None = None,
    email_security_score: int | None = None,
) -> SignalContext:
    return SignalContext(
        detected_slugs=frozenset(slugs),
        dmarc_policy=dmarc_policy,
        primary_email_provider=primary_email_provider,
        email_security_score=email_security_score,
    )


def _names(ctx: SignalContext) -> set[str]:
    return {m.name for m in evaluate_signals(ctx)}


def _absence_names(ctx: SignalContext) -> set[str]:
    reload_signals()
    fired = evaluate_signals(ctx)
    return {m.name for m in evaluate_absence_signals(fired, load_signals(), ctx.detected_slugs)}


# ── Hardened edge archetype ────────────────────────────────────────────


class TestHardenedEdgeArchetype:
    """Layered CDN proxy + enterprise gateway + dual M365/GWS primary.

    Regression guards for A3 (Multi-Cloud vs Edge Layering split), A4 (Legacy
    Provider Residue must not flag current primary), A5 (Dual Email Delivery
    Path naming), and A2 (no noisy missing-counterparts on competing vendors).
    """

    def setup_method(self) -> None:
        reload_signals()

    def _fixture(self) -> SignalContext:
        return _ctx(
            slugs={
                "cloudflare",
                "akamai",
                "proofpoint",
                "microsoft365",
                "google-workspace",
                "okta",
                "wiz",
                "digicert",
            },
            dmarc_policy="reject",
            primary_email_provider="Microsoft 365 + Google Workspace",
            email_security_score=3,
        )

    def test_a3_edge_layering_fires_not_multi_cloud(self) -> None:
        names = _names(self._fixture())
        assert "Edge Layering" in names
        assert "Multi-Cloud" not in names

    def test_a4_legacy_provider_residue_does_not_flag_primary(self) -> None:
        names = _names(self._fixture())
        assert "Secondary Email Provider Observed" not in names

    def test_a5_dual_email_delivery_path_fires(self) -> None:
        names = _names(self._fixture())
        assert "Dual Email Delivery Path" in names

    def test_a5_old_split_brain_name_gone(self) -> None:
        names = _names(self._fixture())
        assert "Split-Brain Email Config" not in names

    def test_a2_enterprise_security_stack_emits_no_missing_counterparts(self) -> None:
        abs_names = _absence_names(self._fixture())
        assert not any(
            "Enterprise Security Stack" in name and "Missing Counterparts" in name
            for name in abs_names
        )

    def test_a2_enterprise_it_maturity_emits_no_missing_counterparts(self) -> None:
        abs_names = _absence_names(self._fixture())
        assert not any(
            "Enterprise IT Maturity" in name and "Missing Counterparts" in name
            for name in abs_names
        )


class TestDmarcGovernanceMissingCounterpartsRemoved:
    """A2: DMARC Governance Investment had competitor vendors listed as missing
    counterparts, producing nitpicky output like "Missing Counterparts:
    proofpoint, mimecast, barracuda, trendmicro" on every run. Audit removed
    that entry; this test pins the removal.
    """

    def setup_method(self) -> None:
        reload_signals()

    def test_dmarc_governance_fires_without_counterpart_noise(self) -> None:
        ctx = _ctx(
            slugs={"agari", "microsoft365", "symantec"},
            dmarc_policy="reject",
            primary_email_provider="Google Workspace",
        )
        assert "DMARC Governance Investment" in _names(ctx)
        abs_names = _absence_names(ctx)
        assert not any(
            "DMARC Governance Investment" in name and "Missing Counterparts" in name
            for name in abs_names
        )


class TestDualProviderBaseline:
    """Both M365 and GWS as primary (via MX topology) — the residue guard
    must not emit on either provider. Baseline for dual-primary outputs.
    """

    def setup_method(self) -> None:
        reload_signals()

    def test_legacy_residue_silent_on_dual_primary(self) -> None:
        ctx = _ctx(
            slugs={"microsoft365", "google-workspace"},
            dmarc_policy="reject",
            primary_email_provider="Microsoft 365 + Google Workspace",
        )
        assert "Secondary Email Provider Observed" not in _names(ctx)


class TestLegacyResidueStillFiresForTrueResidue:
    """A4 residue guard should only silence the *current* primary. A second
    provider present only via TXT/DKIM should still fire the residue signal.
    """

    def setup_method(self) -> None:
        reload_signals()

    def test_residue_fires_for_non_primary_provider(self) -> None:
        ctx = _ctx(
            slugs={"microsoft365", "google-workspace"},
            dmarc_policy="reject",
            primary_email_provider="Microsoft 365",
        )
        # google-workspace is in slugs but not in primary → true residue
        assert "Secondary Email Provider Observed" in _names(ctx)

    def test_residue_does_not_fire_when_only_primary_present(self) -> None:
        ctx = _ctx(
            slugs={"microsoft365"},
            dmarc_policy="reject",
            primary_email_provider="Microsoft 365",
        )
        assert "Secondary Email Provider Observed" not in _names(ctx)


class TestDormantParkedNegative:
    """Edge proxy + strong DMARC alone must NOT produce any maturity or
    hardening verdict. This is the reference negative for the (unshipped)
    hardened-target recognition work in roadmap Soon #1 — guarding against
    a future signal that would overclaim on dormant domains.
    """

    def setup_method(self) -> None:
        reload_signals()

    def test_proxy_plus_dmarc_reject_has_no_maturity_signal(self) -> None:
        ctx = _ctx(
            slugs={"cloudflare"},
            dmarc_policy="reject",
            email_security_score=2,
        )
        names = _names(ctx)
        forbidden = [
            n for n in names
            if "Maturity" in n or "Zero Trust" in n or "Hardening" in n
        ]
        assert forbidden == [], f"Unexpected maturity verdict on dormant fixture: {forbidden}"


class TestSmallShopCdnNegative:
    """Single CDN + single provider + no SaaS. Residue guard must stay silent."""

    def setup_method(self) -> None:
        reload_signals()

    def test_small_shop_no_residue(self) -> None:
        ctx = _ctx(
            slugs={"cloudflare", "google-workspace"},
            dmarc_policy="quarantine",
            primary_email_provider="Google Workspace",
        )
        assert "Secondary Email Provider Observed" not in _names(ctx)


class TestLikelyPrimaryInference:
    """Regression guards for likely_primary_email_provider inference.

    On gateway-fronted domains, MX points to an enterprise gateway and no
    direct provider slug appears in MX evidence. The inference path reads
    non-MX evidence (DKIM, identity endpoint responses, TXT tokens) and
    emits a hedged "likely" downstream so the panel can say something
    useful instead of going silent.
    """

    def setup_method(self) -> None:
        reload_signals()

    def _ev(self, source_type: str, slug: str):
        from recon_tool.models import EvidenceRecord
        return EvidenceRecord(
            source_type=source_type,
            raw_value=f"fixture/{slug}",
            rule_name="fixture",
            slug=slug,
        )

    def test_gateway_with_dkim_downstream_infers_google(self) -> None:
        from recon_tool.merger import _compute_email_topology
        evidence = (
            self._ev("MX", "symantec"),
            self._ev("DKIM", "google-workspace"),
        )
        primary, gateway, likely = _compute_email_topology(evidence)
        assert primary is None
        assert gateway == "Symantec/Broadcom"
        assert likely == "Google Workspace"

    def test_gateway_with_microsoft_oidc_infers_m365(self) -> None:
        from recon_tool.merger import _compute_email_topology
        evidence = (
            self._ev("MX", "proofpoint"),
            self._ev("OIDC", "microsoft365"),
        )
        primary, gateway, likely = _compute_email_topology(evidence)
        assert primary is None
        assert gateway == "Proofpoint"
        assert likely == "Microsoft 365"

    def test_strict_primary_suppresses_likely(self) -> None:
        """When MX directly names a provider, likely stays None to avoid
        duplication between the strict and inferred fields."""
        from recon_tool.merger import _compute_email_topology
        evidence = (
            self._ev("MX", "microsoft365"),
            self._ev("MX", "proofpoint"),
            self._ev("DKIM", "google-workspace"),
        )
        primary, gateway, likely = _compute_email_topology(evidence)
        assert primary == "Microsoft 365"
        assert gateway == "Proofpoint"
        assert likely is None

    def test_gateway_alone_no_likely(self) -> None:
        """Gateway with no downstream evidence → no likely inference."""
        from recon_tool.merger import _compute_email_topology
        evidence = (self._ev("MX", "proofpoint"),)
        _, gateway, likely = _compute_email_topology(evidence)
        assert gateway == "Proofpoint"
        assert likely is None

    def test_no_gateway_no_likely(self) -> None:
        """Without a gateway anchor, non-MX evidence doesn't trigger the
        likely-primary inference — the field is reserved for the specific
        case of gateway-fronted domains."""
        from recon_tool.merger import _compute_email_topology
        evidence = (
            self._ev("DKIM", "google-workspace"),
            self._ev("TXT", "microsoft365"),
        )
        primary, gateway, likely = _compute_email_topology(evidence)
        assert primary is None
        assert gateway is None
        assert likely is None

    def test_residue_guard_uses_likely_primary(self) -> None:
        """The Legacy Provider Residue exclude_matches_in_primary guard
        should treat likely_primary_email_provider as equivalent to
        primary_email_provider for filtering. On a JPM-shape fixture
        (Symantec gateway, likely Google Workspace downstream, GWS slug
        detected), the residue signal should stay silent.
        """
        ctx = SignalContext(
            detected_slugs=frozenset({"symantec", "google-workspace"}),
            dmarc_policy="reject",
            primary_email_provider=None,
            likely_primary_email_provider="Google Workspace",
        )
        names = {m.name for m in evaluate_signals(ctx)}
        assert "Secondary Email Provider Observed" not in names
