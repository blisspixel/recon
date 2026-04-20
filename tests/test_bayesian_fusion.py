"""Tests for Bayesian fusion (v0.11 experimental).

Property: corroborating evidence from higher-prior sources should strictly
increase the posterior compared to a single low-prior observation.
"""

from __future__ import annotations

from recon_tool.fusion import (
    SOURCE_PRIORS,
    SOURCE_WEIGHTS,
    compute_slug_posteriors,
)
from recon_tool.models import EvidenceRecord


def _ev(source_type: str, slug: str) -> EvidenceRecord:
    return EvidenceRecord(
        source_type=source_type,
        raw_value="",
        rule_name="",
        slug=slug,
    )


class TestComputeSlugPosteriors:
    def test_empty_evidence_returns_empty_tuple(self) -> None:
        assert compute_slug_posteriors(()) == ()

    def test_evidence_without_slug_skipped(self) -> None:
        assert compute_slug_posteriors((_ev("TXT", ""),)) == ()

    def test_posterior_in_zero_one_range(self) -> None:
        evidence = (_ev("TXT", "mailchimp"),)
        posteriors = compute_slug_posteriors(evidence)
        assert len(posteriors) == 1
        _, score = posteriors[0]
        assert 0.0 <= score <= 1.0

    def test_high_prior_source_higher_than_low_prior(self) -> None:
        """OIDC evidence should yield a higher posterior than A record evidence."""
        oidc_post = compute_slug_posteriors((_ev("OIDC", "microsoft365"),))
        a_post = compute_slug_posteriors((_ev("A", "exchange-onprem"),))
        assert oidc_post[0][1] > a_post[0][1]

    def test_corroboration_strictly_increases_posterior(self) -> None:
        """Two MX observations should beat one MX observation."""
        one = compute_slug_posteriors((_ev("MX", "google-workspace"),))
        two = compute_slug_posteriors((_ev("MX", "google-workspace"), _ev("MX", "google-workspace")))
        assert two[0][1] > one[0][1]

    def test_multi_source_corroboration_beats_single_source(self) -> None:
        """MX + DKIM for the same slug should beat MX alone."""
        mx_only = compute_slug_posteriors((_ev("MX", "google-workspace"),))
        mx_and_dkim = compute_slug_posteriors((_ev("MX", "google-workspace"), _ev("DKIM", "google-workspace")))
        assert mx_and_dkim[0][1] > mx_only[0][1]

    def test_multiple_slugs_all_present(self) -> None:
        evidence = (
            _ev("OIDC", "microsoft365"),
            _ev("DKIM", "google-workspace"),
            _ev("TXT", "sendgrid"),
        )
        posteriors = compute_slug_posteriors(evidence)
        slugs = {slug for slug, _ in posteriors}
        assert slugs == {"microsoft365", "google-workspace", "sendgrid"}

    def test_output_sorted_by_posterior_desc(self) -> None:
        evidence = (
            _ev("A", "weak-slug"),
            _ev("OIDC", "strong-slug"),
            _ev("TXT", "medium-slug"),
        )
        posteriors = compute_slug_posteriors(evidence)
        scores = [score for _, score in posteriors]
        assert scores == sorted(scores, reverse=True)

    def test_unknown_source_type_uses_default_prior(self) -> None:
        """Evidence from an unknown source type still produces a posterior."""
        posteriors = compute_slug_posteriors((_ev("UNKNOWN_SRC", "slug-x"),))
        assert len(posteriors) == 1
        _, score = posteriors[0]
        assert 0.0 <= score <= 1.0

    def test_prior_map_has_entries_for_common_sources(self) -> None:
        """All source types emitted by the DNS source should have priors."""
        for st in ("OIDC", "DKIM", "MX", "TXT", "NS", "CAA", "SRV", "A", "CNAME"):
            assert st in SOURCE_PRIORS
            assert st in SOURCE_WEIGHTS

    def test_weights_are_positive(self) -> None:
        for weight in SOURCE_WEIGHTS.values():
            assert weight > 0

    def test_priors_have_positive_alpha(self) -> None:
        for alpha, _beta in SOURCE_PRIORS.values():
            assert alpha > 0
