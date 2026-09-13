"""Tests for the per-slug evidence-strength diagnostic.

Repeated views of one observation must not add strength. Distinct observations
retain the existing additive heuristic, without asserting independence.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from recon_tool.fusion import (
    SOURCE_PRIORS,
    SOURCE_WEIGHTS,
    compute_slug_posteriors,
)
from recon_tool.models import EvidenceRecord


def _ev(source_type: str, slug: str, raw_value: str = "") -> EvidenceRecord:
    return EvidenceRecord(
        source_type=source_type,
        raw_value=raw_value,
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

    def test_a_record_uses_its_configured_prior(self) -> None:
        posteriors = compute_slug_posteriors((_ev("A", "exchange-onprem"),))
        assert posteriors == (("exchange-onprem", 0.5556),)

    def test_cname_record_uses_its_configured_prior(self) -> None:
        posteriors = compute_slug_posteriors((_ev("CNAME", "cloud-service"),))
        assert posteriors == (("cloud-service", 0.6),)

    def test_mixed_sources_use_strongest_observed_prior_regardless_of_order(self) -> None:
        forward = compute_slug_posteriors((_ev("A", "service"), _ev("TXT", "service")))
        reverse = compute_slug_posteriors((_ev("TXT", "service"), _ev("A", "service")))
        assert forward == reverse == (("service", 0.75),)

    def test_distinct_mx_values_retain_additive_strength(self) -> None:
        first = _ev("MX", "mail-provider", "10 mx1.example.net")
        second = _ev("MX", "mail-provider", "20 mx2.example.net")
        assert compute_slug_posteriors((first,)) == (("mail-provider", 0.8889),)
        assert compute_slug_posteriors((first, second)) == (("mail-provider", 0.9091),)

    @pytest.mark.parametrize("source_type", [*SOURCE_PRIORS, "UNKNOWN_SRC"])
    def test_repeated_record_and_rule_alias_add_no_strength(self, source_type: str) -> None:
        record = _ev(source_type, "service", "synthetic-value")
        alias = replace(record, rule_name="Another matching rule")
        expected = compute_slug_posteriors((record,))
        assert compute_slug_posteriors((record,) * 100) == expected
        assert compute_slug_posteriors((record, alias)) == expected

    def test_same_value_for_different_slugs_is_retained(self) -> None:
        first = _ev("TXT", "service-a", "synthetic-value")
        second = replace(first, slug="service-b")
        assert compute_slug_posteriors((first, second, first)) == (
            ("service-a", 0.7333),
            ("service-b", 0.7333),
        )

    def test_opaque_value_case_is_preserved(self) -> None:
        first = _ev("TXT", "service", "token=Synthetic")
        second = replace(first, raw_value="token=synthetic")
        assert compute_slug_posteriors((first, second)) == (("service", 0.7778),)

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
        for source_type in ("OIDC", "DKIM", "MX", "TXT", "NS", "CAA", "SRV", "A", "CNAME"):
            assert source_type in SOURCE_PRIORS
            assert source_type in SOURCE_WEIGHTS

    def test_weights_are_positive(self) -> None:
        for weight in SOURCE_WEIGHTS.values():
            assert weight > 0

    def test_priors_have_positive_alpha(self) -> None:
        for alpha, _beta in SOURCE_PRIORS.values():
            assert alpha > 0


@given(
    records=st.lists(
        st.builds(
            EvidenceRecord,
            source_type=st.sampled_from([*SOURCE_PRIORS, "UNKNOWN_SRC"]),
            raw_value=st.sampled_from(["", "synthetic-a", "synthetic-b"]),
            rule_name=st.sampled_from(["", "Rule A", "Rule B"]),
            slug=st.sampled_from(["", "service-a", "service-b"]),
        ),
        max_size=40,
    ),
)
def test_evidence_strength_is_invariant_to_repetition_and_order(records: list[EvidenceRecord]) -> None:
    evidence = tuple(records)
    expected = compute_slug_posteriors(evidence)
    aliases = tuple(replace(record, rule_name="Alternate rule") for record in evidence)
    assert compute_slug_posteriors(evidence + evidence + aliases) == expected
    assert compute_slug_posteriors(tuple(reversed(evidence))) == expected
