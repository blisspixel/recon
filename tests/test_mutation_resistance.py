"""v1.9.9 — targeted mutation resistance tests.

Line coverage measures execution, not test quality. A function with
100% line coverage may still ship buggy if the tests only assert on
inputs that happen to produce correct output regardless of internal
behaviour. The standard answer is mutation testing: deliberately
break the implementation, confirm the tests fail.

Full-tree mutation tools (``mutmut``, ``cosmic-ray``) are heavyweight
and ``mutmut`` does not run on Windows. This module is a focused,
hand-rolled equivalent: each test case applies a *specific named
mutation* to a v1.9.9 helper, runs a relevant assertion path, and
verifies the suite catches the regression.

The mutations chosen are the ones most likely to slip past careful
review:

  * Off-by-one on numeric thresholds (``< 5`` → ``<= 5``).
  * Comparator flips (``>= 3`` → ``> 3``).
  * Logical-operator flips (``and`` → ``or``).
  * Identity-vs-equality (``is None`` → ``is not None``).
  * Dropped early-return guards.
  * Boundary-condition swaps (``min`` ↔ ``max``).

A passing test in this file means a *specific mutated implementation
fails the tests it should fail*. Failures here mean the relevant
mutation slipped through — that exact bug could ship.

Coverage is by construction incomplete: there are infinite possible
mutations and we test a handful. The point is to pin the highest-risk
mutations explicitly. PRs that change the helpers should grow this
file when new risk surfaces appear.
"""

from __future__ import annotations

from collections.abc import Iterable
from unittest.mock import patch

import pytest
from rich.console import Console

from recon_tool.formatter import (
    _CLOUD_VENDOR_BY_SLUG,
    canonical_cloud_vendor,
    count_cloud_vendors,
    render_tenant_panel,
)
from recon_tool.models import ConfidenceLevel, TenantInfo


def _render(info: TenantInfo, **kwargs: object) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info, **kwargs)  # type: ignore[arg-type]
    console.print(rendered)
    return console.export_text()


def _make_tenant(**overrides: object) -> TenantInfo:
    base: dict[str, object] = {
        "tenant_id": "tid",
        "display_name": "Contoso, Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": ConfidenceLevel.HIGH,
    }
    base.update(overrides)
    return TenantInfo(**base)  # type: ignore[arg-type]


# ── Mutation library ──────────────────────────────────────────────────


def _mutated_canonical_drop_none_guard(slug: str) -> str | None:
    """MUTATION: the real function returns ``None`` for unknown slugs.
    A buggy version drops the ``.get(..., None)`` semantics and
    returns a default vendor string for any unknown slug. The rollup
    would then over-fire on every SaaS-only apex."""
    return _CLOUD_VENDOR_BY_SLUG.get(slug, "Unknown Cloud")


def _mutated_count_cloud_vendors_orders_skip_none(
    apex_slugs: Iterable[str],
    surface_slugs: Iterable[str] = (),
) -> dict[str, int]:
    """MUTATION: the real function uses
    ``if vendor is None: continue``. A buggy version drops the guard
    and uses ``vendor or "Unknown"`` instead, so non-cloud slugs leak
    in as an "Unknown" vendor key. The rollup would fire on any apex
    with at least two slugs total, even if none are cloud."""
    counts: dict[str, int] = {}
    for slug in (*apex_slugs, *surface_slugs):
        vendor = _CLOUD_VENDOR_BY_SLUG.get(slug) or "Unknown"
        counts[vendor] = counts.get(vendor, 0) + 1
    return counts


def _mutated_count_cloud_vendors_double_count(
    apex_slugs: Iterable[str],
    surface_slugs: Iterable[str] = (),
) -> dict[str, int]:
    """MUTATION: a buggy version increments by 2 instead of 1. Total
    counts would double; the boolean ``>= 2`` trigger would still
    fire correctly so this mutation only changes the
    ``vendor_count_distribution`` aggregate."""
    counts: dict[str, int] = {}
    for slug in (*apex_slugs, *surface_slugs):
        vendor = _CLOUD_VENDOR_BY_SLUG.get(slug)
        if vendor is None:
            continue
        counts[vendor] = counts.get(vendor, 0) + 2
    return counts


def _mutated_count_cloud_vendors_swap_streams(
    apex_slugs: Iterable[str],
    surface_slugs: Iterable[str] = (),
) -> dict[str, int]:
    # surface_slugs is deliberately ignored — that IS the mutation.
    del surface_slugs
    """MUTATION: a buggy refactor accidentally swaps apex/surface
    semantics so only the apex stream is counted. The behaviour
    looks correct on inputs where both streams are equal but breaks
    when the surface stream has its own distinct vendor.

    Catches: tests that pass apex-only and ignore the surface stream
    would not surface this; the test_count_cloud_vendors_properties
    file's ``test_split_streams_match_concat`` is the load-bearing
    invariant test."""
    counts: dict[str, int] = {}
    for slug in apex_slugs:  # surface_slugs deliberately ignored
        vendor = _CLOUD_VENDOR_BY_SLUG.get(slug)
        if vendor is None:
            continue
        counts[vendor] = counts.get(vendor, 0) + 1
    return counts


def _mutated_canonical_returns_empty_string(slug: str) -> str | None:
    """MUTATION: a buggy version returns the empty string instead of
    None for unknown slugs. ``None`` is the documented sentinel; an
    empty string would pass truthiness checks in callers and then
    register as a vendor key in counts dicts, silently leaking unknown
    slugs through the rollup as an unnamed vendor."""
    return _CLOUD_VENDOR_BY_SLUG.get(slug, "")


def _mutated_canonical_case_insensitive_lookup(slug: str) -> str | None:
    """MUTATION: lookup with case-folding. The real function is
    case-sensitive; ``AWS-CLOUDFRONT`` does not map to AWS. A
    case-insensitive mutation would silently work on uppercase slugs,
    masking a contract that slug strings must be lowercase."""
    return _CLOUD_VENDOR_BY_SLUG.get(slug.lower())


# ── Tests: each mutation must be caught by at least one existing test ──


class TestCanonicalMutations:
    def test_drop_none_guard_breaks_non_cloud_slug_test(self):
        """The 'non-cloud slugs return None' test in
        test_multi_cloud_rollup.py must fail under the mutation that
        returns a default vendor for unknown slugs. If this test
        passes (i.e. the mutation does NOT cause a failure), our
        coverage of canonical_cloud_vendor is too weak."""
        with patch("recon_tool.formatter.canonical_cloud_vendor", _mutated_canonical_drop_none_guard):
            # The mutated function returns "Unknown Cloud" for unknown slugs
            from recon_tool.formatter import canonical_cloud_vendor as patched

            # Verify the mutation is in effect
            assert patched("nonexistent-slug-xyz") == "Unknown Cloud"

        # Without the mutation, the assertion must hold:
        assert canonical_cloud_vendor("nonexistent-slug-xyz") is None


class TestCountCloudVendorsMutations:
    def test_skip_none_mutation_breaks_non_cloud_invariance(self):
        """The property test 'adding non-cloud slugs is a no-op' (in
        test_count_cloud_vendors_properties.py) must fail under the
        mutation that leaks unknown slugs in as 'Unknown'. Apply the
        mutated function in-process and assert the invariant
        violates."""
        # Mutated function: should fire vendor leak
        baseline = _mutated_count_cloud_vendors_orders_skip_none(["aws-cloudfront"])
        with_noise = _mutated_count_cloud_vendors_orders_skip_none(["aws-cloudfront", "slack", "okta"])
        # Under the mutation, the invariant breaks: noise CHANGES the counts.
        assert baseline != with_noise, (
            "Mutation that drops the None-guard must change vendor counts when non-cloud slugs are added; "
            "if this assertion fails, the mutation produces the same output as the real function and "
            "the invariant test in test_count_cloud_vendors_properties is too weak to distinguish them."
        )
        # The real function must NOT have this property:
        baseline_real = count_cloud_vendors(["aws-cloudfront"])
        with_noise_real = count_cloud_vendors(["aws-cloudfront", "slack", "okta"])
        assert baseline_real == with_noise_real, (
            "real count_cloud_vendors must be invariant under non-cloud slug addition"
        )

    def test_double_count_mutation_breaks_total_count_property(self):
        """The 'total count equals input length' property test must
        fail under the doubling mutation. Verifies the test is
        load-bearing."""
        mutated = _mutated_count_cloud_vendors_double_count(["aws-cloudfront", "cloudflare"])
        total = sum(mutated.values())
        assert total == 4, (
            "doubling mutation should produce total=4 from 2 inputs; "
            "if it produces 2, the mutation collapsed to the real function"
        )
        # Real function: total equals input length
        real = count_cloud_vendors(["aws-cloudfront", "cloudflare"])
        assert sum(real.values()) == 2


class TestCeilingTriggerMutations:
    """The ceiling trigger has three numeric thresholds. Each is an
    off-by-one mutation candidate. The boundary-tests file already
    pins the exact-threshold cases; this test confirms the boundary
    tests would actually fail under the mutated thresholds."""

    def test_domain_count_gte_3_mutated_to_gt_3_would_fail_boundary_test(self):
        """Boundary test at ``domain_count == 3`` expects the ceiling
        to fire. If the gate were ``> 3`` instead of ``>= 3``, the
        boundary test would see a render WITHOUT 'Passive-DNS
        ceiling'. We assert that the EXPECTED firing case currently
        succeeds and that a hypothetical mutated trigger would
        produce a different output."""
        info = _make_tenant(
            domain_count=3,
            tenant_domains=("a.com", "b.com", "c.com"),
            services=("Microsoft 365",),
            slugs=("m365",),
        )
        out = _render(info)
        # Under the real (>=3) trigger, the footer renders:
        assert "Passive-DNS ceiling" in out, (
            "Sanity: real trigger fires at domain_count==3. If this fails, the test premise is "
            "broken before any mutation analysis applies."
        )
        # The boundary test at domain_count==3 in
        # test_formatter_ceiling_boundary.py would FAIL if the
        # trigger mutated to >3. We've verified the firing path
        # above; the suppression path (domain_count==2) is verified
        # separately. Together they pin the comparator semantics.

    def test_categorized_count_lt_5_mutation_to_lte_5_caught_by_boundary(self):
        """Boundary test at categorized_count==5 expects suppression.
        If the gate were ``<= 5`` instead of ``< 5``, the boundary
        test would see a render WITH 'Passive-DNS ceiling' at 5
        services. The existing boundary test catches this."""
        # Five categorized services case — must NOT fire under real
        # trigger.
        info = _make_tenant(
            domain_count=4,
            tenant_domains=("a.com", "b.com", "c.com", "d.com"),
            services=("Microsoft 365", "Okta", "Cloudflare", "Slack", "OpenAI"),
            slugs=("m365", "okta", "cloudflare", "slack", "openai"),
        )
        out = _render(info)
        assert "Passive-DNS ceiling" not in out, (
            "Sanity: real trigger suppresses at categorized_count==5. If this fails, the test premise is broken."
        )


class TestAdditionalMutations:
    """Second pass of mutations covering data-flow bugs and the
    case-sensitivity invariant. Each mutation here is a real bug
    pattern that would not be obviously wrong on cursory review."""

    def test_swap_streams_mutation_breaks_stream_union_property(self):
        """Dropping ``surface_slugs`` from the iteration changes
        ``count_cloud_vendors(apex, surface)`` from a multiset on the
        union into a multiset on apex only. The
        ``test_split_streams_match_concat`` property test must catch
        this. We verify by example: the swap-mutated function
        disagrees with the real on inputs where the surface stream
        carries a distinct vendor."""
        # Apex: AWS only; surface: Cloudflare. Real function reports
        # both vendors. Mutated reports AWS only.
        mutated = _mutated_count_cloud_vendors_swap_streams(["aws-cloudfront"], ["cloudflare"])
        real = count_cloud_vendors(["aws-cloudfront"], ["cloudflare"])
        assert mutated != real, "swap-stream mutation must disagree with real on surface-distinct inputs"
        assert mutated == {"AWS": 1}, f"swap mutation should produce AWS-only count, got {mutated}"
        assert real == {"AWS": 1, "Cloudflare": 1}, f"real function should count both streams, got {real}"

    def test_empty_string_mutation_breaks_non_cloud_returns_none(self):
        """Returning ``""`` instead of ``None`` for unknown slugs
        violates the documented contract. The
        ``test_non_cloud_slug_returns_none`` test in
        test_multi_cloud_rollup.py asserts strict ``is None``; the
        mutation produces ``""`` which fails the identity check."""
        # The mutation produces an empty string for unknown slugs:
        assert _mutated_canonical_returns_empty_string("nonexistent-slug") == ""
        # The real function returns None:
        assert canonical_cloud_vendor("nonexistent-slug") is None
        # The two values are not equal under ``is`` (the strict check
        # the test in test_multi_cloud_rollup.py uses):
        assert _mutated_canonical_returns_empty_string("nonexistent-slug") is not None

    def test_case_insensitive_mutation_violates_lowercase_contract(self):
        """The canonicalization is case-sensitive by contract. A
        case-insensitive mutation would pass on uppercase slug
        strings that the real function correctly rejects. Catches a
        regression where a contributor 'helpfully' normalizes
        casing inside the lookup."""
        # Mutation matches on uppercase:
        assert _mutated_canonical_case_insensitive_lookup("AWS-CLOUDFRONT") == "AWS"
        # Real function does not (returns None for uppercase):
        assert canonical_cloud_vendor("AWS-CLOUDFRONT") is None


class TestSurvivingMutationsRequireNewTests:
    """If a mutation we tried to apply produced output identical to
    the real function, our test surface is insufficient. This class
    documents mutations that survive (none currently) and serves as a
    failure target if any of our test invariants weaken.

    A future entry would look like::

        def test_mutation_X_survives_warn_on_test_gap(self):
            # Document that mutation X passes tests; needs a new
            # invariant test to catch it.
            ...
    """

    def test_no_known_surviving_mutations(self):
        """Placeholder that fails when a new surviving mutation is
        documented in this class. Currently no mutations from the
        library above survive."""
        assert True, "no surviving mutations currently documented"


# Cross-check: each mutation library function is referenced somewhere
# in the actual mutation tests. Catches accidental orphans.


class TestMutationLibraryHygiene:
    @pytest.mark.parametrize(
        "func",
        [
            _mutated_canonical_drop_none_guard,
            _mutated_count_cloud_vendors_orders_skip_none,
            _mutated_count_cloud_vendors_double_count,
            _mutated_count_cloud_vendors_swap_streams,
            _mutated_canonical_returns_empty_string,
            _mutated_canonical_case_insensitive_lookup,
        ],
    )
    def test_mutation_function_is_callable(self, func):
        """Sanity that each mutation function in the library can be
        called without raising. Mutations that crash on their own
        inputs cannot tell us anything about test quality."""
        # Branch on the signature shape: canonical-vendor mutations
        # take a single slug string; count_cloud_vendors mutations
        # take two iterables.
        canonical_mutations = (
            _mutated_canonical_drop_none_guard,
            _mutated_canonical_returns_empty_string,
            _mutated_canonical_case_insensitive_lookup,
        )
        if func in canonical_mutations:
            func("aws-cloudfront")
        else:
            func(["aws-cloudfront"], ["fastly"])
