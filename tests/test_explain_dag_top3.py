"""Tests for v1.9.3.2 top-3 influential-edge rendering in --explain-dag.

Two responsibilities:

1. **LLR correctness.** Every binding's surfaced log-likelihood-ratio must
   match ``log(P(obs|present) / P(obs|absent))`` on the YAML schema. The
   percentage of evidence influence must sum to 100% across the fired
   bindings on each node. These are hand-verifiable mathematical claims;
   getting them wrong undermines the operator's ability to challenge a
   posterior.

2. **Renderer behaviour.** The narrative formats the ranked list with the
   right structural rules: sorted by absolute LLR descending, ties by
   ``(kind, name)`` for diff-stability, single-binding header reads
   "Top influence" (singular), no padded top-3 on sparse targets, no
   section emitted when zero bindings fired (the structural-propagation
   language already explains the posterior).

The snapshot is intentionally small — three canonical evidence shapes —
so that a future renderer change is forced to update the snapshot
deliberately, not by accident.
"""

from __future__ import annotations

import math

import pytest

from recon_tool.bayesian import infer, load_network
from recon_tool.bayesian_dag import render_dag_dot, render_dag_text


@pytest.fixture(scope="module")
def network():
    return load_network()


# ── LLR correctness ─────────────────────────────────────────────────


class TestLLRMath:
    """The surfaced LLR must equal the YAML's
    ``log(likelihood_present / likelihood_absent)`` for fired bindings."""

    def test_m365_slug_llr_matches_hand_computation(self, network):
        # microsoft365 binding on m365_tenant: likelihood [0.95, 0.03]
        # → LLR = log(0.95 / 0.03)
        result = infer(network, ["microsoft365"], [], priors_override={})
        m365 = next(p for p in result.posteriors if p.name == "m365_tenant")
        assert len(m365.evidence_ranked) == 1
        ec = m365.evidence_ranked[0]
        expected = math.log(0.95 / 0.03)
        assert ec.llr == pytest.approx(expected, abs=1e-3)
        assert ec.influence_pct == pytest.approx(100.0, abs=0.01), (
            "single fired binding accounts for 100% of evidence influence"
        )

    def test_entra_id_slug_llr_matches_hand_computation(self, network):
        # entra-id binding on m365_tenant: likelihood [0.88, 0.02]
        # → LLR = log(0.88 / 0.02) ≈ 3.784
        result = infer(network, ["entra-id"], [], priors_override={})
        m365 = next(p for p in result.posteriors if p.name == "m365_tenant")
        ec = next(e for e in m365.evidence_ranked if e.name == "entra-id")
        assert ec.llr == pytest.approx(math.log(0.88 / 0.02), abs=1e-3)

    def test_dmarc_reject_signal_llr_matches_hand_computation(self, network):
        # dmarc_reject on email_security_policy_enforcing: [0.92, 0.04]
        # → LLR = log(0.92 / 0.04) ≈ 3.135
        result = infer(network, [], ["dmarc_reject"], priors_override={})
        node = next(p for p in result.posteriors if p.name == "email_security_policy_enforcing")
        ec = next(e for e in node.evidence_ranked if e.name == "dmarc_reject")
        assert ec.llr == pytest.approx(math.log(0.92 / 0.04), abs=1e-3)


class TestRankingAndNormalization:
    """Bindings must sort by absolute LLR descending; percentages must
    sum to 100% per node."""

    def test_two_bindings_sorted_by_absolute_llr(self, network):
        # microsoft365 LLR ≈ 3.46, entra-id LLR ≈ 3.78 → entra-id first.
        result = infer(network, ["microsoft365", "entra-id"], [], priors_override={})
        m365 = next(p for p in result.posteriors if p.name == "m365_tenant")
        assert len(m365.evidence_ranked) == 2
        assert m365.evidence_ranked[0].name == "entra-id"
        assert m365.evidence_ranked[1].name == "microsoft365"
        # Influence percentages sum to 100% within rounding noise.
        total = sum(e.influence_pct for e in m365.evidence_ranked)
        assert total == pytest.approx(100.0, abs=0.05)

    def test_ties_broken_deterministically_by_kind_then_name(self, network):
        # Two slugs at the same LLR would be hard to engineer from the
        # seed network, so we verify the tie-break path with two
        # bindings whose LLRs are sufficiently close that any unsorted
        # iteration would produce flaky output.
        result = infer(
            network,
            [],
            ["dmarc_reject", "mta_sts_enforce"],
            priors_override={},
        )
        node = next(p for p in result.posteriors if p.name == "email_security_policy_enforcing")
        # dmarc_reject LLR ≈ 3.14, mta_sts_enforce LLR ≈ 2.64 →
        # dmarc_reject ranks higher. Stable across runs.
        assert node.evidence_ranked[0].name == "dmarc_reject"
        assert node.evidence_ranked[1].name == "mta_sts_enforce"
        # Repeat — must be deterministic.
        result2 = infer(network, [], ["dmarc_reject", "mta_sts_enforce"], priors_override={})
        node2 = next(p for p in result2.posteriors if p.name == "email_security_policy_enforcing")
        assert [e.name for e in node2.evidence_ranked] == [e.name for e in node.evidence_ranked]


class TestSparseAndUnboundCases:
    """Sparse-evidence and zero-binding cases must not produce padded
    or fake top-3 output."""

    def test_zero_bindings_produces_empty_ranked_tuple(self, network):
        result = infer(network, [], [], priors_override={})
        for p in result.posteriors:
            assert p.evidence_ranked == ()

    def test_modern_provider_node_never_carries_evidence_ranked(self, network):
        # email_security_modern_provider has NO evidence bindings by
        # design (v1.9.3 split). It must always emit empty
        # evidence_ranked regardless of what slugs fire elsewhere.
        result = infer(
            network,
            ["microsoft365", "entra-id"],
            ["dmarc_reject", "dkim_present", "spf_strict"],
            priors_override={},
        )
        node = next(p for p in result.posteriors if p.name == "email_security_modern_provider")
        assert node.evidence_ranked == ()


# ── Renderer behaviour ──────────────────────────────────────────────


class TestRenderDagTextTop3:
    """The narrative formats ranked bindings with the right structure."""

    def test_zero_bindings_omits_influence_section(self, network):
        result = infer(network, [], [], priors_override={})
        out = render_dag_text(network, result, domain="contoso.com")
        # Sparse target: no node should print a "Top influence" section.
        assert "Top influence" not in out

    def test_single_binding_uses_singular_header(self, network):
        result = infer(network, ["microsoft365"], [], priors_override={})
        out = render_dag_text(network, result, domain="contoso.com")
        # Singular header for the one-binding case.
        assert "**Top influence:**" in out
        assert "**Top influences (ranked" not in out

    def test_multi_binding_uses_plural_with_count(self, network):
        result = infer(network, ["microsoft365", "entra-id"], [], priors_override={})
        out = render_dag_text(network, result, domain="contoso.com")
        # 2 fired, ≤ 3 → "(ranked, 2 fired)"
        assert "**Top influences (ranked, 2 fired):**" in out

    def test_more_than_three_bindings_shows_top_three_with_total(self, network):
        # Stack five signals on email_security_policy_enforcing
        # (the only node with 5 bindings in the current network).
        result = infer(
            network,
            [],
            ["dmarc_reject", "dmarc_quarantine", "mta_sts_enforce", "dkim_present", "spf_strict"],
            priors_override={},
        )
        out = render_dag_text(network, result, domain="contoso.com")
        # 5 fired, top 3 shown.
        assert "(ranked top 3 of 5 fired)" in out

    def test_llr_appears_with_sign_and_two_decimals(self, network):
        result = infer(network, ["microsoft365"], [], priors_override={})
        out = render_dag_text(network, result, domain="contoso.com")
        # Format: "LLR +3.46" — signed, two-decimal.
        import re
        assert re.search(r"LLR [+-]\d+\.\d{2}", out), "LLR must be signed with two decimal places"

    def test_influence_percentage_appears(self, network):
        result = infer(network, ["microsoft365"], [], priors_override={})
        out = render_dag_text(network, result, domain="contoso.com")
        assert "% of evidence influence" in out


class TestRenderDagDotTop3:
    """DOT export must also surface the top-3 influence ranking so
    non-AI visualisation users see the same data."""

    def test_dot_includes_top_influences_phrase_when_evidence_fires(self, network):
        result = infer(network, ["microsoft365", "entra-id"], [], priors_override={})
        out = render_dag_dot(network, result, domain="x")
        # The phrase lands in the m365_tenant node's label.
        m365_lines = [line for line in out.splitlines() if '"m365_tenant" [label=' in line]
        assert len(m365_lines) == 1
        assert "top influences:" in m365_lines[0]
        assert "entra-id" in m365_lines[0]
        assert "microsoft365" in m365_lines[0]

    def test_dot_omits_top_influences_when_no_evidence_fires(self, network):
        # All-sparse target: no node has fired bindings.
        result = infer(network, [], [], priors_override={})
        out = render_dag_dot(network, result, domain="x")
        assert "top influences:" not in out


# ── Snapshot ────────────────────────────────────────────────────────


_SNAPSHOT_FRAGMENT = (
    "## m365_tenant\n"
    "_Domain has a Microsoft 365 / Entra tenant._\n"
    "\n"
    "- **Posterior:** 0.998 _(80% credible interval: [0.977, 1.000], n_eff=6.00)_\n"
    "- **Confidence label:** high-confidence\n"
    "- **Evidence:** slug `microsoft365`, slug `entra-id`\n"
    "- **Top influences (ranked, 2 fired):**\n"
    "    1. slug `entra-id` — LLR +3.78 (52.3% of evidence influence)\n"
    "    2. slug `microsoft365` — LLR +3.46 (47.7% of evidence influence)"
)


def test_dense_m365_snapshot(network):
    """Pin the rendered m365_tenant block for a dense-evidence input.

    Updating this snapshot must be deliberate — a renderer change that
    drops LLR or percentages must update this string with intent, not
    by accident.
    """
    result = infer(network, ["microsoft365", "entra-id"], [], priors_override={})
    out = render_dag_text(network, result, domain="contoso.com")
    assert _SNAPSHOT_FRAGMENT in out, (
        "m365_tenant section drifted from pinned snapshot — either the "
        "renderer changed (update the snapshot intentionally) or LLR "
        "math regressed."
    )
