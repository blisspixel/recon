"""Tests for the v1.9 Bayesian DAG renderers (text, DOT, and Mermaid)."""

from __future__ import annotations

import pytest

from recon_tool.bayesian import infer, load_network
from recon_tool.bayesian_dag import (
    _color_for_posterior,
    _model_support_label,
    _node_evidence_phrase,
    render_dag_dot,
    render_dag_mermaid,
    render_dag_text,
)


@pytest.fixture
def network():
    return load_network()


@pytest.fixture
def dense_inference(network):
    return infer(
        network,
        observed_slugs=[],
        observed_signals=[
            "m365_tenant_observed",
            "okta_idp_observed",
            "federated_sso_hub",
            "dmarc_reject",
            "dkim_present",
        ],
        priors_override={},
    )


@pytest.fixture
def sparse_inference(network):
    return infer(network, [], [], priors_override={})


class TestTextRenderer:
    def test_includes_domain_in_header(self, network, dense_inference):
        out = render_dag_text(network, dense_inference, domain="alpha.invalid")
        assert "alpha.invalid" in out

    def test_default_header_when_no_domain(self, network, dense_inference):
        out = render_dag_text(network, dense_inference)
        assert "the queried domain" in out

    def test_includes_inference_summary(self, network, dense_inference):
        out = render_dag_text(network, dense_inference)
        assert "fired bound observation" in out
        assert "summed marginal entropy change" in out

    def test_each_node_appears(self, network, dense_inference):
        out = render_dag_text(network, dense_inference)
        for node in network.nodes:
            assert f"## {node.name}" in out

    def test_topological_order(self, network, dense_inference):
        out = render_dag_text(network, dense_inference)
        # Parents must appear before children. m365_tenant is a parent
        # of federated_identity, which is a parent of okta_idp.
        m365_idx = out.index("## m365_tenant")
        fed_idx = out.index("## federated_identity")
        okta_idx = out.index("## okta_idp")
        assert m365_idx < fed_idx < okta_idx

    def test_evidence_listed(self, network, dense_inference):
        out = render_dag_text(network, dense_inference)
        assert "signal `m365_tenant_observed`" in out
        # federated_sso_hub signal fired for federated_identity
        assert "signal `federated_sso_hub`" in out

    def test_no_evidence_phrase_for_unbound_nodes(self, network, sparse_inference):
        out = render_dag_text(network, sparse_inference)
        assert "no direct evidence" in out

    def test_parent_dependency_listed(self, network, dense_inference):
        out = render_dag_text(network, dense_inference)
        # okta_idp depends on federated_identity
        # The dependency line includes the parent name.
        section_start = out.index("## okta_idp")
        section = out[section_start : section_start + 800]
        assert "Depends on:" in section
        assert "federated_identity" in section

    def test_model_support_label_for_dense_evidence(self, network, dense_inference):
        out = render_dag_text(network, dense_inference)
        assert "high model support" in out
        assert "Confidence label" not in out

    def test_sparse_label_for_no_evidence(self, network, sparse_inference):
        out = render_dag_text(network, sparse_inference)
        # All nodes are sparse, so model-support language should be tentative.
        assert "tentative" in out

    def test_ends_with_newline(self, network, dense_inference):
        out = render_dag_text(network, dense_inference)
        assert out.endswith("\n")


class TestDotRenderer:
    def test_well_formed_digraph(self, network, dense_inference):
        out = render_dag_dot(network, dense_inference, domain="alpha.invalid")
        assert out.startswith('digraph "recon_bayesian_alpha.invalid" {')
        assert out.rstrip().endswith("}")

    def test_one_node_per_network_node(self, network, dense_inference):
        out = render_dag_dot(network, dense_inference, domain="x")
        for node in network.nodes:
            assert f'"{node.name}"' in out

    def test_edges_render_parent_to_child(self, network, dense_inference):
        out = render_dag_dot(network, dense_inference, domain="x")
        # m365_tenant -> federated_identity must be present
        assert '"m365_tenant" -> "federated_identity"' in out
        # google_workspace_tenant -> federated_identity (v1.9.3 expansion)
        assert '"google_workspace_tenant" -> "federated_identity"' in out
        # federated_identity -> okta_idp
        assert '"federated_identity" -> "okta_idp"' in out

    def test_sparse_nodes_are_dashed(self, network, sparse_inference):
        out = render_dag_dot(network, sparse_inference, domain="x")
        # Dashed style marks sparse nodes. Declarative nodes (CAL14) condition on
        # absence so they are not sparse even under no evidence; count the
        # actually-sparse posteriors rather than assuming every node is.
        dashed_count = out.count("rounded,dashed")
        assert dashed_count == sum(1 for p in sparse_inference.posteriors if p.sparse)

    def test_dense_nodes_are_solid(self, network, dense_inference):
        out = render_dag_dot(network, dense_inference, domain="x")
        # m365_tenant has 2 pieces of evidence → not sparse → solid
        m365_lines = [line for line in out.splitlines() if '"m365_tenant"' in line and "label=" in line]
        assert len(m365_lines) == 1
        assert "rounded,solid" in m365_lines[0]

    def test_label_includes_posterior(self, network, dense_inference):
        out = render_dag_dot(network, dense_inference, domain="x")
        # All posterior values that fired should appear in DOT labels
        for p in dense_inference.posteriors:
            assert f"posterior {p.posterior:.3f}" in out


class TestHelpers:
    def test_model_support_label_high_dense(self):
        assert _model_support_label(0.95, sparse=False) == "high model support"

    def test_model_support_label_moderate_dense(self):
        assert _model_support_label(0.75, sparse=False) == "moderate model support"

    def test_model_support_label_ambiguous_dense(self):
        assert _model_support_label(0.45, sparse=False) == "threshold-ambiguous model support"

    def test_model_support_label_sparse_high(self):
        assert _model_support_label(0.85, sparse=True) == "tentative high model support"

    def test_model_support_label_sparse_low(self):
        assert _model_support_label(0.10, sparse=True) == "tentative low model support"

    def test_model_support_label_sparse_declarative_absence(self):
        assert (
            _model_support_label(0.10, sparse=True, absence_informative=True) == "tentative support for public absence"
        )

    def test_color_palette_monotonic(self):
        # Higher posterior → "stronger" color in our hedged palette
        c1 = _color_for_posterior(0.05)
        c2 = _color_for_posterior(0.50)
        c3 = _color_for_posterior(0.95)
        assert c1 != c2 != c3

    def test_node_evidence_phrase_empty(self):
        from recon_tool.bayesian import NodePosterior

        p = NodePosterior(
            name="x",
            description="y",
            posterior=0.5,
            interval_low=0.0,
            interval_high=1.0,
            evidence_used=(),
            n_eff=4.0,
            sparse=True,
        )
        assert "no direct evidence" in _node_evidence_phrase(p)

    def test_node_evidence_phrase_mixed(self):
        from recon_tool.bayesian import NodePosterior

        p = NodePosterior(
            name="x",
            description="y",
            posterior=0.5,
            interval_low=0.0,
            interval_high=1.0,
            evidence_used=("slug:foo", "signal:bar"),
            n_eff=4.0,
            sparse=False,
        )
        out = _node_evidence_phrase(p)
        assert "slug `foo`" in out
        assert "signal `bar`" in out

    def test_node_evidence_phrase_unknown_kind(self):
        from recon_tool.bayesian import NodePosterior

        p = NodePosterior(
            name="x",
            description="y",
            posterior=0.5,
            interval_low=0.0,
            interval_high=1.0,
            evidence_used=("custom:xyz",),
            n_eff=4.0,
            sparse=False,
        )
        out = _node_evidence_phrase(p)
        # Unknown-kind binding renders as-is rather than crashing
        assert "custom:xyz" in out


class TestMermaidRenderer:
    def test_starts_with_graph_lr_header(self, network, dense_inference):
        out = render_dag_mermaid(network, dense_inference, domain="alpha.invalid")
        # Mermaid requires the direction directive on the first non-comment line.
        # Header comment (`%% ...`) carries the domain so an agent can identify the run.
        assert "%% recon Bayesian DAG for alpha.invalid" in out
        assert "graph LR" in out

    def test_includes_every_network_node(self, network, dense_inference):
        out = render_dag_mermaid(network, dense_inference, domain="x")
        for node in network.nodes:
            # Node lines look like `m365_tenant["label..."]`
            assert f"{node.name}[" in out

    def test_edges_render_parent_to_child(self, network, dense_inference):
        out = render_dag_mermaid(network, dense_inference, domain="x")
        # Same structural edges the DOT renderer asserts on.
        assert "m365_tenant --> federated_identity" in out
        assert "google_workspace_tenant --> federated_identity" in out
        assert "federated_identity --> okta_idp" in out

    def test_sparse_nodes_get_dashed_style(self, network, sparse_inference):
        out = render_dag_mermaid(network, sparse_inference, domain="x")
        # Sparse → dashed border via Mermaid `style ... stroke-dasharray`.
        # Declarative nodes (CAL14) are not sparse even under no evidence; count
        # the actually-sparse posteriors.
        dashed_count = out.count("stroke-dasharray:5 5")
        assert dashed_count == sum(1 for p in sparse_inference.posteriors if p.sparse)

    def test_dense_nodes_have_no_dash(self, network, dense_inference):
        out = render_dag_mermaid(network, dense_inference, domain="x")
        # The m365_tenant style line should not carry a dash directive
        m365_style = [line for line in out.splitlines() if line.strip().startswith("style m365_tenant ")]
        assert len(m365_style) == 1
        assert "stroke-dasharray" not in m365_style[0]

    def test_labels_use_html_br_for_line_breaks(self, network, dense_inference):
        out = render_dag_mermaid(network, dense_inference, domain="x")
        # Mermaid quoted labels render `<br/>` as a line break.
        assert "<br/>" in out
        # Raw \n inside a quoted label would break the renderer.
        # Find any quoted label and confirm no literal newline inside it.
        # (We just check the file as a whole has the html break form.)
        assert "posterior " in out

    def test_label_includes_posterior(self, network, dense_inference):
        out = render_dag_mermaid(network, dense_inference, domain="x")
        for p in dense_inference.posteriors:
            assert f"posterior {p.posterior:.3f}" in out

    def test_double_quote_in_description_is_html_escaped(self):
        from recon_tool.bayesian_dag import _mermaid_escape_label

        # Mermaid's quoted-label form requires HTML entity for `"`.
        escaped = _mermaid_escape_label('a "quoted" thing\nsecond line')
        assert '"' not in escaped.replace("&quot;", "")  # all `"` became entities
        assert "&quot;" in escaped
        assert "<br/>" in escaped
