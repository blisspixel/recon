"""Regression cases for model-relative explanations and graph syntax boundaries."""

from __future__ import annotations

from dataclasses import replace

from markdown_it import MarkdownIt

from recon_tool.bayesian import BayesianNetwork, infer, load_network
from recon_tool.bayesian_dag import render_dag_dot, render_dag_mermaid, render_dag_text
from recon_tool.bayesian_models import Node


def test_sparse_parent_can_move_from_child_evidence() -> None:
    network = load_network()
    result = infer(network, [], ["federated_sso_hub"], priors_override={})
    parent = next(post for post in result.posteriors if post.name == "m365_tenant")
    assert parent.evidence_used == ()
    assert parent.sparse
    assert parent.posterior == 0.5199
    assert parent.posterior != network.get(parent.name).prior
    rendered = render_dag_text(network, result)
    assert "evidence at connected nodes" in rendered
    assert "posterior follows network priors and parent claims" not in rendered


def test_conflict_changes_band_mass_but_not_mean_or_proper_score() -> None:
    network = load_network()
    signals = ["m365_tenant_observed", "federated_sso_hub", "dmarc_reject"]
    baseline = infer(network, [], signals, priors_override={})
    conflicted = infer(network, [], signals, conflict_field_count=1, priors_override={})
    assert any(
        left.n_eff != right.n_eff for left, right in zip(baseline.posteriors, conflicted.posteriors, strict=True)
    )
    for left, right in zip(baseline.posteriors, conflicted.posteriors, strict=True):
        assert left.posterior == right.posterior
        assert left.entropy_reduction_nats == right.entropy_reduction_nats
        assert right.n_eff <= left.n_eff


def test_influence_explanation_renders_real_nested_lists_and_qualifies_shares() -> None:
    network = load_network()
    result = infer(network, [], ["dmarc_reject"], priors_override={})
    policy = next(post for post in result.posteriors if post.name == "email_security_policy_enforcing")
    assert policy.evidence_ranked[0].influence_pct == 100.0
    assert policy.absence_informative
    assert any(unit.observed == "absent" for unit in policy.unit_counterfactuals)
    rendered = render_dag_text(network, result)
    assert "% of local fired |LLR|" in rendered
    assert "not percentages of the posterior change" in rendered
    assert any(token.type == "ordered_list_open" for token in MarkdownIt().parse(rendered))
    assert "\u2014" not in rendered


def _custom_network() -> BayesianNetwork:
    root = Node(
        name="end",
        description='literal \\N and \\"quote" <b>markup</b> &amp;\r\nsecond line',
        parents=(),
        prior=0.5,
        cpt={},
        evidence=(),
    )
    child = Node(
        name='child"; injected -> node; //',
        description="child",
        parents=(root.name,),
        prior=None,
        cpt={"end=present": 0.8, "end=absent": 0.2},
        evidence=(),
    )
    # The generated alias for root must not collide with this valid identifier.
    collision = replace(root, name="recon_node_0", description="ordinary")
    return BayesianNetwork(version=1, nodes=(root, child, collision))


def test_dot_quotes_identifiers_and_preserves_literal_backslashes() -> None:
    network = _custom_network()
    rendered = render_dag_dot(network, infer(network, [], [], priors_override={}), domain='x"\r\ninjected')
    assert rendered.startswith('digraph "recon_bayesian_x\\"\\ninjected" {\n')
    assert '"child\\"; injected -> node; //" [label=' in rendered
    assert '"end" -> "child\\"; injected -> node; //";' in rendered
    assert "literal \\\\N" in rendered
    assert '\\\\\\"quote\\"' in rendered
    assert "&amp;\\nsecond line" in rendered
    assert "\r" not in rendered


def test_mermaid_aliases_custom_identifiers_and_escapes_literal_markup() -> None:
    network = _custom_network()
    rendered = render_dag_mermaid(
        network, infer(network, [], [], priors_override={}), domain="x\r\nsubgraph unexpected"
    )
    assert rendered.startswith("%% recon Bayesian DAG for x subgraph unexpected\ngraph LR\n")
    assert 'recon_node_0_["end<br/>' in rendered
    assert 'recon_node_0["recon_node_0<br/>' in rendered
    assert "recon_node_0_ --> recon_node_1" in rendered
    assert "style recon_node_1 " in rendered
    assert "end -->" not in rendered
    assert "<b>" not in rendered
    assert "&lt;b&gt;markup&lt;/b&gt; &amp;amp;<br/>second line" in rendered
    assert "\r" not in rendered
