"""DAG rendering for the v1.9 Bayesian fusion layer (EXPERIMENTAL).

Two outputs:

* ``render_dag_text`` — plain-English narrative describing each node's
  posterior, the evidence that fired, and the parent dependencies that
  shaped it. Designed to read aloud to a non-statistician.
* ``render_dag_dot`` — Graphviz DOT format for image rendering. Edge
  labels carry the conditional dependency, node labels carry the
  posterior + 80% credible interval. Pipe through ``dot -Tpng`` or
  paste into a Graphviz online viewer.

Neither renderer makes a network call; both operate on already-
computed inference output. Per the v1.9 invariants, the renderers
emit hedged language: "the posterior places X at probability ..."
rather than "X is true".
"""

from __future__ import annotations

from recon_tool.bayesian import BayesianNetwork, InferenceResult, NodePosterior

__all__ = [
    "render_dag_dot",
    "render_dag_text",
]


def _confidence_label(posterior: float, sparse: bool) -> str:
    """Return a hedged English confidence label for a posterior."""
    if sparse:
        # Passive-observation ceiling — language stays softer.
        if posterior >= 0.75:
            return "tentative high"
        if posterior >= 0.50:
            return "tentative moderate"
        if posterior >= 0.25:
            return "tentative low"
        return "tentative absent"
    if posterior >= 0.90:
        return "high-confidence"
    if posterior >= 0.70:
        return "moderate-confidence"
    if posterior >= 0.40:
        return "uncertain"
    if posterior >= 0.15:
        return "low-confidence"
    return "very-low-confidence"


def _node_evidence_phrase(posterior: NodePosterior) -> str:
    """Format the bound-evidence list as a readable phrase."""
    if not posterior.evidence_used:
        return "no direct evidence (posterior follows network priors and parent claims)"
    parts: list[str] = []
    for binding in posterior.evidence_used:
        kind, _, name = binding.partition(":")
        if kind == "slug":
            parts.append(f"slug `{name}`")
        elif kind == "signal":
            parts.append(f"signal `{name}`")
        else:
            parts.append(binding)
    return ", ".join(parts)


def _node_conflict_phrase(posterior: NodePosterior) -> str | None:
    """Format conflict_provenance as a readable phrase, or None when empty.

    Each conflict surfaces as ``field (source-a vs source-b) -Nu n_eff``
    so an operator can read both *what* disagreed and *which sources*
    drove the interval widening.
    """
    if not posterior.conflict_provenance:
        return None
    parts: list[str] = []
    for c in posterior.conflict_provenance:
        sources = " vs ".join(c.sources) if c.sources else "sources unrecorded"
        parts.append(f"`{c.field}` ({sources}, -{c.magnitude:.2f} n_eff)")
    return "; ".join(parts)


def render_dag_text(
    network: BayesianNetwork,
    result: InferenceResult,
    domain: str | None = None,
) -> str:
    """Render the inference result as a plain-English narrative.

    The text walks the network in topological order so parent claims
    explain themselves before children depend on them. Each node block
    states the posterior, the credible interval, the bound evidence
    that fired, and (when the node has parents) the structural
    dependency that shaped the prior.
    """
    by_name = {n.name: n for n in network.nodes}
    posteriors_by_name = {p.name: p for p in result.posteriors}

    # Topo order: roots first, children after. Re-derived locally from
    # the network so we don't rely on the order in result.posteriors.
    order: list[str] = []
    incoming = {n.name: set(n.parents) for n in network.nodes}
    queue = sorted(n for n, deps in incoming.items() if not deps)
    while queue:
        cur = queue.pop(0)
        order.append(cur)
        for child_name, deps in incoming.items():
            if cur in deps:
                deps.discard(cur)
                if not deps:
                    queue.append(child_name)
        queue.sort()

    lines: list[str] = []
    header_target = domain or "the queried domain"
    lines.append(f"# Bayesian evidence DAG — {header_target}")
    lines.append("")
    lines.append(
        f"Inference summary: {result.evidence_count} bound observation(s) across "
        f"{len(network.nodes)} node(s); total entropy reduction "
        f"{result.entropy_reduction:.3f} nats; "
        f"{result.conflict_count} cross-source conflict(s) dampening intervals."
    )
    lines.append("")
    lines.append(
        "Each node below is a discrete claim. The posterior is "
        "P(claim | observed evidence); the 80% credible interval reflects "
        "evidence sparsity and conflict. ``Sparse`` flags the passive-"
        "observation ceiling: when DNS / CT publishes little, the interval "
        "stays wide regardless of where the point estimate lands."
    )
    lines.append("")

    for name in order:
        node = by_name[name]
        post = posteriors_by_name[name]
        confidence = _confidence_label(post.posterior, post.sparse)
        evidence_phrase = _node_evidence_phrase(post)

        lines.append(f"## {node.name}")
        lines.append(f"_{node.description}_")
        lines.append("")
        lines.append(
            f"- **Posterior:** {post.posterior:.3f} "
            f"_(80% credible interval: [{post.interval_low:.3f}, {post.interval_high:.3f}], "
            f"n_eff={post.n_eff:.2f}{', sparse' if post.sparse else ''})_"
        )
        lines.append(f"- **Confidence label:** {confidence}")
        lines.append(f"- **Evidence:** {evidence_phrase}")
        conflict_phrase = _node_conflict_phrase(post)
        if conflict_phrase is not None:
            lines.append(f"- **Conflicts:** {conflict_phrase}")
        if node.parents:
            parent_phrases: list[str] = []
            for parent_name in node.parents:
                parent_post = posteriors_by_name.get(parent_name)
                if parent_post is None:
                    parent_phrases.append(f"`{parent_name}`")
                    continue
                parent_phrases.append(f"`{parent_name}` (posterior {parent_post.posterior:.3f})")
            lines.append(
                f"- **Depends on:** {', '.join(parent_phrases)} "
                f"— see CPT in `bayesian_network.yaml` for the conditional table."
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_dag_dot(
    network: BayesianNetwork,
    result: InferenceResult,
    domain: str | None = None,
) -> str:
    """Render the network + inference result as Graphviz DOT.

    Node label includes the description, posterior, and credible
    interval. Edges run parent → child; the parent's CPT shapes the
    child's prior, so the arrow direction matches dependency. Sparse
    nodes get a dashed border, dense nodes a solid one.
    """
    posteriors_by_name = {p.name: p for p in result.posteriors}
    title = domain or "domain"
    lines: list[str] = []
    lines.append(f'digraph "recon_bayesian_{title}" {{')
    lines.append("  rankdir=LR;")
    lines.append('  node [shape=box, style="rounded", fontname="Helvetica"];')
    lines.append('  edge [fontname="Helvetica", fontsize=10];')
    lines.append("")

    for node in network.nodes:
        post = posteriors_by_name.get(node.name)
        if post is None:
            label = node.name
            border = "solid"
            color = "black"
        else:
            conflict_suffix = ""
            if post.conflict_provenance:
                conflict_suffix = "\\nconflicts: " + ", ".join(c.field for c in post.conflict_provenance)
            label = (
                f"{node.name}\\n"
                f"{node.description}\\n"
                f"posterior {post.posterior:.3f}\\n"
                f"[{post.interval_low:.3f}, {post.interval_high:.3f}]"
                f"{' (sparse)' if post.sparse else ''}"
                f"{conflict_suffix}"
            )
            border = "dashed" if post.sparse else "solid"
            color = _color_for_posterior(post.posterior)
        # Escape any double quotes in labels — node names are slug-shaped
        # in our network, but description text could in principle contain
        # them. The replace is cheap and defensive.
        safe_label = label.replace('"', '\\"')
        lines.append(f'  "{node.name}" [label="{safe_label}", style="rounded,{border}", color="{color}"];')

    lines.append("")
    for node in network.nodes:
        for parent in node.parents:
            lines.append(f'  "{parent}" -> "{node.name}";')

    lines.append("}")
    return "\n".join(lines) + "\n"


def _color_for_posterior(posterior: float) -> str:
    """Map posterior to a Graphviz color hint. Hedged palette — no green
    for "good"; we render structural confidence, not safety judgment."""
    if posterior >= 0.85:
        return "navyblue"
    if posterior >= 0.60:
        return "steelblue"
    if posterior >= 0.40:
        return "gray40"
    if posterior >= 0.20:
        return "gray60"
    return "gray80"
