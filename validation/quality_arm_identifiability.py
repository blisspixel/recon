"""Audit whether the frozen v2.11 M365 arms identify a fusion benefit.

This is a structural, network-free check over the shipped code paths. It does
not read the private frame or any target data. The audit enumerates every
presence/absence combination of the DNS evidence roles that can carry a
``microsoft365`` fingerprint into the frozen arms.

Run with::

    python -m validation.quality_arm_identifiability

The JSON output contains only code-derived counts and model values. A violation
of any claimed relationship fails the process instead of publishing a partial
or misleading result.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import combinations
from types import SimpleNamespace

from recon_tool.bayesian import infer, load_network
from recon_tool.bayesian_observations import signals_from_tenant_info
from recon_tool.formatter.roles import POSTERIOR_DECISION_THRESHOLD as _POSTERIOR_DECISION_THRESHOLD
from recon_tool.fusion import compute_slug_posteriors
from recon_tool.models import EvidenceRecord

M365_SLUG = "microsoft365"
M365_NODE = "m365_tenant"

# DNS evidence roles admitted by the frozen predictor channel. TXT and SPF can
# deterministically identify an M365 catalog match, but the shipped role adapter
# deliberately excludes them from the tenancy node. The other four types can
# set ``m365_tenant_observed``.
DNS_EVIDENCE_TYPES = ("TXT", "SPF", "MX", "DKIM", "CNAME", "SRV")
ROLE_BEARING_TYPES = frozenset({"MX", "DKIM", "CNAME", "SRV"})


@dataclass(frozen=True, slots=True)
class ArmState:
    """Binary decisions and diagnostics for one abstract DNS evidence state."""

    evidence_types: tuple[str, ...]
    a0_supported: bool
    a1_supported: bool
    a2_supported: bool
    a3_supported: bool
    a1_score: float | None
    a3_posterior: float
    role_signal_observed: bool


def _all_type_subsets() -> tuple[tuple[str, ...], ...]:
    """Return every subset in deterministic cardinality and lexical order."""
    return tuple(
        subset for size in range(len(DNS_EVIDENCE_TYPES) + 1) for subset in combinations(DNS_EVIDENCE_TYPES, size)
    )


def _evidence(types: tuple[str, ...]) -> tuple[EvidenceRecord, ...]:
    """Create identifier-free evidence occurrences for abstract role states."""
    return tuple(
        EvidenceRecord(
            source_type=source_type,
            raw_value=f"synthetic-{source_type.casefold()}-observation",
            rule_name="Synthetic Microsoft 365 rule",
            slug=M365_SLUG,
        )
        for source_type in types
    )


def evaluate_state(types: tuple[str, ...]) -> ArmState:
    """Evaluate all four frozen arm interpretations for one evidence state."""
    if tuple(source_type for source_type in DNS_EVIDENCE_TYPES if source_type in types) != types:
        raise ValueError("evidence types must be unique and follow the frozen order")

    evidence = _evidence(types)
    # A0 follows the preregistered rule: any deterministic M365 DNS rule is a
    # supported emission. Every occurrence here represents exactly such a fire.
    a0_supported = bool(evidence)

    slug_scores = dict(compute_slug_posteriors(evidence))
    a1_score = slug_scores.get(M365_SLUG)
    # compute_slug_posteriors has no separate emission API. The only direct
    # binary interpretation of its shipped output is whether it emits the slug.
    a1_supported = a1_score is not None

    info = SimpleNamespace(
        auth_type=None,
        google_auth_type=None,
        google_idp_name=None,
        tenant_id=None,
        email_gateway=None,
        dmarc_policy=None,
        dmarc_pct=None,
        dmarc_testing=False,
        mta_sts_mode=None,
        degraded_sources=(),
        evidence=evidence,
    )
    signals = signals_from_tenant_info(info)
    role_signal_observed = "m365_tenant_observed" in signals
    inference = infer(load_network(), observed_slugs=(), observed_signals=signals, priors_override={})
    node = next(item for item in inference.posteriors if item.name == M365_NODE)

    # A2 is the strongest reviewed direct binding. A positive LLR produces a
    # supported emission; no contributing binding abstains. evidence_ranked is
    # the shipped post-group-reduction representation of those bindings.
    a2_supported = bool(node.evidence_ranked and node.evidence_ranked[0].llr > 0.0)
    # A3 uses the one threshold the shipped panel applies to model support.
    a3_supported = node.posterior >= _POSTERIOR_DECISION_THRESHOLD
    return ArmState(
        evidence_types=types,
        a0_supported=a0_supported,
        a1_supported=a1_supported,
        a2_supported=a2_supported,
        a3_supported=a3_supported,
        a1_score=a1_score,
        a3_posterior=node.posterior,
        role_signal_observed=role_signal_observed,
    )


def run_audit() -> dict[str, object]:
    """Return the fail-closed structural-identifiability report."""
    network = load_network()
    node = network.get(M365_NODE)
    states = tuple(evaluate_state(types) for types in _all_type_subsets())

    violations: list[str] = []
    if len(node.evidence) != 1:
        violations.append("m365_tenant no longer has exactly one direct evidence binding")
    if node.evidence and (node.evidence[0].kind, node.evidence[0].name) != (
        "signal",
        "m365_tenant_observed",
    ):
        violations.append("m365_tenant direct binding changed")
    if any(state.a0_supported != state.a1_supported for state in states):
        violations.append("A1 no longer collapses to A0")
    if any(state.a2_supported != state.a3_supported for state in states):
        violations.append("A2 no longer collapses to A3")
    if any(state.a3_supported and not state.a0_supported for state in states):
        violations.append("A3 is no longer structurally dominated by A0")
    if any(state.role_signal_observed != bool(set(state.evidence_types) & ROLE_BEARING_TYPES) for state in states):
        violations.append("the shipped M365 role adapter changed")
    if violations:
        raise RuntimeError("; ".join(violations))

    candidate_only = tuple(state for state in states if state.a3_supported and not state.a0_supported)
    baseline_only = tuple(state for state in states if state.a0_supported and not state.a3_supported)
    posteriors = sorted({state.a3_posterior for state in states})
    a1_scores = sorted({state.a1_score for state in states if state.a1_score is not None})
    return {
        "schema_version": 1,
        "scope": "v2.11-m365-dns-arm-structural-identifiability",
        "network_requests": 0,
        "private_rows_read": 0,
        "enumerated_states": len(states),
        "dns_evidence_types": list(DNS_EVIDENCE_TYPES),
        "role_bearing_types": sorted(ROLE_BEARING_TYPES),
        "model": {
            "node": M365_NODE,
            "direct_binding_count": len(node.evidence),
            "direct_bindings": [f"{item.kind}:{item.name}" for item in node.evidence],
            "decision_threshold": _POSTERIOR_DECISION_THRESHOLD,
            "possible_posteriors": posteriors,
        },
        "arm_relationships": {
            "a1_equals_a0_all_states": True,
            "a2_equals_a3_all_states": True,
            "a3_implies_a0_all_states": True,
            "candidate_only_state_count": len(candidate_only),
            "baseline_only_state_count": len(baseline_only),
            "baseline_only_evidence_types": [list(state.evidence_types) for state in baseline_only],
            "a1_possible_scores": a1_scores,
        },
        "decision_consequence": {
            "candidate_only_positive_discordance_b_is_always_zero": True,
            "benefit_lower_bound_can_clear_zero": False,
            "live_ablation_identifies_fusion_benefit": False,
            "collection_disposition": "cancel-before-contact",
        },
    }


def main() -> int:
    """Print the aggregate, identifier-free audit report."""
    print(json.dumps(run_audit(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
