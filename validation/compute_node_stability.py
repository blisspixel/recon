"""Per-node stability metrics for the v1.9 Bayesian layer (v1.9.5).

Implements the three stability criteria from ``docs/roadmap.md`` §v1.9.5:

* **(b1) Det-positive → Bayesian high.** When ``evidence_used`` is
  non-empty (the deterministic pipeline observed bindings firing) and
  ``sparse=false``, the posterior should be > 0.5 and the credible
  interval should not span the full [0, 1] range.
* **(b2) Det-silent → interval widens.** When ``evidence_used`` is
  empty (no deterministic bindings fired), the posterior should be
  flagged ``sparse=true`` (the layer's own signal that it widened the
  interval rather than collapsing on a confident point estimate).
* **(c) Independent firings.** Number of distinct domains where
  ``evidence_used`` is non-empty for this node, across the combined
  hardened + soft corpus.

Brier score, log-score, and expected calibration error are also
emitted as diagnostics — bad numbers on the deterministic-pipeline
proxy label flag a node for CPT / topology re-examination, but are
not auto-failure criteria (see roadmap §v1.9.5).

Reads gitignored hardened + soft NDJSON; emits anonymized aggregates
only. Output is publicly-reproducible.

Invocation:

    python -m validation.compute_node_stability \\
        --hardened validation/corpus-private/v1.9.4-hardened/results.ndjson \\
        --soft     validation/runs-private/v1.9.4-soft-rerun/results.ndjson \\
        [--json-out validation/v1.9.5-stability.json]
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Threshold constants — keep here so the verdict table can cite them
# directly without re-deriving the rationale.
ECE_MAX_FOR_STABLE = 0.20        # roadmap §v1.9.5 criterion (b) diagnostic
BRIER_MAX_FOR_STABLE = 0.15      # binary forecast companion to ECE
FIRING_MIN_FOR_STABLE = 10       # roadmap §v1.9.5 criterion (c)
N_ECE_BINS = 10
# Deterministic-pipeline "high confidence" threshold for slug bindings.
# Roadmap §v1.9.5 criterion (b1) is phrased "when the deterministic
# pipeline classifies the slug HIGH"; this is the boundary recon's
# fingerprint scoring uses internally for the high / medium / low
# confidence tier.
DET_HIGH_CONFIDENCE_THRESHOLD = 0.7


# Active v1.9.3+ network nodes (skip the deprecated email_security_strong;
# the analyzer reports on whatever appears in ``posterior_observations``).
_KNOWN_NODES = (
    "m365_tenant",
    "google_workspace_tenant",
    "federated_identity",
    "okta_idp",
    "email_gateway_present",
    "email_security_modern_provider",
    "email_security_policy_enforcing",
    "cdn_fronting",
    "aws_hosting",
)

# Nodes whose evidence is entirely propagated from parents — no direct
# slug or signal bindings in ``bayesian_network.yaml``. For these nodes,
# criterion (c) "at least 10 distinct firings" is structurally
# inapplicable: ``evidence_used`` is always empty by design. The
# verdict logic marks (c) as ``n/a`` for these and gates stability on
# (a) and (b) only.
_PURE_PROPAGATION_NODES = frozenset({"email_security_modern_provider"})


@dataclass
class NodeRollup:
    """Per-node aggregates across the combined corpus."""

    name: str
    total_obs: int = 0
    sparse_obs: int = 0
    det_positive_obs: int = 0     # ``evidence_used`` non-empty
    det_silent_obs: int = 0       # ``evidence_used`` empty

    # Criterion (b1): det-positive non-sparse observations whose
    # posterior is > 0.5 AND interval ≠ full [0, 1].
    b1_eligible: int = 0
    b1_passing: int = 0

    # Criterion (b2): det-silent observations that are sparse=true.
    b2_eligible: int = 0
    b2_passing: int = 0

    # Criterion (c): distinct firing-domain count.
    firing_domains: set[str] = field(default_factory=set)

    # Diagnostics: Brier, log-score, ECE inputs.
    # We collect (posterior, label) pairs for every non-sparse observation;
    # sparse observations are excluded from calibration scoring because
    # the layer has explicitly flagged "I'm not predicting confidently."
    predictions: list[tuple[float, int]] = field(default_factory=list)


def _has_high_confidence_binding(
    evidence_used: list[str],
    slug_confidences: dict[str, float],
) -> bool:
    """Return True iff at least one fired binding is a high-confidence
    deterministic verdict.

    Slug bindings are high iff the deterministic pipeline scored the
    slug at ≥ ``DET_HIGH_CONFIDENCE_THRESHOLD``. Signal bindings fire
    binary — presence in ``evidence_used`` is itself the strong verdict.
    """
    for binding in evidence_used:
        if binding.startswith("signal:"):
            return True
        if binding.startswith("slug:"):
            slug = binding.removeprefix("slug:")
            if slug_confidences.get(slug, 0.0) >= DET_HIGH_CONFIDENCE_THRESHOLD:
                return True
    return False


def _accumulate(
    rollup: NodeRollup,
    obs: dict[str, Any],
    domain: str,
    slug_confidences: dict[str, float],
) -> None:
    """Fold one (domain, node) observation into the per-node rollup."""
    rollup.total_obs += 1
    sparse = bool(obs.get("sparse"))
    evidence_used = obs.get("evidence_used") or []
    posterior = float(obs.get("posterior", 0.0))
    interval_low = float(obs.get("interval_low", 0.0))
    interval_high = float(obs.get("interval_high", 1.0))

    det_positive = len(evidence_used) > 0
    det_positive_high = det_positive and _has_high_confidence_binding(
        list(evidence_used), slug_confidences
    )

    if sparse:
        rollup.sparse_obs += 1
    if det_positive:
        rollup.det_positive_obs += 1
        rollup.firing_domains.add(domain)
    else:
        rollup.det_silent_obs += 1

    # b1: det-HIGH (not just det-positive) AND non-sparse must have
    # posterior > 0.5 AND interval not spanning [0, 1]. The roadmap
    # phrasing is explicit: "when the deterministic pipeline classifies
    # the slug HIGH". A medium-confidence slug firing is outside the
    # criterion's scope.
    if det_positive_high and not sparse:
        rollup.b1_eligible += 1
        interval_spans_full = interval_low <= 1e-6 and interval_high >= 1.0 - 1e-6
        if posterior > 0.5 and not interval_spans_full:
            rollup.b1_passing += 1

    # b2: det-silent must be sparse=true.
    if not det_positive:
        rollup.b2_eligible += 1
        if sparse:
            rollup.b2_passing += 1

    # Calibration inputs: non-sparse only. label = 1 iff det-positive
    # (any-confidence; calibration scoring uses the broader signal so
    # the Brier/log-score reflect overall agreement, not just the
    # roadmap-(b1) HIGH-only subset).
    if not sparse:
        rollup.predictions.append((posterior, 1 if det_positive else 0))


def _brier(pairs: list[tuple[float, int]]) -> float | None:
    if not pairs:
        return None
    return sum((p - y) ** 2 for p, y in pairs) / len(pairs)


def _log_score(pairs: list[tuple[float, int]]) -> float | None:
    if not pairs:
        return None
    eps = 1e-6
    total = 0.0
    for p, y in pairs:
        p_clip = max(eps, min(1.0 - eps, p))
        total += -math.log(p_clip) if y == 1 else -math.log(1.0 - p_clip)
    return total / len(pairs)


def _ece(pairs: list[tuple[float, int]], n_bins: int = N_ECE_BINS) -> float | None:
    if not pairs:
        return None
    bins: list[list[tuple[float, int]]] = [[] for _ in range(n_bins)]
    for p, y in pairs:
        # Clamp p to [0, 1) so the upper edge maps to the last bin.
        idx = min(int(p * n_bins), n_bins - 1)
        bins[idx].append((p, y))
    total = len(pairs)
    ece = 0.0
    for bin_pairs in bins:
        if not bin_pairs:
            continue
        bin_size = len(bin_pairs)
        avg_conf = sum(p for p, _ in bin_pairs) / bin_size
        avg_label = sum(y for _, y in bin_pairs) / bin_size
        ece += (bin_size / total) * abs(avg_conf - avg_label)
    return ece


def _read_ndjson(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def _fold_corpus(records: list[dict[str, Any]], rollups: dict[str, NodeRollup]) -> None:
    for rec in records:
        domain = rec.get("queried_domain", "")
        slug_conf_entries = rec.get("slug_confidences") or []
        slug_confidences: dict[str, float] = {}
        for entry in slug_conf_entries:
            if isinstance(entry, list | tuple) and len(entry) == 2:
                slug, score = entry
                if isinstance(slug, str) and isinstance(score, int | float):
                    slug_confidences[slug] = float(score)
        for obs in rec.get("posterior_observations") or []:
            name = obs.get("name")
            if not name:
                continue
            if name not in rollups:
                rollups[name] = NodeRollup(name=name)
            _accumulate(rollups[name], obs, domain, slug_confidences)


def _verdict(rollup: NodeRollup) -> tuple[bool, str, str]:
    """Return (b_pass, c_status, verdict_bc).

    Criterion (a) is exercised by the parametrized regression test in
    ``tests/test_node_stability_criteria.py`` — this analyzer reports
    only (b) and (c). The composer in ``v1.9.5-stability.md`` joins the
    (a) test pass/fail into a final stable / not yet verdict.

    Pure-propagation nodes (``_PURE_PROPAGATION_NODES``) have no direct
    evidence by design; their (c) firing count is structurally zero.
    Mark (c) as ``n/a`` for those and gate stability on (a) + (b) only.
    """
    b1_ratio = (rollup.b1_passing / rollup.b1_eligible) if rollup.b1_eligible else 1.0
    b2_ratio = (rollup.b2_passing / rollup.b2_eligible) if rollup.b2_eligible else 1.0
    b_pass = b1_ratio >= 1.0 and b2_ratio >= 1.0
    if rollup.name in _PURE_PROPAGATION_NODES:
        c_status = "n/a"
        c_ok = True  # don't gate on a criterion that doesn't apply
    elif len(rollup.firing_domains) >= FIRING_MIN_FOR_STABLE:
        c_status = "pass"
        c_ok = True
    else:
        c_status = "fail"
        c_ok = False
    verdict = "stable" if (b_pass and c_ok) else "not yet"
    return (b_pass, c_status, verdict)


def _render_row(name: str, rollup: NodeRollup) -> dict[str, Any]:
    pairs = rollup.predictions
    brier = _brier(pairs)
    log_s = _log_score(pairs)
    ece = _ece(pairs)
    b_pass, c_status, verdict = _verdict(rollup)
    return {
        "node": name,
        "firing_domains": len(rollup.firing_domains),
        "total_obs": rollup.total_obs,
        "sparse_obs": rollup.sparse_obs,
        "det_positive_obs": rollup.det_positive_obs,
        "det_silent_obs": rollup.det_silent_obs,
        "b1_passing": rollup.b1_passing,
        "b1_eligible": rollup.b1_eligible,
        "b2_passing": rollup.b2_passing,
        "b2_eligible": rollup.b2_eligible,
        "brier": brier,
        "log_score": log_s,
        "ece": ece,
        "b_pass": b_pass,
        "c_status": c_status,
        "verdict_bc_only": verdict,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hardened", type=Path, required=True)
    parser.add_argument("--soft", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()

    hardened_records = _read_ndjson(args.hardened)
    soft_records = _read_ndjson(args.soft)

    rollups_combined: dict[str, NodeRollup] = {}
    rollups_hardened: dict[str, NodeRollup] = {}
    rollups_soft: dict[str, NodeRollup] = {}

    _fold_corpus(hardened_records, rollups_combined)
    _fold_corpus(soft_records, rollups_combined)
    _fold_corpus(hardened_records, rollups_hardened)
    _fold_corpus(soft_records, rollups_soft)

    # Preserve the canonical ordering so the verdict table reads top-down.
    nodes_present = [n for n in _KNOWN_NODES if n in rollups_combined]
    # Plus any unexpected extras (e.g. legacy email_security_strong if it
    # still surfaces in old NDJSON) appended at the end for visibility.
    extras = sorted(set(rollups_combined) - set(_KNOWN_NODES))
    nodes_ordered = nodes_present + extras

    rows_combined = [_render_row(name, rollups_combined[name]) for name in nodes_ordered]
    rows_hardened = [_render_row(name, rollups_hardened[name]) for name in nodes_ordered if name in rollups_hardened]
    rows_soft = [_render_row(name, rollups_soft[name]) for name in nodes_ordered if name in rollups_soft]

    summary = {
        "combined": {
            "hardened_domains": len(hardened_records),
            "soft_domains": len(soft_records),
            "rows": rows_combined,
        },
        "hardened": {"rows": rows_hardened},
        "soft": {"rows": rows_soft},
        "thresholds": {
            "ece_max_for_stable": ECE_MAX_FOR_STABLE,
            "brier_max_for_stable": BRIER_MAX_FOR_STABLE,
            "firing_min_for_stable": FIRING_MIN_FOR_STABLE,
        },
    }

    # Human-readable print.
    print("=== v1.9.5 per-node stability metrics ===\n")
    print(f"Hardened corpus: {len(hardened_records)} domains")
    print(f"Soft corpus:     {len(soft_records)} domains")
    print(f"Combined:        {len(hardened_records) + len(soft_records)} domains\n")

    header = (
        f"{'node':<35} {'firings':>8} {'(c)':>6} "
        f"{'b1':>10} {'b2':>10} "
        f"{'brier':>8} {'log':>8} {'ece':>8} {'b/c':>8}"
    )
    print(header)
    print("-" * len(header))
    for row in rows_combined:
        firings = row["firing_domains"]
        c_status = row["c_status"]
        b1 = f"{row['b1_passing']}/{row['b1_eligible']}"
        b2 = f"{row['b2_passing']}/{row['b2_eligible']}"
        brier = "-" if row["brier"] is None else f"{row['brier']:.4f}"
        log_s = "-" if row["log_score"] is None else f"{row['log_score']:.4f}"
        ece = "-" if row["ece"] is None else f"{row['ece']:.4f}"
        verdict_bc = row["verdict_bc_only"]
        print(
            f"{row['node']:<35} {firings:>8} {c_status:>6} "
            f"{b1:>10} {b2:>10} "
            f"{brier:>8} {log_s:>8} {ece:>8} {verdict_bc:>8}"
        )

    print()
    print(
        f"Thresholds: ECE <= {ECE_MAX_FOR_STABLE} (diagnostic), "
        f"Brier <= {BRIER_MAX_FOR_STABLE} (diagnostic), "
        f"firings >= {FIRING_MIN_FOR_STABLE} (gating, except pure-propagation nodes)."
    )
    print(
        "Pure-propagation nodes (no direct evidence) have (c) marked n/a; "
        "stability gates on (a) and (b) only for those."
    )
    print("Criterion (a) -- evidence-response correctness -- is exercised by")
    print("tests/test_node_stability_criteria.py; the verdict table joins")
    print("(a) pass/fail in.\n")

    if args.json_out:
        args.json_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Structured output written to {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
