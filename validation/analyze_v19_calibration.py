"""Analyze v1.9 calibration results from a private corpus run.

Reads an NDJSON output from ``recon batch ... --fusion`` and computes
calibration aggregates. The corpus stays private; only anonymized
aggregates print to stdout for inclusion in the public validation
summary.

Aggregates:

  1. **Per-node distribution.** For each Bayesian-network node, how
     often does the posterior land in each range, and what fraction
     of those are sparse-flagged.
  2. **Calibration spot-check.** For each high-confidence
     (>0.85, non-sparse) posterior, does the deterministic pipeline
     also classify the corresponding slug? Disagreements are listed
     anonymized as "domain hash".
  3. **Multi-signal correlation depth.** What fraction of domains
     produce >1 distinct evidence binding firing across nodes.
  4. **Entropy reduction quartiles.** Distribution of the per-domain
     entropy reduction in nats.
  5. **Conflict count distribution.** Cross-source-conflict count
     across the corpus.

No domain names print. Only counts, fractions, and quartiles.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path


# Mapping from Bayesian network nodes to the deterministic-pipeline
# slugs / signals that *should* be present when the posterior fires
# high. Used by the calibration spot-check.
NODE_TO_DETERMINISTIC_EVIDENCE: dict[str, list[str]] = {
    "m365_tenant": ["microsoft365", "entra-id", "exchange-online"],
    "google_workspace_tenant": ["google-workspace", "gmail"],
    "okta_idp": ["okta"],
    "email_gateway_present": ["proofpoint", "mimecast", "barracuda"],
    "cdn_fronting": ["cloudflare", "akamai", "fastly"],
    "aws_hosting": ["aws", "aws-cloudfront", "aws-route53"],
    # email_security_strong and federated_identity are signal-driven
    # (DMARC, DKIM, SPF, federated_sso_hub); we check the structured
    # fields directly.
}


def _domain_hash(name: str) -> str:
    """Return a short stable hash; never expose the domain name."""
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]


def _quartiles(values: list[float]) -> tuple[float, float, float]:
    if not values:
        return (0.0, 0.0, 0.0)
    return (
        statistics.quantiles(values, n=4)[0],
        statistics.median(values),
        statistics.quantiles(values, n=4)[2],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="NDJSON from recon batch --fusion run.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.85,
        help="Posterior threshold for the high-confidence spot-check (default 0.85).",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"input not found: {args.input}", file=sys.stderr)
        return 2

    domains: list[dict] = []
    with args.input.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "error" in d:
                continue
            domains.append(d)

    if not domains:
        print("no successful domains in input", file=sys.stderr)
        return 1

    n = len(domains)
    print(f"Analyzing {n} successful domain results")
    print()

    # ── 1. Per-node distribution ──────────────────────────────────────

    bins = [
        (0.00, 0.20, "very-low"),
        (0.20, 0.40, "low"),
        (0.40, 0.60, "uncertain"),
        (0.60, 0.85, "moderate"),
        (0.85, 1.00, "high"),
    ]
    node_buckets: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    node_sparse_counts: dict[str, int] = defaultdict(int)
    node_total: dict[str, int] = defaultdict(int)

    for d in domains:
        po = d.get("posterior_observations", [])
        for p in po:
            name = p["name"]
            posterior = p["posterior"]
            for low, high, label in bins:
                if low <= posterior < high or (label == "high" and posterior >= 0.85):
                    node_buckets[name][label] += 1
                    break
            if p.get("sparse"):
                node_sparse_counts[name] += 1
            node_total[name] += 1

    print("=== Per-node posterior distribution ===")
    print(f"{'node':<28} {'very-low':>10} {'low':>8} {'uncertain':>11} {'moderate':>10} {'high':>8} {'sparse%':>8}")
    print("-" * 86)
    for name in sorted(node_total):
        b = node_buckets[name]
        total = node_total[name]
        sparse_rate = node_sparse_counts[name] / total if total else 0.0
        print(
            f"{name:<28} "
            f"{b.get('very-low', 0):>10} "
            f"{b.get('low', 0):>8} "
            f"{b.get('uncertain', 0):>11} "
            f"{b.get('moderate', 0):>10} "
            f"{b.get('high', 0):>8} "
            f"{sparse_rate:>7.1%}"
        )
    print()

    # ── 2. Calibration spot-check ─────────────────────────────────────

    print(f"=== Calibration spot-check (posterior >= {args.threshold}, non-sparse) ===")
    print("For each high-confidence posterior, does the deterministic")
    print("pipeline back it up? Agreements / disagreements per node.")
    print()
    spot_results: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    spot_disagreements: dict[str, list[str]] = defaultdict(list)
    for d in domains:
        po = d.get("posterior_observations", [])
        slugs = set(d.get("slugs", []))
        dmarc = d.get("dmarc_policy")
        mta_sts = d.get("mta_sts_mode")
        evidence = d.get("evidence", []) or []
        has_dkim = any(e.get("source_type") == "DKIM" for e in evidence)
        spf_strict = any(
            e.get("source_type") == "SPF"
            and "-all" in str(e.get("raw_value", "")).lower()
            for e in evidence
        )
        domain_hash = _domain_hash(d.get("queried_domain", ""))

        for p in po:
            if p["posterior"] < args.threshold or p.get("sparse"):
                continue
            name = p["name"]
            agrees = False

            if name in NODE_TO_DETERMINISTIC_EVIDENCE:
                agrees = bool(set(NODE_TO_DETERMINISTIC_EVIDENCE[name]) & slugs)
            elif name == "email_security_strong":
                # Composite: at least 2 of {dmarc_reject, mta_sts_enforce, dkim, spf_strict}
                count = sum(
                    [
                        dmarc == "reject",
                        mta_sts == "enforce",
                        has_dkim,
                        spf_strict,
                    ]
                )
                agrees = count >= 2
            elif name == "federated_identity":
                agrees = d.get("auth_type") == "Federated" or d.get("google_auth_type") == "Federated"

            if agrees:
                spot_results[name]["agree"] += 1
            else:
                spot_results[name]["disagree"] += 1
                spot_disagreements[name].append(domain_hash)

    print(f"{'node':<28} {'agree':>7} {'disagree':>10} {'agree%':>8}")
    print("-" * 56)
    total_agree = 0
    total_disagree = 0
    for name in sorted(spot_results):
        agree = spot_results[name]["agree"]
        disagree = spot_results[name]["disagree"]
        total = agree + disagree
        rate = agree / total if total else 0.0
        total_agree += agree
        total_disagree += disagree
        print(f"{name:<28} {agree:>7} {disagree:>10} {rate:>7.1%}")
    print("-" * 56)
    overall = total_agree + total_disagree
    overall_rate = total_agree / overall if overall else 0.0
    print(f"{'OVERALL':<28} {total_agree:>7} {total_disagree:>10} {overall_rate:>7.1%}")
    print()

    if any(spot_disagreements.values()):
        print("Disagreements (anonymized hashes; verify locally):")
        for name in sorted(spot_disagreements):
            hashes = spot_disagreements[name][:5]
            print(f"  {name}: {hashes}{'  ...' if len(spot_disagreements[name]) > 5 else ''}")
        print()

    # ── 3. Multi-signal correlation depth ─────────────────────────────

    multi_signal_count = 0
    multi_signal_per_node: dict[str, int] = defaultdict(int)
    for d in domains:
        po = d.get("posterior_observations", [])
        evidence_per_node = [len(p.get("evidence_used", [])) for p in po]
        total_bindings = sum(evidence_per_node)
        if total_bindings > 1:
            multi_signal_count += 1
        for p in po:
            if len(p.get("evidence_used", [])) > 1:
                multi_signal_per_node[p["name"]] += 1
    print(f"=== Multi-signal correlation depth ===")
    print(f"  Domains with >1 evidence binding firing across nodes: "
          f"{multi_signal_count}/{n} ({multi_signal_count/n:.1%})")
    print(f"  Per-node count of >1-binding firings:")
    for name in sorted(multi_signal_per_node):
        print(f"    {name}: {multi_signal_per_node[name]}")
    print()

    # ── 4. Entropy reduction (computed locally if not in payload) ────

    # Entropy reduction is on the InferenceResult, not in the per-domain
    # JSON. We can recompute by running inference on TenantInfo, but that
    # needs the full TenantInfo tree. Skip for now; report posterior
    # spread instead.
    posterior_means = []
    for d in domains:
        po = d.get("posterior_observations", [])
        if po:
            posterior_means.append(
                statistics.mean(p["posterior"] for p in po)
            )
    if posterior_means:
        q1, med, q3 = _quartiles(posterior_means)
        print(f"=== Per-domain mean posterior across nodes ===")
        print(f"  Q1={q1:.3f}  Median={med:.3f}  Q3={q3:.3f}")
        print()

    # ── 5. Conflict count distribution ────────────────────────────────

    conflict_counts: list[int] = []
    for d in domains:
        ec = d.get("evidence_conflicts", [])
        conflict_counts.append(len(ec))
    counter = Counter(conflict_counts)
    print(f"=== Cross-source conflict count distribution ===")
    print(f"  {'count':>5} {'domains':>8} {'fraction':>10}")
    for c in sorted(counter):
        frac = counter[c] / n
        print(f"  {c:>5} {counter[c]:>8} {frac:>9.1%}")
    print()

    # ── 6. Sparse-flag rate (overall) ─────────────────────────────────

    total_observations = sum(node_total.values())
    total_sparse = sum(node_sparse_counts.values())
    print(f"=== Sparse-flag rate (overall) ===")
    print(f"  {total_sparse}/{total_observations} ({total_sparse/total_observations:.1%}) "
          f"node-domain observations flagged as sparse")
    print(f"  (Sparse flag fires when n_eff is at the floor — the")
    print(f"  passive-observation ceiling is the load-bearing fact, not")
    print(f"  the point estimate.)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
