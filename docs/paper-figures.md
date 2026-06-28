# Paper Figure Package

Status: active figure package for the external write-up. The SVG assets are
generated from committed aggregate-safe sources and contain no target domains,
organization names, tenant IDs, or per-domain rows.

Regenerate or verify the assets from the repository root:

```bash
uv run python scripts/generate_paper_figures.py
uv run python scripts/generate_paper_figures.py --check
```

`scripts/check.py` runs the `--check` path, so figure drift is part of the local
CI mirror.

## Assets

| Figure | Asset | Source data | Use |
|---|---|---|---|
| Assurance architecture | [assets/paper/assurance-architecture.svg](assets/paper/assurance-architecture.svg) | README, roadmap, data-handling policy, claim map | First-page overview of passive observations, evidence DAG, exact inference, hedged output, and validation tiers. |
| Nine-node Bayesian network | [assets/paper/bayesian-dag.svg](assets/paper/bayesian-dag.svg) | `src/recon_tool/data/bayesian_network.yaml` | Method section topology figure. |
| Reliability bins | [assets/paper/calibration-reliability.svg](assets/paper/calibration-reliability.svg) | [../validation/public-list-calibration.md](../validation/public-list-calibration.md) | Evaluation figure for public-list DMARC and M365 reliability bins with posterior-bin counts. |
| Interval width vs evidence | [assets/paper/interval-width-vs-evidence.svg](assets/paper/interval-width-vs-evidence.svg) | [../validation/public-list-calibration.md](../validation/public-list-calibration.md) | CAL7 figure showing evidence-responsive interval width and grouped-node co-firing control. |

## Caption Drafts

**Figure 1. Assurance architecture and evidence tiers.** recon reads public DNS,
certificate transparency, and unauthenticated identity endpoints, preserves an
evidence DAG, computes exact inference over a small auditable Bayesian network,
and reports hedged observations. Validation claims are tiered by who controls
the evidence: provider-attested, public-declaration, or hideable.

**Figure 2. Nine-node Bayesian network.** The network separates provider
attestation, public-declaration mail policy, derived mail-provider claims, and
hideable infrastructure claims. Parent edges come directly from
`bayesian_network.yaml`.

**Figure 3. Public-list reliability bins.** Public-list aggregate reliability
bins show the DMARC full posterior and the M365 DNS-only predictor against their
respective public references. Circle and bar size encode posterior-bin count.
The figure supports public reproducibility only; private-corpus aggregate rows
remain maintainer-reproducible.

**Figure 4. Interval width falls as effective evidence rises.** Mean 80 percent
interval width decreases with effective evidence count across public Lists A, B,
and C. Grouped nodes stay wider at matched low evidence, which is the intended
co-firing correction.

## Disclosure Boundary

The figure package may show:

- aggregate counts, rates, and intervals;
- node names, claim classes, and validation tiers;
- public-list aggregate bins already committed in validation memos;
- private-corpus memo filenames and aggregate-only status.

The figure package must not show:

- apex lists or subdomains;
- organization names as targets;
- tenant IDs;
- per-domain findings;
- raw private corpus rows;
- unsuppressed strata below the reporting threshold.
