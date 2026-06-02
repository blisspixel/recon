# Bayesian-layer validation checkpoint, 2026-06-02

Pre-2.0 calibration checkpoint on a clean private-corpus sample. Aggregate
metrics only; no domain names appear here (the corpus and per-domain output stay
gitignored under `validation/corpus-private/` and `validation/runs-private/`).

This memo follows the Track C-cal legitimacy refinements in `docs/roadmap.md`:
it reports *consistency*, not ground-truth calibration (CAL1), attaches
uncertainty to the headline number (CAL2), and separates coverage from
calibration in the per-node verdict (CAL5). The open refinements (CAL3 interval
coverage, CAL4 ground-truth subset, CAL6 stratified sampling) are listed under
Limitations.

## Run

- Source: `recon batch <corpus> --ndjson --fusion --no-ct --include-unclassified`
  at batch concurrency 5.
- Sample: 284 successful fusion domains (of 287 processed; ~1% error rate). This
  is a partial pass of the 5,241-domain corpus, in file order (see Limitations).
- No-CT: the nine Bayesian nodes are fed by DNS and identity-discovery
  endpoints, not certificate transparency, so a no-CT pass calibrates the layer
  in full. CT feeds only the separate `infrastructure_clusters` and cert lexical
  surfaces, validated separately under their own rate limits.

## What we measure, and what it does and does not show

The "deterministic-vs-Bayesian" number below is a **consistency** check: the
deterministic pipeline and the Bayesian layer consume the same observed
evidence, so agreement shows the two layers do not contradict each other. It is
**not** calibration against ground truth, and the per-node Brier / log-score /
ECE are computed against the deterministic pipeline as a **proxy label**, not an
independently-verified truth. Real calibration and interval-coverage numbers
require the ground-truth subset (CAL4) and are not yet available.

## Consistency (deterministic vs Bayesian, high-confidence posteriors)

- 736 of 736 high-confidence (posterior >= 0.85, non-sparse) posteriors agree
  with the deterministic pipeline: 100% observed.
- With 0 disagreements in 736, the Rule of Three gives a 95% upper bound on the
  true disagreement rate of approximately 3/736 ~= 0.41%.
- Cross-source conflicts: 0 across all 284 domains.
- Multi-signal correlation depth (north-star): 222/284 = 78.2% of domains have
  more than one evidence binding firing across nodes.

## Per-node verdict, coverage separated from calibration (CAL5)

Coverage = how often the node has direct evidence (firings). Calibration = how
well the posterior tracks the proxy label (Brier / ECE) when it does. The two
are reported separately so a low-coverage node is not mistaken for a
miscalibrated one.

| Node | Firings (coverage) | Brier | ECE | Calibration |
|---|---|---|---|---|
| m365_tenant | 162 | 0.0035 | 0.057 | within gate |
| google_workspace_tenant | 92 | 0.0113 | 0.105 | within gate |
| federated_identity | 78 | 0.0068 | 0.074 | within gate |
| okta_idp | 12 | 0.0106 | 0.092 | within gate |
| email_gateway_present | 61 | 0.0085 | 0.092 | within gate |
| email_security_modern_provider | 0 (pure propagation) | n/a | n/a | n/a |
| email_security_policy_enforcing | 188 | 0.0522 | 0.197 | within gate (weakest) |
| cdn_fronting | 130 | 0.0010 | 0.031 | within gate |
| aws_hosting | 80 | 0.0050 | 0.059 | within gate |

Gates (diagnostic): ECE <= 0.2, Brier <= 0.15, firings >= 10 (coverage).

- All nine nodes are within the calibration gates on this sample, and all
  evidence-bearing nodes now clear the firing-count coverage gate.
- `okta_idp` moved from "not yet" to "pass" between n=217 (9 firings) and n=284
  (12 firings). This confirms its earlier "not yet" was a coverage artifact of
  small n, not a miscalibration: its Brier (0.011) and ECE (0.092) were already
  healthy. The full-corpus run will raise its firing count well past the gate.
- `email_security_policy_enforcing` is the node to watch: highest Brier (0.052)
  and ECE (0.197), still inside the gates but with the least margin.
- Sparse-flag rate is high by design (the passive-observation ceiling is the
  load-bearing fact, not the point estimate); for example `okta_idp` is
  sparse-flagged on ~96% of node-domain observations.

## Limitations (open Track C-cal items)

- **No ground truth yet (CAL3 / CAL4).** Everything above is consistency and
  proxy-label scoring. Real calibration and empirical 80%-interval coverage need
  the hand-labeled ground-truth subset.
- **File-order sample, not stratified (CAL6).** This sample is the first 284
  domains in corpus order; a random / stratified draw (by cloud vendor /
  vertical / region) and the full 5,241 run are pending.
- **Conditional-independence bias (CAL7).** Correlated DNS bindings (for example
  MX + autodiscover + Exchange-DKIM all implying M365) can be double-counted by
  the combination rule, which would narrow intervals. Documented as a known
  limitation pending down-weighting or topology work.
- **Run-parameter note.** A concurrency-16 pass blew the 120s per-domain budget
  on ~84% of domains through resolver saturation; concurrency 5 holds the error
  rate near 1%. Full-corpus DNS / identity passes run at low batch concurrency.
