# Synthetic layer ablations

Interpretation reviewed 2026-07-10. Recorded measurements are unchanged.

Harness: `validation/layer_ablation.py`. Tests:
`tests/test_layer_ablation.py`. Default run: `--samples 20000 --seed 7`.

These experiments test implementation behavior in constructed worlds. They do
not decide whether either advanced layer improves real operator outcomes.

## Experiment A: Bayesian network versus simple score baselines

The sampler draws latent states from the committed prior/CPT graph, then draws
each evidence binding independently as a Bernoulli variable using its marginal
likelihood. It does not implement correlation-group observation structure or
the shipped missingness semantics. Three predictors are scored:

- `full`: shipped Bayesian network;
- `any_fired`: hard 1 when any binding on the node fires, otherwise 0;
- `strongest_only`: marginal prior updated by the one fired binding with largest
  absolute log likelihood ratio.

This is an independent-Bernoulli misspecification stress test that shares
parameters with the committed model. It is not the committed model's generative
process. It cannot validate the model against reality or estimate the cost of
its missingness assumptions.

### Pooled Brier score

Lower is better.

| node | full | any-fired | strongest |
|---|---:|---:|---:|
| `m365_tenant` | 0.1171 | 0.0476 | 0.1015 |
| `google_workspace_tenant` | 0.1029 | 0.0678 | 0.0966 |
| `federated_identity` | 0.1315 | 0.0655 | 0.0906 |
| `okta_idp` | 0.0391 | 0.0245 | 0.0251 |
| `email_gateway_present` | 0.0662 | 0.0499 | 0.0675 |
| `email_security_modern_provider` | 0.2158 | 0.5565 | 0.2468 |
| `email_security_policy_enforcing` | 0.0630 | 0.1522 | 0.1921 |
| `cdn_fronting` | 0.1384 | 0.0379 | 0.1387 |
| `aws_hosting` | 0.1509 | 0.0796 | 0.1517 |

The hard any-fired baseline wins on seven of nine nodes in the pooled synthetic
regime. The full model wins on the propagation node and declarative policy node.
The no-fire regime drives much of the gap because the independent-Bernoulli
generator samples non-fire while shipped hideable-node inference ignores it.
That is a specified generator/inference mismatch, not an estimate of an MNAR
price and not evidence that the real world favors either rule.

### Fired-only Brier score

| node | n fired | full | any-fired | strongest |
|---|---:|---:|---:|---:|
| `m365_tenant` | 6,947 | 0.1235 | 0.1360 | 0.1228 |
| `google_workspace_tenant` | 6,260 | 0.1677 | 0.2081 | 0.1670 |
| `federated_identity` | 5,009 | 0.1290 | 0.1569 | 0.1324 |
| `okta_idp` | 1,741 | 0.1568 | 0.2085 | 0.1650 |
| `email_gateway_present` | 4,551 | 0.1806 | 0.2184 | 0.1860 |
| `email_security_modern_provider` | 0 | n/a | n/a | n/a |
| `email_security_policy_enforcing` | 15,031 | 0.0718 | 0.1902 | 0.1316 |
| `cdn_fronting` | 9,771 | 0.0711 | 0.0758 | 0.0717 |
| `aws_hosting` | 9,382 | 0.1393 | 0.1630 | 0.1410 |

The full model beats the hard baseline in the fired-only regime. The strongest
single binding nearly ties or slightly beats the full model on several simple
roots, including M365 and Google Workspace in this run. Most measured residual
value appears on the policy and propagation structure. The tested any-fired
baseline has no parent-propagation rule, so its loss on
`email_security_modern_provider` does not prove that a Bayesian DAG is the only
simple way to derive that claim.

The product implication is a benchmark requirement, not a victory claim. Compare
deterministic abstention, per-slug evidence strength, strongest reviewed unit,
and full Bayesian fusion on predictor-disjoint labels before deciding which path
belongs in primary output.

## Experiment B: Louvain versus connected components

The generator creates six equal planted clusters of eight hosts, twelve dense
within-cluster certificates per cluster, and a grid of two-host cross-cluster
bridge certificates. It scores recovered partitions with adjusted Rand index.

| bridging certificates | ARI Louvain | ARI connected components |
|---:|---:|---:|
| 0 | 1.0000 | 1.0000 |
| 2 | 1.0000 | 0.5437 |
| 5 | 1.0000 | 0.0000 |
| 10 | 1.0000 | 0.1296 |
| 20 | 1.0000 | 0.0000 |
| 40 | 1.0000 | 0.0000 |

This benchmark is tailored to assortative community detection: uniform dense
clusters are joined by sparse pairwise bridges. It demonstrates that connected
components collapse under bridges and that Louvain recovers this planted family.
It does not establish robustness on real certificate-transparency graphs.

Important omitted structures include:

- heavy-tailed certificate SAN counts;
- multi-tenant hub certificates;
- clique-projection bias;
- missing or duplicated CT entries;
- degree heterogeneity;
- temporal sampling variation;
- non-assortative or overlapping structure.

Seed-sweep ARI on the observed graph tests optimizer stability only. The graph
research gate in `docs/correlation.md` requires data resampling, alternative
representations, a degree-aware null, and operator-supplied grouping evaluation
before graph output can claim measured product value.

## Decision

Both experiments remain useful misspecification, regression, and falsification
scaffolds. Neither
meets the roadmap's product-quality decision rule. Advanced inference and graph
machinery must not expand until the predeclared external benchmark establishes a
named operator benefit over simpler evidence plus abstention.
