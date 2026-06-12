# Layer ablations: what each inference layer adds, measured

Harness: `validation/layer_ablation.py` (fully synthetic, deterministic,
publishable — no corpus, no network). Unit tests:
`tests/test_layer_ablation.py`. This is the "layer ablations" experiment the
paper outline names; the numbers below are from the committed default run
(`--samples 20000 --seed 7`) and are reproducible by anyone.

## What is being asked

recon pairs deterministic slug matching with a small Bayesian network and a
CT co-occurrence graph layer. The architecture begs the question: what does
each layer *add* over the simpler thing? Two experiments, each with the
honest framing attached.

## Experiment A — the Bayesian layer vs slug-matching baselines

Worlds are sampled from the network's own generative process (true states
from the priors/CPTs, evidence from the likelihoods — the
synthetic-calibration sampler), so this measures the inference machinery
*under the model's own assumptions* (CAL1 discipline: not a real-world
validity claim; those live in the reference calibrations against public
records). Three predictors per node: the shipped posterior (`full`), the
deterministic detection baseline (`any_fired`: present iff any binding
fired), and `strongest_only` (the node's marginal prior updated by the
single strongest fired binding — no co-evidence, no absence semantics, no
DAG).

Pooled over all 20,000 worlds (Brier; lower is better):

| node | full | any-fired | strongest |
|---|---|---|---|
| m365_tenant | 0.1171 | 0.0476 | 0.1015 |
| google_workspace_tenant | 0.1029 | 0.0678 | 0.0966 |
| federated_identity | 0.1315 | 0.0655 | 0.0906 |
| okta_idp | 0.0391 | 0.0245 | 0.0251 |
| email_gateway_present | 0.0662 | 0.0499 | 0.0675 |
| email_security_modern_provider | 0.2158 | 0.5565 | 0.2468 |
| email_security_policy_enforcing | 0.0630 | 0.1522 | 0.1921 |
| cdn_fronting | 0.1384 | 0.0379 | 0.1387 |
| aws_hosting | 0.1509 | 0.0796 | 0.1517 |

Fired regime only (at least one of the node's bindings fired — the regime
where the predictors actually compete):

| node | n fired | full | any-fired | strongest |
|---|---|---|---|---|
| m365_tenant | 6,947 | 0.1235 | 0.1360 | 0.1228 |
| google_workspace_tenant | 6,260 | 0.1677 | 0.2081 | 0.1670 |
| federated_identity | 5,009 | 0.1290 | 0.1569 | 0.1324 |
| okta_idp | 1,741 | 0.1568 | 0.2085 | 0.1650 |
| email_gateway_present | 4,551 | 0.1806 | 0.2184 | 0.1860 |
| email_security_modern_provider | 0 | — | — | — |
| email_security_policy_enforcing | 15,031 | 0.0718 | 0.1902 | 0.1316 |
| cdn_fronting | 9,771 | 0.0711 | 0.0758 | 0.0717 |
| aws_hosting | 9,382 | 0.1393 | 0.1630 | 0.1410 |

**The honest reading, which is the result:**

- **The pooled table shows the measured price of the MNAR stance.** On the
  hideable root nodes the hard baselines beat the posterior pooled — almost
  entirely from the no-fire regime, where the engine deliberately sits at
  the prior (absence of hideable evidence is not evidence of absence) while
  the baselines exploit the synthetic world's benign missingness, which
  makes absence genuinely informative. That gap is not the machinery
  losing; it is the price recon knowingly pays to avoid confident false
  negatives on hardened real-world targets, here quantified (roughly 0.05
  to 0.10 Brier on the dense roots).
- **Where absence is honestly informative, conditioning on it wins
  outright.** The declarative policy node (CAL14) reads absence as
  evidence, and the full posterior wins pooled *and* fired (0.0630 /
  0.0718 vs 0.1522 / 0.1902 against any-fired) — the asymmetric
  missingness design demonstrated in one row.
- **In the fired regime the full posterior beats the deterministic baseline
  on every node.** Hedged probabilities out-score hard calls everywhere the
  evidence actually appears.
- **The DAG is irreplaceable for the propagation node.**
  `email_security_modern_provider` has no bindings; slug matching simply
  cannot address it (0.5565, worse than predicting the base rate), while
  the CPT propagation scores 0.2158.
- **One strong signal is nearly sufficient on simple roots.** `strongest`
  ties `full` on m365/gws/cdn/aws in the fired regime — consistent with the
  CAL7 grouping design, which deliberately reduces co-firing grouped
  bindings to their strongest member. The fusion gain concentrates where
  the model has structure to use: multi-signal declarative nodes and
  DAG-derived nodes.

## Experiment B — the graph layer vs naive grouping

Six planted org clusters of eight hosts each (12 intra-org certs per
cluster), plus shared-CDN-style noise certs each bridging two random
clusters. Recovered partitions scored against the planted truth with the
adjusted Rand index (`recon_tool.infra_graph.adjusted_rand_index`, the same
implementation behind the 2.2 `partition_stability` field):

| bridging noise certs | ARI Louvain | ARI connected components |
|---|---|---|
| 0 | 1.0000 | 1.0000 |
| 2 | 1.0000 | 0.5437 |
| 5 | 1.0000 | 0.0000 |
| 10 | 1.0000 | 0.1296 |
| 20 | 1.0000 | 0.0000 |
| 40 | 1.0000 | 0.0000 |

With zero noise the layers are equivalent. With even two bridging certs,
naive grouping starts collapsing planted clusters into one blob, and by
five it has lost the structure entirely, while Louvain holds the planted
partition exactly across the whole grid. This is precisely the
shared-infrastructure failure mode the EXT2 backlog item (SAN-count edge
weighting) targets at the *edge* level; community detection already
absorbs much of it at the *partition* level, and the ablation quantifies
that.

## Scope and limits

- Experiment A's truth is sampled from the model, so it cannot validate the
  CPT values (only the reference calibrations can); it isolates the value
  of the *machinery* given the model.
- Experiment B's noise model (uniform two-cluster bridges) is the simplest
  adversary; real shared-CDN certs are heavier-tailed. The result is a
  lower bound on the failure of naive grouping, not an upper bound on
  Louvain's robustness — and `partition_stability` (2.2) reports the
  seed-consensus caveat on real graphs.
