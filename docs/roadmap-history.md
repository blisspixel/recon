# Roadmap history (shipped-release detail)

This is the per-release build detail moved out of [roadmap.md](roadmap.md) so
that file stays forward-looking, as it says it is. Everything here shipped; it is
kept for the rationale and the per-item disposition. The authoritative shipped
record is [CHANGELOG.md](../CHANGELOG.md). Nothing in this file is a forward plan.

Two anchors are referenced from other docs and are preserved here:
`#v200--maturity` (from [stability.md](stability.md)) and
`#v190--probabilistic-fusion-shipped` (from [mcp.md](mcp.md)).

---

## Build plan

The plan is grouped into a small number of meaningful releases, not a long
trail of patches. Each release ships as a complete unit: a coherent feature
set, a catalog growth pass, and a private-corpus validation run that proves
the new behavior on real targets. Build order respects dependencies - the
graph layer needs the signal coverage that comes before it; the
probabilistic layer needs the signals to feed posteriors. Patches happen
when something actually breaks, not as a way to chunk work.

Standing work that runs alongside every release:

- **Catalog growth.** Each release window includes at least one private-
  corpus scan with `validation/scan.py` against a 4k+ domain library,
  candidate triage via the `/recon-fingerprint-triage` skill, and the
  resulting `cname_target` (or other) rules merged with corpus-delta notes.
- **Fingerprint precision.** Walk the multi-detection backlog one batch
  per release; prioritize identity, security, email, infrastructure where
  false positives have the highest downstream cost.
- **Sparse-result diagnosis.** Every new feature documents its
  passive-observation ceiling. When the rule does not fire, output stays
  hedged and the user understands why.
- **Release and docs reliability.** CI gates cover the same checks as
  release; counts and version references stay tight to this file.
- **Per-release calibration aggregate publish.** Each v1.9.x patch
  ships its own one-page validation summary
  (`validation/v1.9.N-calibration.md`) with sensitivity numbers, ECE
  on the synthetic network, and corpus spot-check rate at that point.
  Established for v1.9.0; the practice continues per patch so
  calibration claims are falsifiable across time, not just at the
  v2.0 lock moment.

### v1.7.0 - Hardened-target signal recovery *(shipped - see [CHANGELOG](../CHANGELOG.md))*

Squeezed more out of CT logs and resolution chains, and surfaced what
we already tracked but didn't expose. Surfaces: wildcard SAN sibling
expansion (`cert_summary.wildcard_sibling_clusters`), temporal CT
issuance bursts (`cert_summary.deployment_bursts`), CNAME chain motif
library (`chain_motifs` array), cross-source evidence conflict
surfacing (`evidence_conflicts` array). All shipped as YAML data
files plus minimal engine extension; the v2.0 schema lock promotes
each to stable per the disposition table below.

### v1.8.0 - Graph correlation *(shipped - see [CHANGELOG](../CHANGELOG.md))*

Built the structural layer on top of the v1.7 cert intelligence.
Surfaces: CT co-occurrence graph + Louvain communities
(`infrastructure_clusters`), fingerprint relationship metadata
(`product_family`, `parent_vendor`, `bimi_org` fields → emitted as
`fingerprint_metadata` map), batch-only hypergraph ecosystem view
(`ecosystem_hyperedges` when `--include-ecosystem`),
vertical-baseline anomaly rules (`expected_categories` /
`expected_motifs` on profiles, hedged-observation output),
`get_infrastructure_clusters` + `export_graph` MCP tools.
Zero new network surface; all derived from already-collected
observables. v2.0 promotes each to stable per the disposition table.

### v1.9.0 - Probabilistic fusion *(shipped, EXPERIMENTAL surfaces - see [CHANGELOG](../CHANGELOG.md), `docs/correlation.md` §4.8, `validation/v1.9-validation-summary.md`)*

Layered Bayesian inference on top of the deterministic engine, gated
behind `--fusion`. Surfaces (`posterior_observations`, `slug_confidences`,
`evidence_conflicts`, `--explain-dag`, `chain_motifs`,
`wildcard_sibling_clusters`, `deployment_bursts`,
`infrastructure_clusters`, `ecosystem_hyperedges`) are all marked
EXPERIMENTAL until the v1.9.x bridge milestones below close out and v2.0
locks the schema. The validation gate (corpus entropy reduction tracked
across releases; high-posterior calibration; interval coverage on
sparse-evidence cases) cleared on the v1.9.0 corpus run; per-node
calibration findings drove the v1.9.3 surgery.

### The path to v2.0 - a numbered sequence (historical)

> This numbered sequence (v1.9.4 to v1.9.11) is kept for the record. Every
> version in it shipped; the project is now at v1.9.54. The current remaining
> work is the execution queue under "Remaining work to v2.0" near the top of
> this file, organized by the five hardening tracks plus the lock ceremony, not
> by this sequence.


v2.0 is the "polished and excellent everywhere" release: schema
lock + doc snapshot + zero EXPERIMENTAL labels anywhere. It is not
a parking lot for feature backlog. Every gated feature ships in a
v1.9.x patch first; v2.0 inherits each as already-present and
locks the shape.

The sequence below is the planned order from where we are now
(post-v1.9.3.10) to v2.0. Each version answers four questions:

- **What ships.** The concrete deliverable.
- **Why this is next.** The dependency chain that puts this
  version where it is, rather than later.
- **Quality bar.** Falsifiable acceptance criteria a reviewer can
  check before the patch tags.
- **Validation step.** How we know the patch is good before it
  ships, separate from the quality-bar checks.
- **Refinement.** What we'd revisit if the validation surfaced
  something the quality bar didn't predict.

Patches ship when their one version's work completes, not on a
fixed schedule. Multiple patches in a day is fine; bundled work
that combines unrelated stories is not (see Patch-release
discipline below). Bug-fix patches between versions claim the
next available `v1.9.X.Y` number and do not block the sequence.

Standing work runs alongside every version: catalog growth
(corpus-observed + vendor-doc-sourced), per-release calibration
aggregate published, CI / lint / typecheck / coverage gates.

#### v1.9.2 - UX validation via agentic QA *(shipped - see [CHANGELOG](../CHANGELOG.md) and `validation/v1.9.2-agentic-ux.md`)*

<details>
<summary>Shipped detail - methodology + findings</summary>

We have not validated that operators benefit from credible
intervals. The entire calibration argument is academic if no one
looks at the `posterior_observations` block before making a
decision. Doing this first, before any schema-affecting work,
prevents us from locking a contract whose user-facing value is
unproven.

The original framing called for three human operator interviews
(SOC analyst, security architect, due-diligence reviewer). We
keep that as a future option, but the **primary v1.9.2
methodology is agentic QA** - one of recon's main user personas
*is* the AI agent (the entire MCP integration story), so
simulating that persona with a script gives us:

- Real signal about whether agents read `posterior_observations`,
  whether they distinguish dense from sparse, whether they cite
  `--explain-dag` output, whether they ask follow-up questions
  the credible interval should answer.
- Reproducibility: anyone can rerun the agentic QA suite against
  a future build and compare.
- Speed: today, not "after we recruit three humans."
- Publishability: synthetic / fictional domains, no private data.

**Method.**

- **Personas as prompt scaffolds.** Three personas - security
  analyst triaging an alert, due-diligence researcher writing a
  vendor assessment, ops engineer comparing two domains. Each
  gets a system prompt that defines their role, the question
  they're trying to answer, and the artifacts available
  (`recon <domain> --fusion --json`, `--explain-dag`, MCP tool
  output). No mention of credible intervals, sparse flags, or
  evidence DAGs in the prompt - we want to see whether the
  agent finds and uses those affordances on its own.
- **Test domains.** Two fictional Microsoft examples
  (`contoso.com` for dense, a deliberately-hardened scenario
  built by stripping a normal lookup down to one slug for
  sparse). Synthetic, public, reproducible.
- **Scoring rubric.**
  - *Did the agent read the posterior block?* (binary; check
    transcript)
  - *Did the agent cite the credible interval explicitly?*
    (binary)
  - *Did `sparse=true` change the agent's conclusion?*
    (compare answers on dense vs sparse domain)
  - *Did the agent run `--explain-dag` or call
    `explain_dag` MCP?* (binary)
  - *Did the agent reach a different conclusion than it would
    have without `--fusion`?* (re-run with `--fusion` off and
    diff)
- **Documented in `validation/v1.9.2-agentic-ux.md`.** The
  prompts, transcripts, and rubric all public-reproducible.
  Per-persona summary table makes the result skimmable.
- **Failure modes that change v2.0.** If the agent ignores the
  posterior block on both runs, intervals are not load-bearing
  and v2.0 should consider promoting `posterior_observations`
  to stable but de-emphasizing it in the panel. If the agent
  consistently misreads `sparse=true` as "low confidence" rather
  than "passive ceiling," the field name is wrong and v2.0
  should rename. If the agent uses `--explain-dag` heavily,
  v2.0 should keep it prominent. Each finding maps to a concrete
  v2.0 disposition decision.

**Human interviews remain a future option.** If the agentic QA
surfaces ambiguous results, or if we want a non-agent persona
(SOC analyst clicking through the CLI), the original three-
interview plan is on the shelf. But agentic QA is genuine
validation for the agent persona, not a placeholder for it.

</details>

#### v1.9.3 - Resolve the `email_security_strong` definitional gap *(shipped - see [CHANGELOG](../CHANGELOG.md) and `validation/v1.9.3-calibration.md`)*

<details>
<summary>Shipped detail - topology surgery rationale</summary>

This is *topology surgery*, not parameter tuning. The v1.9.0
spot-check showed 52.6% agreement on this single node; all other
nodes were at 100%. The cause is not miscalibration. The Bayesian
network's CPT for `email_security_strong` is parameterized over
`{m365_tenant, google_workspace_tenant, email_gateway_present}` -
modern-mail-provider presence. The spot-check tested it against
`dmarc=reject + dkim + spf-strict + mta-sts (≥2 of 4)` - policy
enforcement. **These are different claims.** No CPT tuning makes
them agree. Two principled fixes:

- **Option A - Split the node.** Replace `email_security_strong`
  with two nodes: `email_security_modern_provider` (parameterized
  on M365 / GWS as today) and `email_security_policy_enforcing`
  (parameterized on observed DMARC / DKIM / SPF / MTA-STS signals).
  Defenders care about both, but for different reasons. Two nodes
  with two clear definitions beat one with a muddled one.
- **Option B - Pick a definition and align both layers.** Choose
  whichever definition matches the question defenders actually ask
  (likely policy-enforcing), align the deterministic pipeline check
  and the Bayesian CPT to that definition, and live with the choice.

Default: Option A. It's more model surface but more honest. The
implementation is a schema-additive `bayesian_network.yaml`
change, not a CPT tune. **Gate:** both new nodes ship with explicit
definitions in `docs/correlation.md` and a re-run corpus
spot-check matches the definitions.

**Adjacent suspect - `federated_identity`.** The current model
parameterizes federation only on `m365_tenant`, but federation
exists without M365 (Okta + GWS, Auth0 + custom IdP, standalone
SAML setups). The current network systematically under-attributes
federation when the path doesn't go through M365. This is the
same shape of definitional bug as `email_security_strong`. We
either (a) expand `federated_identity`'s parents and re-derive
its CPT, or (b) keep it `experimental` until corpus evidence
shows the under-attribution rate is acceptable. Decide as part
of this milestone.

**Audit-every-node - backlog, not commitment.** The pragmatic
choice is to fix the one we know is broken, ship, and let the
next corpus run tell us which node is broken next. Sequential
model improvement. The rigorous-but-open-ended alternative - audit
every node for definitional clarity in one pass - is in
[Backlog (after v2.0)](#backlog-after-v20) below.

</details>

#### v1.9.4 - Hardened-adversarial behavior validation

The v1.9.0 corpus skewed enterprise. The asymmetric-likelihood
design (§4.8.3) was justified specifically for hardened targets,
which v1.9.0 did not exercise. This milestone validates the
*design property*, not just the calibration:

- **50-domain hardened-adversarial subset** under
  `validation/corpus-private/hardened.txt`: minimal-DNS,
  wildcard-cert-only, heavily-proxied apexes, randomized CNAME
  chains, short-lived certs.
- **Gate (behavioral, not numeric):** on this subset, the layer
  must (a) flag `sparse=true` on most nodes, (b) report wide
  credible intervals, and (c) refuse to report high-confidence
  posteriors on nodes whose evidence bindings did not fire. The
  exact numeric thresholds are less important than the
  qualitative behavior holding up. Document the result with
  illustrative interval shapes in correlation.md.
- **Public failure-mode catalog.** New section in correlation.md
  enumerating the hardening patterns that defeat each layer and
  the language the layer uses to admit it ("layer X reports
  sparse on this pattern"). Honest framing of where the public
  channel really cannot resolve uncertainty.

**Quality bar - exceptionally well (every item must be checked):**

- [ ] Hardened corpus has explicit *inclusion criteria* documented
  at the top of `validation/corpus-private/hardened.txt`: a domain
  qualifies iff it satisfies ≥ 3 of {wildcard SAN ratio ≥ 80%,
  CNAME chain depth ≥ 3, no public IdP metadata, ≤ 2 public DNS
  records beyond the apex, certificate validity ≤ 30 days}. Public
  enough that someone else can build a comparable corpus from
  CT-log scans + heuristics.
- [ ] **Full v1.9.0 91-domain corpus re-run** against the v1.9.3
  topology (deferred from `v1.9.3-calibration.md`), reported in
  `validation/v1.9.4-calibration.md` alongside the hardened subset.
  Trend numbers v1.9.0 → v1.9.3 → v1.9.4 published per node.
- [ ] **Per-hardening-pattern result rows** in the failure-mode
  catalog. Not "the layer reports sparse on hardened targets" but
  "wildcard-cert-only targets: cdn_fronting fires (CNAME path),
  every other node sparse, federated_identity interval [0.0, 0.45];
  randomized-chain targets: chain_motifs fires when motif library
  hits, otherwise sparse; etc." One row per hardening pattern.
- [ ] **Survival rate** quantified: what fraction of high-confidence
  posteriors *survive* migration from soft-target corpus to
  hardened-target corpus, per node. The honest number - most should
  vanish; the ones that don't are the leak surfaces.
- [ ] **No new code-path regressions on the soft corpus** -
  re-running the v1.9.0 corpus shows the same 100% per-node
  agreement (other than `email_security_strong` which is gone).
- [ ] **Failure-mode catalog cross-referenced** to specific
  defensive guidance in correlation.md §4.8.8 (Defensive value):
  "if you're worried about X, the correlation layer that surfaces
  it is Y; if X is hardened away, the layer reports Z."
- [ ] **Reproducibility section** in `v1.9.4-calibration.md` shows
  how an outside reader could build a comparable hardened corpus
  from public sources (CT-log queries against short-lived issuers,
  filter for wildcard SANs, etc.). Anonymized aggregates only.

#### v1.9.5 - Per-node stability criteria (decide, don't ship the field)

The current EXPERIMENTAL label is atomic - the whole `--fusion`
layer carries it. That's over-broad. `m365_tenant`, `cdn_fronting`,
`aws_hosting`, `google_workspace_tenant` were validated at 100%
spot-check on the v1.9.0 corpus. `email_security_strong` was not.
They should not share a label.

This patch is about *deciding the criteria*, not shipping a
field. v2.0 ships with no `experimental` labels anywhere
(see v2.0.0 below), so the `stability: stable | experimental |
deprecated` field has nothing to express at v2.0 release time.
Ship the field when it's actually needed - which is the first
time a post-v2.0 patch adds a node that doesn't immediately
qualify as `stable`.

- **Per-node stability criteria** (behavioral, not engine-tautological):
  - **(a) Evidence-response correctness.** The node's posterior
    moves in the predicted direction when relevant evidence is
    added or removed, and *does not* move when irrelevant
    evidence is varied. This validates the network propagation
    works as designed for that node, not just that the engine
    runs Bayes.
  - **(b) Calibration in both regimes.** When the deterministic
    pipeline classifies the slug `high`, the Bayesian posterior
    is also high (> 0.5) and the credible interval does not span
    the full `[0, 1]` range. When the deterministic pipeline is
    silent (sparse target), the interval widens appropriately
    rather than collapsing on a confident-looking point estimate.
    Two binary checks; no ground-truth probability claim.
    Alongside these, record per-node **proper scoring rules**
    (Brier score, log-score) and **expected calibration error
    (ECE)** computed against the deterministic pipeline's
    high-confidence verdicts as a proxy label. These are
    diagnostic, not gating: a node with bad ECE on the proxy is
    flagged for re-examination of its CPT or topology, not
    auto-failed. The point is to make the verdict numerically
    defensible rather than purely behavioral.
  - **(c) Independent-firing threshold.** The node's evidence
    bindings have fired on at least N independent domains in
    aggregate corpus runs. Without enough firings we don't have
    enough data to support promotion regardless of point-spot-
    check rates.
- **Apply the criteria to the v1.9.0 seed network.** Each node
  gets a verdict - `stable` (clears all three) or `not yet`
  (one or more criteria unmet). The `not yet` verdicts feed
  the v2.0 disposition decisions: split the node, redefine it,
  remove it after a deprecation patch, or keep working on it
  in v1.9.x.
- **The `stability` field itself ships in v2.1 or later**, the
  first time a new node is added that needs the `experimental`
  value. v2.0 ships without the field; the schema disposition
  table accounts for nodes by name, not by per-node label.

**Quality bar - exceptionally well:**

- [ ] **Per-node verdict table** in `validation/v1.9.5-stability.md`.
  One row per node, three columns (a / b / c), explicit pass/fail.
  Pass requires *all three* - partial-pass nodes are `not yet`.
- [ ] **Numeric backing for criterion (b)**: per-node Brier score,
  log-score, and ECE on the v1.9.4 corpus run, with ranges
  documented (e.g., "ECE ≤ 0.20 considered acceptable for
  stable; > 0.20 flagged for re-examination, not auto-failed").
- [ ] **Independent-firing threshold (c) explicit**: N ≥ 10
  independent domains for stable; the table records the actual
  firing count per node from the v1.9.4 corpus, not a self-report.
- [ ] **Criterion-(a) test exists in code** as a parametrized
  test (`tests/test_node_stability_criteria.py`) - for every
  node, an assertion that varying its bound evidence moves its
  posterior and that varying unbound evidence does *not*. The
  test failing is a regression signal, not a v1.9.5-only check.
- [ ] **`not yet` verdicts route to specific dispositions** before
  v2.0:
  - Split the node (per v1.9.3 surgery template)
  - Redefine it (CPT changes with concept comments per v1.9.6)
  - Remove it (one-patch deprecation → next-patch deletion;
    no "experimental at v2.0" allowance)
  Each `not yet` node carries its disposition decision in the
  same v1.9.5-stability.md row.
- [ ] **No fast-tracking on numbers alone.** A node with great ECE
  but only 4 firings does not pass - the threshold is *all three*.

#### v1.9.6 - CPT-change discipline (concept, then parameter)

The v1.9.0 validation report initially recommended "lower
`P(strong|M365+gateway)` from 0.75 → ~0.55 because the corpus
shows 55%." That recommendation was wrong, not in the target
number but in the framing: it would have tuned a parameter to
match a corpus disagreement that turned out to be definitional
(see v1.9.3 `email_security_strong` split). The v1.9.6 discipline
codifies the right ordering: *question the topology first, then
update parameters with documented Bayesian discipline.*

Three categories of CPT change are distinguishable, and the
discipline treats them differently:

- **Structure learning (auto-deciding edges, banned).** Algorithms
  like PC, FCI, or GES that infer the DAG topology from data
  cross the "no autonomous topology change" invariant. Output as
  an *operator-facing proposal* (a human reads the candidate edges
  and decides whether to add them to YAML) is acceptable; the
  auto-apply step is the disqualifier.
- **Automated parameter fitting (banned).** Pipelines that
  read the corpus and auto-emit CPT values into
  `bayesian_network.yaml` without human topology review. EM
  fitting, Snorkel-style weak supervision, gradient descent on
  CPT entries, and similar fall here. The output is opaque in the
  sense that matters: a reader of the committed YAML cannot
  reconstruct what observed counts produced what posterior values
  without re-running the pipeline. This is the "no learned
  weights" invariant in its specific form.
- **Transparent Bayesian parameter updates (allowed, with
  discipline).** A CPT entry can be updated via an explicit
  Dirichlet posterior from documented corpus counts, provided
  the topology has already been verified and three conditions
  are met:
  1. The prior (its hyperparameters and the rationale for those
     hyperparameters) is published in the YAML comment for the
     CPT entry.
  2. The observed counts and the corpus they came from are
     published in the corresponding validation report.
  3. The posterior is computed exactly from the prior plus the
     counts, and the math is verifiable by a reader from the
     published numbers alone.

The first two categories stay banned because both can produce
CPT values whose derivation a reviewer cannot reconstruct from
committed artifacts. The third is allowed because Bayesian
updates from documented counts are transparent probability
theory, auditable end-to-end, and an unbiased statistical
estimator of the modelled population. Human hand-tuning with a
concept comment (the v1.9.6 worked example) remains acceptable
but is *not* the preferred path going forward: explicit Bayesian
updates with published priors and counts are more honest and
less subject to the cognitive biases of the human tuner.

- **Discipline (ordering, not prohibition).** Corpus runs are
  mirrors first, parameter inputs second. The human's job is to
  question the *topology* (is this node asking the right
  question?) before reaching for any parameter change. If the
  disagreement is high, the *first* hypothesis is that the model
  is conceptually wrong (the v1.9.3 `email_security_strong`
  story). Only after the topology is verified do CPT numbers get
  re-examined, and the preferred method for that re-examination
  is the transparent Bayesian update above, not hand-tuning.
- **Iteration cycle is fine; opaque automation is not.**
  Iterating "look at corpus → rewrite mental model → write new
  CPTs" with a human in the loop is the right cycle. An
  automated pipeline that reads the corpus and emits CPTs
  without topology review crosses the invariant.
- **Enforcement.** A contributor-facing note in
  `CONTRIBUTING.md` describes the three-category framework, the
  topology-first ordering, and the publication requirements for
  transparent Bayesian updates. PR review enforces; no automated
  test, because the test would game the comment requirement
  without measuring whether the concept-questioning actually
  happened.

**Quality bar - exceptionally well:**

- [ ] **Worked example in CONTRIBUTING.md**: the v1.9.3 surgery
  used as the canonical case. "We almost tuned a CPT and shipped;
  the right answer was topology surgery. Here's how to recognize
  the same pattern." Concrete enough that a future contributor
  facing a similar disagreement asks the topology question first.
- [ ] **PR-template addition**: a non-blocking checkbox `[ ] If
  this PR changes any CPT entry in bayesian_network.yaml, the
  YAML carries a comment explaining the *concept* this change
  reflects, not just the corpus statistic that motivated it.`
  Pre-filled in `.github/pull_request_template.md`. Reviewer
  enforces; checkbox is the prompt.
- [ ] **Anti-pattern catalog**: explicit list of changes the
  reviewer should reject - "lowered P(X|Y) from 0.75 to 0.55 to
  match corpus rate" without a concept comment is the canonical
  rejection. Three or four worked rejections in CONTRIBUTING.md.
- [ ] **No automated CPT-fitting tooling**: confirm no script
  under `scripts/` or `validation/` has emerged that auto-emits
  CPT values from corpus statistics. Periodic audit, not a
  test (the audit is the discipline).

#### v1.9.7 - Metadata-coverage gate (presence, not coverage)

The v1.9.0 advisory gate measures description coverage as a
percentage. Forcing 70% coverage means writing ~190 description
strings, many of which would be one-line placeholders just to
clear the gate. That's gate-gaming.

- **Reframe the metric.** Replace "≥ 70% description coverage on
  identity / security / infrastructure" with "every detection in
  identity / security / infrastructure has a non-empty
  description." Binary per-detection, not percentage per-
  category. Catches *omission*, not richness; richness is for
  PR review.
- **Implementation.** Modify
  `scripts/check_metadata_coverage.py` to count
  detections-with-empty-or-missing-description rather than
  percentage. Flip from advisory to enforcing when the count for
  gated categories is zero.

**Quality bar - exceptionally well:**

- [ ] **Per-category gap report**: when the script fails, output
  lists the exact slug + detection-rule pair missing a
  description, grouped by category. A contributor sees "fix
  these 7 entries" not "your category coverage dropped to 87%."
- [ ] **Pre-commit hook entry** added to `.pre-commit-config.yaml`
  so the gate fires locally before push, not just in CI. Faster
  feedback loop; aligns with the project's existing pre-commit
  posture.
- [ ] **What-good-looks-like guide** in `CONTRIBUTING.md`:
  description rubric requiring (a) what slug detects, (b) what it
  doesn't detect, (c) common false positives if known. Two or
  three worked examples (good vs placeholder). Empty-string
  presence checks the floor; the rubric raises it for new
  contributions.
- [ ] **Backfill before flip**: zero detections in
  identity/security/infrastructure are missing descriptions
  before the gate flips from advisory to enforcing. The flip is
  the last commit of v1.9.7, not the first; the patch ships with
  zero CI breakage on main.
- [ ] **Reference-presence reporting** added (advisory only at
  v1.9.7): script also reports references-missing per-detection
  count, but does not fail. Sets up the Track B metadata richness
  pass that follows.

#### Patch-release discipline

Each v1.9.x patch ships when *that one milestone* is complete.
This is intentional:

- **One milestone per patch** keeps the diff small and the changelog
  honest. A user reading "v1.9.4 - hardened-adversarial validation"
  knows exactly what shipped and what to test.
- **No bundling.** Two milestones completing on the same day is
  fine; they still ship as separate patches with separate tags.
  Bundled releases hide work and make rollback harder.
- **Numeric order IS delivery order.** The dependency chain is
  the point of the planning: hardened-adversarial validation
  (v1.9.4) informs the per-node stability decisions (v1.9.5),
  which inform CPT-change discipline (v1.9.6), which precedes
  the metadata-coverage gate flip (v1.9.7), which gates the
  richness pass (v1.9.8), which feeds the detection-gap UX
  surfaces (v1.9.9), which the stratified pre-lock validation
  (v1.9.10) verifies, which the doc-polish dry-run (v1.9.11)
  consolidates before v2.0 tags. Skipping ahead because a later
  patch "feels easier" means we're guessing at the dependency we
  just decided to think about.
- **Bug-fix patches use the next available number.** A regression
  fix that lands between v1.9.5 and v1.9.6 ships as `v1.9.5.1`
  or claims the next minor number - whichever the project's
  versioning strategy prefers at that moment. Bug fixes do not
  block bridge milestones, and bridge milestones do not block
  bug fixes; both make linear progress through their own number
  spaces.

EXPERIMENTAL labels come off per-node as the v1.9.4 → v1.9.11
sequence advances, not all at once. By the time v1.9.11 ships
(the doc-polish dry-run), every surface is either `stable`,
explicitly `experimental` (and we know why), or explicitly
`deprecated`. v2.0 then mechanically strips the remaining
EXPERIMENTAL language.

**v2.0 ships with zero EXPERIMENTAL labels anywhere.** This is a
hard rule, not an aspiration:

- Nodes that have cleared the v1.9.5 stability criteria → ship in
  v2.0 as `stable`.
- Nodes that have not cleared the criteria by v2.0 release time →
  **removed from `bayesian_network.yaml` for v2.0**, not shipped
  as `experimental`. They can be re-added in a v2.x patch once
  the corpus exposure validates them. A removed-and-re-added node
  is honest; an "experimental at v2.0" node is not, because v2.0
  is supposed to be the polished release.
- The per-node `stability` field stays in the schema for *future*
  use (post-v2.0 additions ship as `experimental` and graduate
  to `stable` later). It is not a v2.0 label-leftover surface.

This is stricter than the previous draft. The previous draft
allowed `experimental` per-node at v2.0; we removed that
allowance. If a node can't earn `stable`, it doesn't belong in
v2.0, full stop.

#### v1.9.8 - Catalog metadata richness pass (shipped)

**What shipped.** Description quality and reference coverage lifted
across the entire catalog. After this pass every detection in every
category satisfies all three proxy signals of the new advisory
richness audit:
- 100 percent of detections carry a non-empty `description`
  (presence floor from v1.9.7, retained).
- 100 percent of descriptions clear the 80-char length floor that
  proxies signal 1 of the rubric ("what the slug detects").
- 100 percent of descriptions contain scope-narrowing language
  (proxies signal 2: "what it does not detect"). The audit's token
  set was tuned to the catalog's actual writing style - explicit
  negation (`not`, `does not`) plus the idioms the catalog uses to
  narrow scope (`alternative`, `legacy`, `functionally equivalent`,
  `typically paired`, `same semantics`, `cname through`, `chain
  through`, `subdomain cnames into`, `government cloud`, and so on).
- 100 percent of detections carry a canonical vendor `reference`
  URL (vendor product or docs root, chosen conservatively to
  survive deep-link rot).

The original quality bar was "≥ 80 percent description, ≥ 25
percent reference in identity / security / infrastructure." The
shipped pass overshoots that target across every category.

Also shipped:
- `scripts/check_metadata_coverage.py --report-richness` advisory
  audit. Reports the three signals per category and surfaces a
  per-detection worklist; never gates.
- Inline weight rationale comments above every non-default
  `weight:` key (currently four detections in `security.yaml`).
- `CONTRIBUTING.md` rubric pointer refreshed to v1.9.8+.

**Why this was next.** v1.9.7 turned the metadata-presence gate
enforcing; v1.9.8 raised the floor from "every detection has a
description" to "every description is informative and externally
referenceable." Defenders read the `--explain` panel to decide
whether to act on a finding; a slug labelled `auth0` without a
description forces them to know what Auth0's CNAME pattern looks
like. v2.0 is the polished release; shipping with thin descriptions
or unreferenced detections would undercut the explainability
priority.

**Validation.** `validation/v1.9.8-metadata-audit.md` documents the
end-state numbers, weight-rationale table, and scope decisions.
`scripts/check_metadata_coverage.py --report-richness` shows 100
percent on every category and every signal.

#### v1.9.9 - Detection-gap UX surfaces (shipped)

**What shipped.** Three operator-facing surfaces in the default panel
that make the architectural limits of passive DNS collection visible.
No engine code changes, no JSON schema additions. The fourth roadmap
item from the original v1.9.9 scope (multi-apex CT SAN traversal)
deferred to v1.9.9.1 so the external-HTTP behaviour change can land
with its own validation pass.

1. **Passive-DNS ceiling phrasing.** When the default panel is sparse
   on an apex that probably should not be, a one-line teaching footer
   renders under the Services block: "Passive DNS surfaces what
   publishes externally. Server-side API consumption, internal
   workloads, and SaaS without DNS verification do not appear in
   public DNS records." Trigger heuristic is conservative on purpose:
   fires only when `info.services` is non-empty (a different surface
   owns failed runs), `info.domain_count >= 3` (the apex has multiple
   tenant domains, so sparse is genuinely surprising), categorized
   service families are fewer than 5, AND CNAME-chain subdomain
   attributions are fewer than 5. Both halves of the sparse check must
   hold so a domain with short Services but many surface attributions
   does not gain a misleading footer. `--full` / `--domains` suppresses
   the line because those modes already carry the long surface
   section.
2. **Common-prefix wordlist extensions.** The active-DNS probe in
   `recon_tool/sources/dns.py` and the CT high-signal sort in
   `recon_tool/sources/cert_providers.py` both gained eight prefixes
   covering tiers the prior wordlist ignored: `data`, `analytics`,
   `ai`, `ml`, `internal`, `ops`, `tools`, `security`. Each prefix
   maps to a recognised stack tier with vendor-product backing
   (Snowflake under `data`, Vertex AI under `ai`, internal portals
   under `internal`, SIEM consoles under `security`). The CT-side
   additions keep prioritization parity so a CT response surfacing
   `data.contoso.com` sorts to the top of the bounded output rather
   than falling off the cap.
3. **Apex-level multi-cloud rollup indicator.** When the canonicalized
   vendor count across apex slugs and surface attributions is at least
   two, a `Multi-cloud` row joins the key-facts block above
   Confidence: for example `Multi-cloud: 3 providers observed (AWS,
   Cloudflare, GCP)`. A single-vendor apex stays unannotated. Sibling
   slugs collapse: AWS Route 53 plus AWS CloudFront is one AWS vote.
   Firebase rolls up under GCP. The canonicalization map
   (`_CLOUD_VENDOR_BY_SLUG` in `formatter.py`) is the single source of
   truth; two public helpers (`canonical_cloud_vendor`,
   `count_cloud_vendors`) sit on top of it so future panels and JSON
   paths can reuse the canonicalization without duplicating the table
   inline.

**Why this was next.** v1.9.3.10 surfaced the unclassified-chain gap
and per-provider subdomain counts in the default panel. v1.9.9
completes the detection-gap surface story: the panel now shows what it
cannot see (the ceiling), casts a wider net for what it can see
(enumeration breadth), and summarises the distribution (multi-cloud
indicator). After v1.9.9 the default panel is honest about both its
findings and its limits, which is the v2.0 polish target.

**Quality bar - verified at ship.**
- Ceiling phrasing fires only on sparse-services + multi-domain
  apexes. Both `len(categorized) < 5` and `len(surface_attributions) <
  5` must hold; `domain_count >= 3` gates the multi-domain check.
- Subdomain wordlist additions documented per term with inline
  comments naming the stack tier and the vendor-product idiom that
  motivates inclusion. No speculative additions; the eight prefixes
  map one-to-one to recognised stack tiers.
- Multi-cloud indicator counts canonicalized vendors, not slugs. The
  `count_cloud_vendors` helper round-trips through
  `_CLOUD_VENDOR_BY_SLUG` so sibling slugs collapse before the trigger
  threshold is checked.
- Tests: **167 v1.9.9 tests across 20 new test files** covering six
  orthogonal axes (trigger behaviour, test quality, integration,
  robustness, corpus validation, documentation). Full suite at
  **2481 pass / 1 skip / 4 deselect**; coverage 84% total. Deterministic
  under both `--cov` and non-`--cov` runs.

**Validation.** Two memos:
- `validation/v1.9.9-detection-gap-ux.md` - per-fixture trigger
  behaviour, wordlist rationale, canonicalization decisions
  (Firebase under GCP, Replit and Glitch excluded), test-quality
  manifesto with explicit "what we test and what we honestly do not"
  framing.
- `validation/v1.9.9-corpus-run.md` - synthetic 19-fixture corpus
  results: 8/19 multi-cloud fires (42.1%), 11/19 ceiling fires
  (57.9%). The corpus is publicly reproducible from
  `validation/synthetic_corpus/generator.py`; the aggregator at
  `validation/corpus_aggregator.py` mirrors the renderer's trigger
  logic and emits anonymized counts (no apex names).

**Refinement.** Two items moved to v1.9.9.1:
- Multi-apex CT SAN traversal (pull subdomains from all observed apex
  certs, not just the queried apex's). External-HTTP behaviour change
  warranting its own validation pass against the v1.9.4 hardened
  corpus.
- CT-by-org-name search when an organization name is available from a
  prior lookup. Same external-HTTP rationale.

#### v1.9.10 - Stratified-corpus pre-lock validation (shipped)

**What shipped.** A 60-fixture publicly-reproducible synthetic
corpus across six cloud strata (GCP, Azure non-O365, Oracle,
Alibaba, PaaS/Vercel/Netlify, SSE/SASE), plus the v1.9.9 19-fixture
base corpus = 79 fixtures total. Per-stratum aggregator emits
coverage metrics. Bayesian network re-validated against the v1.9.9
evidence-distribution shift; v1.9.6 disposition table holds. Full
write-up at `validation/v1.9.10-pre-lock.md`,
`validation/v1.9.10-bayesian-revalidation.md`, and
`validation/v1.9.10-mutation-status.md`.

**Why this was next.** Up to v1.9.9 the validation was single-
corpus (enterprise M365/AWS-skewed) plus one small rich-stack
empirical pass (v1.9.3.10). v1.9.10 confirms the engine works
across cloud strata, not just the ones the historical corpus
over-represented. Strata-specific behaviour is documented
explicitly in the per-stratum aggregate output rather than hidden.

**Scope discipline (no real customer data).** The roadmap original
quality bar called for "publicly-documented users of that vendor
sourced from vendor case-studies, vendor blog posts, or job
listings". The maintainer's no-real-data discipline (Microsoft
fictional brands only for committed examples) takes precedence:
v1.9.10 ships with **synthetic** stratified fixtures modelled
after public deployment patterns, not with real customer apex
names. The corpus aggregator is reusable against the maintainer's
gitignored private corpus; that real-corpus run produces the
truth-of-record numbers and remains standing work.

**Quality bar - verified at ship.**
- 60 stratified synthetic fixtures (10 per stratum) all
  Microsoft-fictional, deterministic generator at
  `validation/synthetic_corpus/generator.py`.
- Per-stratum coverage metric reported in
  `validation/synthetic_corpus/aggregate.json` and the
  `validation/v1.9.10-pre-lock.md` table.
- Per-stratum unclassified-termini count: zero (synthetic fixtures
  do not include unclassified CNAME chains by construction).
- Bayesian re-validation: 20/20 v1.9.5 stability tests pass on the
  v1.9.9 codebase; the network's evidence bindings are unchanged
  by the v1.9.9 wordlist additions (the wordlist widens slug
  collection at the surface-attribution layer; the network reads
  upstream signals not affected by the wordlist).
  See `validation/v1.9.10-bayesian-revalidation.md`.
- Aggregate findings published in `validation/v1.9.10-pre-lock.md`.

**Items deferred to v1.9.11 or later.**
- **Trend table v1.6 → v1.9.10 per stratum.** Requires re-running
  earlier versions against the new strata. Substantial standalone
  work; v1.9.11 doc-polish pass is the natural home.
- **Real-corpus aggregator run.** The maintainer runs locally
  against the gitignored private corpus and drops the aggregate
  output into `validation/v1.9.10-corpus-run.md`. The script is
  ready (`validation/corpus_aggregator.py`); the data is not
  committed. Tracked in `validation/invariant_audit.md` item 1.
- **Cosmic-ray full sweep on `formatter.py`.** Slipped to the v2.0
  schema lock with a Linux CI runner. Rationale in
  `validation/v1.9.10-mutation-status.md`: the catalog-driven
  Hypothesis tests added in v1.9.9 already caught a real
  pre-existing bug (the `Data & Analytics` KeyError), which is
  stronger evidence of test-quality breadth than a clean
  cosmic-ray run would be. Tracked in
  `validation/invariant_audit.md` item 2.

**Refinement.** None required. Per-stratum firing rates are within
the synthetic-corpus design envelope (multi-cloud rollup fires
0-70% per stratum depending on whether stratum fixtures are
intentionally single-cloud or multi-cloud; ceiling fires 78-100%
per stratum because synthetic fixtures are sparse-by-design). The
gitignored-private-corpus run will produce the truth-of-record
numbers.

#### v1.9.11 - Documentation polish dry-run (shipped)

**What ships.** Every doc reviewed against the v2.0 quality bar
before v2.0 actually tags. correlation.md polished to the v2.0
draft form (defense ↔ correlation mapping table, prior-art
comparison, dependency-floor manifesto, failure-mode catalog).
README, CONTRIBUTING, AGENTS.md, docs/mcp.md, docs/legal.md,
docs/security.md cross-checked for stale references, dead links,
EXPERIMENTAL labels in user-facing text. Migration guide for
v1.x → v2.0 consumers (`docs/migration-v2.md`, skeleton already
in place) populated with the field-by-field promotion list and
the Bayesian-network node disposition.

**Why this is next.** v2.0 should be a mechanical lock-and-tag
event, not a "let's also rewrite docs" event. If the v2.0 docs are
already polished, the lock just bumps the schema version, strips
EXPERIMENTAL labels from code/JSON descriptions, and tags. Doing
the doc work as v1.9.11 separates the rewriting from the
mechanical lock.

**Quality bar (each item links to a concrete artefact).**

- [ ] **Zero EXPERIMENTAL labels in user-facing surfaces.**
  Current baseline: 38 hits across 14 files
  (`validation/v2.0-prep-baseline.md` §1). v1.9.11 brings this to
  zero. Verified by a CI `grep -ri experimental` gate added in
  the release workflow.
- [ ] **Migration guide populated.** Skeleton at
  `docs/migration-v2.md` lists the field-promotion table,
  Bayesian-node disposition section, schema-version bump notes,
  and downgrade-path recommendation. v1.9.11 fills in any
  per-field details that depended on the v1.9.10 → v1.9.11
  decisions (specifically the `okta_idp` disposition outcome).
- [ ] **Trend table v1.6 → v1.9.11 per Bayesian-network node.**
  Compiled from `validation/v1.9.*-calibration.md` per-release
  numbers and the v1.9.10 stratified-corpus aggregate. Anchors
  the v2.0 "engine got better" claim with public per-release
  numbers. Lives in `validation/v1.9.11-trend-table.md`.
- [ ] **Schema disposition test green.** `tests/test_schema_disposition.py`
  (added in v1.9.10.1 prep) passes with zero entries in
  `_V2_KNOWN_SCHEMA_GAPS`. The current single entry
  (`ecosystem_hyperedges` - batch-wrapper field not in schema)
  is the v1.9.11 worklist item.
- [ ] **`okta_idp` disposition applied.** Decision in
  `validation/v2.0-prep-baseline.md` §3 (keep + corpus-expansion,
  deprecate, or split). Whichever is chosen, the
  `bayesian_network.yaml` and the migration guide reflect the
  final disposition.
- [ ] **Real-corpus aggregator run.** Decision in
  `validation/v2.0-prep-baseline.md` §4 (v2.0 blocker vs.
  maintainer attestation). Whichever is chosen, the artefact or
  attestation is in place before v2.0 tags.
- [ ] **Every cited prior-art reference in correlation.md is
  reachable.** No dead links.
- [ ] **Dependency-floor manifesto matches `pyproject.toml`.**
  Every listed dependency is in the lockfile; every excluded
  dependency is genuinely not pulled in transitively.
- [ ] **CONTRIBUTING.md procedure walkthrough.** A maintainer
  follows the "add a new fingerprint" steps end-to-end using only
  the doc text. Gaps surface here, not after v2.0 ships.

**Validation.** Re-run the synthetic corpus aggregator
(`validation/corpus_aggregator.py`) plus the v1.9.3.10 empirical
sample on the v1.9.11 build. Confirm the trend table numbers
match the per-release memos. No code change between v1.9.11 and
v2.0 should be required.

**Refinement.** If the docs review surfaces gaps in the code (e.g.
a docstring describes behaviour the code doesn't implement),
v1.9.11 ships a follow-up code patch before v2.0 starts. The
v2.0 release notes should read like an inventory, not a feature
list - every claim should already be true at v1.9.11 tag time.

_Additive feature candidates (BIMI VMC clustering, MCP delta helper,
self-audit batch mode, non-MCP graph exports, per-node
`n_eff_multiplier`, corpus-driven Hypothesis tests, Hawkes-kernel
CT burst classification, LPA fallback for `infra_graph`, explicit
ignorance mass, noisy-OR / noisy-AND CPT gates) are now in the
[Backlog (after v2.0)](#backlog-after-v20) section. They were
previously framed as "optional v1.9.x feature additions"; under
the v1.9.4 → v2.0 linear sequence, they no longer claim slots in
the path-to-v2.0 plan. Any of them may be promoted into a
post-v2.0 v2.x.y patch when there's a falsifiable defensive case
and corpus evidence to back it._

### v2.0.0 - Maturity

Lock in what the previous releases proved. Promote stable experimental
fields to the v2.0 schema contract; make the catalog community-PR-
friendly; ensure the framework is suitable for sustained corpus-driven
operation.

**Pre-conditions** - the v1.9.4 → v1.9.11 linear sequence has
completed, in order:

1. **v1.9.4** - Hardened-adversarial behaviour validated; 50-domain
   minimal-DNS corpus exercises the asymmetric-likelihood design.
2. **v1.9.5** - Per-node stability dispositions decided for every
   Bayesian-network node; "not yet" nodes either redefined,
   deprecated, or removed.
3. **v1.9.6** - CPT-change discipline documented in
   `CONTRIBUTING.md` and enforced in review.
4. **v1.9.7** - Metadata-coverage gate flipped from advisory to
   presence-enforcing.
5. **v1.9.8** - Catalog metadata richness: 100 percent of detections
   carry substantive descriptions, scope-narrowing language, and a
   canonical vendor `reference` URL across every category;
   advisory `--report-richness` audit shipped.
6. **v1.9.9** - Detection-gap UX surfaces shipped: passive-DNS
   ceiling phrasing, expanded subdomain enumeration breadth,
   apex-level multi-cloud rollup indicator.
7. **v1.9.10** - Stratified-corpus pre-lock validation passed:
   60-domain stratified suite (per-cloud × 6 strata) shows the
   engine works across cloud customers, not just the
   enterprise-M365/AWS-skewed historical corpus.
8. **v1.9.11** - Documentation polish dry-run: every doc reviewed
   against v2.0 quality bar; migration guide drafted; zero
   EXPERIMENTAL labels remain in any user-facing text.

Each version's prose above documents its own quality bar,
validation step, and refinement check.

Already cleared en route to this sequence:

- ~~v1.9.2 (operator UX validation via agentic QA)~~ - see
  `validation/v1.9.2-agentic-ux.md`.
- ~~v1.9.3 (email_security_strong definitional gap)~~ - see
  `validation/v1.9.3-calibration.md`.
- ~~Supply-chain hardening, SBOM, secrets-scanning, forward-compat
  cache test~~ - shipped in v1.9.3.1.
- ~~Top-3 influential edges in --explain-dag~~ - shipped in v1.9.3.2.
- ~~Cloud-vendor coverage gap fill (GCP / Azure non-O365 / Oracle
  / IBM / Alibaba / PaaS / SSE-SASE / identity extras; 29 new
  fingerprints)~~ - shipped in v1.9.3.9.
- ~~Subdomain-level surface intelligence in default panel
  (unclassified-surface section + per-provider counts)~~ -
  shipped in v1.9.3.10.
- ~~Downstream consumption examples (Splunk + Elasticsearch field
  mappings, CI gate against schema drift)~~ - shipped in v1.9.3.8.

**Schema-lock disposition** (every EXPERIMENTAL field gets a verdict):

| Field | Disposition |
|---|---|
| `posterior_observations` | Promote to stable. Pin `name`, `description`, `posterior`, `interval_low`, `interval_high`, `evidence_used`, `n_eff`, `sparse`. |
| `slug_confidences` | Promote to stable. Existing `[slug, posterior]` shape. |
| `chain_motifs` (v1.7) | Promote to stable if v1.9.x corpus runs continue to fire on real targets. |
| `wildcard_sibling_clusters` (v1.7) | Promote to stable. |
| `deployment_bursts` (v1.7) | Promote to stable. |
| `infrastructure_clusters` (v1.8) | Promote to stable. |
| `ecosystem_hyperedges` (v1.8, batch-only) | Promote to stable; document as batch-only contract. |
| `evidence_conflicts` (v1.7) | Already stable shape; formally promote in schema. |
| `--fusion` flag | Drop EXPERIMENTAL label. |
| `--explain-dag` flag | Drop EXPERIMENTAL label. |
| MCP `get_posteriors` / `explain_dag` tools | Drop EXPERIMENTAL label. |
| `bayesian_network.yaml` topology | Lock at v2.0; further changes require schema-version bump. |
| Bayesian-network nodes that clear v1.9.5 criteria | Ship in v2.0. |
| Bayesian-network nodes that do NOT clear v1.9.5 criteria | Remove via deprecation: a v1.9.x patch marks the node deprecated in CHANGELOG and emits a one-time stderr warning when it's used; the next patch removes it from `bayesian_network.yaml`. v2.0 ships without the node. **No node goes from `experimental` directly to "removed" without a deprecated stop in between.** |
| Per-node `stability` field | Not shipped at v2.0. Reserved for v2.1+ when a new node first needs the `experimental` value. |

**v2.0 itself is purely the lock-and-polish ceremony - three items:**

- **Schema lock.** Apply the disposition table above. Bump
  `docs/recon-schema.json` to v2.0; remove EXPERIMENTAL language
  from the promoted fields' descriptions. This is mechanical
  once the v1.9.x patches have validated everything.
- **Bayesian fusion goes default-on with a clean-panel
  disclosure rule.** See the design-decision subsection
  immediately below this list.
- **Documentation snapshot.** [`correlation.md`](correlation.md)
  (currently a living draft) promoted to a polished reference.
  Sections required for the snapshot:
  - **Defense ↔ correlation mapping** table so a defender can
    read across from "what I'm worried about" (shadow
    infrastructure, lookalike domains, sovereignty drift,
    supply-chain motif change) to "which correlation layer
    surfaces it" (rules, wildcard SAN siblings, temporal bursts,
    chain motifs, community detection, posterior shift).
  - **Prior-art comparison.** Existing probabilistic libraries
    (pgmpy, pomegranate, PyMC / Stan / Pyro) - what they are,
    what they do well, and the specific reasons we did not
    import them. Concepts we adopted are already cited inline
    (Jeffrey 1965, Walley 1991, Augustin et al. 2014, Taroni
    et al. 2014, Minka 2001, Naeini et al. 2015, Pearl 1988,
    Russell-Norvig, Zhang & Poole 1994, Koller & Friedman 2009,
    Blondel et al. 2008, Traag et al. 2019); this section makes
    the *implementation choices* explicit so a careful reader sees
    what we considered and rejected, not just what we used.
  - **Dependency-floor manifesto.** Complete runtime dependency
    graph (httpx, dnspython, pyyaml, typer, rich, mcp, networkx,
    pydantic-via-mcp) and the list of widely-used libraries we
    *deliberately do not* depend on (numpy, scipy, pandas,
    pgmpy, pomegranate, PyMC, Stan, Pyro, scikit-learn, Redis,
    SQLite, Celery, FastAPI, Shodan / Censys / SecurityTrails
    APIs, GeoIP / ASN databases) with one-sentence reasons.
    Defensive, adaptive, and coding-discipline posture as one
    artifact.
  - **Failure-mode catalog** carried forward from v1.9.4 with
    additional examples accumulated from corpus runs.
  - **Engineering quality posture** carried forward from this
    roadmap, edited for the polished-doc voice.

**v2.0 design decision: Bayesian fusion goes default-on with a
clean-panel disclosure rule.**

Through v1.9.x the Bayesian inference layer was gated behind
`--fusion` because the math was EXPERIMENTAL. The v1.9.4 →
v1.9.10 stability work was specifically the path from experimental
to "stable enough to ship by default." Once that path completed,
keeping the layer opt-in became a half-promotion that contradicted
correlation.md §5.1 ("hedging is a calibration choice, not
politeness") and made the default panel less honest than the
inference engine knew how to be.

v2.0 flips the default. The math runs unconditionally; the panel
stays clean; users who want a purist rule-based view can opt
out.

*Default behavior at v2.0:*

- **Compute always.** Bayesian inference runs on every lookup.
  Cost is zero network calls (the comment at `cli.py:2365`
  already documents this: "Costs nothing, no network calls, so
  the recompute is cheap").
- **`--json` always emits** `posterior_observations` and
  `slug_confidences`. Schema-additive per the v2.0 contract; no
  consumer that ignores unknown fields breaks.
- **Default panel stays clean.** The rule-based verdict
  (Provider, Tenant, Confidence dots, Services) renders exactly
  as it does today. The credible interval is computed but not
  rendered in the default panel.
- **Default panel speaks up when the layers disagree.** When
  `sparse=true` fires on a node the panel is reporting a
  verdict for, or when the posterior mode disagrees with the
  deterministic slug, the panel surfaces the interval inline
  and demotes the confidence-dot indicator. This is the
  operator-actionable case: the deterministic engine says one
  thing, the Bayesian layer says "but the evidence is thin."
  Quiet on the easy cases, loud when it matters.

*User control surfaces at v2.0:*

- `--verbose` (existing flag): always render the credible
  interval inline in the panel, including on easy cases. For
  operators who want the math visible by default.
- `--explain` (existing flag): full evidence-DAG provenance.
  Unchanged from v1.9.x.
- `--explain-dag` (existing flag): render the Bayesian DAG.
  Unchanged.
- `--no-fusion` (new at v2.0): disables Bayesian computation
  entirely. The `--json` output omits `posterior_observations`
  and `slug_confidences`. Output reverts to the v1.x rule-based
  shape. For SIEM consumers who want stable rule-based output
  without the additive Bayesian fields, and for purists who
  want only the deterministic engine. Documents the opt-out as
  a stable surface; not a deprecation path.
- `--fusion` (existing flag): kept as a deprecated no-op for
  v2.0.x to preserve back-compat with automation that flips it
  on explicitly. Removed in v2.1.

*Why the disagreement-detection rule rather than always-show or
never-show:*

Always-show clutters the default panel for the 70 percent of
cases where rule-based and Bayesian agree (a Microsoft 365 tenant
with 4 sources of evidence does not need a credible interval to
be readable). Never-show contradicts the doc's epistemology and
hides the load-bearing field. The middle path surfaces the math
precisely when it changes the operator's read of the situation:
hardened targets, sparse evidence, conflicting signals. The
v1.9.4 hardened-adversarial validation showed 64 percent
sparse-flag firing on hardened targets, which is exactly the
population this rule is designed to escalate.

*Implementation surface (lock-ceremony work, not earlier):*

- Remove the `if fusion or explain_dag:` gate at `cli.py:2374`.
  Compute Bayesian inference unconditionally.
- Add `--no-fusion` (typer.Option with `--fusion/--no-fusion`
  pair semantics; default True).
- Gate panel-rendering of the credible interval in
  `formatter.py` on `--verbose` OR on the disagreement rule
  (`sparse=true` on a reported node, or posterior-mode/slug
  disagreement).
- Update `docs/stability.md` `--fusion` row from "Opt-in
  Bayesian fusion" to "Bayesian fusion control (default on
  v2.0+; `--no-fusion` opts out)."
- Update the README example panel to show what happens in the
  disagreement case (operator sees the credible interval
  inline) versus the easy case (panel unchanged from today).
- Document `--no-fusion` in `docs/stability.md` as a stable
  surface at v2.0.

This is the only behavioral change in v2.0 beyond the schema
lock. Tests already exercise both code paths (the `--fusion`
code path runs in the test suite); the change is moving the
default and adding the inverse flag, not adding new logic.

**v2.0.1 panel-disclosure design (the disagreement rendering). Shipped v2.0.1.**

v2.0 shipped the default panel unchanged and the math in `--json` and
`--explain-dag`. v2.0.1 adds the panel "speak up" rendering. The design as built:

- **The confidence dots map to a single defined quantity.** When fusion has run,
  the dots reflect a claimed node's posterior support relative to the
  present/absent decision threshold (0.5), in three levels: the whole 80%
  credible interval above the threshold renders `●●●`; the point estimate above
  but the interval dipping below renders `●●○` (thin); the point estimate below
  the threshold renders `●○○` (the evidence leans against the call). The dots are
  one honest reading (posterior support), not a fusion of the source count and
  the interval width; the deterministic corroboration stays in the `(N sources)`
  text. Without posteriors (`--no-fusion`) the dots fall back to the deterministic
  tier and the panel is byte-identical to v1.x.
- **The weakest claimed node drives the line.** A claimed node is one with fired
  evidence (`evidence_used` non-empty), so a declarative node correctly reporting
  absence (for example "not enforcing", no fired binding) does not demote a
  strong verdict. The panel is as confident as its shakiest asserted claim.
- **One plain-language clause, dimmed.** When the weakest claimed node is below
  full confidence the panel adds a dimmed line under the Confidence row: "thin on
  <claim>" at `●●○`, "the evidence does not back <claim>" at `●○○`. The claim is
  named in human terms, not by node id.
- **Accessibility.** Solid versus hollow carries the whole signal with no color;
  a green / blue / terracotta hue is the second channel, never the only one.
  Glyphs are limited to `●` and `○` for terminal-font safety.
- **`--verbose`.** The Evidence Detail section lists each claimed node's
  `posterior [low, high]` (comma range), under a "Posteriors (80% credible
  interval)" heading so the range is not read as a frequentist confidence
  interval.
- **Determinism.** The dot fill is a pure function of the posterior, the interval,
  and the threshold, pinned by a property test (`tests/test_posterior_dots.py`)
  so the renderer cannot drift or recalibrate through the UI.

Deferred past v2.0.1: localized dimming of a disputed claim's span in the Provider
line (the dots plus the named clause already point the operator at the shaky
claim), density glyphs, and sparklines. The panel earns a word only when the
evidence does.

---

That is v2.0. Everything else - feature additions, MCP tools,
exports - ships in v1.9.x patch releases as work completes,
under the same EXPERIMENTAL labelling discipline. By the time the
schema lock runs, the features are already in the wild and their
shapes are known.

**Validation gate for v2.0** - re-run the full corpus with the
locked schema; confirm no field-shape regressions. Trend metrics
across v1.6 → v2.0 demonstrate the correlation engine got better
without overclaiming.

**Quality bar for v2.0 itself - exceptionally well:**

- [x] **Schema lock validates against published consumers.** The
  Track B SIEM examples re-parse without modification on the v2.0
  schema. Pinned by `tests/test_siem_examples.py` (37 tests
  covering field-presence contracts, Splunk + Elastic README
  field-mapping accuracy, search-safety patterns, and severity
  mapping consistency). If a SIEM example breaks, this test
  suite fails first.
- [x] **`validation/v2.0-validation-summary.md` published** -
  full corpus results, trend table v1.6 → v1.7 → v1.8 → v1.9.0 →
  v1.9.3 → v1.9.4 → v1.9.14 per node, security-closure trail
  through v1.9.14. The trend table is the public evidence the
  engine got better. Shipped in commit `ec14bdc` (v2.0 prep);
  real-corpus numbers in `validation/v2.0-corpus-run.md` from
  the v1.9.14 scan (commit `cca815c`).
- [x] **All Track A + Track B pre-conditions ticked off** in the
  v2.0 release CHANGELOG entry, each with a link to its shipping
  patch. Staged in `validation/v2.0-release-notes-draft.md` (12
  pre-v2.0 releases, v1.9.3 → v1.9.14, each row linked to its
  tag and validation memo; security closure table separately
  linked per closing commit). Moves into `CHANGELOG.md` under
  `## [2.0.0]` at lock time.
- [x] **Zero EXPERIMENTAL labels** in any docstring, panel string,
  CLI help text, MCP tool description, or schema field
  description. `grep -ri experimental recon_tool/` returns zero
  user-facing hits (internal test markers excepted). The one
  residual mention in `docs/stability.md:139` is descriptive
  past-tense ("the EXPERIMENTAL qualifier in docstrings and
  schema descriptions is removed") rather than an active label.
- [x] **No "v1.9.x" references** linger in user-facing docs as
  forward-looking commitments. A v1.9.x audit found one
  historical mention in `docs/roadmap.md` ("future v1.9.x
  reports") and one "post-v2.0 surface" deferment note in
  `examples/siem/splunk/props.conf` for `--emit-timestamp`;
  both are honest historical or deferment framing rather than
  forward-looking commitments the user reads as broken
  promises.
- [x] **Polish-doc cross-checks** in correlation.md: every cited
  prior-art reference is reachable (no dead links); every
  dependency in the manifesto matches `pyproject.toml`'s actual
  dependency list (no manifesto/code drift).
- [x] **`recon doctor` updated** to print "v2.0 stable schema" in
  its first line, and to verify the locked schema fields are all
  present in a sample lookup output. Already wired in
  `recon_tool/cli.py:1805-1809`: the doctor preamble flips to
  "v2.0 stable schema" when `__version__.startswith("2.")` and
  shows "pre-v2.0 schema" otherwise. Activates automatically the
  moment the lock-ceremony version bump lands.

### v2.1.0 - Operator-driven catalog growth (closed-loop fingerprint mining)

The first slot after v2.0 lock. Composability is next in priority
order (correctness → reliability → explainability → composability →
features), and v2.0 doesn't advance it - v2.0 is pure
lock-and-polish on what already works.

**Framing.** The recon catalog is shaped by passive-DNS observation
of real corpora. Today, that observation is maintainer-side: the
maintainer runs `validation/scan.py` against a private corpus, the
post-triage gap list surfaces unfingerprinted CNAME terminals, and
catalog patches land in `recon_tool/data/fingerprints/`. The v1.9.11
4,270-apex pre-v2.0 scan was the most recent execution of this
pattern (28 new slugs in one batch, see CHANGELOG). v2.1 promotes
this from maintainer-only tooling to a public operator workflow:
any operator with a private domain list of their own can run the
same scan-aggregate-triage loop locally, add catalog entries to
`~/.recon/fingerprints.yaml` for their environment, and contribute
broadly-useful ones back upstream. This is a composability win
(the catalog becomes user-extendable along the same primitive the
maintainer uses) rather than a feature addition.

The mining primitive already ships. The MCP tool
`discover_fingerprint_candidates(domain)` (live in `server.py`
since v1.7) already does the hard work: resolves the domain,
captures unclassified CNAME chains, applies intra-org / already-
covered filters via `recon_tool/discovery.py::find_candidates`,
and returns a ranked candidate list. The
`/recon-fingerprint-triage` Claude Code skill is already designed
to turn that list into YAML stanzas for `surface.yaml`.

What's missing is *the loop*: a reproducible runner that uses
the existing MCP composition (`lookup_tenant` →
`chain_lookup` → `discover_fingerprint_candidates` →
`test_hypothesis` → `get_posteriors`) to systematically expand
the catalog while measuring whether the expansion actually
tightens correlation depth on the corpus. This makes the "art of
correlation" *executable at scale* instead of a one-time
hand-tuning exercise.

**Primary v2.1 surface:**

- **One new MCP skill:**
  - `run_fingerprint_mining(seed_domains, max_candidates_per_domain=20,
    dry_run=True)` - for each seed, runs the existing chain →
    discovery → hypothesis-test pipeline and draws candidates
    from three already-shipped graph layers: chain motifs (v1.7
    `motifs.yaml` + `discover_fingerprint_candidates`), Louvain
    communities (v1.8 `infrastructure_clusters`), and ecosystem
    hyperedges (v1.8 batch hypergraph). Outputs ranked candidates
    plus the projected impact on the corpus (Δ correlation depth,
    Δ entropy reduction, conflict rate against existing nodes if
    the candidate were accepted). Never writes to committed
    catalogs. `dry_run=True` is the only supported value at v2.1
    ship.
- **One CLI command:**
  - `recon run fingerprint-mining --seed=<domain> --iterations=N
    --dry-run` (alias `recon mine`). Uses the MCP client
    internally so agent and CLI behavior stay identical.
  - Default output is one-line-per-candidate ranked summary
    (rank, candidate suffix, count, projected Δ-correlation-
    depth). `--detail` flag surfaces the full per-candidate
    impact analysis; `--detail --json` emits the structured
    NDJSON for agent consumption. Avoids drowning the operator
    in metrics by default while keeping them one flag away.

**Projection method.** The Δ-metric claims are *empirical*, not
closed-form. For each candidate, the runner constructs a
hypothetical fingerprint (the candidate stanza), uses the
existing `test_hypothesis` MCP path to ephemerally inject it,
re-runs inference on the corpus snapshot, and diffs against the
baseline. No new math, no learned weights, just inference
re-runs over a hypothetical catalog.

**Mining-corpus / holdout-validation-corpus split (load-bearing).**
The most consequential design choice in v2.1 is that the corpus
mined from and the corpus the projected delta is evaluated against
*must not be the same set of domains*. Mining candidates from
corpus $C$ and then computing their projected delta on the same
$C$ is textbook data snooping: the runner systematically prefers
candidates that look good on $C$ because they were mined to look
good on $C$. The projected delta on $C$ does not generalise; any
calibration claim downstream of v2.1 mining (ECE, Brier, survival
ratios in future v1.9.x reports) would be compromised the moment
a mined candidate enters the committed catalog.

The discipline is explicit:

- The private corpus must be partitioned into
  `validation/corpus-private/mining/` and
  `validation/corpus-private/holdout/`. The partition is one-time,
  documented, and stable across releases. The current
  v1.9.4-hardened-adversarial 50-domain corpus and v1.9.0 91-domain
  soft corpus together form the partition input;
  `mining/` should be the larger split (roughly 100 domains) and
  `holdout/` the smaller (roughly 40 domains stratified to mirror
  `mining/`'s posture mix).
- `run_fingerprint_mining` mines candidates only from `mining/`.
  The MCP tool refuses to mine from `holdout/`; the runner's
  configuration explicitly disallows it.
- The projected delta for each candidate is computed *against the
  holdout corpus*, not against the mining corpus. This is the
  unbiased estimate of generalisation.
- Acceptance criterion: a candidate enters the committed catalog
  only if the holdout-corpus projected delta is **statistically
  significant**, not merely "within some fraction of the mining
  delta." A flat shrinkage factor (the original draft proposed
  60%) is arbitrary: a $0.06$-nat entropy reduction on a small
  holdout set might be driven by a single domain rather than
  genuine structural signal.
  - **Test:** paired permutation test on per-domain entropy
    reduction (or per-domain correlation-depth change) on the
    holdout corpus, comparing the inference run with the
    candidate injected against the baseline run without it.
    Null hypothesis: the candidate produces no per-domain
    improvement on average. Two-sided $p$-value computed via
    $10^4$ random sign-flip permutations of the per-domain
    difference vector. Reject the null at $p < 0.05$ for the
    candidate to pass.
  - **Effect-size guard:** the median per-domain entropy
    reduction on the holdout set must be at least one-quarter
    of the median on the mining set. This catches candidates
    that achieve nominal significance from a long tail of
    barely-improved domains without meaningful structural
    impact.
  - **Cross-validation:** if the holdout set is small enough
    that one domain dominates the test ($k$-domain leave-one-out
    instability above 20% on the permutation $p$-value), the
    candidate is held until the holdout corpus grows or the
    operator manually reviews the dominant domain's impact.
  - Candidates that fail any of the three tests are flagged as
    "may not generalise" and require additional review; they do
    not enter the committed catalog through the automatic path.
- After acceptance, the v1.9.x calibration reports that use
  `mining/` lose their unbiased-estimator status for any node
  affected by the newly accepted catalog change. The honest
  reporting move is to re-run all affected calibration on
  `holdout/` and publish *those* numbers as the post-v2.1
  authoritative figures.

Falsifiable: if the operator accepts a candidate and re-runs the
full corpus, the realized delta should match the projected
*holdout* delta to within a documented tolerance. If the realized
delta matches the mining delta but not the holdout delta, the
candidate was over-fit to the mining set and the discipline has
been violated; investigate.

This split is a precondition for v2.1, not a post-condition. The
partition lands in v1.9.10 (the stratified-corpus pre-lock
validation milestone, which already produces strata that can be
allocated to mining or holdout). v2.1 cannot ship before the split
exists; the alternative is shipping a runner whose every output
silently undermines the project's downstream calibration claims.

**Candidate schema (machine-readable).** Each candidate emitted
by the runner is a dict with these fields:

  - `pattern` (str) - the suffix or substring to match.
  - `tier` (`"application" | "infrastructure"`) - attribution
    precedence layer.
  - `suggested_slug` (str) - slug-shaped identifier proposed for
    the new fingerprint.
  - `count` (int) - how many distinct domains in the corpus
    showed this pattern.
  - `samples` (list of `{subdomain, terminal}`) - up to five
    representative chains for human review.
  - `projected_delta` (dict) - `{correlation_depth, entropy_reduction,
    conflict_rate}` from the empirical re-run.
  - `clue_source` (`"chain_motif" | "graph_community" | "hyperedge"`)
    - which already-shipped layer surfaced the candidate. Lets
    PR review trace each candidate back to a specific motif
    match, Louvain community ID, or hyperedge type rather than
    treating the runner as a black box. Carry the source ID in
    the YAML triage stanza so the provenance chain stays intact
    after merge.
  - `triage_yaml` (str) - pre-formatted YAML stanza ready for
    pasting into `recon_tool/data/fingerprints/surface.yaml`
    pending human review.

**Output contract.** Every run emits NDJSON to
`validation/runs-private/<stamp>/mining/` with three
artifacts: ranked candidates (per the schema above), projected
corpus-level metric deltas, and a triage-ready YAML diff that a
human can review and apply (or reject) by hand.

**Secondary v2.1 surface (only if the primary proves out):**

- `run_validation_suite(domains, metrics=[...])` - packages the
  existing corpus metrics into a reproducible call.
- `batch_posterior_query(domains, nodes=[...])` - parallel
  `get_posteriors` with aggregated stats.

These are wrappers over capabilities the MCP server already
ships. They land only after v2.1 mining itself ships and proves
useful - not preemptively.

**Invariants this preserves:**

- 100% passive - runner only calls existing public-signal tools.
- Data-file only - discovered candidates land in a review queue,
  never in a committed catalog. **`run_fingerprint_mining` ships
  with `dry_run=True` as the only supported value in v2.1.** Any
  future "auto-apply" mode requires its own invariant review and
  a separate release.
- No ML, no autonomous LLM agent inside recon. The "agent" in
  this design is the operator running the CLI or an MCP client;
  the runner is a deterministic coordinator over tools that
  already ship. If we ever want LLM-driven discovery, that's a
  separate invariant decision.
- No active probes, no internet crawling beyond what the
  underlying tools already do.

**Failure modes to avoid:**

- Letting the runner auto-edit `recon_tool/data/fingerprints/`.
  The whole auditability story collapses if recon edits its own
  rules in the dark. Human triage is non-negotiable.
- Calling it "agentic self-improvement" in marketing. We did not
  build a self-improving model; we built a *coordinator over
  existing skills* that helps a human curator move faster. The
  framing matters because it sets the right expectations.
- Adding fifteen new MCP skills as part of v2.1. The cap is one
  primary skill (`run_fingerprint_mining`) plus at most two
  secondaries that are wrappers, not new capabilities. Anything
  more is scope creep and breaks the v2.0 schema-lock contract
  we just wrote.
- Shipping before v2.0 schema lock + v1.9.2 agentic QA prove
  agents use the existing posteriors. v2.1 optimizes a surface;
  if the surface isn't useful, optimization is wasted.

**Why this is the right v2.1 move:**

- v2.1 is **the first release where recon's value compounds with
  use.** Every corpus run produces candidates; every accepted
  candidate increases correlation depth on the next run. The tool
  gets better the more it is used. v1.7 through v2.0 ship a
  static engine; v2.1 is where the engine starts learning from
  its own corpus exposure (with humans-in-the-loop, not
  autonomous fitting).
- It directly advances the north-star metric (multi-signal
  correlation depth) without new math, new network code, or new
  fingerprint surfaces.
- It uses what's already shipped - `discover_fingerprint_candidates`,
  `chain_lookup`, `test_hypothesis`, `get_posteriors` - and
  packages them into a feedback loop that measures its own
  impact.
- It is the natural composability move the priority order
  predicts after explainability is locked.
- It does not require v2.0 to be re-opened. It is purely
  additive on top of the locked v2.0 schema.

**v2.2 escalation path (sketch only).** Pure-`dry_run` removes
auto-edit risk but creates friction: every accepted candidate has
to be hand-pasted from the runner's YAML diff into the catalog.
Tedious tasks don't get done. v2.2 considers a
`--propose-pr` mode that opens a draft GitHub PR with the
candidate stanza added, requires human merge, and never auto-
merges. The audit trail moves from local YAML diff → reviewable
PR. Auto-merge is *never* shipped - that line is permanent. We
articulate the v2.2 path here so the v2.1 friction has a known
answer rather than an open question.

This sketch is **not committed.** The actual v2.1 plan gets
written after v2.0 ships and the agentic-QA findings from v1.9.2
inform whether the mining loop is what operators actually want or
whether some other composability primitive is more valuable.

