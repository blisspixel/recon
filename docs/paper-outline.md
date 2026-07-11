# Paper skeleton (aspirational)

Status: a working outline, not a release gate and not on the critical path
of any version. It exists so the experiments are designed into the
validation harnesses rather than retrofitted, and so the framing settled
here survives between work sessions. The literature positioning lives in
[related-work.md](related-work.md); the forward plan and which pieces are
shipped live in the [roadmap](roadmap.md) research write-up section.

The prose expansion of this outline (full section drafts, with corpus-gated
empirical cells constrained by the claim map) lives in
[paper-draft.md](paper-draft.md).
The external write-up readiness sequence lives in
[external-writeup-plan.md](external-writeup-plan.md), and the current claim map
lives in [paper-claim-map.md](paper-claim-map.md). The figure package lives in
[paper-figures.md](paper-figures.md). The certificate-transparency corpus work
is closed as a bounded aggregate-only partial pass in
[c3-ct-validation-plan.md](c3-ct-validation-plan.md). Any paper update must use
only aggregate-safe public memos and synthetic or public reproduction harnesses,
never private target rows.

## Thesis

When a classifier's ground truth is structurally unobservable and the
subject can choose what to reveal, calibration-against-truth is the wrong
bar for the claims whose signals an operator can hide. Of recon's nine
nodes, the declarative policy node carries a self-defining public reference,
the M365 tenancy node carries channel-split provider corroboration with a
shared tenant-provisioning caveat, Google carries one-sided attestation with
no authoritative negative, and the remaining claim families have no external
two-class reference. The honest substitute is a layered argument:
(1) observed public facts; (2) internally verified, model-relative
computation; (3) dependency-qualified external corroboration; and (4)
independent predictive validation only when parameter development and predictor
inputs are both disjoint from the evaluation labels.
No current claim family has a clean passing level-4 result.
recon is the worked artifact for that argument in passive external
attack-surface measurement.

The seam the paper is built around is evidence *removal* versus *addition*.
The shipped result against removal is narrow: with fixed local prior odds and
positive independent likelihood-ratio units, deleting a fired unit cannot
increase its local odds contribution. It does not force a full-network claim
toward 0.5, widen the uncertainty band, or prevent a confident false negative.
Evidence addition is also important: a fully passive operator who publishes one
truthful decoy record can move a model-relative posterior across a threshold,
and recon cannot tell a decoy from a real record without additional assumptions.
The deeper research direction is a provenance-constrained robustness envelope
over compatible evidence states, explicit threat models, dependency units,
parameter classes, and removal and planting budgets.

## Honest contribution statement

Not a new inference algorithm. Variable elimination, community detection,
and Beta-shaped display bands are established components. The contribution is a
combination uncommon in the passive-recon literature, plus an unusually
explicit account of what is and is not validated:

- a zero-credential, strictly passive external-surface tool that keeps
  full provenance (every conclusion reachable through the evidence DAG);
- deterministic graph correlation over certificate-transparency
  co-occurrence paired with a small auditable Bayesian network;
- a conservative likelihood-ratio-one rule for non-fired hideable evidence,
  stated as a modeling choice under unknown MNAR rather than derived from it;
- a formal local deletion nonincrease lemma with its fixed-assumption boundary
  stated explicitly;
- a four-level assurance architecture separating observation, model-relative
  computation, external corroboration, and independent predictive validation.

Scope of the claim, stated plainly: the formal result is elementary once
the model is set up; its value is the framing and the honesty, not theorem
depth. The intended venue is a measurement or security audience (for
instance a measurement or security conference, primary category cs.CR,
secondary stat.ML or cs.SE), not a machine-learning theory venue. This is
an independent submission with no affiliation needed.

## Writing standard (how this paper should read)

Clarity is the bar, not a trade against rigor. The papers that get cited read
like a sharp colleague explaining something at lunch, not a performance. The
rules we hold this draft to:

- Abstract in 150 to 250 words, plain enough for someone outside the subfield:
  one sentence of problem, one of what we did, one of why it matters, one of the
  result. No undefined jargon.
- The first two paragraphs of the introduction land for a reader in the broader
  field (security or measurement), starting from the real problem before zooming
  in. If the contribution does not fit in one plain-English sentence, it is not
  yet understood well enough.
- Explain before formalizing, in every technical section: the intuition (a toy
  example or a figure), then the math, then why it works in words.
- Define every term and acronym on first use; prefer short common words; active
  voice ("we show", not "it is shown"). Read each sentence as if saying it to a
  colleague, and cut whatever sounds pompous.
- Structure for skimming: abstract, introduction with a contributions bullet
  list, related work that is generous and fair, preliminaries, method (figures
  and pseudocode), experiments (tables with error bars and ablations),
  discussion and limitations, short conclusion.
- One figure on page 1 or 2 that tells the whole story. The likely candidate is
  the node-tiering picture: which nodes carry which guarantee, and why.
- Own the limitations early and credit prior work generously; the field is
  small. Honesty reads as trust here, and it is the posture the tool already
  takes everywhere else.
- Target 8 to 12 pages plus appendix; shorter is usually better. Link the
  reproducible artifact (the public references and the synthetic harnesses) so a
  reader can run it in an afternoon.
- Draft the prose before every experiment is in. Writing forces the idea to
  clarify, and the harness inventory above is built to be filled in.

## Working title candidates

Humble and descriptive:

- "Auditable Passive Inference from Public Evidence under Strategic
  Missingness"
- "Evidence-Responsive Uncertainty for Zero-Credential Infrastructure
  Fingerprinting"
- "Provenance-Constrained Robustness for Passive Domain Intelligence"

## Abstract (draft)

External attack-surface tools infer an organization's technology stack
from public signals. The honest version of that task faces a problem the
calibration literature usually sidesteps: the ground truth is not
observable, and the subject can hide signals, so a confident-looking
verdict can be confidently wrong. We present a passive, zero-credential
inference tool that pairs deterministic certificate-transparency
correlation with a small auditable Bayesian network. A non-fired hideable
binding contributes no likelihood factor, a conservative product rule under
unknown missingness. We prove a narrow local deletion result: under fixed prior
odds and positive independent evidence units, removing a fired unit cannot
increase its local odds contribution. This does not guarantee movement toward
0.5, a wider uncertainty band, or full-network robustness. On the one node whose
label is a public self-declaration (the DMARC email-policy record), we report
DMARC-anchored agreement, honest that the label is also the
node's dominant input; a predictor-input-disjoint residual check performs poorly
but reuses parameter-development data. M365 tenancy
receives channel-split corroboration with its shared-cause caveat. A separate
split-conformal harness reports dependent empirical re-split diagnostics, not a
future-point coverage guarantee, and does not validate the Bayesian uncertainty
band. We release a reproducible public-proof and synthetic artifact; private
cohort numbers remain maintainer-reproducible aggregates.

## Introduction (draft)

Security teams increasingly need to know what an organization's external
footprint reveals before an attacker reads the same channel: which identity
provider a domain delegates to, whether its mail policy is enforced, what
fronts its origin. External attack-surface tools answer these questions
from public signals - DNS records, certificate-transparency logs,
unauthenticated provider endpoints - and they answer confidently. The
confidence is the problem. The ground truth behind these claims is not
observable from outside, and the subject of the measurement controls most
of the evidence: a hardened organization publishes less, a careless one
publishes more, and a tool that reads "no signal" as "no technology" is
confidently wrong about exactly the targets that matter most.

The standard remedy - calibrate the classifier against labeled truth - is
structurally unavailable here. There is no label set for "what this
organization actually runs"; the operator can delete most of the
indicators a passive observer relies on; and the deletion is not random,
it correlates with security maturity, which is often the very thing being
estimated. This is missingness that is not at random in the adversarial
sense, and the calibration literature's usual assumptions (exchangeable
data, missingness independent of the input) exclude it by construction.

We present recon, a deployed, open-source, zero-credential
external-surface tool built around that predicament rather than despite
it. Every conclusion is reachable through an evidence DAG of re-queryable
public observations; high-level claims are computed by a nine-node
Bayesian network small enough to audit by hand. Tested queries are cross-checked
against exact enumeration of the 512-state latent joint over a structured
evidence sweep; and absent evidence on hideable claims
contributes a likelihood ratio of one - absence of evidence is treated as
no model-assigned evidence, never as evidence of absence. The reported network
mean is model-relative, and its 80% evidence-responsive uncertainty band is not
a credible interval, confidence interval, identification region, or calibrated
coverage statement. In one sentence: this paper contributes a validation
architecture for inference whose ground truth is structurally
unobservable and partly adversarial, worked end-to-end in a real tool.

The architecture stands on one seam, stated early because it bounds
everything else: evidence *removal* versus evidence *addition*. We prove
a local deletion nonincrease lemma under fixed prior odds and positive
independent evidence units, and machine-check selected shipped-model deletion
cases. The result does not establish full-network monotonicity, movement toward
0.5, uncertainty-band widening, or protection from false negatives. Addition
remains unconstrained: a fully passive operator who publishes one truthful decoy
record can move a model-relative posterior across a threshold.

Validation then proceeds by tier, with the tier decided by whether an
external reference exists. The DMARC full score receives a DMARC-anchored
agreement check, and the M365 score receives channel-split provider
corroboration with its shared-cause caveat. A held-out construction masks the
DMARC-defining evidence out of the policy predictor and produces the important
negative result. A separate split-conformal harness reports dependent empirical
re-split behavior only; its scorer was not frozen on a disjoint training cohort.
Where no external reference exists, we claim only observed facts and internally
sound model-relative computation. The synthetic ablation independently samples
grouped evidence bindings and can produce combinations that violate declared
group semantics. It is a reproducible misspecification stress test, not the
committed model's generative process or a quantified price of the missingness
policy.

Concretely, this paper contributes:

- a deployed passive-inference system that preserves full provenance and
  pairs deterministic certificate-transparency correlation with a small
  Bayesian network checked against full latent-joint enumeration over a
  structured evidence sweep (Section 3);
- a conservative missing-evidence treatment (the likelihood-ratio-one absence
  rule) with a proved and machine-checked local deletion nonincrease result and
  an explicit account of the claims it does not support (Section 4);
- a four-level assurance architecture separating observed facts, model-relative
  computation, dependency-qualified corroboration, and independent predictive
  validation (Section 5);
- an evaluation with mixed implementation stress-test results, dependency-
  qualified public-reference comparisons, an input-disjoint but training-
  overlapping negative result, dependent conformal re-split diagnostics, and
  finite scenario containment under parameter imprecision (Section 6);
- a reproducible public-proof and synthetic artifact, with private-cohort rows
  explicitly limited to maintainer-reproducible aggregates (Section 9).

Section 2 places this against the label-free calibration, conformal, and
principle-based-validation threads; Sections 7 and 8 state what remains
unvalidated and why, which we consider part of the contribution rather
than its caveat.

## Section skeleton

1. Introduction. The passive EASM task; the unobservable-ground-truth
   predicament; the failure mode of false confidence on hardened targets;
   the layered answer; contributions list.
2. Background and related work. The label-free / conformal / principle-
   based threads and where each stops short of this setting; the
   Bayesian-network inference lineage as correctness backdrop; cGraph as
   the adjacent passive-DNS system with different epistemics. Assembled
   from [related-work.md](related-work.md).
3. System and model. The nine-node network, the evidence DAG and
   provenance, exact variable elimination, the fingerprint catalog, the
   hideability spectrum (operator-vanity, operator-functional,
   provider-attested).
4. Adversarial missing data. The likelihood-ratio-one absence rule as a
   conservative modeling choice under unknown MNAR; the local deletion
   nonincrease lemma and its limits; the provenance-constrained robust score
   envelope as future work; and the coherent joint-law and observation-kernel
   requirements that gate any later partial-identification claim.
5. The layered assurance argument. The four-level evidence ledger: observed,
   internally sound and model-relative, dependency-qualified corroboration, and
   independent predictive validation; the current result for each claim family.
6. Evaluation. The experiment inventory below, each mapped to a harness.
7. Discussion. What is and is not validated; the honest boundary; threats to
   validity (correlated bindings, in-sample parameter development, the
   near-tautological consistency check, iid interval assumptions, and a
   synthetic observation sampler that violates group semantics). Treat the
   ablation as a misspecification stress test, not a measured missingness-policy
   price or product-value result.
8. Limitations and ethics. Passive-only, defensive-only, no released
   target list, the data-handling policy as a design constraint.
9. Reproducibility. Separate the reproducible build and public-proof/synthetic
   methods from private-cohort aggregate results that outsiders cannot recreate.
   The public no-private-data bundle runs with
   `python -m validation.reproduce_paper_numbers`.

## Proposition 1 (local deletion nonincrease), as it will be stated

For one binary claim, hold the prior odds fixed and reduce its fired bindings to
independent evidence units. If every fired unit has a positive likelihood ratio
of at least one, the local presence odds equal the prior odds times the product
of those ratios. Deleting one fired unit divides the odds by a value at least
one, so it cannot increase those local odds.

This is not a full-network monotonicity theorem. Parent messages, declarative
absence factors, and downstream propagation can change other marginals. The
result does not force a claim toward 0.5 or an all-absent value, widen the
uncertainty band, or prevent a confident false negative.

The result is elementary and bounds only evidence removal. It says nothing
about evidence addition: publishing a record that fires a unit raises the
posterior on a premise recon cannot check passively, so a planted truthful
decoy defeats it. That removal-versus-addition line, not the passive/active
line, is the limit of the guarantee.

Selected shipped-model cases are machine-checked by
`validation/adversarial_properties.py`, gated by
`tests/test_adversarial_properties.py`, with the exact boundary in
[correlation.md section 3.4](correlation.md#34-evidence-removal).

## Evaluation inventory (each maps to a harness)

| Experiment | What it shows | Harness / status |
|---|---|---|
| DMARC-anchored agreement | the email-policy full model-relative posterior agrees with the DMARC record (fixed-bin ECE 0.0761, legacy index-sliced equal-mass ECE 0.0651, n=2,906 DMARC publishers); this is in-sample level-3 definitional agreement because DMARC is also the dominant input | `validation/reference_calibration.py`; historical refresh 2026-06-28 |
| Held-out residual negative result | mask the DMARC unit and evaluate the predictor-input-disjoint residual against the DMARC label; same-corpus parameter development blocks level 4, and the publisher-conditional development row performs poorly (fixed-bin ECE 0.3747, legacy equal-mass ECE 0.3263) | `validation/reference_calibration.py`; historical refresh 2026-06-28 |
| Held-out residual diagnosis | after DMARC is masked, the remaining signal path is weak by construction: MTA-STS is rare even among enforcing domains, and strict SPF is only a supporting signal | `src/recon_tool/data/bayesian_network.yaml`; `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| Adversarial add/remove perturbation | selected fixed-assumption deletion checks show no local increase; planted evidence can cross model-relative decision boundaries in finite synthetic paired perturbations | `validation/adversarial_properties.py`; public reproduction bundle |
| Tenancy corroboration (provider endpoints) | DNS-only M365 score versus endpoint attestation, split by channel but sharing tenant provisioning and development-corpus reuse; GWS remains one-sided | historical refresh: fixed-bin ECE 0.0471, legacy equal-mass ECE 0.0440, agreement 0.889, n=3,296; GWS recall 0.3636 (n=11) |
| Legacy conformal re-split diagnostic | 20 dependent splits of a separately recorded 4,290-row extraction; scorer training was not disjoint, cohort comparability is unproven, and the row carries no future-point coverage claim | `validation/conformal_coverage.py`; historical refresh 2026-06-28 |
| ECE estimator diagnostics | the tested tie-preserving estimator is required for the next private rerun, but no current tie-preserving numeric estimate exists; every committed ECE is historical, index-sliced equal-mass values are legacy, and recorded row-bootstrap and Wilson intervals are naive-iid diagnostics with no coverage interpretation | `validation/calibration_estimators.py`; `tests/test_calibration_estimators.py` |
| Uncertainty-band scenario containment | the 80% evidence-responsive band contains selected CAL8 perturbed-model conditionals in the recorded finite experiment; this is not empirical coverage, calibration, or an identification region | `validation/interval_coverage.py`; shipped |
| Likelihood sensitivity (CAL8) | the posteriors and agreement are stable under a plus-or-minus-20-percent likelihood perturbation | `validation/likelihood_sensitivity.py`; shipped; full public proof run 2026-06-28 |
| Signed marginal entropy change (CAL10) | the selected-list distribution of model-relative marginal entropy change across construction-linked posture buckets; sums can double count dependent nodes and do not measure pointwise information leakage or a population hardening effect | per-node surfacing shipped (stable field: `entropy_reduction_nats` on every posterior); public-list aggregate cross-check in `validation/public-list-calibration.md`; mapped in `paper-claim-map.md` |
| Layer ablations | implementation stress behavior against selected simple baselines | `validation/layer_ablation.py`; the latent DAG is sampled, but bindings are independent Bernoulli draws that can violate declared group semantics, so recorded contrasts are not model-generated truth or a missingness-price estimate; the graph fixture remains a tailored assortative benchmark |
| Posture stratification | aggregate behavior across hardening postures, as distributions not exemplars | `validation/posture_distributions.py` (entropy reduction bucketed by edge-proxied/direct x evidence tier; interval width vs n_eff for the CAL7 figure); aggregate numbers are in `paper-draft.md` Section 6, mapped in [paper-claim-map.md](paper-claim-map.md), and rendered in [paper-figures.md](paper-figures.md); framing in correlation.md 4.10-4.11 |
| Differential verification | variable elimination matches a 512-state latent-joint reference over a structured none/one/all evidence sweep plus exhaustive local subsets for three factor-heavy nodes | `validation/differential_verification.py`; shipped; public proof run 2026-06-28 |
| Per-vertical stratification | full-posterior consistency and held-out residual failure are stratified across the disclosed private-corpus verticals | `validation/2026-06-28-full-corpus-calibration-refresh.md`; refreshed 2026-06-28 (22 verticals, full-posterior fixed-bin ECE 0.065 to 0.098 per populated stratum; held-out residual fixed-bin ECE 0.258 to 0.498) |

One-command public reproduction:
`python -m validation.reproduce_paper_numbers` runs the public rows above that
do not need private corpora. Use `--profile smoke` for a quick orchestration
check; the default `paper` profile runs the full local bundle.

Figures: [paper-figures.md](paper-figures.md) now defines deterministic SVG
assets for the assurance architecture, nine-node DAG, public-list reliability
bins with posterior histograms, and the CAL7 interval-width-versus-evidence plot.
The package regenerates through `scripts/generate_paper_figures.py --check` and
uses color-blind-safe palettes.

## The data-publication constraint as a design feature

The repository invariants keep target rows and private identifier lists out of
version control. The build, public-proof methods, and synthetic harnesses are
reproducible. Private-cohort numbers are disclosure-reviewed,
maintainer-reproducible aggregates only: outsiders cannot reconstruct the
gitignored lists, historical DNS state, or every recorded cohort. That boundary
is recorded in [data-handling-policy.md](data-handling-policy.md).

## Candidate framing: why the honesty matters operationally (Discussion)

A short motivation paragraph worth landing in the introduction or discussion,
drafted here as a candidate. recon is increasingly *consumed by LLM agents*
(it ships an MCP server), and that sharpens why evidence-responsive honesty is
the right design rather than a concession. An agent is a confident summarizer:
given a point estimate it will state a verdict, and given a wide band it
will round it away unless the surface forbids it. The honest contract recon
already makes is narrower: a model-relative posterior is not an observed fact,
and a non-fired hideable binding is not evidence of absence. The `sparse` flag
means that effective display mass is at its configured floor; it does not mean
the posterior is near 0.5 or that the claim is absent. This is exactly the
property a downstream agent cannot reconstruct for itself once provenance and
missingness semantics are discarded. So recon's value in an agent stack is as a
*grounding/verifier primitive* that preserves the boundary between observed,
derived, and unresolved claims. This is
the same argument the paper makes for human operators, but it bites harder for
automated consumers, and it motivates surfacing uncertainty at the tool level
(the `sparse_count` summary and the per-node band lead the machine-readable
output, with explicit reading guidance in the server instructions), not only
in prose. The point is not that recon does AI; it is that recon is the honest
input an AI consumer needs and cannot fake. (Implementation: the MCP
"Reading the posteriors" instruction and `get_posteriors` `sparse_count`,
pinned by `tests/test_posterior_reading_guidance.py`.)

## Open items before this is submittable

The gating work is no longer harness construction, figure construction, or
default runtime expansion. The remaining work is to make the draft externally
reviewable:

Resolved for this submission: the stratified public probability-sampling path is
closed by [public-label-snapshot-decision.md](public-label-snapshot-decision.md).
Public-list numbers remain robustness checks rather than population rates unless
a future data-handling and architecture review approves a new public release
model.

Resolved for this submission: the M365 independent-instrument decision is closed
by [m365-tenancy-decision.md](m365-tenancy-decision.md). No passive candidate is
independent enough to promote the result beyond channel-split corroboration, so
the paper keeps the result named as corroboration rather than calibration.

Final claim audit is complete and refreshed for the current draft package. The
public memo
[2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md)
records the passing claim-map audit, figure drift check, public proof smoke,
full public proof, local gate, and release readiness checks.
The latest local submission-freeze public proof record is
[2026-06-30-submission-freeze-local-proof.md](../validation/2026-06-30-submission-freeze-local-proof.md).

Current technical artifact blockers: none for this draft package. Any future
experiment, paper wording, package, or claim-map change can move a claim between
support tiers, so it must rerun the final claim audit before submission
packaging.

## Decisions still open

- Venue and timing. The substance is mostly assembled; the gating item is
  the remaining empirical runs, not the writing.
- Whether the level-2 structural-property suite gets a named, standing gate of
  its own or stays inside `validation/adversarial_properties.py`.

Resolved: the conformal diagnostic was adopted and shipped
(`validation/conformal_coverage.py`, the selected DMARC-labeled policy output
only). It remains separate from the Bayesian uncertainty band and is an
evaluation row above, not a decision.
