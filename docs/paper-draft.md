# Robust to Hiding, Not to Lying: One-Sided Guarantees for Passive Inference under Adversarial Missingness

Working draft. This is the prose expansion of [paper-outline.md](paper-outline.md),
assembled from the shipped design and validation docs. It is not a release gate
and not on any version's critical path. Empirical cells that depend on the
gitignored corpus must stay limited to disclosure-safe aggregate wording in
[paper-claim-map.md](paper-claim-map.md); every other claim is grounded in a
committed harness or memo cited inline. Literature positioning is in
[related-work.md](related-work.md); the statistical assurance dossier is in
[statistical-assurance.md](statistical-assurance.md). Submission figures and
their regeneration command are in [paper-figures.md](paper-figures.md).

Primary category cs.CR; secondary stat.ML (inference framing) or cs.SE
(artifact). Independent submission, no affiliation.

---

## Abstract

External attack-surface tools infer an organization's technology stack from
public signals. The honest version of that task faces a problem the calibration
literature usually sidesteps: the ground truth is not observable, and the
subject can hide signals, so a confident-looking verdict can be confidently
wrong. We present recon, a passive, zero-credential inference tool that pairs
deterministic certificate-transparency correlation with a small auditable
Bayesian network and treats absent evidence as adversarially missing, so the
reported credible interval widens rather than collapses when a target is
hardened. We prove a suppression-monotonicity property: holding other evidence
fixed, hiding any observed signal can only move a claim toward its all-absent
baseline, never to a confident false positive. We are explicit about the limit:
the guarantee bounds evidence removal, not addition, and a fully passive
operator who publishes one truthful decoy record can still force a confident
false positive. Our headline empirical finding is a negative one, from the one
construction that makes a predictor disjoint from its label: with the defining
DMARC record masked out of the public-declaration mail-policy node, the
multi-signal posterior does not recover enforcing policy from the
non-suppressible residual (fixed-bin ECE 0.3747, equal-mass ECE 0.3263,
agreement 0.1896 over 2,906 domains). The
full-posterior agreement with the DMARC record is near-perfect, but we label it
consistency, not calibration, because the record is also the node's dominant
input. The provider-attested tenancy node admits a channel-split check (a
DNS-only predictor against the identity-endpoint label, fixed-bin ECE 0.0471 and
equal-mass ECE 0.0440 over 3,296 domains) that we report with its
shared-common-cause caveat, plus a
distribution-free conformal coverage statement on the labelable nodes with its
exchangeability boundary made explicit.
Every hideable node carries only the structural guarantees, and we say so. We
evaluate against public references anyone can re-query and synthetic harnesses
that need no private data, on a curated cohort whose selection bias we state, and
we release a reproducible, signed artifact.

---

## 1. Introduction

Security teams increasingly need to know what an organization's external
footprint reveals before an attacker reads the same channel: which identity
provider a domain delegates to, whether its mail policy is enforced, what fronts
its origin. External attack-surface management (EASM) tools answer these
questions from public signals (DNS records, certificate-transparency logs,
unauthenticated provider endpoints), and they answer confidently. The confidence
is the problem. The ground truth behind these claims is not observable from
outside, and the subject of the measurement controls most of the evidence: a
hardened organization publishes less, a careless one publishes more, and a tool
that reads "no signal" as "no technology" is confidently wrong about exactly the
targets that matter most.

The standard remedy, calibrating the classifier against labeled truth, is
structurally unavailable here. There is no label set for "what this organization
actually runs"; the operator can delete most of the indicators a passive
observer relies on; and the deletion is not random, it correlates with security
maturity, which is often the very thing being estimated. This is missingness
that is not at random (MNAR) in the adversarial sense, and the calibration
literature's usual assumptions (exchangeable data, missingness independent of
the input) exclude it by construction.

We present recon, a deployed, open-source, zero-credential external-surface tool
built around that predicament rather than despite it. Every conclusion is
reachable through an evidence directed acyclic graph (DAG) of re-queryable public
observations; high-level claims are computed by a nine-node Bayesian network
small enough to audit by hand and verified exhaustively against its full joint;
and absent evidence on hideable claims contributes a likelihood ratio of one
(absence of evidence is treated as no evidence, never as evidence of absence), so
the reported 80% credible interval widens on hardened targets instead of
collapsing to a false verdict. In one sentence: this paper contributes a
validation architecture for inference whose ground truth is structurally
unobservable and partly adversarial, worked end-to-end in a real tool.

The architecture stands on one seam, stated early because it bounds everything
else: evidence *removal* versus evidence *addition*. We prove a
suppression-monotonicity property (holding other evidence fixed, hiding any
observed indicator can only move a claim toward its all-absent baseline, never to
a confident false positive) and machine-check it over every per-node evidence
subset. The guarantee does not extend to addition: a fully passive operator who
publishes one truthful decoy record can plant a confident false positive, and no
passive tool can distinguish a decoy from a real record. The honest contract is
therefore "robust to hiding, exposed to planting," and the boundary is not the
passive/active measurement line, because the cheap attack is itself passive.

Validation then proceeds by tier, with the tier decided by whether an external
reference the operator cannot suppress exists. Where one does (the DMARC record
is its own definition of an enforcing mail policy; Microsoft's identity endpoints
attest tenancy in both directions) we calibrate against it, including a held-out
construction that masks the label-defining evidence out of the predictor, and we
add a distribution-free conformal coverage statement with its exchangeability
boundary made explicit. Where no reference exists, we claim only the structural
properties, and we say so. We also measure what the honesty costs: in a synthetic
ablation against the model's own generative process, the adversarial-missingness
stance pays a quantified Brier penalty on hideable claims under benign
missingness (a hard detector that reads absence wins pooled scores by roughly
0.05 to 0.10), while the one claim whose absence is genuinely informative (the
declarative mail-policy node, where the model does condition on absence) wins
outright. The price of refusing to read absence is real, bounded, and paid
deliberately; we believe reporting it is more useful than hiding it.

**Contributions.**

- A deployed passive-inference system that preserves full provenance and pairs
  deterministic certificate-transparency correlation with a small,
  exhaustively-verified Bayesian network (Section 3).
- An adversarial missing-data treatment (the likelihood-ratio-one absence rule,
  grounded in m-graphs and partial identification) with a proved and
  machine-checked suppression-monotonicity guarantee, and an explicit statement
  of its limit at evidence addition (Section 4).
- A node-tiered validation architecture (reference calibration and conformal
  coverage where a self-defining label exists, structural principle-compliance
  everywhere else) with the boundary between tiers derived from who controls the
  evidence (Section 5).
- An evaluation that includes the cost of the design, not only its benefit: layer
  ablations quantifying the MNAR price under benign worlds and the fusion gain in
  the fired regime, alongside reference calibration on real public records and
  synthetic coverage under parameter imprecision (Section 6).
- A reproducible artifact: every empirical claim is checkable against public
  references anyone can re-query or fully synthetic harnesses, because the tool's
  own data-handling policy forbids publishing targets (Section 9).

Section 2 places this against the label-free calibration, conformal, and
principle-based-validation threads; Sections 7 and 8 state what remains
unvalidated and why, which we consider part of the contribution rather than its
caveat.

---

## 2. Background and related work

recon is a probabilistic classifier whose ground truth is, for most of its
claims, not observable. A passive external observer cannot see whether an
organization actually runs Okta, only what the public channel happens to reveal,
and the target can choose to reveal less. This is the hard corner of a problem
the machine-learning literature has been circling from the easier side: how do
you make a calibration statement about a classifier when you cannot get labels
for its outputs? Three sub-threads each stop just short of recon's setting.

**Label-free performance estimation.** CBPE (arXiv:2505.05295) estimates
confusion-matrix metrics on unlabeled data by treating per-item confidences as
parameters of Poisson-binomial distributions over the matrix counts. We borrow
the framing that a calibrated probability is itself an estimator of aggregate
performance, so a monitoring signal can exist without labels. We cannot borrow
the guarantees: they rest on perfect calibration and offer nothing under concept
shift, and the calibration of a hideable node is the very thing recon declines to
assert. CBPE describes the comfortable case recon is denied.

**Conformal prediction under noisy or missing labels.** NACP (arXiv:2501.12749)
gives finite-sample coverage from noisy calibration labels under a known noise
level; conformal performance-range prediction (arXiv:2407.13307) wraps heuristic
per-item bounds in split conformal under exchangeability. Both assume the noise
or missingness is independent of the input; recon's missingness is
feature-dependent by construction (whether a signal is absent depends on what it
would have revealed and on the target's intent), which both papers name as out of
scope. What we can adopt, on the nodes where a label exists, is split conformal as
a complementary distribution-free coverage statement: for the email-policy node
and the M365 tenancy node we report a conformal set beside the Bayesian interval,
with an explicit note that the conformal guarantee is conditional on
exchangeability and so is not claimed for hardened targets. The boundary where
conformal coverage stops being guaranteed is the same boundary where the
suppression guarantee keeps holding, which is the honest seam this paper is built
around.

**Principle-based calibration of epistemic uncertainty (arXiv:2407.12211).** When
calibration against truth is hard, this thread argues an uncertainty measure
should instead be held to checkable structural principles, and tests compliance
rather than coverage. This is the methodology recon already follows without
having named it: suppression-monotonicity is a principle-compliance result, and
interval-widening (the interval grows as effective evidence falls) is a second.
Framing recon's guarantees this way places them in a recognized tradition and
makes the reservation precise: recon says "calibrated" only where an external
reference exists, and even there only partially, and "evidence-responsive,
principle-compliant" everywhere else.

**Surrogate-label calibration (arXiv:2209.05486)** substitutes a model's own
confident predictions for missing ground truth. recon deliberately does not adopt
this: using the model's own outputs as stand-in labels is the circularity the
deterministic-versus-Bayesian consistency check already warns about (it is
near-tautological under the virtual-evidence construction, so it tests the
inference plumbing, not the conditional-probability values). recon's answer is
the opposite discipline: find the one kind of observable that is its own external
reference, calibrate only there, and state that the result does not generalize.

**Inference lineage and the adjacent system.** recon's core is exact variable
elimination on a fixed nine-node network. The tractable-inference literature
(Darwiche on variable elimination and functional CPTs, arXiv:2002.09320;
treewidth-based selection, arXiv:1506.08544; credal benchmarking CREPO,
arXiv:2105.04158) is recon's correctness backdrop, not a source of methods to
add: nine binary nodes are fully enumerable (512 states), so the inference is
verifiable by exhaustion rather than trusted by reputation. The closest neighbor
in subject matter is cGraph (arXiv:2202.07883), which runs belief propagation
over passive-DNS graphs for maliciousness scoring against a labeled oracle. It
shares recon's passive-DNS substrate but targets a different question with
different epistemics: same raw channel, different ground-truth situation.

---

## 3. System and model

recon reads only the public channel: DNS records (MX, CNAME, SPF, DMARC, TXT),
certificate-transparency subject-alternative-name (SAN) sets, and the
unauthenticated identity-discovery endpoints Microsoft and Google publish for
tenant resolution. There are no credentials, no port scanning, and no login
attempts; by default the only request the queried domain's own servers see is the
standard MTA-STS policy fetch (two direct-probe enrichments are opt-in and off by
default). A deterministic fingerprint catalog turns observed records into
*bindings*: named indicators such as `slug:microsoft365` or `signal:dmarc_reject`,
each carrying a vendor-documentation provenance pointer.

Bindings feed a Bayesian network of nine binary claim nodes (m365_tenant,
google_workspace_tenant, federated_identity, okta_idp, email_gateway_present,
email_security_modern_provider, email_security_policy_enforcing, cdn_fronting,
aws_hosting). Each node reports an 80% credible interval, not a yes/no verdict.
Inference is exact variable elimination; because the joint has only 512 states,
the `validation/differential_verification.py` harness cross-checks variable
elimination against a brute-force full-joint reference on every enumerable
evidence configuration, so the factor construction (declarative conditioning,
grouped evidence, virtual evidence) is verified, not merely tested.

Every claim is reachable through an evidence DAG: the binding, the record it came
from, and the inference path are all re-queryable, which is what lets an operator
verify a conclusion before acting on it. Nodes sit on a hideability spectrum that
turns out to govern everything in Section 5: provider-attested (the provider's
own endpoint answers authoritatively), public-declaration (a record that is its
own definition, such as DMARC), and hideable (no external reference; absence may
be genuine or adversarial).

---

## 4. Adversarial missing data

**Intuition.** When a hardened operator strips a public OIDC discovery endpoint,
the absence of the `microsoft365` binding is not random: it is correlated with
the latent tenancy claim through the operator's deliberate choice. A model that
reads non-firing bindings as evidence *against* a claim (symmetric Bayesian
conditioning) is correct under missing-completely-at-random or missing-at-random,
but biased under MNAR, and the bias points toward whichever absences the
mechanism produces. recon's input distribution is dominated by partially or fully
hardened targets, so reading absence as disconfirmation would over-claim absence
on exactly the targets recon must refuse to overclaim about.

**The rule.** recon's likelihood factor for a node X is the product over only the
bindings that fired,

L(O | X) = product over b in O ∩ B(X) of l_b(X),

with un-fired bindings contributing nothing. Equivalently, the likelihood ratio
recon assigns to the *absence* of a binding is exactly 1: an absent binding
provides no discriminatory power between "X is truly absent" and "X is present
and the operator hid the indicator." This is the precise mathematical content of
"we do not condition on absence" (correlation.md 4.3). We are careful not to
overstate the formal grounding: the m-graph framework (Mohan and Pearl 2021)
supplies a non-recoverability verdict for this missingness structure, it does not
by itself derive the LR=1 choice, which is a modeling decision we make and then
defend by the monotonicity lemma below and a machine check; the Manski reference
is the partial-identification posture, not a bound we compute. The one exception
is the declarative mail-policy node, where the
reference (the DMARC/SPF/MTA-STS records) is itself public and non-hideable, so
its absence *is* informative and the model conditions on it (the CAL14
"missingness: declarative" model with grouped absence; `validation/cal14-missingness-design.md`).

**Proposition 1 (suppression-monotonicity).** Hold all evidence outside a node X
fixed, and reduce X's bindings to evidence units (one independent binding, or one
mutually-exclusive group). X's presence-posterior odds equal a prior baseline
odds times a product of per-unit likelihood ratios. Under the hypotheses (each
fired unit is a positive indicator with ratio at least one, and on the
declarative node each not-fired unit is disconfirming with ratio at most one),
hiding any fired binding replaces a ratio of at least one with a ratio of at most
one, so the posterior moves monotonically down toward the node's suppression
floor B_X (the all-absent posterior) and never above the fully-observed value.
For a hideable node B_X is the prior baseline; for the declarative node it is the
strictly lower all-absent posterior (about 0.055, below its 0.62 prior). Hiding
therefore cannot manufacture confidence; it can only move a claim toward "we
cannot tell."

**The limit.** The result is elementary, and that is the point: its value is the
framing and the honesty, not theorem depth. It bounds only evidence *removal*. It
says nothing about evidence *addition*: publishing a record that fires a unit
raises the posterior on a premise recon cannot check passively, so a planted
truthful decoy defeats it. That removal-versus-addition line, not the
passive/active line, is the limit of the guarantee. Proposition 1 is
machine-checked by `validation/adversarial_properties.py`, gated by
`tests/test_adversarial_properties.py`, with the full statement in
correlation.md 4.3.

---

## 5. The layered assurance argument

Because calibration-against-truth is unavailable for most nodes, recon makes a
layered argument and states, per claim, the highest tier of support it has and
where that support stops (the evidence ledger in
[statistical-assurance.md](statistical-assurance.md)). The tier is decided by who
controls the evidence.

| Node class | Example nodes | Reference label | Guarantees available |
|---|---|---|---|
| Provider-attested | m365_tenant, google_workspace_tenant | the provider's own identity endpoint (authoritative) | calibration and, as a complement, conformal coverage; plus the structural guarantees |
| Public-declaration | email_security_policy_enforcing | the DMARC record (its own definition of enforcing) | full-posterior calibration strong but DMARC-anchored (fixed-bin ECE 0.0761, equal-mass ECE 0.0651; DMARC is also the input, so the bulk is a definitional agreement check), the clean DMARC-disjoint residual disconfirmed (fixed-bin ECE 0.3747, equal-mass ECE 0.3263); conformal coverage measured (0.9992 at a 0.90 target); plus the structural guarantees |
| Hideable | okta_idp, federated_identity, cdn_fronting, aws_hosting, email_gateway_present | none (absence may be genuine or adversarial) | structural guarantees only: suppression-monotonicity and interval widening (evidence-responsive) |

The structural guarantees (Proposition 1 and interval-widening) are
principle-compliance results that hold by construction, including under hiding.
Reference calibration is computed only where a self-defining record exists, and
even there honestly: on the public-declaration node the DMARC record is both the
label and the dominant input, so only the strict-SPF + MTA-STS residual is an
independent tier-4 check. A held-out construction sharpens this by masking the
label-defining unit out of the predictor (`masked_units`, treated as structurally
unobserved rather than absent, so the declarative node does not read the deletion
as disconfirmation) and calibrating the residual, making predictor and label
disjoint. The conformal complement adds a frequentist distribution-free coverage
statement on the labelable nodes, with a deliberately non-exchangeable split
demonstrating the guarantee failing exactly where it is claimed to fail. The
claim is not that recon calibrates everything; it is that this tiering is the
honest envelope for a passive classifier, with the labelable-versus-hideable
boundary stated as a different cut than Proposition 1's removal-versus-addition
boundary.

---

## 6. Evaluation

Each experiment maps to a committed harness. The corpus runs below were executed
once over a curated cohort of 5,241 domains (0 resolve failures); the cohort's
selection bias is stated under Threats below, and the per-domain data is never
published (Section 9), only the aggregates here.

| Experiment | Result | Status |
|---|---|---|
| Differential verification | variable elimination matches a full-joint reference on every enumerable configuration | shipped (`validation/differential_verification.py`) |
| Interval coverage (synthetic) | the 80% interval absorbs elicitation imprecision under the +/-20% likelihood band | shipped (`validation/interval_coverage.py`) |
| Likelihood sensitivity | posteriors and agreement stable under a +/-20% likelihood perturbation | shipped (`validation/likelihood_sensitivity.py`) |
| Layer ablations (synthetic) | the MNAR price and the fusion gain (below) | shipped and run (`validation/layer-ablation.md`) |
| Held-out residual (the headline) | DMARC unit masked, predictor and label disjoint: fixed-bin ECE 0.3747, equal-mass ECE 0.3263 (CI80 [0.3177, 0.3349]), Brier 0.2448, agreement 0.1896 (n=2,906). The residual (strict SPF plus MTA-STS) does NOT recover enforcing policy once the defining record is removed. A real, falsifiable negative result. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| DMARC full posterior | agreement 1.000, fixed-bin ECE 0.0761, equal-mass ECE 0.0651 (CI80 [0.0639, 0.0668]), Brier 0.0077 (n=2,906). Labeled CONSISTENCY, not calibration: the DMARC record is the node's dominant input, so this is a definitional-agreement check. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| Tenancy, M365 | DNS-only predictor vs the identity-endpoint label: fixed-bin ECE 0.0471, equal-mass ECE 0.0440 (CI80 [0.0402, 0.0506]), Brier 0.0796, agreement 0.8890 (n=3,296). Caveat: the two channels share the tenant-provisioning common cause, so this controls shared measurement error, not confounding; the base rate is 0.7897, so agreement is only modestly above always-present. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| Tenancy, Google Workspace | one-sided recall 0.3636 (n=11), Wilson80 [0.2071, 0.5556]; no authoritative negative on the Google channel. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| Conformal coverage | mean coverage 0.9992 vs 0.90 target, mean set size 0.9992, n=4,290, 20 splits. Over-covers on this exchangeable cohort; not claimed for hardened (non-exchangeable) targets. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| Information recovered, posture stratification | public-list cross-check across about 575 public, re-queryable domains in 22 disjoint sectors: overall median entropy reduction 1.967 / 1.932 / 1.846 nats across Lists A/B/C; the sparse tier is the genuine hardening signal (`direct / sparse` medians 0.999 / 0.742 / 0.721), not the edge-proxied flag. CAL7 width diagnostic reproduces across all three lists: grouped nodes are not narrower than ungrouped at matched n_eff near the ceiling. | `validation/public-list-calibration.md` |
| Per-vertical stratification (22 private-corpus verticals, min cell 10) | the pattern is uniform in the disclosure-reviewed aggregate memo: full-posterior fixed-bin ECE 0.065-0.098 per populated vertical (pooled 0.0761, equal-mass 0.0651, agreement 1.0), held-out residual fixed-bin ECE 0.258-0.498 (pooled 0.3747, equal-mass 0.3263, agreement 0.1896). The negative finding is not a single-sector artifact, but the population remains curated and high-base-rate. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |

The figure package in [paper-figures.md](paper-figures.md) renders this section's
submission figures from committed aggregate-safe sources: the assurance
architecture, nine-node DAG, public-list reliability bins, and CAL7 interval
width diagnostic.

**The headline result is a negative one, reported as such.** The one construction
that makes predictor and label disjoint, the held-out residual on the only node
with an external non-suppressible reference, shows the multi-signal posterior
cannot recover enforcing mail policy from the residual signals once the defining
DMARC record is masked (fixed-bin ECE 0.3747, agreement 0.1896, below the
cohort's 0.8352
always-enforcing baseline). We foreground this rather than the near-perfect
full-posterior agreement, because the latter scores the node against its own
dominant input and is a consistency check, not calibration. The tenancy
channel-split (fixed-bin ECE 0.0471, equal-mass ECE 0.0440) is the strongest
genuinely-disjoint signal, and even it is confounded by a shared upstream and
flattered by a 0.7897 base rate. The honest
summary: recon currently has no node with a clean, independent, passing
calibration result, and the experiment built to produce one instead falsifies it.
That is a finding, not a gap to paper over. The per-vertical stratification rules
out a single-sector artifact: the residual is weak across all 22 disclosed
private-corpus verticals (pooled held-out fixed-bin ECE 0.3747, equal-mass ECE
0.3263, agreement 0.1896), while the full-posterior consistency is equally
uniform (pooled fixed-bin ECE 0.0761, equal-mass ECE 0.0651), which is
exactly what a definitional-agreement check looks like when read honestly.

The collapse is also explainable from the remaining signal strengths. Once the
DMARC policy group is masked, the residual has only strict SPF and MTA-STS
enforce to speak for the policy node. The committed model data records the June
2026 regrounding that made MTA-STS rare even among enforcing domains (about 6
percent present for enforcing domains, about 1 percent for non-enforcing), so
MTA-STS absence is almost neutral. Strict SPF is more common but still weak
(about 53 percent present for enforcing domains, about 27 percent for
non-enforcing), so it supports enforcement without defining it. In a curated
cohort whose enforcing base rate is already 0.8352, those two residual signals
cannot recover the label after the label-defining DMARC record is removed. This
is a diagnostic reading of the committed likelihoods and aggregate memo, not a
causal proof about all domains.

**Threats this evaluation does not control.** (1) The cohort is ~5,200 curated,
tech-forward firms (about 83 percent DMARC-enforcing, 79 percent M365), which
over-represents well-instrumented, non-hardened targets, the easy regime the
adversarial-missingness design claims not to need; the hardened cell the thesis
is about is nearly empty, and the reliability mid-range (0.4 to 0.7) is
unpopulated, which partly explains the low ECE. A stratified probability sample
from a public zone, stratified by a hardening proxy, is required before any rate
transfers beyond this population. Current validation summaries also report an
equal-mass, mean-confidence ECE with deterministic bootstrap CI so future reruns
can separate estimator choice from model behavior; the June memo numbers above
remain the legacy fixed-width ECE until rerun. (2) The credible interval now uses
exact Beta quantiles for unimodal moment-matched cases and keeps the validated
mean-centered fallback for boundary-skewed cases, because equal-tailed Beta
intervals can exclude their own posterior near 0 or 1. The fallback is a
deliberate coverage-preserving contract, not an untracked approximation. (3) The
conformal over-coverage with decisive set size is expected on a bimodal,
exchangeable cohort and says nothing about hardened targets.

**The cost of honesty, with numbers.** The layer ablation runs over 20,000
synthetic worlds drawn from the model's own generative process and is fully
reproducible (`validation/layer-ablation.md`). It demonstrates the predicted
asymmetry. On hideable root nodes, a hard detector that reads absence as
disconfirmation beats the MNAR posterior on pooled Brier, because the synthetic
world's missingness is benign rather than adversarial: for example m365_tenant
scores 0.0476 (hard baseline) versus 0.1171 (full posterior), a roughly 0.05 to
0.10 Brier price recon pays deliberately to avoid false negatives on hardened
real targets. On the declarative node, where absence is honestly informative and
the model conditions on it, the full posterior wins both pooled and in the
fired regime (0.0630 / 0.0718 versus the any-fired baseline's 0.1522 / 0.1902).
This is the CAL14 asymmetry demonstrated: the price of refusing to read absence
is real and bounded on hideable nodes, and is not paid where absence genuinely
carries information. The graph layer's contribution is shown separately: Louvain
community detection holds adjusted Rand index 1.0 across a bridging-noise grid
where naive connected components collapse to 0.

---

## 7. Discussion

What is and is not validated is itself part of the contribution. recon validates
exhaustively where it can (the inference math, by full-joint cross-check) and
calibrates only where a self-defining reference exists, reporting
evidence-responsiveness, not calibration, elsewhere. Three threats to validity
are stated rather than hidden. First, the deterministic-versus-Bayesian
consistency number is near-tautological under the virtual-evidence construction,
so it tests the plumbing, not the conditional-probability values, and we never
report it as calibration. Second, co-firing bindings that share a group are
correlated readings of one underlying fact; the documented correlated-binding
over-confidence (CAL7) means richly-instrumented targets can get a tighter
interval than the evidence warrants, which the interval-width-versus-evidence-count
diagnostic surfaces. Third, the synthetic ablation is drawn from the model's own
generative process and so cannot falsify the model's structure; it measures
relative layer contribution and the MNAR price, not absolute correctness.

The honesty has an operational payoff that sharpens with recon's deployment as a
grounding primitive for LLM agents (it ships an MCP server). An agent is a
confident summarizer: given a point estimate it states a verdict, and given a
wide interval it rounds it away unless the surface forbids it. recon's contract
(a low or sparse posterior means "we cannot tell from the public channel," not
"not present") is exactly the property a downstream consumer cannot reconstruct
for itself, because the missingness structure lives in recon, not in the
consumer's context. recon's value in an agent stack is therefore as the honest
"we cannot tell" the consumer would otherwise hallucinate past, which is why the
machine-readable output leads with the per-node interval and a sparse-count
summary rather than burying uncertainty in prose.

---

## 8. Limitations and ethics

recon is passive-only and defensive-only by invariant: no credentials, no active
scanning, no paid APIs, no learned weights, no persistent cross-domain store. The
suppression guarantee does not cover evidence addition, so a passive operator who
plants a truthful decoy record can force a confident false positive; recon cannot
detect this without the active probing it forbids. Coverage depends on public
DNS, so organizations behind heavy proxies or with minimal records return sparse
results by design, which the widened interval and `sparse` flag report honestly.
The fingerprint catalog is rule-based and solo-maintained, so confident-looking
output can still be wrong, which is why every detection carries a vendor-doc
pointer for independent re-verification. Ethically, recon reads only what an
organization already publishes, reports it with provenance and hedged
uncertainty, and leaves business interpretation to the operator; it does not
score, rank, or enrich organizations.

---

## 9. Reproducibility

The repository invariants (no real company data, ever; the corpus stays
gitignored; committed examples use the Microsoft fictional brands) make the data
constraint a method, not an obstacle. Every empirical claim is reproducible
either against public references anyone can re-query (DMARC/SPF/MTA-STS records
as their own truth; the Microsoft and Google identity endpoints for tenancy) or
against fully synthetic harnesses (the ablation, interval coverage, likelihood
sensitivity, and differential verification all ship and run with no private
data). Only aggregate, posture-stratified statistics, synthetic reproductions,
and public-reference calibration are ever published; the per-domain corpus never
appears. This is the discipline recon's cohort summary and maintainer-validation
loop already follow, recorded in [data-handling-policy.md](data-handling-policy.md).
The artifact is a bit-for-bit reproducible build with sigstore-signed PyPI
attestations and a locked JSON schema, so the tool a reader runs is the tool the
paper describes. The public no-private-data evidence bundle is reproducible from
a clean checkout with `python -m validation.reproduce_paper_numbers`; it records
the exact commands and artifacts in a local manifest under `validation/local/`.
The reviewer-facing command sequence and result boundaries are in
[artifact-review.md](artifact-review.md).

We separate two reproducibility claims that are easy to conflate. Build
reproducibility (the signed, bit-identical artifact) is real and complete. Result
reproducibility is not: the corpus aggregates above (for example the M365
fixed-bin ECE of 0.0471) cannot be regenerated by an outsider, because the
domain list is gitignored
by invariant and DNS/CT state drifts daily, and the synthetic harnesses reproduce
the method and the relative-layer results but not the public-cohort numbers.
[public-label-snapshot-decision.md](public-label-snapshot-decision.md) defers a
frozen real-apex label snapshot under the current data-handling policy: a
hash-pinned identifier list would improve benchmark reproducibility, but it
would still publish a durable real-target corpus. Until a separate review changes
that policy, the corpus numbers are maintainer-reproducible only.

---

## 10. Conclusion

When a classifier's ground truth is structurally unobservable and the subject can
choose what to reveal, calibration-against-truth is the wrong bar for the claims
whose signals an operator can hide. The honest substitute is a layered argument:
structural guarantees that hold by construction (including under adversarial
hiding), a partial external check on the subset of claims that have a
self-defining reference, and an explicit per-claim ledger of where support stops.
recon is the worked artifact for that argument in passive external attack-surface
measurement. The one-sided guarantee (robust to hiding, exposed to planting) is
not a weakness to apologize for; it is the precise, checkable statement of what a
passive observer can and cannot promise.

---

## Open items before submission

Done (refreshed 2026-06-28, aggregates in Section 6): the held-out residual, the
DMARC full-posterior consistency check, the M365 and Google tenancy calibrations,
the conformal coverage pass, and equal-mass mean-confidence ECE with
deterministic bootstrap CI. Done in this draft pass: the residual collapse is now
diagnosed from
the remaining signal strengths, with MTA-STS rarity and strict SPF weakness
called out as the mechanism visible in the committed model data. Done in the
figure pass: [paper-figures.md](paper-figures.md) and `docs/assets/paper/*.svg`
provide deterministic, aggregate-safe assets for the architecture, DAG,
reliability, and interval-width figures.

The remaining blockers are concrete and bounded:

| Blocking open item | Why it matters | Minimum closure before submission |
|---|---|---|
| Stratified public probability-sampling protocol | The current public lists are reproducible but still convenience samples, and the private cohort is curated and high-base-rate. | Either approve a data-handling review for a new public release model, or keep the draft explicit that public-list numbers are robustness checks and private-corpus rows are maintainer-reproducible aggregates only. |
| M365 independent-instrument check | The DNS-only predictor and endpoint label are channel-split, but they still share tenant provisioning as a common cause. | Identify a passive instrument with no mail-routing path to the endpoint label, or keep the result named corroboration rather than calibration. |
| Adversarial planting and stripping harness | Proposition 1 measures evidence removal, while the paper also discusses planted evidence as the limit case. | Add a synthetic or controlled-domain harness that measures posterior movement under stripping and planting, or keep the planting discussion as a threat-model boundary without empirical rates. |
| Final claim audit | Any new experiment or wording can move a claim between support tiers. | Re-run claim-map tests, figure drift check, public proof smoke, full public proof, local gate, and release readiness from the final draft commit. |
