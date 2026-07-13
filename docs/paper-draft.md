# Auditable Passive Inference from Public Evidence under Strategic Missingness

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

External attack-surface tools often promote public signals around a domain into
claims about an organization's technology stack. recon addresses the narrower
question of what the queried public namespace reveals. The honest version of
that task faces a problem the calibration
literature usually sidesteps: the ground truth is not observable, and the
subject can hide signals, so a confident-looking verdict can be confidently
wrong. We present recon, a zero-credential tool with a passive collection scope
that pairs
deterministic certificate-transparency correlation with a small auditable
Bayesian network. For hideable evidence, a non-fired binding contributes no
likelihood factor. This is a conservative product rule, not a derivation from
unknown missingness and not a claim that a hidden technology is absent. The
shipped deletion result is correspondingly narrow: with fixed local prior odds
and positive independent evidence units, removing a fired unit cannot increase
the local odds contribution. It does not guarantee movement toward 0.5, a wider
uncertainty band, or protection from false negatives in the full network.
Evidence addition remains unconstrained: a truthful decoy record can move a
model-relative posterior across a decision threshold. Our headline empirical
finding is a negative one, from the construction that makes predictor inputs
disjoint from its label but reuses parameter-development data: with the defining
DMARC record masked out of the public-declaration mail-policy node, the
multi-signal posterior does not recover enforcing policy from the DMARC-masked
residual (historical fixed-bin ECE 0.3747, historical legacy index-sliced
equal-mass ECE 0.3263,
agreement 0.1896 over 2,906 domains). The
full-posterior agreement with the DMARC record is near-perfect, but we label it
consistency, not calibration, because the record is also the node's dominant
input. The provider-attested tenancy node admits a channel-split corroboration check (a
DNS-only predictor against the identity-endpoint label, historical fixed-bin ECE
0.0471 and historical legacy index-sliced equal-mass ECE 0.0440 over 3,296
domains) that we report with its
shared tenant-provisioning caveat. A separate split-conformal harness currently
reports only dependent empirical re-split diagnostics on a selected
DMARC-labeled development sample. The scorer was not frozen on a disjoint
training cohort, so the recorded run carries no future-point coverage claim and
does not validate the Bayesian uncertainty band.
Every hideable node remains at internally sound, model-relative support, and we
say so. We
publish reproducible public-proof and synthetic methods. Private-cohort rows
remain disclosure-reviewed, maintainer-reproducible aggregates whose selection
and parameter-development overlap we state.

---

## 1. Introduction

Security teams increasingly need to know what a domain's public namespace
reveals before an attacker reads the same channel: which identity provider the
namespace indicates, whether its mail policy is enforced, and what fronts its
origin. A domain is a query coordinate, not an organization identifier.
External attack-surface management (EASM) tools answer these
questions from public signals (DNS records, certificate-transparency logs,
unauthenticated provider endpoints), and they answer confidently. The confidence
is the problem. The ground truth behind these claims is not observable from
outside, and the domain operator can control much of the evidence: one namespace
publishes less, another publishes more, and a tool that reads "no signal" as
"no technology" can be confidently wrong about exactly the targets that matter
most.

The standard remedy, calibrating the classifier against labeled truth, is
structurally unavailable here. There is no label set for "which products are
operationally used behind this namespace"; the operator can delete most of the
indicators a public-metadata observer relies on. The deletion mechanism can
depend on disclosure policy, deployment choices, and other unobserved state, so
independent missingness is not justified. We therefore treat adversarial MNAR as
a plausible design condition, not as an empirically established relationship
between missingness and security maturity. The calibration literature's usual
assumptions (exchangeable data, missingness independent of the input) do not
cover that condition.

We present recon, a deployed, open-source, zero-credential external-surface tool
built around that predicament rather than despite it. Its explanation surface
emits a reconstructed evidence directed acyclic graph (DAG) with completeness
diagnostics and named disconnected terminals; high-level claims are computed by
a nine-node Bayesian network
small enough to audit by hand. Each tested query is cross-checked against exact
enumeration of its 512-state latent joint over a structured evidence sweep;
and absent evidence on hideable claims contributes a likelihood ratio of one
(absence of evidence is treated as no evidence, never as evidence of absence).
The network mean is a model-relative posterior. Its accompanying 80% display is
an evidence-responsive uncertainty band, not a credible interval, confidence
interval, identification region, or calibrated coverage statement. In one
sentence: this paper contributes a
validation architecture for inference whose ground truth is structurally
unobservable and partly adversarial, worked end-to-end in a real tool.

The architecture stands on one seam, stated early because it bounds everything
else: evidence *removal* versus evidence *addition*. We prove and machine-check a
local deletion nonincrease property under fixed assumptions: removing a fired
positive unit cannot raise its local odds contribution. This does not establish
monotonic behavior for every downstream claim in the full directed acyclic
graph, force uncertainty to increase, or rule out confident false negatives.
The result also does not extend to addition: selected synthetic additions move
model-relative posteriors across the 0.5 threshold. That is finite sensitivity,
not evidence that one record forces a confident real-world false positive. The broader
research target is therefore a provenance-constrained robustness envelope over
explicit removal, planting, dependency, and parameter assumptions.

Validation then proceeds by tier, with the tier decided by whether an external
reference the operator cannot suppress exists. Where one does (the DMARC record
is its own definition of an enforcing mail policy; Microsoft's identity endpoints
attest tenancy in both directions) we compare output with that channel and name
the dependency. A held-out construction masks the label-defining evidence out of
the predictor. A separate split-conformal harness reports dependent empirical
re-split diagnostics only; its current scorer was informed by the same
development corpus. Where no reference exists, we claim only model-relative
computation and tested structural properties. The synthetic layer ablation is
also narrower than an external evaluation: it samples grouped bindings
independently from per-binding likelihood parameters, including combinations
the declared groups call redundant or mutually exclusive. Its recorded values
are a misspecification stress test of implementation behavior, not a draw from
the committed model, a causal estimate, or a quantified price of the
missingness policy.

**Contributions.**

- A deployed passive-inference system that emits evidence-linked explanations
  and explicit completeness diagnostics, and pairs deterministic
  certificate-transparency correlation with a small Bayesian
  network whose inference is checked against full latent-joint enumeration over
  a structured evidence sweep (Section 3).
- A conservative missing-evidence treatment (the likelihood-ratio-one absence
  rule) with a proved and machine-checked local deletion nonincrease result, plus
  an explicit account of what unknown MNAR and evidence planting leave
  unidentified (Section 4).
- A four-level assurance architecture separating observed facts, internally
  sound model-relative computation, dependency-qualified corroboration, and
  independent predictive validation (Section 5).
- An evaluation that reports mixed implementation stress-test results,
  dependency-qualified external agreement, a predictor-input-disjoint negative
  result, dependent conformal re-split diagnostics, and finite scenario
  containment under parameter perturbation (Section 6).
- A reproducible public-proof and synthetic artifact, plus clearly separate
  maintainer-reproducible aggregate rows for private cohorts that cannot be
  independently regenerated from the repository (Section 9).

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
level and assumes the noisy label is independent of the input conditional on the
truth. recon's feature-dependent observation process does not satisfy that noise
model. Conformal performance-range prediction (arXiv:2407.13307) instead wraps
heuristic per-item bounds in split conformal under exchangeability of calibration
and future items; it does not justify input-independent missingness. What we can
adopt on the currently labelable email-policy output is the ordinary
split-conformal construction. Its mathematical finite-sample condition is a
scorer fixed independently of the calibration sample, with calibration and
future points exchangeable; recon's
stricter level-4 policy additionally requires predictor inputs to be disjoint
from the label-defining field so a mathematically covered but circular predictor
is not presented as independent evidence. Repeated splits of one selected list
are descriptive stability checks, not independent replications, conditional
coverage, or validation of the model-relative uncertainty band. We do not
transfer the statement to hardened targets or other claim families.

**Principle-based calibration of epistemic uncertainty (arXiv:2407.12211).** When
calibration against truth is hard, this thread argues an uncertainty measure
should instead be held to checkable structural principles, and tests compliance
rather than coverage. recon follows the narrower defensible version of that
methodology: exact arithmetic, grouping invariance, bounded ordered displays,
and a local deletion nonincrease lemma are testable level-2 properties. The band
is not guaranteed to widen under evidence removal because deletion can change
both its center and effective mass. Structural compliance does not substitute
for empirical calibration.

**Surrogate-label calibration (arXiv:2209.05486)** substitutes a model's own
confident predictions for missing ground truth. recon deliberately does not adopt
this: using the model's own outputs as stand-in labels is the circularity the
deterministic-versus-Bayesian consistency check already warns about (it is
near-tautological under the virtual-evidence construction, so it tests the
inference plumbing, not the conditional-probability values). recon's answer is
the opposite discipline: find the one kind of observable that is its own external
reference, report the exact comparison and its dependency, and state that the
result does not generalize.

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
attempts. DNS reads use the configured recursive resolver, so authoritative DNS
infrastructure may observe resulting resolver traffic. The standard MTA-STS
policy fetch is the only default target-owned HTTP or application request; two
direct-probe enrichments are opt-in and off by default. A deterministic
fingerprint catalog turns observed records into
*bindings*: named indicators such as `slug:microsoft365` or `signal:dmarc_reject`,
each carrying a vendor-documentation provenance pointer.

Bindings feed a Bayesian network of nine binary claim nodes (m365_tenant,
google_workspace_tenant, federated_identity, okta_idp, email_gateway_present,
email_security_modern_provider, email_security_policy_enforcing, cdn_fronting,
aws_hosting). Each node reports a model-relative posterior and an 80%
evidence-responsive uncertainty band, not a yes/no verdict. The band is a
post-inference display with hand-constructed effective mass. It is not a
credible interval over uncertain model parameters.
Inference is exact variable elimination; because the joint has only 512 states,
the `validation/differential_verification.py` harness cross-checks variable
elimination against a brute-force full-latent-joint reference. The harness walks
a none/one/all cross-product plus every local subset for three factor-heavy
nodes under sparse and dense backgrounds. Agreement verifies the tested factor
construction paths; it does not enumerate the global power set of evidence
bindings.

The emitted explanation DAG reconstructs evidence reachability and names any
terminal claim it cannot connect. For directly retained evidence and exact claim
contracts, an operator can re-query the public record before acting. Reachability
does not establish exact generation-time lineage for insight or posture
associations reconstructed from rendered text or proxy rule matches. Nodes sit
on a hideability spectrum that
turns out to govern everything in Section 5: provider-attested (the provider's
own endpoint answers authoritatively), public-declaration (a record that is its
own definition, such as DMARC), and hideable (no external reference; absence may
be genuine or adversarial).

---

## 4. Adversarial missing data

**Intuition.** When a hardened operator strips a public OIDC discovery endpoint,
the absence of the `microsoft365` binding is not random: it is correlated with
the latent tenancy claim through the operator's deliberate choice. Without a
specified observation mechanism or sensitivity class, unknown missingness that
is not at random does not identify the likelihood ratio for a non-observation.
Treating every non-fire as disconfirmation would add an unsupported observation
model. recon instead declines to extract negative evidence from an optional,
hideable publication channel.

**The rule.** recon's likelihood factor for a node X is the product over only the
bindings that fired,

L(O | X) = product over b in O ∩ B(X) of l_b(X),

with un-fired bindings contributing nothing. Equivalently, the likelihood ratio
recon assigns to the *absence* of a binding is exactly 1: an absent binding
provides no model-assigned discriminatory power between "X is truly absent" and
"X is present and the operator hid the indicator." This is the precise
mathematical content of "we do not condition on absence" in
[correlation.md](correlation.md#33-missingness). We are careful not to
overstate the formal grounding: the m-graph framework (Mohan and Pearl 2021)
supplies a non-recoverability verdict for this missingness structure, it does not
by itself derive the LR=1 choice, which is a modeling decision we make and then
defend by the monotonicity lemma below and a machine check; the Manski reference
is the partial-identification posture, not a bound we compute. The one exception
is the declarative mail-policy node, where the
reference (the DMARC/SPF/MTA-STS records) is itself public and non-hideable, so
its absence *is* informative and the model conditions on it (the CAL14
"missingness: declarative" model with grouped absence; `validation/cal14-missingness-design.md`).

**Proposition 1 (local deletion nonincrease).** Consider one binary claim with
fixed prior odds and independent fired evidence units whose likelihood ratios
are each at least one. Its local presence odds are the prior odds multiplied by
those unit ratios. Deleting a fired unit divides the local odds by a value at
least one, so it cannot increase those local odds. The implementation checks the
corresponding selected deletion property over the shipped network.

The hypotheses and scope matter. The proposition does not say that every
downstream marginal in the full network decreases, that a claim moves toward
0.5 or an all-absent value, that the uncertainty band widens, or that a hidden
claim cannot become a confident false negative. Declarative absence factors and
parent messages require their own explicit analysis.

**The limit.** The result is elementary, and that is the point: its value is the
framing and the honesty, not theorem depth. It bounds only evidence *removal*. It
says nothing about evidence *addition*: publishing a record that fires a unit
raises the posterior on a premise recon cannot check passively, so a planted
truthful decoy defeats it. That removal-versus-addition line, not the
passive/active line, is the limit of the guarantee. Proposition 1 is
machine-checked by `validation/adversarial_properties.py`, gated by
`tests/test_adversarial_properties.py`, with its exact boundary documented in
[correlation.md](correlation.md#34-evidence-removal).

---

## 5. The layered assurance argument

Because calibration-against-truth is unavailable for most nodes, recon makes a
layered argument and states, per claim, the highest level of support it has and
where that support stops (the evidence ledger in
[statistical-assurance.md](statistical-assurance.md)). The first two levels
concern provenance and faithful computation. The last two concern comparison
with external evidence.

| Level | Meaning | Current examples | What it does not establish |
|---|---|---|---|
| 1, observed | a bounded collector returned a re-queryable public fact | DNS records, CT SANs, identity-endpoint responses | current product use, ownership, or private state |
| 2, internally sound and model-relative | a rule or committed model computed its documented result faithfully | exact network marginal, grouped evidence, uncertainty band, graph partition | correctness of hand-set priors, likelihoods, dependence, or graph projection in reality |
| 3, external corroboration with stated dependency | output agrees with an overlapping, one-sided, or selection-biased external channel | DMARC-anchored policy agreement; M365 channel-split corroboration; Google one-sided recall | general two-class calibration |
| 4, independent predictive validation | a parameter-development-disjoint and predictor-input-disjoint two-class reference evaluates the stated claim family and population | none currently passing | transfer beyond the evaluated population and observation regime |

The policy node illustrates why the levels matter. Its full score agrees strongly
with DMARC, but DMARC is also the dominant predictor, so the result is level-3
definitional agreement. Masking the DMARC unit creates a predictor-input-disjoint
diagnostic, but same-corpus parameter development prevents a level-4 result; the
strict-SPF plus MTA-STS residual also performs poorly. This blocks a clean
calibration claim. The M365 result remains
level-3 corroboration because DNS and the provider endpoint share tenant
provisioning as a common cause. The separate conformal artifact reports
dependent empirical re-split behavior only: the scorer was not frozen on a
training cohort disjoint from the recorded sample. It neither raises these
evidence levels nor validates the Bayesian uncertainty band.

---

## 6. Evaluation

Each experiment maps to a committed harness. The June artifacts came from
selected private development-corpus runs, but they do not establish one common
evaluation population. The policy rows contain 2,906 DMARC publishers from a
5,241-domain run; the separately recorded 4,290-row conformal extraction lacks
enough lineage to treat it as the same cohort. Several committed parameters were
also informed by the June corpus. These rows are in-sample, aggregate
diagnostics, not an out-of-sample benchmark. Per-domain data is never published
(Section 9).

| Experiment | Result | Status |
|---|---|---|
| Differential verification | variable elimination matches a 512-state latent-joint reference over the none/one/all cross-product and exhaustive local subsets for three factor-heavy nodes under two backgrounds | shipped (`validation/differential_verification.py`) |
| Adversarial add/remove perturbation | selected shipped-model checks find no local deletion increase under their fixed assumptions. Paired additions can move model-relative posteriors across the 0.5 decision boundary in synthetic contexts (8 reported nodes, 774 paired add/remove cases). This is finite model-internal sensitivity and not a full-network hiding guarantee. It is not attacker prevalence. | `validation/adversarial_properties.py` |
| Uncertainty-band scenario containment | the 80% evidence-responsive band contains selected CAL8 perturbed-model conditionals under the recorded +/-20% scenarios. This is finite model-internal containment, not empirical coverage or calibration. | shipped (`validation/interval_coverage.py`) |
| Likelihood sensitivity | recorded model-relative posteriors and agreement are stable under the selected +/-20% likelihood perturbation | shipped (`validation/likelihood_sensitivity.py`) |
| Layer ablations (synthetic) | implementation behavior under an independent-Bernoulli observation stress generator that does not enforce declared group semantics | shipped and run (`validation/layer-ablation.md`) |
| Held-out residual negative result | DMARC unit masked, making the row's predictor inputs disjoint from the label but not its parameter-development data: historical fixed-bin ECE 0.3747, historical legacy index-sliced equal-mass ECE 0.3263, Brier 0.2448, agreement 0.1896 (n=2,906 DMARC publishers). The recorded row-resampling interval is a naive-iid diagnostic with no coverage interpretation. The residual does not recover enforcing policy in this development sample. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| DMARC-anchored agreement | agreement 1.000, historical fixed-bin ECE 0.0761, historical legacy index-sliced equal-mass ECE 0.0651, Brier 0.0077 (n=2,906 DMARC publishers). This is in-sample definitional agreement because the DMARC record is the node's dominant input. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| Tenancy, M365 | DNS-only predictor vs identity-endpoint label: historical fixed-bin ECE 0.0471, historical legacy index-sliced equal-mass ECE 0.0440, Brier 0.0796, agreement 0.8890 (n=3,296). This is selected development-sample channel corroboration, not independent calibration; both channels share tenant provisioning and the base rate is 0.7897. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| Tenancy, Google Workspace | one-sided recall 0.3636 (n=11); the recorded row-level Wilson interval is a naive-iid diagnostic, and the Google channel has no authoritative negative. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| Legacy conformal re-split diagnostic | mean empirical coverage 0.9992 vs nominal 0.90, legacy mean set-size field 0.9992, n=4,290, 20 dependent seeded re-splits. The scorer was not trained independently, set-composition rates were not recorded, and cohort lineage does not establish comparability with the 2,906 policy rows. This row carries no future-point coverage claim. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |
| Signed marginal entropy change, posture stratification | selected public-list cross-check across about 575 public, re-queryable domains in 22 disjoint sectors: overall median summed marginal entropy change 1.967 / 1.932 / 1.846 nats across Lists A/B/C; `direct / sparse` medians are 0.999 / 0.742 / 0.721. These construction-linked buckets are descriptive, and sums can double count dependent nodes. CAL7 width diagnostics reproduce across all three lists, but do not establish a general width monotonicity law. | `validation/public-list-calibration.md` |
| Per-vertical stratification (22 private-corpus verticals, min cell 10) | the pattern is uniform in the disclosure-reviewed aggregate memo: historical full-posterior fixed-bin ECE 0.065-0.098 per populated vertical (pooled 0.0761, legacy equal-mass 0.0651, agreement 1.0), historical held-out residual fixed-bin ECE 0.258-0.498 (pooled 0.3747, legacy equal-mass 0.3263, agreement 0.1896). The negative finding is not a single-sector artifact, but the population remains curated and high-base-rate. | `validation/2026-06-28-full-corpus-calibration-refresh.md` |

No current tie-preserving reliability estimate is available for these private
cohorts. Every ECE number in this section is from the historical 2026-06-28
aggregate and must not be presented as output from the replacement estimator.

The figure package in [paper-figures.md](paper-figures.md) renders this section's
submission figures from committed aggregate-safe sources: the assurance
architecture, nine-node DAG, public-list reliability bins, and CAL7 interval
width diagnostic.

**The headline diagnostic is a negative one, reported as such.** Masking the
DMARC unit makes the residual predictor's row inputs disjoint from its label,
but the committed parameters were informed by the same development corpus. In
the 2,906 DMARC-publisher rows, the residual cannot recover enforcing mail
policy from strict SPF and MTA-STS (fixed-bin ECE 0.3747, agreement 0.1896,
below the cohort's 0.8352 always-enforcing baseline). We foreground this rather
than the near-perfect
full-posterior agreement, because the latter scores the node against its own
dominant input and is a consistency check, not calibration. The tenancy
channel-split (fixed-bin ECE 0.0471, legacy index-sliced equal-mass ECE 0.0440)
is useful corroboration, but it is still confounded by shared tenant provisioning and
flattered by a 0.7897 base rate. The honest
summary: recon currently has no node with a clean, training-disjoint,
predictor-input-disjoint passing calibration result. The per-vertical
stratification shows the same weak residual pattern across all 22 disclosed
private-corpus verticals (pooled held-out fixed-bin ECE 0.3747, legacy equal-mass ECE
0.3263, agreement 0.1896), while the full-posterior consistency is equally
uniform (pooled fixed-bin ECE 0.0761, legacy equal-mass ECE 0.0651), which is
exactly what a definitional-agreement check looks like when read honestly. The
M365 tenancy decision is closed for this submission in
[m365-tenancy-decision.md](m365-tenancy-decision.md): no passive candidate is
independent enough to promote the DNS-only comparison beyond corroboration, so
the paper keeps the stronger calibration claim unmade.

The selected-cohort failure is also explainable from the remaining signal strengths. Once the
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

**Threats this evaluation does not control.** (1) The cohort is about 5,200 curated,
tech-forward firms (about 83 percent DMARC-enforcing, 79 percent M365), which
over-represents well-instrumented, non-hardened targets, the easy regime the
adversarial-missingness design claims not to need; the hardened cell the thesis
is about is nearly empty, and the reliability mid-range (0.4 to 0.7) is
unpopulated, which partly explains the low ECE. A stratified probability sample
from a public zone, stratified by a hardening proxy, is required before any rate
transfers beyond this population. The policy metrics are conditional on the
2,906 DMARC publishers retained by the historical harness, not all successfully
observed domains. Selected parameters were manually regrounded from this
development corpus, so no row is out of sample. The June 28 equal-mass
implementation split tied scores by index, and its row bootstrap and Wilson
intervals assume iid observations even though the selected rows are dependent.
The recorded intervals are naive-iid diagnostics with no coverage
interpretation. Older memos keep their dated estimator labels and are not
silently reinterpreted. (2) The uncertainty
band uses central Beta quantiles when the implementation's shape and containment
conditions hold, and a clamped mean-centered fallback otherwise. Its effective
mass is hand constructed. Neither branch supplies a credible interval,
confidence interval, identification region, or empirical coverage guarantee.
(3) The conformal scorer was not frozen on a training cohort disjoint from its
calibration and test rows. Its dependent re-split numbers are empirical shape
diagnostics only; they carry no future-point guarantee and do not validate the
uncertainty band.

**Synthetic stress behavior, with numbers.** The layer ablation runs 20,000
reproducible constructed worlds (`validation/layer-ablation.md`). Its latent
states follow the committed prior/CPT DAG, but its observation sampler draws
each binding independently. That can co-fire mutually exclusive or redundant
group members, so it is not the committed model's generative process. The
recorded table is still useful as a misspecification stress test: for example,
the hard any-fired baseline scores 0.0476 versus 0.1171 for the full M365
posterior, while the declarative policy posterior scores 0.0630 versus 0.1522
for any-fired. Those contrasts describe this generator only. They do not
estimate a causal or real-world "MNAR price," and the product decision must come
from the predeclared training-disjoint benchmark. The graph layer is shown separately:
Louvain community detection holds adjusted Rand index 1.0 on the assortative
planted benchmark across its bridging-noise grid, while naive connected
components fall sharply and reach 0 at three grid points. This tailored
benchmark does not establish real CT
relationship accuracy.

---

## 7. Discussion

What is and is not validated is itself part of the contribution. recon checks
each swept inference query against full latent-joint enumeration and
limits external claims to the narrow comparisons the claim map permits.
The June 28 aggregate refresh does not promote recon to a broadly calibrated
classifier. It sharpens the tiering: the DMARC full-posterior row is
DMARC-anchored consistency; the DMARC-held-out residual is input-disjoint but
not parameter-development-disjoint and it performs poorly; the M365 row is channel-split
corroboration with a shared tenant-provisioning caveat; and Google Workspace
remains one-sided recall on attested positives. That leaves recon with no clean
independent calibration result today. The claim is smaller and stronger: the
system proves its inference arithmetic, states a local deletion nonincrease
result under fixed assumptions, and refuses to turn passive public observations
into ground truth.

Three threats to validity are stated rather than hidden. First, the deterministic-versus-Bayesian
consistency number is near-tautological under the virtual-evidence construction,
so it tests the plumbing, not the conditional-probability values, and we never
report it as calibration. Second, co-firing bindings that share a group are
correlated readings of one underlying fact; the documented correlated-binding
concentration (CAL7) means richly-instrumented targets can get a tighter display
band when correlated units are counted separately, which the
interval-width-versus-evidence-count diagnostic surfaces. Third, the synthetic
ablation's independent-Bernoulli binding sampler violates declared group
semantics. It is a misspecification stress test, not model-generated truth or an
estimate of the missingness policy's cost.

The honesty has an operational payoff that sharpens with recon's deployment as a
grounding primitive for LLM agents (it ships an MCP server). An agent is a
confident summarizer: given a point estimate it states a verdict, and given a
wide band it may round it away unless the surface forbids it. recon's contract is
that a model-relative posterior is not an observed fact and a non-fired hideable
binding is not evidence of absence. The `sparse` flag has a narrower meaning: the
hand-constructed effective display mass is at its floor. It does not imply that
the posterior is near 0.5 or that the claim is absent. This distinction is a
property a downstream consumer cannot reconstruct after provenance and
missingness semantics are discarded, which is why the machine-readable output
surfaces the per-node band, sparse-count summary, and explicit reading guidance.

---

## 8. Limitations and ethics

recon is defensive and passive in collection scope by invariant: no credentials,
port scans, login attempts, paid APIs, runtime-trained model, or persistent
cross-domain store. DNS resolver traffic can be externally visible. The
standards-compliant MTA-STS fetch is the only default target-owned HTTP request;
Google CSE and BIMI certificate requests are explicit opt-in direct probes. Some
manually encoded parameters were informed by a development corpus.
The local deletion result does not cover evidence addition; selected synthetic
additions move model-relative posteriors across 0.5, but do not establish a
forced, confident, real-world false positive. Coverage depends on public
DNS, so namespaces behind heavy proxies or with minimal records can return
sparse results. The `sparse` flag reports only that effective display mass is at
its configured floor; band width need not increase and the posterior need not
move toward 0.5.
The fingerprint catalog is rule-based and solo-maintained, so confident-looking
output can still be wrong, which is why every detection carries a vendor-doc
pointer for independent re-verification. Ethically, recon reads public metadata
that a domain operator or public provider exposes, reports it with provenance
and hedged uncertainty, and leaves business interpretation to the operator; it
does not score, rank, or enrich organizations.

---

## 9. Reproducibility

The repository invariants keep real target rows and private identifier lists out
of version control. Public-proof methods and synthetic harnesses can be rerun
from a clean checkout. The software build has the bounded deterministic-build
evidence described below. Private-cohort metrics are not independently
result-reproducible because the selected domain list is gitignored, public DNS
changes over time, and the recorded aggregate artifacts do not retain enough
lineage to reconstruct every cohort. Only aggregate statistics are published;
the per-domain corpus never appears. This is the discipline recorded in
[data-handling-policy.md](data-handling-policy.md).
CI verifies byte-identical wheel and sdist hashes across two builds of the same
source with a fixed `SOURCE_DATE_EPOCH` inside one Ubuntu job and one resolved
build-tool window. PyPI attestations bind published artifacts to the release
workflow, and the JSON schema is locked. This evidence supports deterministic
rebuilding under the tested recipe; it does not establish byte identity across
every operating system and toolchain. The public no-private-data evidence bundle
is reproducible from a clean checkout with
`python -m validation.reproduce_paper_numbers`; it records the exact commands
and artifacts in a local manifest under `validation/local/`. The reviewer-facing
command sequence and result boundaries are in
[artifact-review.md](artifact-review.md).

We separate two reproducibility claims that are easy to conflate. Deterministic
build evidence is bounded to the tested same-job CI comparison
described above. Result reproducibility is more limited: the corpus aggregates
above (for example the M365 fixed-bin ECE of 0.0471) cannot be regenerated by an
outsider, because the domain list is gitignored by invariant and DNS/CT state
drifts daily. The synthetic harnesses reproduce the method and the
relative-layer results; they do not reproduce the private-cohort or public-list
aggregate numbers.
[public-label-snapshot-decision.md](public-label-snapshot-decision.md) defers a
frozen real-apex label snapshot under the current data-handling policy: a
hash-pinned identifier list would improve benchmark reproducibility, but it
would still publish a durable real-target corpus. Until a separate review changes
that policy, private-corpus rows are maintainer-reproducible aggregates only.

---

## 10. Conclusion

When a classifier's ground truth is structurally unobservable and the subject can
choose what to reveal, calibration-against-truth is the wrong bar for the claims
whose signals an operator can hide. The honest substitute is a layered argument:
observed public facts, internally verified model-relative computation, narrowly
scoped public-reference checks with their dependencies stated, and independent
predictive validation only where a training-disjoint and predictor-input-disjoint study passes. The
strongest empirical
result is negative: once the DMARC-defining evidence is masked, the residual
signals do not recover enforcing policy. The tenancy check supports
corroboration, not independent calibration. recon is therefore not a broadly
calibrated truth oracle; it is a worked artifact for making passive inference
auditable and honest about what the public channel cannot decide. Its current
deletion result is local and assumption-bound. A provenance-constrained
robust score envelope over compatible evidence states, model classes, and
explicit removal and planting budgets is the next research direction, not a
shipped guarantee. It becomes a partial-identification program only after a
coherent joint evidence law and observation kernel are defined.

---

## Open items before submission

Recorded in the 2026-06-28 development artifacts: the held-out residual, DMARC
full-posterior consistency, M365 corroboration, Google one-sided tenancy check,
dependent conformal re-split diagnostic, and legacy index-sliced equal-mass ECE
with naive-iid row-bootstrap intervals. These remain aggregate development
diagnostics, not submission-ready independent validation. Done in this draft
pass: the residual collapse is now
diagnosed from
the remaining signal strengths, with MTA-STS rarity and strict SPF weakness
called out as the mechanism visible in the committed model data. Done in the
figure pass: [paper-figures.md](paper-figures.md) and `docs/assets/paper/*.svg`
provide deterministic, aggregate-safe assets for the architecture, DAG,
reliability, and interval-width figures. Done in the adversarial perturbation
pass: `validation/adversarial_properties.py` now reports paired evidence-removal
and planted-evidence movement over the shipped network. Done in the publication
decision pass: [public-label-snapshot-decision.md](public-label-snapshot-decision.md)
now closes the stratified public probability-sampling path for this submission
by keeping public-list numbers as robustness checks rather than population
rates.

The M365 independent-instrument decision is closed for this submission:
[m365-tenancy-decision.md](m365-tenancy-decision.md) records why no passive
candidate is independent enough to promote the result beyond corroboration.

The most recent recorded final claim audit is the historical
[2026-06-29 claim-audit memo](../validation/2026-06-29-scorecard-gate-claim-audit.md).
The most recent recorded local public proof is the historical
[2026-06-30 submission-freeze memo](../validation/2026-06-30-submission-freeze-local-proof.md).
Both apply only to the exact commits they name. Later experiment, paper wording,
package, and claim-map changes leave this draft unfrozen. A new claim audit,
figure drift check, public proof, local gate, release-readiness check, and freeze
record are required before submission packaging.
