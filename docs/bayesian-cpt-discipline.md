# Bayesian CPT-change discipline

The v1.9 Bayesian layer (`recon_tool/data/bayesian_network.yaml`) is a
**data file with semantic content**, not a free parameter surface to
tune against the corpus. Every CPT entry encodes a claim about how
evidence should move the posterior. Changing a number changes a
claim.

The discipline is one rule: **corpus runs are mirrors, not fitters.**
When the corpus disagrees with the network, the first question is
*is this node asking the right question?*, not *what number gets
the disagreement number down?* Only after the topology is clean do
CPT numbers get re-examined, and only with explicit reasoning
written in the YAML alongside the change.

This doc is the deep-dive reference. The short version lives in
[`CONTRIBUTING.md`](../CONTRIBUTING.md#cpt-change-discipline-v196)
and points here for the worked examples and anti-pattern catalog.

## When you are about to change a CPT entry

Work the decision through in this order before editing the YAML:

1. **Is the disagreement reproducible?** Re-run the calibration
   against the current corpus. Single-domain anomalies are noise;
   patterns across >= 3 domains warrant continuing.
2. **Does the bound evidence's likelihood ratio match the binding's
   semantic claim?** A signal with LR 2.8 says "observing this
   roughly triples our odds of the node being present." If that's
   wrong as a *semantic* statement about what the signal actually
   indicates, the binding is mis-modeled, and the fix is either
   removing the binding or replacing it, not retuning the number to
   game the criterion.
3. **Is the prior consistent with the target population?** recon
   predicts enterprise apex domains. If a prior reflects the
   internet-at-large base rate when the network's input population
   is enterprise apexes, the prior is structurally wrong. Adjusting
   it is a CPT change *with a target-population concept comment*,
   not parameter-tuning.
4. **Is the topology asking the right question?** If a node's
   description doesn't match the claim its evidence bindings
   support, the topology is wrong. The answer is structural
   surgery, not a number adjustment. See the v1.9.3 worked
   example below.

## Worked example 1: v1.9.3 surgery on `email_security_strong`

**The temptation.** The v1.9.0 corpus showed 52.6% deterministic-
pipeline agreement on the `email_security_strong` node, much lower
than the other nodes (90%+). The corpus-fitting reflex was to
lower `P(strong | M365=present, gateway=present)` from 0.75 to
0.55 to "match the corpus rate of 55%."

**The pause.** Before tuning, we asked *what does
`email_security_strong` claim?* The description and the parent CPT
both said "the domain runs a modern, managed mail provider." But
the evidence bindings tested DMARC, DKIM, SPF, and MTA-STS, which is
*policy enforcement*, not *provider presence*. A weak-policy M365
tenant and a strong-policy on-prem domain were being scored
against the same node. No CPT tuning could reconcile them because
the node was entangling two distinct claims.

**The fix.** Topology surgery: `email_security_strong` was split
into `email_security_modern_provider` (CPT-driven, provider
presence) and `email_security_policy_enforcing` (evidence-driven,
policy enforcement). Both claims became first-class. Operators
who want the conjunction can compute it downstream from the two
posteriors.

**The lesson.** A 52.6%-agreement number can come from a node
that's correct on average across two populations and wrong on
both individually. Tuning the number averages harder; topology
surgery decomposes the claim.

## Worked example 2: v1.9.6 surgery on `email_security_policy_enforcing`

**The temptation.** The v1.9.5 stability report
(`validation/v1.9.5-stability.md`) found that 10 of 129
det-positive-HIGH non-sparse observations had posterior <= 0.5,
failing criterion (b1). Every one of those 10 cases was
`evidence_used = ('signal:dkim_present',)` alone. With
`dkim_present` likelihood `[0.85, 0.30]` and prior 0.25, the
posterior came out to ~0.486, just under 0.5. The corpus-fitting
reflex was to lower the likelihood for the absent case from 0.30
to 0.20, lifting the dkim-only posterior to 0.59. Criterion passes.

**The pause.** Before tuning, we asked *what does `dkim_present`
mean as evidence for `email_security_policy_enforcing`?* The node
claims "observable email-authentication policy is enforcing"
(DMARC reject/quarantine + DKIM + strict SPF + optional MTA-STS
enforce). DKIM publication is widespread: domains publish DKIM
for deliverability whether or not they enforce DMARC. A 2.83x
likelihood ratio (the current 0.85/0.30) says "observing DKIM
roughly triples our odds of enforcement." Empirically, that's not
true: DKIM is published by a large fraction of non-enforcing
domains as well.

**The fix.** Remove `dkim_present` as an evidence binding for
`email_security_policy_enforcing`. The node's remaining four
bindings (`dmarc_reject`, `dmarc_quarantine`, `mta_sts_enforce`,
`spf_strict`) all speak directly to enforcement. The dkim-only
domains correctly move to `evidence_used = ()` -> sparse=true,
joining (b2)'s det-silent-correctly-hedged set.

**The lesson.** Tuning a likelihood to lift a posterior over a
threshold is fitting the criterion, not improving the model.
Removing a binding that doesn't speak to the node's claim
improves the model.

## Anti-pattern catalog

The following PR change descriptions should be rejected by
reviewers without further evidence. Each is a real corpus-fitting
reflex worth catching in the review:

1. **"Lowered P(X | Y) from 0.75 to 0.55 to match the corpus rate."**
   Rejection prompt: "What conceptual claim does this change
   reflect? What did you learn about Y when you saw the
   disagreement?" If the answer is "the corpus disagreed and 0.55
   makes it agree," the change is corpus-fitting, not
   model-improvement.
2. **"Adjusted likelihood to clear ECE threshold."** Rejection
   prompt: "Which binding's *semantic* claim changed? If none,
   why is the new number more accurate than the old one?"
3. **"Added priors override YAML to compensate for posterior
   miscalibration."** The priors-override mechanism
   (`~/.recon/priors.yaml`) is for operator base-rate adjustments,
   e.g., *I'm only looking at financial-sector domains, so raise
   the m365 prior*. It is not a place to silently fix engine
   miscalibration without changing the shipped CPT. If the
   shipped prior is wrong, change the shipped prior with a
   concept comment.
4. **"Wrote a script to auto-tune CPTs against corpus statistics."**
   Crosses the no-learned-weights invariant. Iteration with a
   human in the loop is the right cycle; automation of the
   number-fitting step is the wrong cycle. Reject.

## The concept-comment requirement

Every CPT or prior change in `bayesian_network.yaml` must carry a
YAML comment, immediately above the change, that:

1. Cites the corpus disagreement or design observation that
   surfaced the question.
2. States the conceptual claim the new number reflects.
3. Notes any prior alternatives considered and why they were
   rejected.

The comment is for future contributors who will look at the
number and wonder why it is what it is. "0.40 because corpus rate"
is a corpus-statistic comment, not a concept comment: reject.
"0.40 reflects the enterprise-apex target population's published
DMARC-enforcement rate per [reference]; 0.25 was the internet-at-
large base rate and is structurally wrong for recon's input
distribution" is a concept comment.

## What this discipline does NOT prohibit

* **Iterating in a human-in-the-loop cycle.** "Look at corpus,
  rewrite mental model, write new CPTs" with a human deciding
  what to change is the right cycle. The corpus is data; the
  human is the fitter.
* **Adjusting numbers when the *semantic* claim has changed.** If
  a binding's likelihood ratio changes because empirical
  evidence about the binding's meaning has changed, not just
  because the corpus disagrees, that's a model improvement.
* **Splitting, redefining, or removing nodes.** Topology change
  at bridge milestones (v1.9.3 surgery, v1.9.5 dispositions,
  v1.9.6 binding removal) is explicitly authorized when the
  network's structure is asking the wrong question.

## The priors ledger (CAL12)

CAL12 requires the elicitation of every root prior to be written down
against the observed corpus base rate, because the prior is load-bearing
exactly where recon says the honest field lives: strong likelihoods wash
the prior out of a densely-evidenced point estimate, but the sparse-case
posterior and the credible interval inherit it directly. This ledger is
that record. Two readings to hold while using it:

- A corpus *detection* rate is not a population base rate. The
  maintainer's corpus skews enterprise (it exists to exercise the
  catalogue), and a "high-confidence rate" is bounded by what passive
  observation can see - it estimates `P(detected)` on that sample, not
  `P(present)` for an arbitrary queried domain. A deliberate gap between
  prior and corpus rate is therefore not automatically an error; an
  *undocumented* gap is.
- The prior answers "an arbitrary domain someone points recon at."
  Operators whose scope skews (an M365-heavy consultancy, a
  fintech-only portfolio) are expected to override via
  `~/.recon/priors.yaml`; that override path exists precisely so the
  shipped priors can stay population-shaped rather than corpus-shaped.

| Node | Prior | Status | Observed (2026-06 corpus, ~5.2k domains) | Elicitation note |
|---|---|---|---|---|
| `email_security_policy_enforcing` | 0.62 | **corpus-grounded** | 61.7% of 5,238 publish an enforcing DMARC policy | Re-grounded from a hand-set 0.25 in the 2026-06 pass; the one prior whose reference is a public declaration, so the corpus rate *is* the base rate for the declaring population |
| `m365_tenant` | 0.30 | hand-set; known corpus gap, kept deliberately | high-confidence M365 in ~60% of corpus domains | The corpus is enterprise-skewed by construction; 0.30 is the arbitrary-domain stance. The gap is the documented CAL12 mismatch - revisit if the PV2 re-grounding shows the *general*-population rate drifting |
| `google_workspace_tenant` | 0.25 | hand-set | not separately recorded | Elicited as "somewhat less common than M365 in the queried population"; the PV2 loop should record its corpus rate next pass |
| `email_gateway_present` | 0.18 | hand-set | not separately recorded | Third-party gateways are a minority posture even among enterprises; awaiting a recorded rate |
| `cdn_fronting` | 0.45 | hand-set | not separately recorded | Near-half reflects how common edge-proxying is among domains worth querying; awaiting a recorded rate |
| `aws_hosting` | 0.40 | hand-set; known corpus gap | ~28% observable AWS | Kept above the observed rate because AWS presence is under-detected passively (internal workloads invisible - the limitations doc's ceiling); the gap direction is deliberate, its size is judgement |
| `federated_identity` | CPT | seeded + tuned | - | GWS-path entries seeded at v1.9.3 (see the YAML comment); the M365-path entries carried from v1.9.0 |
| `okta_idp` | CPT | hand-set | - | 0.30 given federation, 0.005 without: Okta's share of the federated-IdP market vs near-zero outside it |
| `email_security_modern_provider` | CPT | hand-set, propagation-only | - | No own evidence; the CPT is the claim (provider presence given parents), preserved from the v1.9.0 structure |

The maintenance loop: the PV2 routine re-grounds the recordable rates each
release (`docs/maintainer-validation.md`), and any prior move it proposes
is a CPT change under this file's discipline - concept comment, validation
rerun, drift-gate acknowledgement. The "not separately recorded" cells are
the open half of CAL12: the next full-corpus pass should fill them, after
which this table carries a number or a documented refusal for every row.

## Enforcement

The PR template (`.github/pull_request_template.md`) carries a
non-blocking checkbox prompting reviewers to confirm a YAML
concept comment is present for any CPT change. The checkbox is
the prompt, not the gate: reviewer judgement is the gate. There
is intentionally no CI test enforcing this: a CI test would game
the comment requirement (it could pass on a comment that doesn't
actually question the concept). The discipline is a review
practice, not an automated check.
