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

## Enforcement

The PR template (`.github/pull_request_template.md`) carries a
non-blocking checkbox prompting reviewers to confirm a YAML
concept comment is present for any CPT change. The checkbox is
the prompt, not the gate: reviewer judgement is the gate. There
is intentionally no CI test enforcing this: a CI test would game
the comment requirement (it could pass on a comment that doesn't
actually question the concept). The discipline is a review
practice, not an automated check.
