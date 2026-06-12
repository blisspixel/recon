# Paper skeleton (aspirational)

Status: a working outline, not a release gate and not on the critical path
of any version. It exists so the experiments are designed into the
validation harnesses rather than retrofitted, and so the framing settled
here survives between work sessions. The literature positioning lives in
[related-work.md](related-work.md); the forward plan and which pieces are
shipped live in the [roadmap](roadmap.md) research write-up section.

## Thesis

When a classifier's ground truth is structurally unobservable and the
subject can choose what to reveal, calibration-against-truth is the wrong
bar for the claims whose signals an operator can hide (five of recon's nine
nodes have no external reference; the engine applies the MNAR absence rule to
eight, the ninth being the declarative policy node). The honest substitute is a layered argument:
(1) structural guarantees that hold by construction, including under
adversarial hiding; (2) a partial external check on the subset of claims
that have a self-defining reference; and (3) an explicit ledger that states,
per claim, the highest tier of support it has and where that support stops.
recon is the worked artifact for that argument in passive external
attack-surface measurement.

The seam the paper is built around is evidence *removal* versus *addition*.
The structural guarantee holds against removal: hiding signals can only move
a claim toward its baseline, never to a confident false positive. It does not
hold against addition: a fully passive operator who publishes one truthful
decoy record can plant a confident false positive, and recon cannot tell a
decoy from a real record without the active probing it forbids. So the honest
contract is *robust to evidence removal, exposed to evidence addition*, and
that line is not the passive/active measurement line, because the cheap attack
is itself passive. The earlier "robust to hiding, not to lying" phrasing holds
only if "lying" is read to include truthful-but-decoy records.

## Honest contribution statement

Not a new inference algorithm. Variable elimination, community detection,
and Beta-style credible intervals are textbook. The contribution is a
combination uncommon in the passive-recon literature, plus an unusually
explicit account of what is and is not validated:

- a zero-credential, strictly passive external-surface tool that keeps
  full provenance (every conclusion reachable through the evidence DAG);
- deterministic graph correlation over certificate-transparency
  co-occurrence paired with a small auditable Bayesian network;
- an adversarial missing-data treatment (MNAR, the likelihood-ratio-one
  absence rule, grounded in m-graphs and Manski partial identification) so
  the credible interval widens on hardened targets instead of collapsing
  to a false verdict;
- a formal suppression-monotonicity result that turns "we cannot see
  ground truth" into a precise statement of what an adversary can and
  cannot do to the posterior;
- a node-tiered validation architecture: calibration where a self-defining
  reference exists, principle-compliant evidence-responsiveness everywhere
  else, with the boundary made explicit.

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

- "Calibrated, Provenance-Aware Passive Inference for External
  Attack-Surface Management"
- "Evidence-Responsive Uncertainty for Zero-Credential Infrastructure
  Fingerprinting"
- "Robust to Hiding, Not to Lying: One-Sided Guarantees for Passive
  Inference under Adversarial Missingness"

## Abstract (draft)

External attack-surface tools infer an organization's technology stack
from public signals. The honest version of that task faces a problem the
calibration literature usually sidesteps: the ground truth is not
observable, and the subject can hide signals, so a confident-looking
verdict can be confidently wrong. We present a passive, zero-credential
inference tool that pairs deterministic certificate-transparency
correlation with a small auditable Bayesian network and treats absent
evidence as adversarially missing, so the reported credible interval
widens rather than collapses when a target is hardened. We prove a
suppression-monotonicity property: hiding any observed signal can only move
a claim toward its all-absent baseline, never to a confident false positive.
We are explicit about its limit: the guarantee bounds evidence removal, not
addition, and a fully passive operator who plants one truthful decoy record
can still force a confident false positive. On the one node whose label is a
public self-declaration (the DMARC email-policy record) we report a partial
calibration against that record, honest that the label is also the node's
dominant input; everywhere else we report evidence-responsiveness, which
governs interval width and not point-estimate accuracy, and say so. We
evaluate against public references and synthetic harnesses that need no
private data, and we release a reproducible, signed artifact.

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
4. Adversarial missing data. The MNAR / likelihood-ratio-one absence rule;
   m-graphs and Manski partial identification; the suppression-monotonicity
   proposition and proof; the removal-versus-addition boundary as the
   guarantee limit.
5. The layered assurance argument. The four-tier evidence ledger; the
   structural guarantees as principle compliance; reference calibration on
   self-defining records; the conformal coverage complement on labelable
   nodes; the node-tiering table.
6. Evaluation. The experiment inventory below, each mapped to a harness.
7. Discussion. What is and is not validated; the honest boundary; threats
   to validity (the documented correlated-binding over-confidence, the
   near-tautological consistency check, synthetic versus real).
8. Limitations and ethics. Passive-only, defensive-only, no released
   target list, the data-handling policy as a design constraint.
9. Reproducibility. Public references anyone can re-query, the synthetic
   harnesses, the bit-for-bit reproducible signed artifact and locked
   schema.

## Proposition 1 (suppression-monotonicity), as it will be stated

Hold all evidence outside a node X fixed, and reduce X's bindings to
evidence units (one independent binding, or one mutually-exclusive group).
X's presence-posterior odds equal a prior baseline odds times a product of
per-unit likelihood ratios. Under the hypotheses (each fired unit is a
positive indicator with ratio at least one, and on the declarative node each
not-fired unit is disconfirming with ratio at most one), hiding any fired
binding replaces a ratio of at least one with a ratio of at most one, so the
posterior moves monotonically down toward the node's suppression floor B_X,
the all-absent posterior, and never above the fully-observed value. For a
hideable node B_X is the prior baseline; for the declarative node it is the
strictly lower all-absent posterior (the policy node's is about 0.055, below
its 0.62 prior). Hiding therefore cannot manufacture confidence; it can only
move a claim toward "we cannot tell."

The result is elementary and bounds only evidence removal. It says nothing
about evidence addition: publishing a record that fires a unit raises the
posterior on a premise recon cannot check passively, so a planted truthful
decoy defeats it. That removal-versus-addition line, not the passive/active
line, is the limit of the guarantee.

Machine-checked by `validation/adversarial_properties.py`, gated by
`tests/test_adversarial_properties.py`, with the full statement in
correlation.md section 4.3.

## Evaluation inventory (each maps to a harness)

| Experiment | What it shows | Harness / status |
|---|---|---|
| Reference calibration (DMARC) | the email-policy posterior agrees with the DMARC record (ECE about 0.077, miss conservative); tier 4 for the strict-SPF + MTA-STS residual only, since DMARC is also the dominant input | `validation/reference_calibration.py`; shipped |
| Held-out residual calibration | recompute the policy posterior with the DMARC unit masked as structurally unobserved (`masked_units`, not "absent" — the declarative node would read deletion as disconfirmation) and calibrate the residual against the DMARC label, so predictor and label are disjoint (a clean tier-4 claim) | `validation/reference_calibration.py` (both modes print full + held-out blocks); harness shipped, maintainer run pending |
| Conformal coverage on labelable nodes | a distribution-free finite-sample coverage statement beside the Bayesian interval, with the exchangeability boundary stated | candidate validation extension; not yet built |
| Interval coverage (synthetic) | the 80% interval absorbs the elicitation imprecision under the CAL8 band | `validation/interval_coverage.py`; shipped |
| Likelihood sensitivity (CAL8) | the posteriors and agreement are stable under a plus-or-minus-20-percent likelihood perturbation | `validation/likelihood_sensitivity.py`; shipped |
| Information recovered (CAL10) | the per-domain entropy-reduction distribution across postures, as the operational reading of what the channel still leaks after hardening | calibration pass; partially measured |
| Layer ablations | what the graph layer and the Bayesian layer add over single-source slug matching | small extension of existing harnesses |
| Posture stratification | aggregate behavior across hardening postures, as distributions not exemplars | the correlation.md failure-mode catalogue (sections 4.10 to 4.11) |
| Differential verification | variable elimination matches a full-joint reference on every enumerable configuration | `validation/differential_verification.py`; shipped |
| Per-vertical stratification | the calibration holds across industries | the by-vertical corpus lists; not yet run |

Figures: an architecture diagram, the nine-node network as a clean DAG,
reliability diagrams with the posterior histogram, and an
interval-width-versus-evidence-count plot that surfaces the documented
correlated-binding over-confidence (CAL7). Color-blind-safe palettes.

## The data-publication constraint as a design feature

The repository invariants (no real company data, ever; the corpus stays
gitignored; committed examples use the Microsoft fictional brands) mean
the empirical section cannot print targets. The paper turns that into a
method: every empirical claim is reproducible against public references
anyone can re-query (DMARC / SPF / MTA-STS records as their own truth, the
Microsoft and Google identity endpoints for tenancy) plus the fully
synthetic harnesses. Only aggregate, posture-stratified statistics,
synthetic reproductions, and the public-reference calibration are
published; the per-domain corpus never appears. This is the discipline the
cohort summary and the maintainer-validation loop already follow, recorded
in [data-handling-policy.md](data-handling-policy.md).

## Open items before this is submittable

Evidence not yet in hand, in roughly the order the roadmap sequences it:

- per-vertical stratification of the reference calibration;
- provider-endpoint corroboration for the tenancy nodes (which also gives
  those nodes a reference label, extending calibration and the conformal
  check past the single email-policy node);
- the conformal coverage harness on the labelable nodes, if adopted;
- the layer ablations and the posture-stratified aggregates;
- the writing itself.

## Decisions still open

- Venue and timing. The substance is mostly assembled; the gating item is
  the remaining empirical runs, not the writing.
- Whether to adopt the conformal coverage complement now (a small
  validation harness, labelable nodes only) or leave it as a paper-time
  experiment. Recorded as a candidate in the roadmap.
- Whether the principle-compliance suite gets a named, standing gate of its
  own or stays inside `validation/adversarial_properties.py`.
