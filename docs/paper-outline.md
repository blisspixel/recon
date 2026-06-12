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
bar for most of its claims. The honest substitute is a layered argument:
(1) structural guarantees that hold by construction, including under
adversarial hiding; (2) genuine calibration on the subset of claims that
have a self-defining external reference; and (3) an explicit ledger that
states, per claim, the highest tier of support it has and where that
support stops. recon is the worked artifact for that argument in passive
external attack-surface measurement.

The seam the paper is built around: the boundary where the calibration and
conformal guarantees stop being available is the same boundary where the
structural guarantee keeps holding, and both coincide with the
passive/active measurement line. Stated in the project's existing terms,
the model is robust to hiding and is explicitly not robust to lying.

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
widens rather than collapses when a target is hardened. We give a
suppression-monotonicity result showing that hiding any observed signal
can only move a claim toward its prior baseline, never to a confident
false positive, and we identify the passive/active boundary as the limit
of that guarantee. Where a self-defining external reference exists (a
DMARC record for email-policy enforcement, provider identity endpoints for
tenancy) we calibrate against it and add a distribution-free conformal
coverage check; everywhere else we report principle-compliant
evidence-responsiveness and say so. We evaluate against public references
and synthetic harnesses that need no private data, and we release a
reproducible, signed artifact.

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
   theorem statement and proof sketch; the passive/active boundary as the
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

## Theorem 1 (suppression-monotonicity), as it will be stated

Under the positive-indicator hypothesis (each evidence binding has a
presence likelihood ratio of at least one), a node's presence posterior
odds equal its baseline odds times the product of the likelihood ratios of
the bindings that fired. Hiding any fired binding removes a factor of at
least one, so the posterior odds move monotonically toward the baseline
and stay within the closed interval from the baseline value to the
fully-observed value. Hiding therefore cannot raise a claim above its
fully-observed posterior and cannot manufacture confidence; it can only
move the claim toward "we cannot tell." The guarantee covers hiding
(suppressing true signals) and explicitly does not cover forging
(emitting false signals), and that division is the passive/active line.

Machine-checked by `validation/adversarial_properties.py`, gated by
`tests/test_adversarial_properties.py`, with the full statement in
correlation.md section 4.3.

## Evaluation inventory (each maps to a harness)

| Experiment | What it shows | Harness / status |
|---|---|---|
| Reference calibration (DMARC) | the email-policy posterior is calibrated against an authoritative external definition on real records | `validation/reference_calibration.py`; shipped, tier 4, ECE about 0.077, conservative direction |
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
