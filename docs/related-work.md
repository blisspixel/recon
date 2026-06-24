# Related work: calibration without observable ground truth

This note positions recon inside the research conversation it belongs to.
It is the source material for the paper's related-work and discussion
sections (see [paper-outline.md](paper-outline.md)), and it records, for
each external thread, what recon borrows, what it cannot borrow, and why.
It is a positioning document, not a novelty claim: the contribution recon
makes is stated honestly in the outline, and most of the machinery it
uses is textbook.

The papers cited here live, with per-paper insight notes, under the
research library the maintainer keeps outside this repository. Only the
public arXiv identifiers and the reading appear here; no private corpus
data is involved.

## The problem class

recon is a probabilistic classifier whose ground truth is, for most of
its claims, not observable. A passive external observer cannot see
whether an organization actually runs Okta, only what the public channel
happens to reveal, and the target can choose to reveal less. This is the
hard corner of a problem the machine-learning literature has been
circling from the easier side: how do you make a calibration statement
about a classifier when you cannot get labels for its outputs?

Three sub-threads in that literature each stop just short of recon's
setting. recon sits past the assumption each one needs.

## Label-free performance estimation: CBPE (arXiv:2505.05295)

CBPE (Calibration-Based Performance Estimation) estimates any
confusion-matrix metric (accuracy, precision, recall, F1) on unlabeled
data by treating the per-item confidences as parameters of Poisson
binomial distributions over the matrix counts. Given calibrated
confidences and no labels, it returns full distributions for each metric.

What recon takes from it: the framing that a calibrated probability is
itself an estimator of aggregate performance, so a monitoring signal can
exist without labels.

What recon cannot take: every CBPE guarantee rests on the assumption of
perfect calibration, and the paper states there is no guarantee under
concept shift. recon cannot grant either condition for a node a target
can hide. Adversarial hiding is a worst-case, input-dependent shift, and
the calibration of a hideable node is the very thing recon declines to
assert (it reports evidence-responsiveness instead, per CAL13). So CBPE
describes the comfortable case recon is denied, and it enters the paper
as a contrast that sharpens why recon's setting needs a different answer,
not as a method recon adopts.

## Conformal prediction under noisy or missing labels

Two papers here. NACP (Noise-Aware Conformal Prediction,
arXiv:2501.12749) calibrates conformal prediction sets from a calibration
set whose labels are noisy, under a known noise level, and gives a
finite-sample coverage guarantee that does not degrade with the number of
classes. Conformal performance-range prediction (arXiv:2407.13307) wraps
heuristic per-item bounds in split conformal so the reported interval
contains the true quality metric with probability at least 1 minus alpha,
distribution-free, under exchangeability of the calibration and test
sets.

What recon cannot take wholesale: NACP's guarantee is derived under the
assumption that the noisy label is independent of the input given the
truth, and the paper names feature-dependent noise as out of scope.
recon's missingness is feature-dependent by construction: whether a
signal is absent depends on what that signal would have revealed and on
the target's intent. recon is precisely the case that thread excludes.
And the conformal coverage guarantee holds only under exchangeability,
which fails on the adversarially-hardened targets recon flags as
the interesting ones.

What recon can take, on the nodes where a label exists: split conformal
is adoptable as a complementary, distribution-free coverage statement for
any node that has an external reference. That is the email-policy node
(the DMARC record is its own reference, per the existing reference
calibration) and the M365 tenancy node (Microsoft's identity endpoints
are an authoritative two-class attestation; the Google channel turned out
one-sided on source review — federated redirects only, no managed
detection, no authoritative negative — so `google_workspace_tenant`
carries a recall check, not a label, see correlation.md 4.3). For the
labelable nodes recon can report a conformal prediction
set beside the Bayesian credible interval: two guarantees of different
kinds, one subjective-Bayesian and one frequentist-distribution-free,
with an explicit note that the conformal guarantee is conditional on
exchangeability and so is not claimed for hardened targets. The boundary
where conformal coverage stops being guaranteed is the same boundary
where the suppression guarantee keeps holding, which is the honest seam
the paper is built around. This was the one concrete validate-differently
implication of the library; it has since shipped as
`validation/conformal_coverage.py` (with a deliberate falsifiability
split demonstrating the exchangeability boundary), and the tenancy label
side as `validation/tenancy_reference_calibration.py`.

## Principle-based calibration of epistemic uncertainty (arXiv:2407.12211)

This paper argues that when calibration against ground truth is hard, an
uncertainty measure should instead be held to checkable structural
principles, and it proposes two (uncertainty falls as data grows,
uncertainty rises as model expressiveness grows) and tests compliance
rather than coverage.

This is the methodology recon already follows without having named it.
The suppression-monotonicity property (correlation.md section 4.3) is a
principle-compliance result: hiding an observed binding moves a node's
presence posterior toward its all-absent baseline, never to a confident
false positive (it bounds evidence removal, and not the addition of decoy
records). The interval-widening property (the credible interval grows as
n_eff falls) is a second such principle, governing interval width. Framing recon's guarantees this
way places them in a recognized methodological tradition and makes the
reservation precise: recon says "calibrated" only where an external
reference exists, and even there only partially (the DMARC node shares its
label with its dominant input, so only the residual is independently
checked), and "evidence-responsive, principle-compliant" everywhere else
(CAL13). recon can name its principle suite
explicitly and test compliance as a standing gate, which the existing
`validation/adversarial_properties.py` already begins.

## Surrogate-label calibration (arXiv:2209.05486)

This paper substitutes a model's own confident predictions for missing
ground truth to compute calibration metrics, and adds Wasserstein-distance
metrics to an ideal reliability histogram.

recon deliberately does not adopt the surrogate-label substitution. Using
the model's own confident outputs as stand-in labels is the circularity
CAL1 already warns about: the deterministic-versus-Bayesian consistency
check is near-tautological under the virtual-evidence construction, so it
tests the inference plumbing, not the CPT values, and a surrogate-label
calibration would dress that same circularity up as a coverage number.
recon's answer is the opposite discipline: find the one kind of observable
that is its own external reference (a public self-declaration like a DMARC
record) and calibrate only there, and state plainly that the result does
not generalize to the hideable nodes. The contrast is worth stating in
the paper, because the tempting shortcut is common and recon's refusal of
it is part of the honest-evaluation posture.

## Bayesian-network inference lineage

recon's inference core is exact variable elimination on a deliberately
small, fixed nine-node network. The relevant lineage (Darwiche's work on
variable elimination and functional CPTs, arXiv:2002.09320; treewidth and
exact-versus-approximate selection, arXiv:1506.08544; junction-tree and
recursive-conditioning methods; credal-network benchmarking, CREPO
arXiv:2105.04158) is about making inference tractable at scale. recon does
not need that: nine binary nodes are fully enumerable (512 states), which
is why the differential-verification harness can cross-check variable
elimination against a brute-force full-joint reference on every evidence
configuration. So this literature is recon's correctness backdrop, not a
source of methods to add; the paper cites it to explain why recon's
inference is verifiable by exhaustion rather than trusted by reputation.

One forward pointer worth recording: the credal-network framing (sets of
CPTs, imprecise probabilities) would give guaranteed posterior bounds
over the hand-elicitation uncertainty, in place of the current CAL8
plus-or-minus-20-percent sensitivity sweep. It is heavier than the
deliberately-small ethos wants, so it stays a noted alternative, not a
plan.

A closer neighbor in subject matter is cGraph (arXiv:2202.07883), which
runs belief propagation over passive-DNS domain graphs for threat
intelligence. It shares recon's passive-DNS substrate but targets a
different question (maliciousness scoring from labeled seeds) with a
different method (graph belief propagation, supervised seeds), and it
reports precision and recall against a labeled benign/malicious oracle,
which recon's setting does not have. It is the right adjacent system to
contrast against in the paper: same raw channel, different epistemics.

## How recon relates, by node

The threads above converge on a single picture: which guarantee a node
can carry is decided by whether an external reference label exists for
it, and that tracks the hideability spectrum in correlation.md.

| Node class | Example nodes | Reference label | Guarantees available |
|---|---|---|---|
| Provider-attested | m365_tenant, google_workspace_tenant | the provider's own identity endpoint (authoritative) | calibration (CAL3/CAL4) and, as a candidate, conformal coverage; plus the structural guarantees |
| Public-declaration | email_security_policy_enforcing | the DMARC record (its own definition of enforcing) | full-posterior calibration strong but DMARC-anchored (ECE 0.076; DMARC is also the input, so the bulk is a definitional agreement check), the clean DMARC-disjoint residual disconfirmed (ECE 0.373); conformal coverage measured (0.999 at a 0.90 target); plus the structural guarantees |
| Hideable | okta_idp, federated_identity, cdn_fronting, aws_hosting, email_gateway_present | none (absence may be genuine or adversarial) | structural guarantees only: suppression-monotonicity and interval widening (evidence-responsive, CAL13) |

The paper's claim is not that recon calibrates everything. It is that the
honest envelope for a passive classifier is this tiering: full
calibration where a self-defining reference exists, principle-compliant
evidence-responsiveness everywhere else, and a clear statement of the
boundary between them: a node is calibratable only where a reference an
operator cannot hide exists (the labelable-versus-hideable line), which is a
different cut than the suppression proposition's removal-versus-addition
boundary.

## Pointers

- The formal model and the suppression proposition: [correlation.md](correlation.md), sections 1.5 and 4.3.
- Where each claim sits on the evidence ledger: [statistical-assurance.md](statistical-assurance.md).
- The reference-calibration result: [../validation/reference-calibration.md](../validation/reference-calibration.md).
- The paper skeleton these notes feed: [paper-outline.md](paper-outline.md).
