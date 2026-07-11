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

recon is a passive evidence-correlation system with a probabilistic diagnostic
layer. For most high-level claims, external ground truth is not observable. A passive external observer cannot see
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
And the conformal coverage guarantee holds only under exchangeability, which is
not established when transferring from recon's selected development corpus to
adversarially hardened targets.

What recon can take, on the nodes where a label exists: split conformal
can support a separate risk or prediction-set statement only where the scorer
is fixed independently of the calibration sample and the calibration and future
points are exchangeable. recon's stricter level-4 interpretation rule also
requires predictor inputs not to consume the label-defining field.
DMARC is not a clean reference for the full email-policy predictor
because it is also the dominant input. The M365 provider endpoint is useful
channel-split corroboration, not fully independent calibration, because the DNS
predictor and provider label share tenant provisioning as a common cause
([m365-tenancy-decision.md](m365-tenancy-decision.md)). The Google channel is
one-sided: federated redirects only, no managed detection, and no authoritative
negative. It supports a recall check on observed positives, not calibration.
`validation/conformal_coverage.py` implements and unit-tests the split-conformal
construction. The recorded private-corpus run reused parameter-development data,
so it is a dependent empirical re-split diagnostic, not an application of the
future-point coverage theorem. It does not turn recon's model-relative
uncertainty band into a credible or confidence interval.

## Principle-based calibration of epistemic uncertainty (arXiv:2407.12211)

This paper argues that when calibration against ground truth is hard, an
uncertainty measure should instead be held to checkable structural
principles, and it proposes two (uncertainty falls as data grows,
uncertainty rises as model expressiveness grows) and tests compliance
rather than coverage.

recon has related construction properties, but their scope is narrower. Under
fixed local positive-factor assumptions, deleting evidence cannot raise local
presence odds. For a fixed posterior, lowering `n_eff` widens the current band.
Neither result establishes movement toward 0.5, general evidence-monotone width,
global DAG robustness, or empirical calibration. The current harnesses are
useful standing regression gates when reported with those limits. The proposed
claim-robustness envelope tests evidence removal and planting directly instead
of extending the narrow propositions by analogy.

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
recon's answer is the opposite discipline: use training-disjoint,
predictor-input-disjoint references where they exist, call overlapping
self-declarations agreement rather than independent calibration, and state
plainly when a hideable node has no suitable reference. The contrast is worth stating because surrogate-label circularity is
tempting and easy to overstate.

## Bayesian-network inference lineage

recon's inference core is exact variable elimination on a deliberately
small, fixed nine-node network. The relevant lineage (Darwiche's work on
variable elimination and functional CPTs, arXiv:2002.09320; treewidth and
exact-versus-approximate selection, arXiv:1506.08544; junction-tree and
recursive-conditioning methods; credal-network benchmarking, CREPO
arXiv:2105.04158) is about making inference tractable at scale. recon does
not need that: each nine-binary-node query can enumerate its 512 latent states.
The differential-verification harness cross-checks variable elimination against
that brute-force latent-joint reference over a structured none/one/all evidence
sweep plus exhaustive local subsets for three factor-heavy nodes. It does not
enumerate the global evidence power set. This literature is recon's correctness
backdrop, not a source of methods to add.

One forward pointer worth recording: a coherent credal-network framing could
give model-relative posterior bounds over admitted CPT sets, in place of the
current CAL8 plus-or-minus-20-percent sensitivity sweep. It would not identify
the real-world claim without a defensible joint evidence and observation model.
It stays a noted alternative, not a plan.

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
| Provider-attested | m365_tenant | Microsoft's identity endpoint | Channel-split corroboration plus internal soundness; not fully independent calibration |
| One-sided provider channel | google_workspace_tenant | observed federated redirect only | Positive-class recall check plus internal soundness; no two-class calibration |
| Public-declaration | email_security_policy_enforcing | DMARC, also the dominant predictor input | Low-ECE overlapping agreement; the DMARC-disjoint residual is poorly calibrated, so no clean calibration claim |
| Hideable | okta_idp, federated_identity, cdn_fronting, aws_hosting, email_gateway_present | no training-disjoint and predictor-input-disjoint two-class reference | Internal computation and selected construction properties only |

The defensible claim is narrower: observed facts, faithful model computation,
overlapping corroboration, and independent validation are distinct levels.
Self-defining references can test agreement but do not independently validate
the predictor that consumes them. Hideable claims remain model-relative until a
training-disjoint, predictor-input-disjoint reference and evaluation population
exist.

## Pointers

- The formal model, removal proposition, and robustness research program:
  [correlation.md](correlation.md), sections 3.4 and 5.
- Where each claim sits on the evidence ledger: [statistical-assurance.md](statistical-assurance.md).
- The reference-calibration result: [../validation/reference-calibration.md](../validation/reference-calibration.md).
- The paper skeleton these notes feed: [paper-outline.md](paper-outline.md).
