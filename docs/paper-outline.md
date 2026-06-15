# Paper skeleton (aspirational)

Status: a working outline, not a release gate and not on the critical path
of any version. It exists so the experiments are designed into the
validation harnesses rather than retrofitted, and so the framing settled
here survives between work sessions. The literature positioning lives in
[related-work.md](related-work.md); the forward plan and which pieces are
shipped live in the [roadmap](roadmap.md) research write-up section.

The prose expansion of this outline (full section drafts, with corpus-gated
empirical cells marked pending) lives in [paper-draft.md](paper-draft.md).

## Thesis

When a classifier's ground truth is structurally unobservable and the
subject can choose what to reveal, calibration-against-truth is the wrong
bar for the claims whose signals an operator can hide (of recon's nine
nodes, two carry a two-class external reference — the declarative policy
node and the provider-attested M365 tenancy node — one carries only a
one-sided attestation, the Google channel being behavioral with no
authoritative negative, and the remaining six have none; the engine applies
the MNAR absence rule to eight, the ninth being the declarative policy
node). The honest substitute is a layered argument:
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

## Introduction (draft)

Security teams increasingly need to know what an organization's external
footprint reveals before an attacker reads the same channel: which identity
provider a domain delegates to, whether its mail policy is enforced, what
fronts its origin. External attack-surface tools answer these questions
from public signals — DNS records, certificate-transparency logs,
unauthenticated provider endpoints — and they answer confidently. The
confidence is the problem. The ground truth behind these claims is not
observable from outside, and the subject of the measurement controls most
of the evidence: a hardened organization publishes less, a careless one
publishes more, and a tool that reads "no signal" as "no technology" is
confidently wrong about exactly the targets that matter most.

The standard remedy — calibrate the classifier against labeled truth — is
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
Bayesian network small enough to audit by hand and verified exhaustively
against its full joint; and absent evidence on hideable claims
contributes a likelihood ratio of one — absence of evidence is treated as
no evidence, never as evidence of absence — so the reported 80% credible
interval widens on hardened targets instead of collapsing to a false
verdict. In one sentence: this paper contributes a validation
architecture for inference whose ground truth is structurally
unobservable and partly adversarial, worked end-to-end in a real tool.

The architecture stands on one seam, stated early because it bounds
everything else: evidence *removal* versus evidence *addition*. We prove
a suppression-monotonicity property — holding other evidence fixed,
hiding any observed indicator can only move a claim toward its all-absent
baseline, never to a confident false positive — and we machine-check it
over every per-node evidence subset. The guarantee does not extend to
addition: a fully passive operator who publishes one truthful decoy
record can plant a confident false positive, and no passive tool can
distinguish a decoy from a real record. The honest contract is therefore
"robust to hiding, exposed to planting," and the boundary is not the
passive/active measurement line, because the cheap attack is itself
passive.

Validation then proceeds by tier, with the tier decided by whether an
external reference the operator cannot suppress exists. Where one does —
the DMARC record is its own definition of an enforcing mail policy;
Microsoft's identity endpoints attest tenancy in both directions — we
calibrate against it, including a held-out construction that masks the
label-defining evidence out of the predictor, and we add a
distribution-free conformal coverage statement with its exchangeability
boundary made explicit. Where no reference exists, we claim only the
structural properties, and we say so. We also measure what the honesty
costs: in a synthetic ablation against the model's own generative
process, the adversarial-missingness stance pays a quantified Brier
penalty on hideable claims under benign missingness (a hard detector
that reads absence wins pooled scores by roughly 0.05 to 0.10), while
the one claim whose absence is genuinely informative — the declarative
mail-policy node, where the model does condition on absence — wins
outright. The price of refusing to read absence is real, bounded, and
paid deliberately; we believe reporting it is more useful than hiding
it.

Concretely, this paper contributes:

- a deployed passive-inference system that preserves full provenance and
  pairs deterministic certificate-transparency correlation with a small,
  exhaustively-verified Bayesian network (Section 3);
- an adversarial missing-data treatment (the likelihood-ratio-one absence
  rule, grounded in m-graphs and partial identification) with a proved
  and machine-checked suppression-monotonicity guarantee, and an explicit
  statement of its limit at evidence addition (Section 4);
- a node-tiered validation architecture — reference calibration and
  conformal coverage where a self-defining label exists, structural
  principle-compliance everywhere else — with the boundary between tiers
  derived from who controls the evidence (Section 5);
- an evaluation that includes the cost of the design, not only its
  benefit: layer ablations quantifying the MNAR price under benign worlds
  and the fusion gain in the fired regime, alongside reference
  calibration on real public records and synthetic coverage under
  parameter imprecision (Section 6);
- a reproducible artifact: every empirical claim is checkable against
  public references anyone can re-query or fully synthetic harnesses,
  because the tool's own data-handling policy forbids publishing targets
  (Section 9).

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
   near-tautological consistency check, synthetic versus real). Include the
   measured price of honesty from the ablation
   (`validation/layer-ablation.md`): under benign missingness the hideable
   nodes pay a quantified ~0.05–0.10 Brier for the MNAR stance a hard
   detector does not pay, while the declarative node — where absence is
   honestly informative — wins outright; the trade the theory argues for,
   demonstrated with numbers. Pairs with the CAL7 observation that one
   strong binding nearly ties full fusion on simple roots: the machinery
   earns its keep exactly where the model has structure (DAG nodes,
   multi-signal declarative nodes), which is the right shape for a tool
   whose claims are the structured ones.
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
| Tenancy corroboration (provider endpoints) | the M365 tenancy posterior computed from the DNS channel alone, calibrated against Microsoft's own endpoint attestation (two-class label: tenant ID / namespace positive, documented not-found negative) — predictor and label disjoint by observation channel; GWS reported one-sided (recall on attested-federated) because the Google channel has no authoritative negative | `validation/tenancy_reference_calibration.py`; harness shipped, maintainer run pending |
| Conformal coverage on labelable nodes | a distribution-free finite-sample coverage statement beside the Bayesian interval, with the exchangeability boundary stated and demonstrated (a deliberately non-exchangeable split shows the guarantee failing where claimed to fail) | `validation/conformal_coverage.py`; harness shipped, maintainer run pending |
| Interval coverage (synthetic) | the 80% interval absorbs the elicitation imprecision under the CAL8 band | `validation/interval_coverage.py`; shipped |
| Likelihood sensitivity (CAL8) | the posteriors and agreement are stable under a plus-or-minus-20-percent likelihood perturbation | `validation/likelihood_sensitivity.py`; shipped |
| Information recovered (CAL10) | the per-domain entropy-reduction distribution across postures, as the operational reading of what the channel still leaks after hardening | per-node surfacing shipped (2.2 diagnostics: `entropy_reduction_nats` on every posterior); the posture-stratified distribution is a corpus-run readout; first full-corpus pass measured median ~0.85 nats |
| Layer ablations | what the graph layer and the Bayesian layer add over single-source slug matching | `validation/layer_ablation.py`; shipped and run (synthetic, reproducible): in the fired regime the posterior beats the deterministic baseline on every node and the DAG-only node is unreachable by matching; pooled, the hideable roots pay a quantified ~0.05–0.10 Brier MNAR price while the declarative node wins outright (the CAL14 asymmetry demonstrated); Louvain holds ARI 1.0 across a bridging-noise grid where connected components collapse to 0 — numbers in `validation/layer-ablation.md` |
| Posture stratification | aggregate behavior across hardening postures, as distributions not exemplars | `validation/posture_distributions.py` (entropy reduction bucketed by edge-proxied/direct × evidence tier; interval width vs n_eff for the CAL7 figure); harness shipped, maintainer run pending; framing in correlation.md 4.10–4.11 |
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

## Candidate framing: why the honesty matters operationally (Discussion)

A short motivation paragraph worth landing in the introduction or discussion,
drafted here as a candidate. recon is increasingly *consumed by LLM agents*
(it ships an MCP server), and that sharpens why evidence-responsive honesty is
the right design rather than a concession. An agent is a confident summarizer:
given a point estimate it will state a verdict, and given a wide interval it
will round it away unless the surface forbids it. The honest contract recon
already makes — a low or sparse posterior means "we cannot tell from the
public channel", not "not present" (the MNAR rule) — is exactly the property a
downstream agent cannot reconstruct for itself, because the missingness
structure lives in recon, not in the agent's context. So recon's value in an
agent stack is as a *grounding/verifier primitive*: it supplies the calibrated
"we cannot tell" that the consumer would otherwise hallucinate past. This is
the same argument the paper makes for human operators, but it bites harder for
automated consumers, and it motivates surfacing uncertainty at the tool level
(the `sparse_count` summary and the per-node interval lead the machine-readable
output, with explicit reading guidance in the server instructions), not only
in prose. The point is not that recon does AI; it is that recon is the honest
input an AI consumer needs and cannot fake. (Implementation: the MCP
"Reading the posteriors" instruction and `get_posteriors` `sparse_count`,
pinned by `tests/test_posterior_reading_guidance.py`.)

## Open items before this is submittable

Evidence not yet in hand, in roughly the order the roadmap sequences it:

- the maintainer-local runs of the shipped harnesses: the held-out residual
  and per-vertical stratification (`validation/reference_calibration.py`),
  the tenancy corroboration (`validation/tenancy_reference_calibration.py`,
  M365 two-class; GWS one-sided by the channel's nature), and the conformal
  coverage pass (`validation/conformal_coverage.py`) — every harness now
  exists, so this is collection, not construction (the layer ablations are
  already run and committed, being fully synthetic:
  `validation/layer-ablation.md`);
- the posture-stratified aggregates (`validation/posture_distributions.py`
  exists; the run is collection, not construction);
- the writing itself.

## Decisions still open

- Venue and timing. The substance is mostly assembled; the gating item is
  the remaining empirical runs, not the writing.
- Whether the principle-compliance suite gets a named, standing gate of its
  own or stays inside `validation/adversarial_properties.py`.

Resolved: the conformal coverage complement was adopted and shipped
(`validation/conformal_coverage.py`, labelable nodes only, with the
falsifiability split), so it is an evaluation row above, not a decision.
