# Statistical-assurance dossier

This document is one honest ledger of what recon's numbers are backed by. For
each statistical claim the tool emits, it names the highest tier of evidence that
supports it, and says plainly where that support stops. It is written for a
reader deciding how much weight to put on a recon posterior or interval, and for
an external write-up that must not overstate what the passive channel can show.

The discipline behind it is the calibration-legitimacy track (CAL1 to CAL14 in
[correlation.md](correlation.md)): name what each number tests, never let a
self-consistency check read as ground-truth calibration, and reserve the firmest
words for the best-supported evidence. This dossier collects that discipline into
a single map. The mechanism-to-test mapping is in
[assurance-case.md](assurance-case.md); the interval coverage detail is in
[interval-coverage.md](../validation/interval-coverage.md); the publication
constraint that shapes how any of this can be reported is in
[data-handling-policy.md](data-handling-policy.md).

## The four tiers of evidence, on two axes

Every recon claim sits at one of four tiers, but the tiers are not one monotone
scale of trust. Reading them as "a higher tier means the number is more likely
right" is the specific error this dossier exists to prevent. They answer two
different questions:

- **Provenance and internal soundness:** is the observation a real,
  re-queryable fact, and is the inference computed faithfully from the model?
  Tier 1 (Observed) and tier 3 (Evidence-responsive) live here, with tier 2
  (Consistency) a near-tautological special case.
- **External validation:** is the inferred number right against a truth recon
  did not itself produce? Only tier 4 (Empirical coverage) lives here.

The consequence a careful reader must hold onto: a tier-3 node has a
faithfully-computed, honestly-widening interval, but with respect to whether its
point estimate is *correct* it is just as unvalidated as a tier-1 raw fact. Tiers
2 and 3 are properties that hold by construction, and a property true by
construction carries no information about whether the model tracks reality. A
claim is reported at the highest tier its evidence reaches, and the gap above it
is stated, not hidden.

1. **Observed.** A direct, re-queryable fact: a DNS record, a
   certificate-transparency SAN, a fired fingerprint slug, an identity-endpoint
   response. Anyone can re-run the underlying query and see the same observation.
   This is the evidence layer, and it is the highest tier because it asserts
   nothing beyond what the public channel literally returned.

2. **Consistency.** Agreement between the deterministic pipeline and the Bayesian
   layer: a high, non-sparse posterior is backed by a fired deterministic
   detection. CAL1 shows this agreement is near-tautological under the
   virtual-evidence construction (a high non-sparse posterior requires a fired
   positive binding, which is itself a deterministic detection), so it tests the
   inference plumbing and the binding wiring, not the CPT or likelihood values.
   It is reported as a real but weak regression guard, never as calibration. The
   full-corpus result to date is that every high-confidence posterior is backed
   by a deterministic detection, which is near-tautological by construction.

3. **Evidence-responsive.** The credible interval widens on sparse or hardened
   evidence and narrows as the channel constrains the claim. CAL13 reserves this
   term: it is a monotonicity property of the interval, shown two ways. The
   differential-verification harness proves the interval is computed faithfully
   from the model, exhaustively over the enumerable joint (nine binary nodes), and
   the perturbation-coverage gate (v2.1.15) shows the 80% interval contains the
   correct-world conditional under a plus-or-minus 20% likelihood-imprecision band
   on every node, measured at or above 0.999 and gated at the nominal 0.80. This
   is model-internal coverage against parameter misspecification, not ground-truth
   calibration.

4. **Empirical coverage.** Frequentist coverage against an independent
   ground-truth label: over many domains whose true state is known, does the 80%
   interval contain the truth about 80% of the time? This is the only tier that
   can falsify the CPT and likelihood values themselves (CAL3). For most of
   recon's claims this tier is structurally unavailable, and the dossier says so
   rather than implying it is met.

The honest shape of recon's assurance is: provenance and internal soundness
established at tiers 1 to 3, external validation (tier 4) reached in part on the
email-policy node (full-posterior calibration strong but DMARC-anchored, the clean
residual disconfirmed) and reached as channel-split corroboration on the M365
tenancy node, and absent by the nature of the setting on the hideable nodes. Tiers 1 to 3 are not a
substitute for tier 4; they are a different axis, and on the hideable nodes the
point estimate stays unvalidated against truth.

## Why tier 4 is reachable for some nodes and not others

The dividing line is not "is the claim important" but "does an external attestor
exist that the operator cannot hide." recon's evidence sits on a spectrum from
operator-controlled to provider-attested ([correlation.md](correlation.md)
section 4.3, the operator/provider hideability spectrum), and tier 4 is reachable
exactly where the top of that spectrum reaches:

- **An external attestor exists (tier 4 reachable only when the reference is
  independent enough for the claim).** Two kinds. A *public declaration*: the
  email policy's DMARC record is its own ground truth (an enforcing `p=reject` is
  a fact anyone can read, not an inference; CAL14 made the node `declarative`).
  And *provider attestation*: whether a domain is a Microsoft 365 tenant is
  answered by Microsoft's own unauthenticated identity endpoints, keyed on the
  domain, in both directions (a resolved tenant ID or Managed/Federated namespace
  attests presence; the documented tenant-not-found response attests absence).
  That provider channel is useful, but it still shares tenant provisioning with
  the DNS footprints used as the predictor, so
  [m365-tenancy-decision.md](m365-tenancy-decision.md) keeps the result named
  corroboration rather than independent calibration. For the
  policy node the calibration has run at full corpus (n=2,906 with a published
  DMARC policy, 2026-06 refresh): the full posterior is strongly calibrated
  against the DMARC record (fixed-bin ECE 0.0761, equal-mass ECE 0.0651, stable
  across all 22 verticals, the miss in the conservative under-confident
  direction), but the held-out DMARC-disjoint residual is weak and poorly
  calibrated (fixed-bin ECE 0.3747, equal-mass ECE 0.3263). The honest reading
  is a strong but DMARC-anchored full-posterior calibration plus an agreement
  check for the DMARC-driven bulk; the strict-SPF + MTA-STS residual is not a
  clean tier-4 result, the disjoint construction disconfirms it
  (`validation/reference-calibration.md`,
  `validation/2026-06-28-full-corpus-calibration-refresh.md`). For
  `m365_tenant` the channel-split corroboration run also landed (n=3,296, the
  DNS-driven posterior against the provider endpoint attestation): fixed-bin ECE
  0.0471, equal-mass ECE 0.0440, agreement 0.889, useful corroboration rather
  than clean independent calibration
  (`validation/tenancy_reference_calibration.py`). The
  Google channel is one-sided (it attests only observed federated routing,
  never managed tenancy, and has no authoritative negative; correlation.md
  4.3), so `google_workspace_tenant` admits a recall check on attested
  positives, not a calibration, and stays at tier 3.

- **No external attestor (tier 4 unavailable by the nature of the setting).**
  `cdn_fronting`, `aws_hosting`, `okta_idp`, `email_gateway_present`, and the
  non-provider parts of `federated_identity` rest on operator-controlled DNS and
  CT. A hardened operator can strip those indicators, so their absence is
  adversarially missing and there is no label set to compute frequentist coverage
  against. These claims are honest at tiers 1 to 3, tier 4 is not available, and
  the interval's widening is the model declining to claim what it cannot see. The
  suppression proposition (correlation.md 4.3) is what makes that honest rather
  than merely cautious in the hiding direction: hiding can only push these toward
  "we cannot tell," never to a confident false answer. It does not protect the
  other direction: a forged administrative token fires these nodes at full
  strength (correlation.md 4.11, Pattern I) and the ungrouped dense nodes
  over-count co-firing evidence (correlation.md 4.3), so a confident false
  positive can be planted or over-counted here even though it cannot be hidden
  into existence.

## The ledger

| Claim / node | Highest tier today | What backs it | Where it stops |
|---|---|---|---|
| Fired slugs and signals (the evidence layer) | Observed | The underlying DNS / CT / identity query, re-runnable | Heuristic catalogue; a rule can mis-fire, so each carries a vendor-doc reference |
| `m365_tenant` | Evidence-responsive | Tiers 1 to 3; two-class provider attestation exists (tenant ID / namespace, and the documented not-found response), and the channel-split corroboration harness ships (`validation/tenancy_reference_calibration.py`) | The channel-split refresh landed 2026-06-28 (fixed-bin ECE 0.0471, equal-mass ECE 0.0440, agreement 0.889, n=3,296), a reached corroboration result against provider attestation |
| `google_workspace_tenant` | Evidence-responsive | Tiers 1 to 3; the provider channel attests only observed federated routing (one-sided, no authoritative negative, no managed detection) | Tier 4 unreachable on this channel: a one-sided recall check on attested positives is reported, never a calibration |
| `okta_idp`, `federated_identity` | Evidence-responsive | Tiers 1 to 3 | Tier 4 unavailable: federation indicators are hideable |
| `email_gateway_present`, `cdn_fronting`, `aws_hosting` | Evidence-responsive | Tiers 1 to 3 | Tier 4 unavailable: all hideable infrastructure |
| `email_security_modern_provider` | Consistency | Pure propagation from parents (no own evidence), so it inherits its parents' tier | Not an independent measurement |
| `email_security_policy_enforcing` | Full-posterior calibration (strong, DMARC-anchored); the clean residual disconfirmed | Calibrated against the DMARC record on real domains (full posterior fixed-bin ECE 0.0761, equal-mass ECE 0.0651, n=2,906, stable across 22 verticals, miss conservative). DMARC is also the node's dominant input, so the full-posterior agreement is largely definitional; the full-corpus held-out run shows the DMARC-disjoint residual is weak and poorly calibrated (fixed-bin ECE 0.3747, equal-mass ECE 0.3263), so it is not a clean tier-4 result. See `validation/reference-calibration.md` and `validation/2026-06-28-full-corpus-calibration-refresh.md` | The result is for a domain *declaring* an enforcing policy, not enforcing it, and the declaration is forgeable at zero cost (correlation.md 4.11, Pattern I) |
| The 80% credible interval (all nodes) | Evidence-responsive | Differential verification plus perturbation coverage (v2.1.15) | Frequentist ground-truth coverage (tier 4) only where a public reference exists |
| Cohort-summary prevalences (PV1) | Observed plus evidence-responsive | Observability-adjusted rates over the caller's set, with denominators | Ecological-fallacy discipline; never a population claim |

## What each tier licenses, and what it does not

- **Observed** licenses "the public channel returned this." It does not license
  "the organization runs this," because a record can be stale or a slug can
  mis-fire; that is why every detection carries a re-verification reference.
- **Consistency** licenses "the two layers agree." It does not license "the CPT
  values are right," because the agreement is near-tautological (CAL1). Reading
  the consistency number as calibration is the specific error this dossier exists
  to prevent.
- **Evidence-responsive** licenses "the interval honestly tracks how much the
  channel constrains the claim, and absorbs the acknowledged likelihood
  imprecision." It governs the interval's *width* and is silent about its
  *location*: a wrong CPT produces a tight interval around the wrong mean, and
  evidence-responsiveness does not catch that. It does not license "the interval
  has 80% frequentist coverage against ground truth," which is tier 4.
- **Empirical coverage** licenses the frequentist statement. It is claimed only
  where measured, and today it is the open frontier.

## The frontier

The CAL3 / CAL4 reference calibration has run at full corpus on the nodes where it
is possible: `email_security_policy_enforcing` against the DMARC record and
`m365_tenant` against the provider endpoints (aggregates only, no apexes
committed, per [data-handling-policy.md](data-handling-policy.md); detail in
`validation/reference-calibration.md` and
`validation/2026-06-28-full-corpus-calibration-refresh.md`). For the policy node
the full posterior is strongly calibrated (fixed-bin ECE 0.0761, equal-mass ECE
0.0651, n=2,906, stable across 22 verticals), but because DMARC is also its
dominant input that agreement is largely definitional; the held-out
DMARC-disjoint residual, the construction that would make the residual a clean
tier-4 result, instead runs weak and poorly calibrated (fixed-bin ECE 0.3747,
equal-mass ECE 0.3263), so it disconfirms the clean claim rather than
establishing it. What remains is bounded and honest:

- The `m365_tenant` claim is corroborated against Microsoft's own identity
  endpoints with both label classes; the channel-split refresh landed
  (fixed-bin ECE 0.0471, equal-mass ECE 0.0440, agreement 0.889, n=3,296 over
  the DNS-driven posterior against the endpoint attestation), a reached result.
  `google_workspace_tenant` gets only the one-sided recall check the Google
  channel supports (n=11 attested positives, recall 0.3636); a calibration there
  would need a two-class attestor recon's passive channel does not have.
- The hideable-infrastructure nodes have no external reference by the nature of
  the adversarial-missingness setting, so they stay at tier 3 by design, not by
  omission. The dossier reports them that way rather than implying coverage it
  cannot have.

This is the honest position: recon's numbers have sound provenance and a faithful,
verified inference engine behind them, the email-policy node has a strong
full-posterior calibration against the DMARC record (DMARC-anchored, the clean
residual disconfirmed) and the M365 tenancy node a strong channel-split
corroboration against provider attestation, and recon says where that support ends
rather than implying more. The point estimates on the hideable nodes remain
unvalidated against truth, by the nature of the passive setting.
