# CAL14 design RFC: node-dependent missingness (MAR vs MNAR)

Status: proposal, for review. Nothing in this document is implemented yet.

This is a self-contained design note for the one substantive engine change left
in the recon Bayesian calibration track (Track C-cal, item CAL14). It is written
so an outside reviewer can critique the modeling choices without reading the
whole codebase. The open questions are collected at the end.

## 0. One-paragraph summary

recon's Bayesian layer treats "a binding did not fire" as no evidence (likelihood
ratio 1). That is correct for infrastructure an operator can hide (you cannot
conclude "no Microsoft 365" from the absence of an M365 token, because the token
may simply be unpublished). It is wrong for public-declaration signals such as
DMARC / SPF / MTA-STS email policy, where the record is meant to be public and
its absence is genuine, not hidden. Because the model cannot use "no enforcing
DMARC" as evidence against the "email policy is enforcing" claim, that node is
over-confident: a synthetic calibration measured it at conditional ECE about
0.31, with the 0.85 reliability bin realizing only 0.166. CAL14 makes absence
count as evidence for declarative nodes. The trap is that the strongest signals
(`dmarc_reject` and `dmarc_quarantine`) are mutually exclusive, so a naive
"penalize every non-fired binding" rule would wrongly penalize a `p=reject`
domain for "lacking" quarantine. The proposal handles this with per-evidence-group
absence conditioning and a small set of new, explicitly-justified parameters.

## 1. How inference works today (the relevant slice)

The network is nine binary nodes, exact inference by variable elimination. Each
node has a prior (or CPT) and a set of evidence bindings. A binding has two
likelihoods, `[P(observed | node present), P(observed | node absent)]`.

The observation factor for a node is built in `recon_tool/bayesian.py`,
`_factor_for_evidence` (around line 570). The current rule:

- Only bindings that fired contribute. The factor is the product of the fired
  bindings' likelihoods (after reducing each correlation group to its strongest
  fired member, so redundant readings of one fact are not double-counted).
- A binding that did not fire contributes nothing (likelihood ratio 1).
- If nothing fired, the function returns no factor and the node sits at its
  prior.

The rationale is documented in the code and in `docs/correlation.md` section
4.3: passive collection cannot distinguish "this node truly lacks the binding"
from "the binding is there but the operator hid it," so conditioning on absence
would over-claim absence on hardened targets. This is the right call for
hideable infrastructure (m365, okta, aws hosting, CDN).

## 2. The problem: public-declaration nodes

The node `email_security_policy_enforcing` (claim: "observable email-authentication
policy is enforcing") has four bindings, all public declarations:

| binding | `[present, absent]` | likelihood ratio |
|---|---|---|
| `dmarc_reject` | `[0.92, 0.04]` | 23.0 |
| `dmarc_quarantine` | `[0.55, 0.10]` | 5.5 |
| `mta_sts_enforce` | `[0.70, 0.05]` | 14.0 |
| `spf_strict` | `[0.70, 0.45]` | 1.6 |

These are not hideable. A DMARC record is published in DNS for the world to read;
the absence of `p=reject` *is* the absence of a reject policy, not a hidden one.
So treating absence as no-evidence has a concrete failure mode: the model can
raise the posterior when signals fire, but can never lower it when they are
genuinely absent. A domain that publishes only `spf_strict` (near-ubiquitous
hygiene) plus one weak signal can reach a high posterior the records do not
justify, and a domain that publishes nothing stays at the prior instead of being
disconfirmed.

The measured cost (2026-06 synthetic calibration): this node at conditional ECE
about 0.31, the 0.85 reliability bin realizing only 0.166. A v1.9.71 down-weight
of `spf_strict` from `[0.75, 0.30]` to `[0.70, 0.45]` took it to about 0.28 as a
partial mitigation. The real fix is missingness handling.

## 3. The trap: mutually-exclusive bindings

`dmarc_reject` and `dmarc_quarantine` are alternatives. A domain's DMARC policy
is exactly one of `p=reject`, `p=quarantine`, `p=none`, or absent. A `p=reject`
domain fires `dmarc_reject` and, by construction, does not fire `dmarc_quarantine`.

A naive "condition on the absence of every non-fired binding" rule would multiply
in a penalty for the missing `dmarc_quarantine` on a `p=reject` domain, which is
exactly backwards: it would penalize the domain with the strongest possible
signal. So absence conditioning cannot operate per independent binary feature. It
must respect the categorical structure: the DMARC policy level is one ordinal
observation, not two independent ones.

## 4. Proposal

### 4.1 Mark nodes by missingness type

Add an optional per-node field in `recon_tool/data/bayesian_network.yaml`:

```yaml
missingness: declarative   # absence is genuine evidence (MAR)
# default (field omitted): hideable  -> current LR=1 behavior (MNAR)
```

Only nodes whose claim is a public declaration get `declarative`. Best current
read: this is `email_security_policy_enforcing` and likely only that node. The
tenancy, IdP, hosting, and CDN nodes stay `hideable`. Keeping the scope to one
node bounds the blast radius (see open question 6).

### 4.2 Group the mutually-exclusive bindings

Put `dmarc_reject` and `dmarc_quarantine` in a correlation group (the mechanism
already exists for co-firing reduction):

```yaml
- signal: dmarc_reject
  likelihood: [0.92, 0.04]
  group: dmarc_policy
- signal: dmarc_quarantine
  likelihood: [0.55, 0.10]
  group: dmarc_policy
```

For a *fired* group the existing code already takes the strongest member, so a
`p=reject` domain uses `dmarc_reject` and ignores the structurally-absent
`dmarc_quarantine`. CAL14 adds: when the *entire* `dmarc_policy` group is absent
(neither member fired, i.e. `p=none` or no DMARC), the group contributes a single
absence factor.

### 4.3 Condition on absence for declarative units

For a `declarative` node, the observation factor multiplies in, for each
declarative evidence unit (a group, or an independent binding) that did not fire:

$$\text{like\_present} \mathrel{*}= L^{0}_{\text{present}}, \qquad
  \text{like\_absent} \mathrel{*}= L^{0}_{\text{absent}}$$

where `L0` is the unit's "produced no signal" likelihood pair. For an independent
binary binding the natural choice is the complement, `1 - likelihood`. For a
mutually-exclusive group it is a single modeled pair (not the product of
complements, because the members are exclusive). The `if nothing fired -> no
factor` early return is removed for declarative nodes, because all-absent is now
informative.

### 4.4 Proposed parameters (the numbers that need review)

Each is a claim about base rates, in the spirit of the CPT-change discipline
(`CONTRIBUTING.md`), not a corpus-fitted value.

| unit | "no signal" `[present, absent]` | reasoning |
|---|---|---|
| `dmarc_policy` group | `[0.05, 0.85]` | An enforcing domain almost always publishes `reject` or `quarantine`, so "no DMARC policy given enforcing" is rare (~0.05). A non-enforcing domain usually has `p=none` or no record, so "no DMARC policy given not enforcing" is common (~0.85). This is the strong disconfirmation. |
| `mta_sts_enforce` | `[0.30, 0.95]` (complement) OR keep LR=1 | MTA-STS adoption is low even among genuinely enforcing domains, so its absence may be weak evidence. The complement `[0.30, 0.95]` may over-penalize enforcing domains that simply have not deployed MTA-STS. See open question 2. |
| `spf_strict` | `[0.30, 0.55]` (complement) OR keep LR=1 | Already down-weighted as a positive signal. Whether its absence should disconfirm is unclear: a strict SPF is common, so its absence is mild evidence against enforcement. See open question 3. |

The `dmarc_policy` group is the load-bearing change. The `mta_sts` and
`spf_strict` absence terms are the uncertain ones.

## 5. Ripple effects (the reason this is not a one-line change)

1. **`n_eff` and the `sparse` flag.** The interval width is driven by `n_eff`,
   which today grows with the count of *fired* bindings. A declarative node that
   is confidently absent (all signals genuinely missing) would have zero fired
   bindings and therefore be flagged `sparse` with a wide interval, which would
   contradict its now-confident "absent" posterior. Absence evidence must count
   toward `n_eff` for declarative nodes, so a confidently-disconfirmed node is
   not mislabeled sparse.
2. **Stability criterion (a).** The current invariant is "every binding raises
   the posterior above the all-absent baseline." With absence conditioning the
   all-absent baseline for a declarative node sits *below* the prior, and toggling
   a binding present raises it. The criterion reframes to "toggling a binding to
   present raises the posterior relative to the declarative all-absent baseline."
3. **v2.0 gate.** Gate on the *maximum* per-node conditional ECE, not the mean,
   so a single overconfident node cannot hide behind well-behaved ones.

## 6. Validation plan

- `validation/synthetic_calibration.py` already samples observations from the
  likelihoods given the true state, including the no-signal outcome. After the
  change, re-run it and confirm `email_security_policy_enforcing` conditional ECE
  drops from about 0.31 toward the other nodes' range, with no regression
  elsewhere.
- `validation/likelihood_sensitivity.py` (CAL8) re-run to confirm the node stays
  robust to the new parameters.
- Full `pytest` suite green. Tests that assert specific email-policy posteriors
  will shift and must be updated deliberately (the shift is the point).
- A small hand-checked table of canonical cases: `p=reject` only, `p=none` +
  `spf_strict`, nothing published, full stack, to confirm the posteriors move in
  the intended direction.

## 7. Questions for a reviewer

1. Are the `dmarc_policy` group absence likelihoods `[0.05, 0.85]` reasonable as
   base-rate claims? What would you use?
2. Should `mta_sts_enforce` condition on absence at all, given low adoption even
   among enforcing domains? If yes, is the complement `[0.30, 0.95]` too strong?
3. Should `spf_strict` absence disconfirm, or stay LR=1 (absence of a common
   hygiene signal as only mild evidence)?
4. Is per-group absence conditioning the right abstraction, or is the cleaner
   model a single multi-valued DMARC node (`none` / `quarantine` / `reject`)
   rather than binary bindings? The latter is more correct but a larger change.
5. For `n_eff`: how should absence evidence count toward effective sample size so
   a confidently-absent declarative node is not flagged sparse, without
   overstating precision?
6. Is `email_security_policy_enforcing` the only declarative node, or are there
   others whose absence is genuinely public (and not hideable) that should also
   switch? Mis-classifying a hideable node as declarative would reintroduce the
   over-claim-on-hardened-targets failure the LR=1 rule exists to prevent.

## 8. Non-goals

- This does not change any hideable node. The asymmetric LR=1 absence rule stays
  the default and stays correct for hidden infrastructure.
- This is not a corpus-fitting exercise. The numbers are base-rate claims to be
  argued on their merits, then validated for calibration, not tuned to hit a
  target ECE.
