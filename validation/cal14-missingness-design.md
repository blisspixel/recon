# CAL14 historical design RFC: node-dependent missingness

Status: implemented. This RFC was authored on 2026-06-04 at commit
[`0605e228`](https://github.com/blisspixel/recon/commit/0605e22884a540aa6fcc8a6cea226be0433e1df3)
and implemented on 2026-06-05 at commit
[`957e1f6d`](https://github.com/blisspixel/recon/commit/957e1f6d109faf04ceb80c7eabe90105c5c4ddca).
The current runtime and `src/recon_tool/data/bayesian_network.yaml` are the
normative sources. This record preserves the pre-implementation diagnosis,
historical measurements, proposed parameters, and review questions that led to
the shipped design.

## 0. One-paragraph summary

Before CAL14, recon's Bayesian layer treated "a binding did not fire" as no
evidence (likelihood ratio 1). That remains the policy for infrastructure an
operator can hide. You cannot conclude "no Microsoft 365" from the absence of
an M365 token, because the token
may simply be unpublished). The RFC identified that behavior as wrong for
successfully observed public declarations such as
DMARC / SPF / MTA-STS email policy, where the record is meant to be public and
its defined absence is observed, not hidden. Because the old model could not use
"no enforcing DMARC" as evidence against the "email policy is enforcing" claim,
that node was overconfident in the historical synthetic experiment: the
experiment measured conditional ECE about 0.31, with the 0.85 reliability bin
realizing only 0.166. CAL14 makes absence count as evidence for declarative
nodes. The trap is that the strongest signals
(`dmarc_reject` and `dmarc_quarantine`) are mutually exclusive, so a naive
"penalize every non-fired binding" rule would wrongly penalize a `p=reject`
domain for "lacking" quarantine. The shipped implementation handles this with
per-evidence-group absence conditioning and a small set of explicitly justified
parameters. This is a specified observation model, not a claim that the data are
missing at random.

## 1. How inference worked before CAL14

The network is nine binary nodes, exact inference by variable elimination. Each
node has a prior (or CPT) and a set of evidence bindings. A binding has two
likelihoods, `[P(observed | node present), P(observed | node absent)]`.

At the RFC commit, the observation factor was built by `_factor_for_evidence` in
the then-current `recon_tool/bayesian.py`. The pre-CAL14 rule was:

- Only bindings that fired contribute. The factor is the product of the fired
  bindings' likelihoods (after reducing each correlation group to its strongest
  fired member, so redundant readings of one fact are not double-counted).
- A binding that did not fire contributes nothing (likelihood ratio 1).
- If nothing fired, the function returned no node-local observation factor. The
  node's prior or CPT and the rest of the network still participated.

The rationale is now formalized in `docs/correlation.md` section 3.3: public
metadata collection cannot distinguish "this node truly lacks the binding"
from "the binding is there but the operator hid it," so conditioning on absence
would over-claim absence for domains that suppress or omit indicators. This is
the documented conservative policy for hideable infrastructure (M365, Okta, AWS
hosting, CDN).

## 2. The problem: public-declaration nodes

The node `email_security_policy_enforcing` (claim: "observable email-authentication
policy is enforcing") has four bindings, all public declarations:

| binding | then-current `[present, absent]` | likelihood ratio |
|---|---|---|
| `dmarc_reject` | `[0.92, 0.04]` | 23.0 |
| `dmarc_quarantine` | `[0.55, 0.10]` | 5.5 |
| `mta_sts_enforce` | `[0.70, 0.05]` | 14.0 |
| `spf_strict` | `[0.70, 0.45]` | 1.6 |

These are public declarations. After successful collection, the absence of
`p=reject` is an observed absence of a reject policy, not an unpublished positive
indicator. Source failure remains structurally unobserved. Treating every
non-fire as no evidence had a concrete failure mode: the old model could raise
the posterior when signals fired but could not lower it when a defined public
declaration was successfully observed as absent. A domain that published only
`spf_strict` plus one weak signal could reach a high posterior the records did
not justify, and an all-absent observed pattern stayed at the prior instead of
being disconfirmed.

The historical 2026-06 synthetic run reported conditional ECE about 0.31, with
the 0.85 reliability bin realizing only 0.166. A v1.9.71 down-weight of
`spf_strict` from `[0.75, 0.30]` to `[0.70, 0.45]` took it to about 0.28 as a
partial mitigation. The RFC concluded that missingness handling was the
structural fix.

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

## 4. Accepted design and shipped implementation

### 4.1 Mark nodes by missingness type

The implementation added an optional per-node field in
`src/recon_tool/data/bayesian_network.yaml`:

```yaml
missingness: declarative   # successfully observed absence is modeled
# default (field omitted): hideable -> non-fire contributes LR=1
```

Only nodes whose claim is a public declaration get `declarative`. The shipped
network applies it only to `email_security_policy_enforcing`. The tenancy, IdP,
hosting, and CDN nodes stay `hideable`. Source failure is represented separately:
an unavailable observation unit is masked and contributes no positive or absence
factor.

### 4.2 Group the mutually-exclusive bindings

The implementation puts `dmarc_reject` and `dmarc_quarantine` in a correlation
group, using the mechanism that already existed for co-firing reduction:

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
`dmarc_quarantine`. CAL14 added one grouped absence factor when the *entire*
`dmarc_policy` group is absent. When neither member fires, as with `p=none` or no
DMARC record after successful observation, the group contributes that single
absence factor.

### 4.3 Condition on absence for declarative units

For a `declarative` node, the observation factor multiplies in, for each
declarative evidence unit (a group, or an independent binding) that did not fire:

$$\text{like\_present} \mathrel{*}= L^{0}_{\text{present}}, \qquad
  \text{like\_absent} \mathrel{*}= L^{0}_{\text{absent}}$$

where `L0` is the unit's "produced no signal" likelihood pair. For an independent
binary binding, the implementation uses the complement, `1 - likelihood`. For a
mutually exclusive group it uses one modeled pair, not the product of
complements, because the members are alternatives. The `if nothing fired -> no
factor` early return was removed for declarative nodes because an observed
all-absent pattern is informative.

### 4.4 Historical proposed parameters and final values

The following table preserves the RFC proposal. These are not all current
binding likelihoods.

| unit | "no signal" `[present, absent]` | reasoning |
|---|---|---|
| `dmarc_policy` group | `[0.05, 0.85]` | An enforcing domain almost always publishes `reject` or `quarantine`, so "no DMARC policy given enforcing" is rare (~0.05). A non-enforcing domain usually has `p=none` or no record, so "no DMARC policy given not enforcing" is common (~0.85). This is the strong disconfirmation. |
| `mta_sts_enforce` | `[0.30, 0.95]` (complement) OR keep LR=1 | MTA-STS adoption is low even among genuinely enforcing domains, so its absence may be weak evidence. The complement `[0.30, 0.95]` may over-penalize enforcing domains that simply have not deployed MTA-STS. See open question 2. |
| `spf_strict` | `[0.30, 0.55]` (complement) OR keep LR=1 | Already down-weighted as a positive signal. Whether its absence should disconfirm is unclear: a strict SPF is common, so its absence is mild evidence against enforcement. See open question 3. |

The accepted group-absence pair remains `[0.05, 0.85]`. Subsequent CAL12
regrounding changed the positive binding likelihoods to `[0.06, 0.01]` for
`mta_sts_enforce` and `[0.53, 0.27]` for `spf_strict`. Their current independent
absence pairs are the complements `[0.94, 0.99]` and `[0.47, 0.73]`,
respectively. See the YAML comments for parameter provenance and
`docs/bayesian-cpt-discipline.md` for the current discipline.

## 5. Anticipated ripple effects and their resolution

1. **`n_eff` and the `sparse` flag.** The implementation counts each informative
   declarative evidence unit, whether fired or observed absent, toward `n_eff`.
   Correlation groups count once. Structurally unobserved units do not count.
2. **Stability criterion (a).** The former invariant was "every binding raises
   the posterior above the all-absent baseline." With absence conditioning, the
   all-absent baseline for a declarative node sits *below* the prior, and toggling
   a binding present raises it. The criterion reframes to "toggling a binding to
   present raises the posterior relative to the declarative all-absent baseline."
3. **Calibration review.** Historical calibration work examined maximum per-node
   conditional ECE so a single overconfident node could not hide behind a mean.
   Those synthetic results remain model-relative, not real-world calibration.

## 6. Historical validation plan

The RFC called for synthetic calibration, likelihood sensitivity, the full test
suite, and hand-checked canonical cases. CAL14 was subsequently implemented and
covered by runtime tests. Historical CAL8 numbers predate CAL14 and must not be
read as validation of the current model. The current sensitivity harness is a
descriptive binding-likelihood perturbation experiment with its own documented
observation-model limitations, not a pass/fail calibration gate.

## 7. Historical review questions and shipped resolutions

1. The `dmarc_policy` grouped absence pair was accepted as `[0.05, 0.85]`.
2. MTA-STS absence is modeled by the complement of the later regrounded binding
   likelihood, producing a near-neutral absence ratio.
3. Strict-SPF absence is modeled by the complement of its later regrounded
   binding likelihood and mildly disconfirms enforcement.
4. The implementation retained binary bindings with one grouped DMARC absence
   factor instead of adding a multi-valued latent node.
5. Informative declarative units count toward `n_eff` once per unit. This remains
   a display-mass heuristic, not an effective sample size estimate.
6. `email_security_policy_enforcing` remains the only declarative node in the
   shipped network.

## 8. Non-goals

- CAL14 did not change any hideable node. The asymmetric LR=1 non-fire rule
  remains the documented conservative default for hideable infrastructure.
- The RFC was not a corpus-fitting exercise. Later human-reviewed parameter
  regrounding used development-corpus aggregates, so current parameters are not
  independent validation results and must not be presented as such.
