# v2.11 M365 arm-identifiability audit

- **Date:** 2026-08-13
- **Disposition:** Stop before collection
- **Target-network requests:** 0
- **Private evaluation rows read:** 0

## Decision

The frozen Microsoft 365 four-arm evaluation cannot identify a benefit from
the current Bayesian fusion path. The planned 2026-08-17 through 2026-08-23
collection window is cancelled before target contact. The committed private
frame and key remain unchanged as historical preregistration materials, but
they must not be used for this voided design.

This is a structural result from the shipped code paths, not an empirical
outcome and not a population claim. It prevents an unnecessary multi-thousand
domain collection whose primary promotion condition cannot succeed.

## Reproduction

From a clean checkout with the locked development environment:

```bash
uv sync --all-groups --locked
uv run python -m validation.quality_arm_identifiability
uv run pytest tests/test_quality_arm_identifiability.py -q
```

The script enumerates all 64 presence and absence combinations over the six
DNS evidence roles capable of carrying a deterministic `microsoft365`
fingerprint: TXT, SPF, MX, DKIM, CNAME, and SRV. It calls the shipped slug
scorer, role-observation adapter, Bayesian network, and panel decision
threshold. It performs no network I/O and reads no corpus.

## Findings

| Property | Exhaustive result |
|---|---:|
| Abstract DNS evidence states | 64 |
| A1 decisions equal A0 decisions | 64 of 64 |
| A2 decisions equal A3 decisions | 64 of 64 |
| States where A3 supports and A0 abstains | 0 |
| States where A0 supports and A3 abstains | 3 |
| A3 posterior values | 0.3000, 0.9314 |
| Direct bindings on `m365_tenant` | 1 |

The direct `m365_tenant` node has one binding,
`signal:m365_tenant_observed`. The shipped adapter produces that signal from
role-bearing MX, DKIM, CNAME, or SRV evidence. A deterministic M365 rule has
already fired in every such state, so A3 support implies A0 support. TXT-only,
SPF-only, and TXT-plus-SPF states explain the three baseline-only cases because
the role adapter deliberately excludes verification and policy evidence from
the tenancy node.

A1 has no independent binary emission API. Reading the presence of its emitted
`microsoft365` score as support makes it identical to A0. A2 has only the one
positive direct binding to choose, making it identical to A3. The panel's
0.5 model-support threshold maps the A3 prior state to unresolved and the fired
state to supported.

Therefore the positive-stratum candidate-only discordance count is fixed at
`b_positive = 0` for every possible DNS snapshot under the frozen channel
mapping. The preregistered benefit lower bound is

```text
CP_lower(0, n_positive) - CP_upper(c_positive, n_positive) <= 0
```

for every positive sample size and every nonnegative baseline-only count. At
the frozen minimum `n_positive = 155`, even `c_positive = 0` gives
`-0.023518`, not a value above zero. The promotion intersection cannot pass.

## Preregistration consequence

The audit also found that the preregistration's phrase "shipped default
emission behavior" was not operationally complete. A1 returns evidence-strength
scores, A2 was only described as a reduction rule, and A3 supplies model
support alongside the deterministic product claim rather than controlling
whether that claim is emitted. Choosing new binary adapters now would define a
new experiment, not complete the frozen one.

No reference label, DNS result, arm output, or per-domain outcome was collected
or inspected. The dated amendment therefore records a design defect before
unblinding. The honest disposition is to stop, retain the aggregate structural
result, and apply the preregistered non-promotion outcome without inventing a
replacement threshold.

## Next operation

The next release operation is the already-planned quality-decision application:
classify fusion as an explicit advanced diagnostic while preserving stable JSON
and MCP compatibility. The subsequent SemVer review found that flipping the
stable v2 CLI default in a minor release would violate the stability policy.
ADR-0013 therefore preserves implicit v2 behavior with an interactive
explicit-choice notice and assigns the default-off change to v3. A future
fusion candidate may earn a new real-domain evaluation only after it has at
least two non-collapsed evidence units, a binary operator action connected to
shipped behavior, an executable dominance and identifiability preflight,
disjoint labels, and a newly frozen design.
