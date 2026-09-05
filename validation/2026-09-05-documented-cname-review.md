# Documented CNAME candidate review

Date: 2026-09-05 UTC

## Scope and frozen regression budget

This follow-up to the [claim review](2026-09-05-catalog-claim-review.md) uses
provider documentation and network-free synthetic detector tests. Before
catalog edits, the round froze baseline commit
`f4466d549a46d1e49c8fa3c06212d5494e712646` and a zero-regression budget for
existing rule selection, lookalike matches, queried owner names, and apex
service or email-control promotion. Only the two exact target additions below
were permitted. Existing edge attribution must remain available alongside an
application match. Empty, degraded and wildcard-echo observations must not
acquire service claims.

This is a synthetic detector-contract budget, not measured precision. No live
domain collection, customer labels, held-out accuracy estimate, or population
inference was performed. Only generic provider patterns, public references and
reserved synthetic fixtures enter this artifact. Historical corpus artifacts
remain unchanged.

## Disposition and claim boundary

| Candidate | Exact rule and independent basis | Supported observation and limits |
|---|---|---|
| Retool | `cname_target`, `^custom-domain\.retool\.com\.?$`; the [Retool custom-domain guide](https://docs.retool.com/org-users/guides/cloud/custom-domains) names one fixed shared endpoint. | A related host routes to the documented endpoint. This does not establish completed setup, a running application, accessible data, plan or account ownership. Self-hosted deployments and apex A records need not expose it. |
| Postmark | `cname_target`, `^pm\.mtasv\.net\.?$`; the [custom return-path guide](https://www.postmarkapp.com/support/article/910-how-do-i-add-a-custom-return-path) and [Domains API documentation](https://postmarkapp.com/developer/api/domains-api) identify this CNAME value. | A related host routes to the custom return-path endpoint. This does not establish inbound mailbox hosting, delivered messages, message-level SPF alignment or active account use. |

Both use the existing application tier and require exact hostname matches, not
parent-zone suffixes. Postmark extends the existing slug; Retool adds one
medium-confidence fingerprint. Confidence is a rule tier, not an accuracy
estimate. Review dates record these documentation checks only.

## Separately scoped legacy Postmark retirement

After the two-addition contract was tested, an independent follow-up reviewed
the older `cname_target` suffixes `postmarkapp.com` and `pstmrk.com` and the SPF
suffix `postmarkapp.com`. This is a separately declared correction, not a change
hidden inside the earlier frozen budget. No current first-party basis was
found for those customer CNAME or SPF include grammars. They are retired pending
support, rather than merely given softer descriptions that the resulting
application attribution would not carry. This does not disprove historical
ownership or use. The current
[link-tracking guide](https://postmarkapp.com/developer/user-guide/tracking-links)
names `click.pstmrk.it`, not `pstmrk.com`; this is not evidence for silently
substituting a new CNAME rule. The Domains API distinguishes the SPF record's
owner from its `include:spf.mtasv.net` value. That target is already covered by
the unchanged legacy `mtasv.net` SPF rule, which remains undated because an exact
documented example does not independently verify every suffix match.

The separate correction preserves unmatched chains, recognized CDN attribution
and complete chain evidence, existing Postmark policy-reference detection,
other SPF providers, cache serialization and the two exact additions. Its six
new CNAME retirement assertions and six SPF/description assertions failed
before correction. No collector, owner-list or model parameter changed.
Because the SPF target parser retains non-positive qualifiers and redirects,
the retained description says policy reference, not positive authorization or
actual sending. Cached results can retain old classifications until refreshed
or invalidated; a catalog-driven disappearance is not evidence of target change.

## Collection opportunity and provenance

No owner probes are added. Retool can be observed at an existing bounded prefix
such as `app`, or a name already supplied by CT or another existing source.
Postmark's conventional `pm-bounces` owner is not in the fixed prefix set; it
can be classified only if an existing discovery path supplies it. Arbitrary
owner names are not enumerable, and absence does not establish non-use.

Synthetic pipeline tests exercise the real CNAME walker with a mocked DNS
resolver. They pin owner, complete observed chain, service name, exact selected
rule, application/edge separation, and one classified catalog opportunity.
The related-host result remains outside apex services, slugs, mail-provider
fields and email-control counts. Degraded collection hides the derived claim
while retaining raw evidence for inspection; it does not erase history.

## Gate ledger

| Gate | Evidence |
|---|---|
| Exact shape, reference and date | Anchored escaped patterns, current first-party references, `verified: 2026-09-05` |
| Positive and deceptive-negative fixtures | Exact, uppercase and trailing-dot positives; parent, child, prefixed, embedded and regex-lookalike negatives |
| Sparse, wildcard and provenance boundaries | Empty/wildcard suppression, unavailable CNAME projection, source-owner and chain assertions |
| Synthetic regression budget | Baseline catalog selection suite: 202 passed. Two-addition catalog and surface suite: 292 passed. After the separately scoped retirement, the expanded suite passes 304 tests. No owner-list or model-parameter change. |
| Independent review and integration | Independent first-party and rule-overlap review completed; final provider/control isolation assertions pass. Full local test run: 7,372 passed, 27 skipped, 91.54 percent branch-inclusive coverage against the unchanged 90.2 percent floor. |
| Publication boundary | Require the complete canonical local gate and all exact-head PR and merged-main hosted checks separately. Synthetic tests and YAML existence alone do not establish promotion or publication. |

The suffix-only promotion evaluator cannot execute these anchored regex rules.
They use dedicated detector-contract tests rather than conversion to a broader
suffix. No additive classification diagnostic is presented as an accuracy test.
