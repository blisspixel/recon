# Hosting catalog refinement, 2026-10-23

This documentation and offline regression round began at release revision
`114aaa670c2eea8e0e9f06ea0f0dbb069fe2de58`. Its bounded question was whether
six existing hosting and developer-tool families had independently supported
record shapes, DNS boundaries, and appropriately limited claims. It did not
collect customer namespaces, use private result rows, consume a holdout, or
estimate precision, recall, or representative coverage.

The maintainer [catalog-maintenance skill](../agents/maintainer/skills/recon-catalog-maintenance/SKILL.md)
and [fingerprint-triage workflow](../agents/maintainer/skills/recon-fingerprint-triage/SKILL.md)
guided the review. The fictional offline maintenance example completed with
zero network calls. Primary vendor documentation was read separately; network
access to those pages is research, not validation of a deployed customer.

## Decisions and primary basis

| Family | Decision | Primary basis checked on 2026-10-23 |
| --- | --- | --- |
| Fly.io | Replace the unbounded apex CNAME regex with the `fly.dev` DNS-label suffix; date and narrow the related-host description. Retire `edgeapp.net` attribution because the reviewed current source does not support that legacy family. Preserve unmatched records. | [Custom domains](https://docs.fly.io/networking/custom-domain) documents app-specific `.fly.dev` CNAME targets and separate ownership/certificate validation. |
| Railway | Narrow apex CNAME attribution to `up.railway.app`; refresh both apex and related-host rules. Retain the existing related-host tier. | [Working with domains](https://docs.railway.com/networking/domains/working-with-domains) documents that routing suffix and requires a separate TXT record. CNAME publication alone is not completed verification. |
| Netlify | Replace corporate-wide `netlify.com` related-host attribution with the exact `apex-loadbalancer.netlify.com` target. Refresh apex and related-host `netlify.app` rules. | [External DNS configuration](https://docs.netlify.com/manage/domains/configure-domains/configure-external-dns/) documents site CNAMEs and the load-balancer target. Flattening can hide the latter; no A-record inference was added. |
| Vercel | Add `_vercel` owner-qualified, nonempty `vc-domain-verify=` TXT detection. Correct the existing legacy CNAME claim so it cannot imply authoritative DNS delegation. | [Claiming domain ownership](https://vercel.com/docs/domains/working-with-domains/claim-domain-ownership) specifies the marker; the [migration guide](https://vercel.com/kb/guide/how-to-migrate-from-fastly-to-vercel-with-zero-downtime) retains `cname.vercel-dns.com` routing. |
| Render | Date and narrow the `onrender.com` apex CNAME rule to published routing only. | [Cloudflare DNS configuration](https://render.com/docs/configure-cloudflare-dns) documents the service CNAME target. |
| Linear | Defer exact TXT grammar review. Leave its existing rule undated; do not treat general domain-claiming documentation as verification of a particular prefix. | [SAML domain management](https://linear.app/docs/saml-and-access-control) requires TXT publication but does not specify the exact value prefix in its text. |

The same review did not independently establish the exact legacy apex TXT
prefixes `vercel-domain-verification=`, `netlify=`, `verified-for-netlify=`,
or `render-domain-verification=`, or the Netlify `netlifyglobalcdn.com`
routing family. Those existing rules remain undated and unreviewed for exact
grammar; this round neither promotes them nor claims they are false. New
Render certificate-validation CNAME families are deferred because routing and
challenge roles need separate treatment. Existing dated Vercel target rules
were not refreshed automatically. The wider undated catalog remains a backlog.

## Regression contracts

The [hosting refinement tests](../tests/test_hosting_catalog_refinement.py)
exercise documented positive routes, case and terminal-dot variants, deceptive
prefixes, appended foreign suffixes, wrong TXT owners, empty markers,
missing and failed DNS sources, duplicate evidence, network-free replay,
complete DNS-source merge, and human and structured rendering.

The new negatives exposed a separate cached-replay bug: plain CNAME suffixes
were compiled as regexes there, although fresh detection used DNS labels.
Both paths now share the same matcher. Explicit regex rules retain regex
semantics and longest-pattern precedence. Related-host attribution remains
separate from apex service claims.

Exact before/after claim digests and retirement reasons are retained in the
[rule review ledger](../docs/catalog-rule-reviews.json). The generated catalog,
freshness gate, and finite cross-slug overlap gate cover the resulting catalog;
the latter does not prove general regex equivalence or empirical collision rates.

## Aggregate scope

| Built-in catalog measure | Before | After |
| --- | ---: | ---: |
| Entries | 873 | 873 |
| Unique slugs | 698 | 698 |
| Detection rules | 1,122 | 1,123 |
| Dated rules | 178 | 188 |
| Undated rules | 944 | 935 |
| Dated share | 15.9% | 16.7% |
| Dated rules older than 365 days | 0 | 0 |

The net addition combines four new rule identities, three retired identities,
and six existing-rule edits, each with an explicit semantic disposition.
The unchanged entry and slug counts are intentional: correct boundaries and
claims matter more than inflating catalog size. No model, collector, lookup
flag, or operator setup was added. The existing generic TXT collector obtains
the newly documented `_vercel` owner through its catalog rules.

These are finite synthetic behavioral guarantees and dated documentation
checks. Collection completeness, real-world accuracy, independent-stratum
performance, and calibrated probabilities were not measured. Hosted CI and
release evidence belong to the associated pull request and release; this memo
does not claim that an unmerged patch was shipped or deployed.
