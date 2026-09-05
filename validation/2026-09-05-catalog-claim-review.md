# Catalog claim and retirement review

Date: 2026-09-05 UTC

## Scope and evidence

This is a first-party documentation review and synthetic detector regression
pass, not a corpus study or a precision estimate. No target domains, customer
records, credentials, paid sources, or direct probes were used. Existing
historical validation artifacts remain unchanged. The decision unit is the
individual rule and its emitted claim, not the number of catalog entries.

## Dispositions

| Existing rule | Reviewed basis | Decision and bounded claim |
|---|---|---|
| Vercel CNAME target fragment `vercel-dns-` | Vercel documents a [project-specific target family](https://vercel.com/docs/domains/working-with-domains/add-a-domain) and a [general-purpose target](https://vercel.com/docs/domains/set-up-custom-domain). | Replace the fragment with label-bounded `vercel-dns-017.com` and exact `cname.vercel-dns-0.com`. Do not extrapolate to arbitrary numbered domains. Retain legacy routes with configuration-only wording, not authoritative DNS or active hosting claims. |
| SES CNAME target `awsapps.com` | The [AWS access portal guide](https://docs.aws.amazon.com/singlesignon/latest/userguide/using-the-portal.html) uses this domain for IAM Identity Center. | Retire the generic SES attribution; retain separately supported SES receiving MX rules. An unknown generic AWS route does not establish mail or identity deployment. |
| Okta apex TXT `^_oktaverification=` | The [custom-domain guide](https://developer.okta.com/docs/guides/custom-url-domain/main/) separates the generated Host from Data and gives `_oktaverification.login.example.com` as an owner. | Retire the owner/value-confused apex matcher. Do not manufacture an opaque-value fingerprint or new owner enumeration. Other existing Okta rules remain; an undated legacy prefix remains explicitly undated. |
| GitHub Advanced Security `_github-challenge:.+` | [Domain verification](https://docs.github.com/en/organizations/managing-organization-settings/verifying-or-approving-a-domain-for-your-organization) is a separate organization workflow; [security feature availability](https://docs.github.com/en/code-security/getting-started/github-security-features) depends on feature and plan. The reviewed guide does not establish the old fixed owner grammar. | Retire this unsupported product fingerprint and its downstream signal/posture dependencies. Do not relabel a generic challenge as proof of enabled security features or a completed verification. Other GitHub indicators remain. |
| Slack `_slack-challenge:.` | The [current email-domain guide](https://slack.com/help/articles/5513043606547-Claim-and-verify-email-domains) specifies this owner for wildcard domains across paid plans. | Retain and date the owner rule, remove Enterprise-only claims. A nonempty value at this owner is an indicator, not proof of plan, completed verification, SSO enforcement, or active use. The legacy apex prefix remains undated. |
| Glitch `glitch.me` | The [hosting retirement announcement](https://blog.glitch.com/post/changes-are-coming-to-glitch) and [July 2025 follow-up](https://blog.glitch.com/post/goodbye-glitch) describe hosting closure and retained redirects. | Retain as legacy routing or stale configuration, not evidence of a running application. A lifecycle review date is not a live endpoint check. |

Retirement intentionally changes detections. Cached historical results or
caller-held capsules can retain an old slug; fresh collection and replay have
different catalog commitments. Do not silently rewrite those historical
artifacts or claim equal-catalog comparisons. Public lookup fields and network
collection boundaries are unchanged.

## Verification contract

The regression suite exercises positive routes, deceptive suffixes, exact
owner/value distinctions, empty observations, case/trailing-dot handling,
application/edge coexistence, and the absence of the retired product claims.
The generated artifact is rebuilt from the reviewed YAML; existing stable-slug
tests enumerate the intentional retirement instead of removing their guard.
Metadata dates record review of the cited basis, not measured detection
precision or evidence of current service use.

## Research queue, not promoted rules

Whole-catalog review identified two bounded candidates for a separate round:

- Retool's [custom-domain guide](https://docs.retool.com/org-users/guides/cloud/custom-domains)
  documents exact `custom-domain.retool.com`. The candidate would describe a
  route to Retool, not exposed data, running applications, or account ownership.
- Postmark's [custom return-path guide](https://www.postmarkapp.com/support/article/910-how-do-i-add-a-custom-return-path)
  documents exact `pm.mtasv.net`. The candidate would describe return-path
  routing, not inbound mail hosting or observed message delivery. Existing SPF
  and other Postmark rules are not proof that this CNAME opportunity is covered.

Neither candidate is added here. Exact synthetic fixtures, owner-discovery
opportunity analysis, overlap/precedence checks, and independent review come
before promotion. A corpus round, if requested, also needs the frozen frame,
collection boundaries, development/holdout split, and decision ledger in
[catalog maintenance](../docs/catalog-maintenance.md). Do not add probes just
to make a candidate observable, and do not treat new match counts as precision.
