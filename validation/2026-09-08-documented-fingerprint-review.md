# Documented fingerprint additions

Date: 2026-09-08 UTC

## Scope

This is a vendor-documentation review with network-free synthetic detector
tests. No target domains, customer records, or direct probes were used. The
decision unit is the individual rule and its emitted claim.

## Dispositions

| Candidate | Exact rule and independent basis | Supported observation and limits |
|---|---|---|
| Tailscale | `subdomain_txt`, `_tailscale-challenge:.`; the [domain verification guide](https://tailscale.com/docs/account/domain-verification) names `_tailscale-challenge.example.com`. | Nonempty TXT at that owner is an administrative verification indicator. It does not establish completed verification, an active mesh, enrollment, or that the queried namespace is the tailnet primary domain. |
| PostHog authentication domain | `subdomain_txt`, `_posthog-challenge:.`; the [SSO guide](https://posthog.com/docs/settings/sso) names `_posthog-challenge.yourdomain.com`. | Nonempty TXT at that owner is an authentication-domain indicator. It does not establish completed verification, enforced SSO, event capture, or a Cloud plan. |
| PostHog managed proxy | `cname_target`, `\.proxy-us\.posthog\.com\.?$`; the [reverse-proxy guide](https://posthog.com/docs/advanced/proxy) shows `*.proxy-us.posthog.com`. | A related host routes to the documented US proxy zone. The current page's example is US-only, so EU or self-hosted proxy forms are not claimed. This does not establish live ingestion or SDK installation. |
| Resend tracking | `cname_target`, `^links1\.resend-dns\.com\.?$`; the [create-domain API example](https://resend.com/docs/api-reference/domains/create-domain) uses `links1.resend-dns.com`. | A related host routes to that tracking endpoint. Dashboard-generated SPF/MX/CNAME variants, including Amazon SES return-path hosts, are not claimed as Resend. |

## Deferred

| Candidate | Reason |
|---|---|
| Bitwarden claimed-domain TXT | The [claimed domains guide](https://bitwarden.com/help/claimed-domains/) uses an apex TXT but does not publish a reusable prefix or owner. |
| Notion verification TXT | Existing rules remain; the current public help surface does not independently date the prefix grammar. |
| PostHog `proxy-eu.posthog.com` | Not named on the reviewed proxy page. |
| Resend `feedback-smtp.*.amazonses.com` MX | Already covered as Amazon SES sending infrastructure, not a Resend-specific inbound or tracking claim. |

## Gate ledger

| Gate | Evidence |
|---|---|
| Exact shape, reference and date | Owner-qualified TXT and exact or zone-anchored CNAME patterns; current first-party URLs; `verified: 2026-09-08` |
| Positive and lookalike negatives | Exact owners; wrong-owner, apex, parent, child, and suffix negatives |
| Sparse and related-host boundaries | Empty collection does not synthesize these slugs; CNAME matches stay on the related host and do not enter apex services |
| Publication boundary | Generic provider patterns, public references, and reserved synthetic fixtures only |
