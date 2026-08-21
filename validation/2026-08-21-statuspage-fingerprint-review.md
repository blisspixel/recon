# Statuspage Fingerprint Review

Status: complete on 2026-08-21; three rules dated from current first-party
evidence; four rules retained undated with narrower claims.

## Scope

This review covers all seven Statuspage rules in the built-in catalog. It
checks the exact DNS value and the role recon assigns to that value. It does
not treat a Statuspage hostname as evidence of page availability, current
incident activity, subscriber delivery, ownership of the queried namespace,
or use of another Atlassian product.

The previous shared reference,
`https://support.atlassian.com/statuspage/docs/customize-your-status-page/`,
returned HTTP 404 on 2026-08-21. The replacement basis is Atlassian's current
[Configure your DNS](https://support.atlassian.com/statuspage/docs/configure-your-dns/)
guide, supported by the current
[custom-domain guide](https://support.atlassian.com/statuspage/docs/set-a-custom-domain-and-ssl/).
Exact searches of the current Atlassian Statuspage support and developer
surfaces found no first-party page naming the four undated variants for their
cataloged DNS roles. Search absence is not retirement evidence, so those rules
remain in the catalog without a review date.

## Dispositions

| Type and pattern | Current first-party evidence | Decision | Claim boundary |
|---|---|---|---|
| TXT `^status-page-domain-verification=` | The current DNS guide publishes this prefix followed by an organization code for custom notification-sending domain ownership. A disclosure-safe example is `status-page-domain-verification=synthetic-domain-token-001`. | Retain, reference the current guide, date `2026-08-21`, and replace the unrelated SSO and provisioning wording. | Domain control for Statuspage notification email configuration only. Do not infer page hosting, SSO, incidents, or delivered mail. |
| SPF `stspg-customer.com` | The current DNS guide requires an SPF record including `stspg-customer.com` for a custom notification-sending address. | Retain, reference the current guide, and date `2026-08-21`. | Sender authorization only. Do not infer page hosting, subscriber delivery, incidents, or broader Atlassian use. |
| CNAME target `stspg-customer.com` | The current DNS guide publishes `<PAGE_CODE>.stspg-customer.com` as the expected custom-domain CNAME target. | Retain, reference the current guide, and date `2026-08-21`. | A route toward a Statuspage page only. Do not infer activation, visibility, current health, or organizational ownership. |
| TXT `^statuspage-domain-verification=` | No current first-party page found. The current documented value contains `status-page`, not `statuspage`. | Retain undated as a legacy catalog observation and remove the dead reference. | Do not equate this variant with the current custom-email verification flow or infer page hosting, SSO, or active use. |
| CNAME `statuspage.io` | Current guides identify `*.statuspage.io` as the default page hostname, but direct current custom-domain CNAMEs to `stspg-customer.com`. | Retain undated and remove the dead reference. | An observed hostname relationship only. Do not claim it is the current custom-domain route or an active public page. |
| CNAME target `statuspage.io` | Same evidence boundary as the apex or `www` CNAME rule. | Retain undated and remove the dead reference. | An observed chain target only. Do not claim current custom-domain configuration or activity. |
| CNAME target `statuspageio.com` | No current first-party page found naming the host or its role. | Retain undated as a legacy catalog observation and remove the dead reference. | Do not infer current configuration, page activity, or parity with the documented route. |

## Precision and reproducibility

The review adds dedicated regression coverage for:

- exact metadata, evidence URLs, dates, and bounded descriptions for the three
  current rules;
- explicit undated status and absent references for the four unsupported
  variants;
- exact TXT matching;
- parsed SPF include matching on DNS-label boundaries;
- current CNAME-chain matching and deceptive-suffix rejection;
- retained `statuspage.io` CNAME matching and deceptive-suffix rejection; and
- exact provenance keys for TXT, SPF, and CNAME observations.

The catalog remains at 869 entries, 692 unique slugs, and 1,108 detections.
Dated coverage rises from 138 to 141 detections, or 12.7 percent, with zero
stale dated rules under the 365-day threshold.
