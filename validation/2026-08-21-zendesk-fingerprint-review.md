# Zendesk Fingerprint Review

Status: complete on 2026-08-21; four rules dated from current first-party
evidence; two rules retained undated with narrower claims.

## Scope

This review covers all six Zendesk rules in the built-in catalog. It checks
both the exact DNS shape and the role recon assigns to each observation. It
does not treat a Zendesk-controlled hostname or sender include as evidence of
help-center availability, ticket activity, mail delivery, product edition,
ownership of the queried namespace, or broader Zendesk use.

The previous shared reference,
`https://support.zendesk.com/hc/en-us/articles/4408822492698`, did not provide
usable current support for any of the six cataloged roles on 2026-08-21. The
replacement basis is Zendesk's current
[email DNS troubleshooting guide](https://support.zendesk.com/hc/en-us/articles/4811307516954-How-to-fix-the-email-error-messages-on-forwarding-SPF-DNS-and-TXT-records),
[outbound SPF guide](https://support.zendesk.com/hc/en-us/articles/4408832543770-Allowing-Zendesk-to-send-email-on-behalf-of-your-email-domain),
and
[help-center host-mapping guide](https://support.zendesk.com/hc/en-us/articles/4408838571930-Host-mapping-Changing-the-URL-of-your-help-center).
Exact searches of current Zendesk support found no first-party page naming the
two undated variants for their cataloged DNS roles. Search absence is not
retirement evidence, so those observations remain without review dates.

## Dispositions

| Type and pattern | Current first-party evidence | Decision | Claim boundary |
|---|---|---|---|
| Subdomain TXT `zendeskverification:.` | Current external-email guidance directs the operator to publish an account-provided value at `zendeskverification.<domain>`. | Replace the unsupported apex `zendeskverification=` value, reference the current guide, and date `2026-08-21`. | Email-domain control only. Do not infer help-center hosting, forwarding success, outbound authorization, ticket activity, or broader product use. |
| SPF `mail.zendesk.com` | Current outbound-email guidance recommends `include:mail.zendesk.com` and identifies older `smtp.zendesk.com` and `support.zendesk.com` forms as outdated. | Retain the exact include, reference the current guide, and date `2026-08-21`. | Sender authorization only. Do not infer inbound routing, delivery, ticket activity, or help-center use. |
| CNAME `zendesk.com` | Current host-mapping guidance directs a branded help-center subdomain to the account or brand hostname at `yoursubdomain.zendesk.com`. | Retain the apex or `www` detector, reference the current guide, and date `2026-08-21`. | A route toward Zendesk only. Do not infer activation, reachability, public visibility, or ownership. |
| CNAME target `zendesk.com` | The same current host-mapping guidance supports the related-hostname chain role. | Retain the related-hostname detector, reference the current guide, and date `2026-08-21`. | A route only. Do not infer activation, reachability, ticket activity, product edition, or organizational ownership. |
| TXT `^zendesk-domain-verification=` | No current first-party page found naming this exact apex value. Current email-domain guidance uses the owner-qualified form instead. | Retain undated as a legacy catalog observation and remove the unusable reference. | Do not treat this prefix as the current email-domain flow or infer help-center hosting, SSO, or active account use. |
| SPF `zendesk.com` | Current guidance names the exact `mail.zendesk.com` include, not every possible host under the broader domain family. | Retain undated as a broad legacy observation and remove the unusable reference. | A relationship to a Zendesk-controlled SPF namespace only. Do not claim current recommended configuration or mail delivery. |

## Precision and reproducibility

The review adds dedicated regression coverage for:

- exact metadata, evidence URLs, dates, and bounded descriptions for the four
  current rules;
- explicit undated status and absent references for the two unsupported
  variants;
- exact owner-qualified TXT matching, including rejection of the old apex
  value, lookalike owners, and empty values;
- parsed SPF include matching on DNS-label boundaries;
- apex and `www` CNAME matching on DNS-label boundaries;
- related-hostname CNAME-target matching and deceptive-suffix rejection; and
- exact provenance keys for TXT, SPF, and CNAME observations.

The catalog remains at 869 entries, 692 unique slugs, and 1,108 detections.
Dated coverage rises from 141 to 145 detections, or 13.1 percent, with zero
stale dated rules under the 365-day threshold.
