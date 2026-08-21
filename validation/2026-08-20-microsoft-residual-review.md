# Microsoft Residual Fingerprint Review

Status: complete on 2026-08-20; four rules dated from current first-party
evidence; one rule retained undated with a narrower claim.

## Scope

This review covers only the five Microsoft patterns named in the active
roadmap: `tm-3.office.com`, `svc.cloud.microsoft`, `svc.sovcloud.cn`,
`eo.outlook.com`, and `msv1.invalid`. It decides each rule independently. It
does not stamp Microsoft 365 as a family and does not treat endpoint ownership
as evidence of tenant activation, workload use, or organizational location.

The review checked current Microsoft Learn and Support pages, the official
Microsoft 365 endpoint web service for Worldwide, China, GCC High, and DoD,
and DNS-label behavior. Microsoft-hosted Q&A was treated as discovery material,
not as a current authoritative product contract.

## Disposition

| Pattern | Current first-party evidence | Decision | Claim boundary |
|---|---|---|---|
| `tm-3.office.com` | [Microsoft 365 URLs and IP address ranges](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges) lists `*.office.com` as a required Microsoft 365 endpoint family. | Retain and date `2026-08-20`; replace the unrelated add-domain reference. | A CNAME route into Microsoft 365 infrastructure only. Do not infer Autodiscover, Teams, a tenant, or active use. |
| `svc.cloud.microsoft` | [Unified cloud.microsoft domain for Microsoft 365 apps](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cloud-microsoft-domain) states that `*.cloud.microsoft` is Microsoft-only and used by Microsoft 365 apps and services. Current product pages also publish exact hosts below `svc.cloud.microsoft`. | Retain and date `2026-08-20`; remove the Autodiscover-equivalence claim. | A Microsoft service route only. The shared zone does not identify a workload, tenant, or active use. |
| `svc.sovcloud.cn` | [Microsoft 365 operated by 21Vianet endpoint guidance](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges-21vianet) lists `*.sovcloud.cn` as a required Microsoft 365 Common and Office Online destination. | Retain and date `2026-08-20`; replace the unrelated add-domain reference. | A route into the 21Vianet endpoint family only. Do not infer tenant location, workload, data residency, or subscription. |
| `eo.outlook.com` | [Current inbound SMTP DANE guidance](https://learn.microsoft.com/en-us/exchange/security-and-compliance/how-dane-secures-email) names `mail.eo.outlook.com` as a legacy MX form to replace during DNSSEC adoption. | Narrow the detection to `mail.eo.outlook.com` and date `2026-08-20`. | Exchange Online routing residue or an earlier route. Do not match undocumented sibling zones, call it the current recommended form, or infer DANE enablement. |
| `msv1.invalid` | No current first-party product page found. Microsoft-hosted Q&A results conflict on the operational interpretation, and the current endpoint service does not document the name. The private catalog basis remains 14 corpus observations. | Retain undated; remove the unsupported mid-migration and disabled-inbound claim. | A non-routable Microsoft domain-verification MX observation. Do not infer Exchange Online inbound routing, migration state, or current verification. |

Absence from an endpoint list is not retirement evidence. That is why
`msv1.invalid` is retained rather than removed. Conversely, a broad documented
endpoint suffix does not justify a product-specific workload claim. The three
CNAME descriptions therefore stop at the narrow route observation.

## Verification

The focused gate covers current metadata, positive matches, deceptive suffix
lookalikes, sparse input, and exact matched-rule provenance for all five
patterns. Result: 46 focused tests passed. The deterministic installed catalog
artifact regenerated cleanly with 869 entries and 1,108 detections. Freshness
coverage is 138 dated detections (12.5 percent), with zero stale dated rules.

No paid API or model call was used. External spend: $0.
