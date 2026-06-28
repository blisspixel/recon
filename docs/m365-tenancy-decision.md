# M365 Tenancy Corroboration Decision

Status: closed for the current external write-up.

## Decision

Do not promote the M365 tenancy result to an independent calibration claim for
this submission. Keep it named as channel-split corroboration.

The current construction remains useful: the predictor is computed from the DNS
channel alone, while the label comes from Microsoft identity endpoints. That
split reduces shared measurement error between recon's shipped full pipeline
and the reference label. It does not remove the upstream common cause: both
channels depend on the domain being provisioned in Microsoft 365 or Entra ID.

## Why No New Instrument Is Adopted

The researched passive candidates are not independent enough for a stronger
paper claim:

- Microsoft OpenID Connect metadata and realm discovery are provider identity
  endpoints. They are appropriate provider attestations, but adding more
  identity endpoints would still read the same tenant registry class.
- Microsoft 365 DNS setup records, including MX, SPF, Autodiscover, DKIM,
  service CNAMEs, SRV records, and TXT verification records, are provisioning
  artifacts from the same tenant and mail setup path that already drives the
  DNS-only predictor.
- Exchange Autodiscover federation-domain information can expose tenant
  domains, but it is still part of the Microsoft 365 tenant and mail discovery
  path. It is useful evidence, not an independent external reference.
- Certificate-transparency names, hosted service CNAMEs, and discovered
  `onmicrosoft.com` breadcrumbs can corroborate footprint visibility, but they
  are optional public artifacts and cannot supply an authoritative negative.

Adopting any of these as a new "independent" instrument would make the paper
look stronger while weakening its epistemic boundary. The honest closure is to
keep the result as corroboration and leave clean independent calibration
unclaimed.

## Allowed Wording

Use this wording family:

- "M365 DNS-only tenancy corroboration."
- "DNS-only predictor compared with provider endpoint attestation."
- "Channel-split corroboration with a shared tenant-provisioning common-cause
  caveat."

Avoid this wording family:

- "Independent M365 calibration."
- "Clean M365 calibration."
- "M365 predictor calibrated independently against Microsoft endpoints."
- "Provider endpoints prove ground truth independent of provisioning."

## Sources Reviewed

- Microsoft identity platform OpenID Connect metadata:
  <https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc>
- Microsoft 365 domain DNS record guidance:
  <https://learn.microsoft.com/en-us/microsoft-365/admin/get-help-with-domains/information-for-dns-records>
- Microsoft 365 external DNS records:
  <https://learn.microsoft.com/en-us/microsoft-365/enterprise/external-domain-name-system-records>

## Closure Criteria

- The draft, outline, claim map, artifact guide, roadmap, and external write-up
  plan all call the result corroboration rather than calibration.
- No open-item table lists the M365 independent-instrument check as a remaining
  blocker for this submission.
- `scripts/check_paper_claims.py` fails if the paper package reintroduces
  M365 calibration wording or drops this decision document.
