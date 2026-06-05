# 2026-06-04 - External corroboration spot-check (case-study sanity check)

A small, deliberately external sanity check of recon's vendor detections against
public vendor case studies. This is **not** calibration and **not** a coverage
statistic; it is an independent spot-check that asks: when a vendor publicly
names a customer ("Company X uses Vendor Y"), does recon's passive DNS signal,
run independently on that customer, corroborate the vendor?

This validation layer is **optional and external** to recon. A recon user does
not need it; it is available to anyone who wants extra assurance. recon stays the
passive primitive; the corroboration sits outside it.

Aggregate-only and anonymized by construction. Vendor names are detection
classes and are recorded; the customer companies are not, per the project's
no-real-company-data rule. The per-company runs stay local.

## Method

1. Collect (customer, vendor) pairs from public vendor case studies, across
   DNS-observable vendor classes (CDN, customer identity) plus one deliberately
   hard class (internal workforce identity, which is often not published in
   public DNS).
2. Run recon on each named customer's apex independently.
3. Score each case-study claim as corroborated (recon detects the named vendor),
   silent (recon does not), or contradicted (recon detects something that rules
   the claim out). Record silences honestly, with the reason.

Neutral framing: claims are taken from the vendor's own customer list, recon is
run blind, and silences and their causes are recorded rather than explained away.

## Result (n = 12 case-study claims)

| Vendor class | Claims | Corroborated | Silent | Contradicted |
|---|---|---|---|---|
| CDN (Fastly, Cloudflare, Akamai) | 6 | 4 | 2 | 0 |
| Customer identity (Auth0) | 3 | 2 | 1 | 0 |
| Internal workforce identity (Okta) | 3 | 1 | 2 | 0 |
| **Total** | **12** | **7** | **5** | **0** |

Zero false positives: recon never claimed a vendor a case study contradicts. All
seven positive detections matched the vendor's own published customer claim.

## The silences are principled, not errors

The five silences break into two honest causes, neither of which is recon
mis-reading the surface it examined:

- **Different public surface than the apex (3).** The case study describes the
  vendor on the customer's product infrastructure, a specific application, or a
  login subdomain, while recon analyzed the apex. recon reported what is actually
  on the apex (in one case a different CDN entirely), which is correct for the
  surface it looked at. This is the "scope the claim to recon's observable"
  lesson made concrete: match a case-study claim to the surface recon examines
  before scoring it.
- **Internal / hidden infrastructure (2).** Internal workforce SSO is not
  published in public DNS. recon stays silent rather than guessing. This is the
  intended design property (absent evidence is treated as no evidence, not
  evidence of absence; the Bayesian layer holds the likelihood ratio at 1 for
  hideable infrastructure), and it is the right behavior: a false "they use this
  IdP" would be worse than an honest silence. One of the three workforce-identity
  claims was corroborated because that customer exposes an identity signal in
  public DNS; the other two do not, and recon correctly says nothing.

## What this does and does not show

It shows: in this sample, recon's positive vendor detections are accurate (7 of 7
corroborated, 0 false positives), and its gaps are scope-bounded or hidden by
design, not fabrications.

It does not show: a coverage or calibration statistic. The sample is small
(n = 12) and biased toward companies large enough to appear in vendor case
studies. It is a sanity check, not a frequentist coverage claim, and it carries
the direction-ambiguity caveat surfaced in earlier prototyping (a "company plus
vendor" relationship can run several ways; a published case study scopes it, but
the claim must still be matched to recon's actual observable). It complements,
and does not replace, the oracle-backed calibration (DMARC / SPF / MTA-STS
records as their own truth; M365 / GWS tenancy via the providers' own endpoints)
planned for the C3 calibration work.
